// SPDX-License-Identifier: MIT

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>
#include <uuid.h>
/*
 * For basic MIN()/MAX(), but it's not as good as kernel min()/max(),
 * thus we shouldn't use anything like MIN(x++,y).
 */
#include <sys/param.h>
#include "compat.h"
#include "volumes.h"
#include "super.h"
#include "messages.h"
#include "metadata.h"
#include "ctree.h"
#include "libs/raid56.h"

/*
 * This is for SINGLE/DUP/RAID1C*, which is purely mirror based.
 *
 * No stripe split is needed.
 */
static int mirrored_read(struct btrfs_fs_info *fs_info,
			 struct btrfs_chunk_map *map, char *buf, size_t size,
			 u64 logical, int mirror_num);

/*
 * For RAID0/RAID10, which is pure stripe based with mirrors, no pairty nor
 * stripe rotation.
 */
static int simple_stripe_read(struct btrfs_fs_info *fs_info,
			      struct btrfs_chunk_map *map, char *buf, size_t size,
			      u64 logical, int mirror_nr);

/* For RAID5/6 */
static int raid56_read(struct btrfs_fs_info *fs_info,
		       struct btrfs_chunk_map *map, char *buf, size_t size,
		       u64 logical, int mirror_nr);

const struct btrfs_raid_attr btrfs_raid_array[BTRFS_NR_RAID_TYPES] = {
	[BTRFS_RAID_SINGLE] = {
		.max_mirror = 1,
		.read_func = mirrored_read,
	},
	[BTRFS_RAID_RAID0] = {
		.max_mirror = 1,
		.read_func = simple_stripe_read,
	},
	[BTRFS_RAID_RAID1] = {
		.max_mirror = 2,
		.read_func = mirrored_read,
	},
	[BTRFS_RAID_DUP] = {
		.max_mirror = 2,
		.read_func = mirrored_read,
	},
	[BTRFS_RAID_RAID10] = {
		.max_mirror = 2,
		.read_func = simple_stripe_read,
	},
	[BTRFS_RAID_RAID5] = {
		.max_mirror = 2,
		.read_func = raid56_read,
	},
	[BTRFS_RAID_RAID6] = {
		.max_mirror = 3,
		.read_func = raid56_read,
	},
	[BTRFS_RAID_RAID1C3] = {
		.max_mirror = 3,
		.read_func = mirrored_read,
	},
	[BTRFS_RAID_RAID1C4] = {
		.max_mirror = 4,
		.read_func = mirrored_read,
	},
};

static LIST_HEAD(global_fs_list);

/* Helper structure for raid56 rebuild */
struct raid56_rebuild_ctrl {
	/* Logical bytenr of the full stripe */
	u64 full_stripe_start;
	u64 chunk_flags;
	u16 num_stripes;
	u16 data_stripes;

	/*
	 * >=0 to indicate which stripe is corrupted, while -1 means
	 * not corrupted (e.g. for RAID5, bad_index[1] should always be -1).
	 */
	int bad_index[2];

	/*
	 * data[0] is the first data stripe of the full stripe.
	 * data[data_stripes - 1] is the last data stripe of the full stripe.
	 * data[data_stripes] is the P parity.
	 * data[data_stripes + 1] is the Q parity (only for RAID6).
	 */
	void *data[];
};

static size_t raid56_rebuild_ctrl_size(u16 num_stripes)
{
	return sizeof(struct raid56_rebuild_ctrl) +
	       sizeof(char *) * num_stripes;
}

static void free_raid56_rebuild_ctrl(struct raid56_rebuild_ctrl *ctrl)
{
	int i;

	for (i = 0; i < ctrl->num_stripes; i++)
		free(ctrl->data[i]);
	free(ctrl);
}
static struct raid56_rebuild_ctrl *alloc_raid56_rebuild_ctrl(u16 num_stripes)
{
	struct raid56_rebuild_ctrl *ret;
	int i;

	ret = calloc(1, raid56_rebuild_ctrl_size(num_stripes));
	if (!ret)
		return NULL;

	ret->num_stripes = num_stripes;
	for (i = 0; i < num_stripes; i++) {
		ret->data[i] = calloc(1, BTRFS_STRIPE_LEN);
		if (!ret->data[i])
			goto error;
	}
	return ret;
error:
	free_raid56_rebuild_ctrl(ret);
	return NULL;
}

static int global_add_device(const char* path, const u8 *fsid,
			     const u8 *dev_uuid, u64 devid)
{
	struct btrfs_fs_devices *fs_devs;
	struct btrfs_fs_devices *found_fs_devs = NULL;
	struct btrfs_device *dev;
	struct btrfs_device *found_dev = NULL;

	list_for_each_entry(fs_devs, &global_fs_list, fs_list) {
		if (memcmp(fsid, fs_devs->fsid, BTRFS_UUID_SIZE) == 0) {
			found_fs_devs = fs_devs;
			break;
		}
	}
	/* Allocate a new fs_devs */
	if (!found_fs_devs) {
		found_fs_devs = malloc(sizeof(*found_fs_devs));
		if (!found_fs_devs)
			return -ENOMEM;
		INIT_LIST_HEAD(&found_fs_devs->dev_list);
		found_fs_devs->num_devices = 0;
		memcpy(found_fs_devs->fsid, fsid, BTRFS_UUID_SIZE);
		list_add_tail(&found_fs_devs->fs_list, &global_fs_list);
	}

	list_for_each_entry(dev, &found_fs_devs->dev_list, list) {
		/* Conflicts found */
		if (dev->devid == devid &&
		    memcmp(dev_uuid, dev->uuid, BTRFS_UUID_SIZE)) {
			error("conflicting device found for devid %llu",
				devid);
			return -EEXIST;
		}
		if (dev->devid == devid &&
		    !memcmp(dev_uuid, dev->uuid, BTRFS_UUID_SIZE)) {
			found_dev = dev;
			break;
		}
	}
	if (!found_dev) {
		found_dev = malloc(sizeof(*found_dev));
		/*
		 * Here we can exit directly, for worst case we just added an empty
		 * btrfs_fs_dev, can be easily cleaned up.
		 */
		if (!found_dev) {
			if (found_fs_devs->num_devices == 0) {
				list_del(&found_fs_devs->fs_list);
				free(found_fs_devs);
			}
			return -ENOMEM;
		}
		if (path)
			found_dev->path = strndup(path, PATH_MAX);
		if (!found_dev->path && path) {
			if (found_fs_devs->num_devices == 0) {
				list_del(&found_fs_devs->fs_list);
				free(found_fs_devs);
			}
			free(found_dev);
			return -ENOMEM;
		}

		found_dev->devid = devid;
		memcpy(found_dev->uuid, dev_uuid, BTRFS_UUID_SIZE);
		

		/* fd and fs_info will be set when we mount the fs */
		found_dev->fd = -1;
		found_dev->fs_info = NULL;

		/* Add the new device to corresponding fs_devs */
		list_add_tail(&found_dev->list, &found_fs_devs->dev_list);
		found_fs_devs->num_devices++;
	}
	return 0;
}

int btrfs_scan_device(const char *path, struct btrfs_super_block *sb)
{
	struct btrfs_super_block buf;
	u64 devid;
	int ret = 0;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	ret = btrfs_read_from_disk(fd, (char *)&buf, BTRFS_SUPER_INFO_OFFSET,
				   BTRFS_SUPER_INFO_SIZE);
	if (ret < BTRFS_SUPER_INFO_SIZE) {
		if (ret > 0)
			ret = -EIO;
		goto out;
	}

	ret = btrfs_check_super(&buf);
	if (ret < 0)
		goto out;
	devid = btrfs_stack_device_id(&buf.dev_item);

	ret = global_add_device(path, buf.fsid, buf.dev_item.uuid, devid);
	if (ret < 0)
		goto out;
	if (sb)
		memcpy(sb, &buf, BTRFS_SUPER_INFO_SIZE);
out:
	close(fd);
	return ret;
}

struct btrfs_fs_devices *btrfs_open_devices(struct btrfs_fs_info *fs_info)
{
	struct btrfs_fs_devices *fs_dev;
	struct btrfs_fs_devices *found_fs_dev = NULL;
	struct btrfs_device *device;
	u8 *fsid = fs_info->fsid;

	list_for_each_entry(fs_dev, &global_fs_list, fs_list) {
		if (!memcmp(fsid, fs_dev->fsid, BTRFS_UUID_SIZE)) {
			found_fs_dev = fs_dev;
			break;
		}
	}
	if (!found_fs_dev)
		return ERR_PTR(-ENOENT);

	list_for_each_entry(device, &found_fs_dev->dev_list, list) {
		/* Already opened */
		if (device->fd >= 0) {
			ASSERT(device->fs_info);
			continue;
		}

		device->fs_info = fs_info;

		/* We allow missing devices (aka, degraded by default) */
		if (!device->path) {
			warning("devid %llu missing", device->devid);
			continue;
		}
		device->fd = open(device->path, O_RDONLY);
		if (device->fd < 0)
			warning("failed to open devid %llu path %s", device->devid,
				device->path);
	}
	return found_fs_dev;
}

/* Find a device which belongs to the fs specified by @fs_info */
struct btrfs_device *btrfs_find_device(struct btrfs_fs_info *fs_info, u64 devid,
				       const u8 *dev_uuid)
{
	struct btrfs_fs_devices *fs_devs = fs_info->fs_devices;
	struct btrfs_device *device;
	struct btrfs_device *found_dev = NULL;

	ASSERT(fs_devs);
	list_for_each_entry(device, &fs_devs->dev_list, list) {
		if (device->devid == devid &&
		    !memcmp(dev_uuid, device->uuid, BTRFS_UUID_SIZE)) {
			found_dev = device;
			break;
		}
	}
	return found_dev;
}

static inline int btrfs_chunk_item_size(int num_stripes)
{
	return sizeof(struct btrfs_chunk) +
		num_stripes * sizeof(struct btrfs_stripe);
}

/*
 * Add a chunk map to @fs_info.
 *
 * @logical:	 Logical bytenr of the chunk
 * @stack_chunk: The chunk item
 * @size_max:	 The maximum chunk size, this is to co-operate with superblock
 * 		 sys_chunk_array which doesn't have item_size to show its size
 */
static int add_chunk_map(struct btrfs_fs_info *fs_info, u64 logical,
			 struct btrfs_chunk *stack_chunk, int max_size)
{
	struct rb_node **p = &fs_info->mapping_root.rb_node;
	struct rb_node *parent = NULL;
	struct btrfs_chunk_map *map;
	u64 length = btrfs_stack_chunk_length(stack_chunk);
	int num_stripes;
	int i;

	/* Sanity check to ensure we don't go beyond @max_size */
	if (btrfs_chunk_item_size(1) > max_size) {
		error("invalid chunk size, expected max %u has minimal %u",
			max_size, btrfs_chunk_item_size(1));
		return -EUCLEAN;
	}
	num_stripes = btrfs_stack_chunk_num_stripes(stack_chunk);
	if (btrfs_chunk_item_size(num_stripes) > max_size) {
		error("invalid chunk size, expected max %u has minimal %u",
			max_size, btrfs_chunk_item_size(num_stripes));
		return -EUCLEAN;
	}
	while (*p) {
		parent = *p;
		map = rb_entry(parent, struct btrfs_chunk_map, node);

		if (logical < map->logical)
			p = &(*p)->rb_left;
		else if (logical > map->logical)
			p = &(*p)->rb_right;
		else if (logical == map->logical && length == map->length &&
			 num_stripes == map->num_stripes)
			return 0;
		else
			return -EEXIST;
	}

	map = calloc(1, btrfs_chunk_map_size(num_stripes));
	if (!map)
		return -ENOMEM;
	map->length = length;
	map->logical = logical;
	map->stripe_len = btrfs_stack_chunk_stripe_len(stack_chunk);
	map->sub_stripes = btrfs_stack_chunk_sub_stripes(stack_chunk);
	map->flags = btrfs_stack_chunk_type(stack_chunk);
	map->num_stripes = num_stripes;

	for (i = 0; i < num_stripes; i++) {
		struct btrfs_device *dev;
		u64 devid = btrfs_stack_stripe_devid(&stack_chunk->stripes[i]);

		dev = btrfs_find_device(fs_info, devid,
					stack_chunk->stripes[i].dev_uuid);
		if (!dev) {
			int ret;

			warning("devid %llu is missing", devid);
			ret = global_add_device(NULL, fs_info->fsid,
					stack_chunk->stripes[i].dev_uuid, devid);
			if (ret < 0) {
				free(map);
				return PTR_ERR(dev);
			}
			dev = btrfs_find_device(fs_info, devid,
					stack_chunk->stripes[i].dev_uuid);
			ASSERT(dev);
		}
		map->stripes[i].dev = dev;
		map->stripes[i].physical =
			btrfs_stack_stripe_offset(&stack_chunk->stripes[i]);
	}
	rb_link_node(&map->node, parent, p);
	rb_insert_color(&map->node, &fs_info->mapping_root);
	return 0;
}

int btrfs_read_sys_chunk_array(struct btrfs_fs_info *fs_info)
{
	struct btrfs_super_block *sb = &fs_info->super_copy;
	u32 sys_chunk_size = btrfs_super_sys_array_size(sb);
	int cur = 0;

	while (cur < sys_chunk_size) {
		struct btrfs_disk_key *disk_key;
		struct btrfs_chunk *chunk;
		u16 num_stripes;
		int ret;
		/*
		 * Make sure we have enough space to contain one disk_key +
		 * one chunk.
		 */
		if (sys_chunk_size - cur < sizeof(struct btrfs_disk_key) +
		    btrfs_chunk_item_size(1)) {
			error(
		"invalid sys_chunk_size, has %u bytes left expected minimal %zu",
				sys_chunk_size - cur,
				sizeof(struct btrfs_disk_key) +
				btrfs_chunk_item_size(1));
			return -EUCLEAN;
		}
		disk_key = (struct btrfs_disk_key *)(sb->sys_chunk_array + cur);
		if (btrfs_disk_key_objectid(disk_key) !=
		    BTRFS_FIRST_CHUNK_TREE_OBJECTID ||
		    btrfs_disk_key_type(disk_key) != BTRFS_CHUNK_ITEM_KEY) {
			error("invalid disk key found, (%llu %u %llu)",
				btrfs_disk_key_objectid(disk_key),
				btrfs_disk_key_type(disk_key),
				btrfs_disk_key_offset(disk_key));
			return -EUCLEAN;
		}
		chunk = (struct btrfs_chunk *)(disk_key + 1);
		num_stripes = btrfs_stack_chunk_num_stripes(chunk);

		ret = add_chunk_map(fs_info, btrfs_disk_key_offset(disk_key),
				chunk, sys_chunk_size - sizeof(*disk_key) - cur);
		if (ret < 0) {
			error("failed to add chunk %llu: %d",
				btrfs_disk_key_offset(disk_key), ret);
			return ret;
		}
		cur += btrfs_chunk_item_size(num_stripes) + sizeof(*disk_key);
	}
	return 0;
}

static int read_one_dev(struct btrfs_fs_info *fs_info, struct btrfs_path *path)
{
	struct btrfs_dev_item *di;
	struct btrfs_device *device;
	u8 fsid[BTRFS_UUID_SIZE];
	u8 dev_uuid[BTRFS_UUID_SIZE];
	u64 devid;

	di = btrfs_item_ptr(path->nodes[0], path->slots[0], struct btrfs_dev_item);
	devid = btrfs_device_id(path->nodes[0], di);

	read_extent_buffer(path->nodes[0], dev_uuid,
			(unsigned long)btrfs_device_uuid(di), BTRFS_UUID_SIZE);
	read_extent_buffer(path->nodes[0], fsid,
			(unsigned long)btrfs_device_fsid(di), BTRFS_UUID_SIZE);
	device = btrfs_find_device(fs_info, devid, dev_uuid);
	if (!device) {
		int ret;

		warning("devid %llu is missing", devid);
		ret = global_add_device(NULL, fsid, dev_uuid, devid);
		if (ret)
			return ret;
	}
	return 0;
}

int btrfs_read_chunk_tree(struct btrfs_fs_info *fs_info)
{
	struct btrfs_path path = {} ;
	struct btrfs_key_range range;
	int ret = 0;

	range.objectid = BTRFS_DEV_ITEMS_OBJECTID;
	range.type_start = range.type_end = BTRFS_DEV_ITEM_KEY;
	range.offset_start = 0;
	range.offset_end = (u64)-1;
	ret = btrfs_search_keys_start(fs_info->chunk_root, &path, &range);
	if (ret < 0) {
		error("failed to read dev items: %d", ret);
		return ret;
	}

	/* Read all device items */
	while (true) {
		ret = read_one_dev(fs_info, &path);
		if (ret < 0)
			goto out;

		ret = btrfs_search_keys_next(&path, &range);
		if (ret < 0)
			goto out;
		if (ret > 0) {
			ret = 0;
			break;
		}
	}

	btrfs_release_path(&path);
	range.objectid = BTRFS_FIRST_CHUNK_TREE_OBJECTID;
	range.type_start = range.type_end = BTRFS_CHUNK_ITEM_KEY;
	range.offset_start = 0;
	range.offset_end = (u64)-1;
	ret = btrfs_search_keys_start(fs_info->chunk_root, &path, &range);
	if (ret < 0) {
		error("failed to read chunk items: %d", ret);
		return ret;
	}

	/* Read all chunk items */
	while (true) {
		struct btrfs_key key;
		struct btrfs_chunk *chunk;

		btrfs_item_key_to_cpu(path.nodes[0], &key, path.slots[0]);
		chunk = (struct btrfs_chunk *)(path.nodes[0]->data +
			btrfs_item_ptr_offset(path.nodes[0], path.slots[0]));

		ret = add_chunk_map(fs_info, key.offset, chunk,
			btrfs_item_size_nr(path.nodes[0], path.slots[0]));
		if (ret < 0)
			goto out;

		ret = btrfs_search_keys_next(&path, &range);
		if (ret < 0)
			goto out;
		if (ret > 0) {
			ret = 0;
			break;
		}
	}

out:
	btrfs_release_path(&path);
	return ret;
}

/* Basic sanity check for reads */
static int check_read(struct btrfs_chunk_map *map, u64 logical, size_t size,
		      int mirror_nr)
{
	enum btrfs_raid_types index = btrfs_bg_flags_to_raid_index(map->flags);
	int max_mirror = btrfs_raid_array[index].max_mirror;

	if (logical >= map->logical + map->length ||
	    logical + size <= map->logical) {
		error("logical %llu is not in chunk range [%llu, %llu)",
			logical, map->logical, map->logical + map->length);
		return -EUCLEAN;
	}
	if (mirror_nr > max_mirror) {
		error("bad mirror_nr for logical %llu, has %u wanted %u",
			logical, max_mirror, mirror_nr);
		return -EUCLEAN;
	}
	return 0;
}

static int mirrored_read(struct btrfs_fs_info *fs_info,
			 struct btrfs_chunk_map *map, char *buf, size_t size,
			 u64 logical, int mirror_nr)
{
	int ret;
	struct btrfs_io_stripe *stripe;
	u64 offset = logical - map->logical;

	ret = check_read(map, logical, size, mirror_nr);
	if (ret < 0)
		return ret;

	stripe = &map->stripes[mirror_nr - 1];

	if (stripe->dev->fd >= 0)
		ret = btrfs_read_from_disk(stripe->dev->fd, buf,
					   stripe->physical + offset, size);
	else
		ret = -EIO;
	return ret;
}

static int simple_stripe_read(struct btrfs_fs_info *fs_info,
			      struct btrfs_chunk_map *map, char *buf, size_t size,
			      u64 logical, int mirror_nr)
{
	struct btrfs_io_stripe *stripe;
	int ret;
	const u64 offset = logical - map->logical;
	const u64 stripe_len = map->stripe_len;
	const u16 sub_stripes = map->sub_stripes;
	const u16 data_stripes = map->num_stripes / map->sub_stripes;
	const u32 full_stripe_len = data_stripes * stripe_len;
	u16 index;
	u64 len;

	ret = check_read(map, logical, size, mirror_nr);
	if (ret < 0)
		return ret;
	/*
	 * Current btrfs is using fixed stripe len (64K), and we will later
	 * rely on round_down() which requires the parameter is power of 2.
	 */
	ASSERT(is_power_of_2(stripe_len));
	len = MIN(size, round_down(offset + stripe_len, stripe_len) - offset);

	/*
	 * Calculate the stripe index.
	 *
	 * offset / stripe_len get the total stripe number.
	 * Then % data_stripes gives which stripe group we should be.
	 *
	 * For RAID1, at this strage it's what we need already.
	 * For RAID10, since we still have another copy, we need to multiply by
	 * sub_stripes, so we can choose the mirror based on mirror_nr.
	 */
	index = (offset / stripe_len) % data_stripes * sub_stripes;
	index += mirror_nr - 1;
	stripe = &map->stripes[index];

	/* Now do the real IO */
	if (stripe->dev->fd >= 0) {
		u64 physical = offset / full_stripe_len * stripe_len +
			       offset % map->stripe_len + stripe->physical;

		ret = btrfs_read_from_disk(stripe->dev->fd, buf, physical, len);
	} else {
		ret = -EIO;
	}
	return ret;
}

static int raid56_read(struct btrfs_fs_info *fs_info,
		       struct btrfs_chunk_map *map, char *buf, size_t size,
		       u64 logical, int mirror_nr)
{
	struct raid56_rebuild_ctrl *ctrl;
	const u64 offset = logical - map->logical;
	const u64 stripe_len = map->stripe_len;
	const u16 num_stripes = map->num_stripes;
	const u16 data_stripes = (map->flags & BTRFS_BLOCK_GROUP_RAID5) ?
				num_stripes - 1 : num_stripes - 2;
	const u16 nr_tolerated = (map->flags & BTRFS_BLOCK_GROUP_RAID5) ?
				 1 : 2;
	/* How many full stripes needs to be skipped */
	const u32 full_stripe_nr = offset / (data_stripes * stripe_len);
	/* Btrfs RAID56 rotate right */
	const int rot = full_stripe_nr % num_stripes;
	struct btrfs_io_stripe *stripe;
	u64 physical;
	u32 read_len;
	u16 raw_stripe_index;
	u16 stripe_index;
	u16 nr_failed = 1;
	int ret;
	int i;

	/* min(data stripe end, read range end) - logical */
	read_len = MIN(round_down(offset, stripe_len) + stripe_len + map->logical,
		       logical + size) - logical;

	/* First get the index as if there is no rotation */
	raw_stripe_index = (offset - full_stripe_nr * (data_stripes * stripe_len)) /
			    stripe_len;
	/* Then add the rotation value */
	stripe_index = (raw_stripe_index + rot) % num_stripes;
	stripe = &map->stripes[stripe_index];

	/* Direct read from data stripes */
	if (mirror_nr <= 1 && stripe->dev->fd > 0) {
		physical = stripe->physical +
			   full_stripe_nr * BTRFS_STRIPE_LEN +
			   offset % BTRFS_STRIPE_LEN;

		return btrfs_read_from_disk(stripe->dev->fd, buf, physical,
					    read_len);
	}

	/* Has to rebuild the data stripe */
	ctrl = alloc_raid56_rebuild_ctrl(num_stripes);
	if (!ctrl)
		return -ENOMEM;

	ctrl->num_stripes = num_stripes;
	ctrl->data_stripes = data_stripes;
	ctrl->chunk_flags = map->flags;
	ctrl->full_stripe_start = full_stripe_nr * data_stripes * stripe_len +
				  map->logical;
	/*
	 * The rebuild contrl doesn't take rotation into consideration.
	 * And since we're here, we already tried and failed to read using
	 * mirror 1, thus the raw_stripe_index must point to the corrupted
	 * data stripe.
	 */
	ctrl->bad_index[0] = raw_stripe_index;

	/* This will be determined later */
	ctrl->bad_index[1] = -1;

	/* Now read all stripes */
	for (i = 0; i < num_stripes; i++) {
		stripe_index = (i + rot) % num_stripes;
		stripe = &map->stripes[stripe_index];
		physical = stripe->physical + full_stripe_nr * BTRFS_STRIPE_LEN;

		if (stripe->dev->fd > 0) {
			ret = btrfs_read_from_disk(stripe->dev->fd,
						   ctrl->data[i], physical,
						   BTRFS_STRIPE_LEN);
			if (ret == BTRFS_STRIPE_LEN)
				continue;
			/* Read failure falls through */
		}

		/* Known corrupted position, no need to update the count */
		if (stripe_index == (raw_stripe_index + rot) % num_stripes)
			continue;

		nr_failed++;
		if (nr_failed > nr_tolerated)
			break;
		ctrl->bad_index[nr_failed - 1] = i;
	}
	if (nr_failed > nr_tolerated) {
		error(
	"not enough stripes to rebuild full stripe %llu, failed %u tolerance %u",
		      ctrl->full_stripe_start, nr_failed, nr_tolerated);
		ret = -EIO;
		goto out;
	}

	/*
	 * TODO: We have no way to tell RAID6 how to exhaust all combinations to
	 * recover data stripes.
	 * This means, if we have two data stripes corrupted, but no device
	 * missing, we will just try to rebuild current stripe using parity.
	 *
	 * Even btrfs kernel implementation has this problem, it's not really
	 * any better than dm/md RAID56 recovery.
	 *
	 * In theory we can expand mirror_nr for RAID6 to try all combinations.
	 */
	ret = raid56_recov(num_stripes, BTRFS_STRIPE_LEN, map->flags,
			   ctrl->bad_index[0], ctrl->bad_index[1],
			   ctrl->data);
	if (ret > 0)
		ret = -EIO;
	if (ret < 0)
		goto out;

	/* Finally copy the recovered data back to buffer */
	memcpy(buf, ctrl->data[raw_stripe_index] + logical % stripe_len,
	       read_len);
	ret = read_len;
out:
	free_raid56_rebuild_ctrl(ctrl);
	return ret;
}

static struct btrfs_chunk_map *lookup_chunk_map(struct btrfs_fs_info *fs_info,
						u64 logical)
{
	struct rb_node *node = fs_info->mapping_root.rb_node;
	struct btrfs_chunk_map *entry;

	while (node) {
		entry = rb_entry(node, struct btrfs_chunk_map, node);

		if (logical < entry->logical)
			node = node->rb_left;
		else if (logical >= entry->logical + entry->length)
			node = node->rb_right;
		else
			return entry;
	}
	return NULL;
}

int btrfs_num_copies(struct btrfs_fs_info *fs_info, u64 logical)
{
	struct btrfs_chunk_map *map;
	enum btrfs_raid_types index;

	map = lookup_chunk_map(fs_info, logical);
	if (!map) {
		error("can not find chunk for logical %llu", logical);
		return -ENOENT;
	}

	index = btrfs_bg_flags_to_raid_index(map->flags);
	return btrfs_raid_array[index].max_mirror;
}

int btrfs_read_logical(struct btrfs_fs_info *fs_info, char *buf, size_t size,
			u64 logical, int mirror_nr)
{
	struct btrfs_chunk_map *map;
	enum btrfs_raid_types index;
	int ret;

	map = lookup_chunk_map(fs_info, logical);
	if (!map) {
		error("can not find chunk for logical %llu", logical);
		return -ENOENT;
	}
	index = btrfs_bg_flags_to_raid_index(map->flags);

	ret = btrfs_raid_array[index].read_func(fs_info, map, buf, size,
			logical, mirror_nr);
	return ret;
}

void btrfs_exit(void)
{
	struct btrfs_fs_devices *fs_devs;
	struct btrfs_fs_devices *tmp_devs;

	list_for_each_entry_safe(fs_devs, tmp_devs, &global_fs_list, fs_list) {
		struct btrfs_device *dev;
		struct btrfs_device *tmp;

		list_for_each_entry_safe(dev, tmp, &fs_devs->dev_list, list) {
			if (dev->fd > 0) {
				char fsid_buf[BTRFS_UUID_UNPARSED_SIZE];

				uuid_unparse(fs_devs->fsid, fsid_buf);
				warning("devid %llu for fsid %s is not closed",
					dev->devid, fsid_buf);
				close(dev->fd);
				dev->fd = -1;
			}
			free(dev->path);
			list_del(&dev->list);
			free(dev);
		}
		list_del(&fs_devs->fs_list);
		free(fs_devs);
	}
}
