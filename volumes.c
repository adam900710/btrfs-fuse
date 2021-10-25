// SPDX-License-Identifier: MIT

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>
#include "volumes.h"
#include "disk-io.h"
#include "messages.h"

static LIST_HEAD(global_fs_list);

static struct btrfs_device *global_add_device(const char* path, const u8 *fsid,
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
			return ERR_PTR(-ENOMEM);
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
			return ERR_PTR(-EEXIST);
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
			return ERR_PTR(-ENOMEM);
		}
		found_dev->path = strndup(path, PATH_MAX);
		if (!found_dev->path) {
			if (found_fs_devs->num_devices == 0) {
				list_del(&found_fs_devs->fs_list);
				free(found_fs_devs);
			}
			free(found_dev);
			return ERR_PTR(-ENOMEM);
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

	if (IS_ERR(global_add_device(path, buf.fsid, buf.dev_item.uuid, devid)))
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
	map->flags = btrfs_stack_chunk_type(stack_chunk);
	map->num_stripes = num_stripes;

	for (i = 0; i < num_stripes; i++) {
		struct btrfs_device *dev;
		u64 devid = btrfs_stack_stripe_devid(&stack_chunk->stripes[i]);

		dev = btrfs_find_device(fs_info, devid,
					stack_chunk->stripes[i].dev_uuid);
		if (!dev) {
			warning("devid %llu is missing", devid);
			dev = global_add_device(NULL, fs_info->fsid,
					stack_chunk->stripes[i].dev_uuid, devid);
			if (IS_ERR(dev)) {
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
