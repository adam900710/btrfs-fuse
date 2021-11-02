// SPDX-License-Identifier: MIT

#include <unistd.h>
#include <errno.h>
#include <uuid.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "ondisk_format.h"
#include "super.h"
#include "messages.h"
#include "hash.h"
#include "volumes.h"
#include "metadata.h"

int btrfs_read_from_disk(int fd, char *buf, u64 offset, u32 len)
{
	int cur = 0;

	while (cur < len) {
		int ret;

		ret = pread(fd, buf + cur, len - cur, offset + cur);
		if (ret < 0) {
			ret = -errno;
			return ret;
		}
		cur += ret;
	}
	return len;
}

int btrfs_check_super(struct btrfs_super_block *sb)
{
	u8 result[BTRFS_CSUM_SIZE];
	u32 sectorsize;
	u32 nodesize;
	u16 csum_type;
	int csum_size;

	if (btrfs_super_magic(sb) != BTRFS_MAGIC)
		return -EINVAL;

	csum_type = btrfs_super_csum_type(sb);
	if (csum_type >= btrfs_super_num_csums()) {
		error("unsupported checksum algorithm %u", csum_type);
		return -EIO;
	}
	csum_size = btrfs_super_csum_size(sb);

	btrfs_csum_data(csum_type, (u8 *)sb + BTRFS_CSUM_SIZE,
			result, BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE);

	if (memcmp(result, sb->csum, csum_size)) {
		error("superblock checksum mismatch");
		return -EIO;
	}

	/* We don't support seed/dumps/FSID change yet */
	if (btrfs_super_flags(sb) & ~BTRFS_HEADER_FLAG_WRITTEN) {
		error("unsupported super flags: %llx", btrfs_super_flags(sb));
		goto error_out;
	}

	/* Root level checks */
	if (btrfs_super_root_level(sb) >= BTRFS_MAX_LEVEL) {
		error("tree_root level too big: %d >= %d",
			btrfs_super_root_level(sb), BTRFS_MAX_LEVEL);
		goto error_out;
	}
	if (btrfs_super_chunk_root_level(sb) >= BTRFS_MAX_LEVEL) {
		error("chunk_root level too big: %d >= %d",
			btrfs_super_chunk_root_level(sb), BTRFS_MAX_LEVEL);
		goto error_out;
	}
	if (btrfs_super_log_root_level(sb) >= BTRFS_MAX_LEVEL) {
		error("log_root level too big: %d >= %d",
			btrfs_super_log_root_level(sb), BTRFS_MAX_LEVEL);
		goto error_out;
	}

	/* Sectorsize/nodesize checks */
	sectorsize = btrfs_super_sectorsize(sb);
	nodesize = btrfs_super_nodesize(sb);

	if (!is_power_of_2(sectorsize) || sectorsize > BTRFS_SECTORSIZE_MAX ||
	    sectorsize < BTRFS_SECTORSIZE_MIN) {
		error("invalid sectorsize: %u", sectorsize);
		goto error_out;
	}
	if (!is_power_of_2(nodesize) || nodesize> BTRFS_NODESIZE_MAX ||
	    nodesize < BTRFS_NODESIZE_MIN || nodesize < sectorsize) {
		error("invalid nodesize: %u", nodesize);
		goto error_out;
	}

	/*
	 * Root alignment check
	 *
	 * We may have rare case where chunk is sectorsize aligned but not
	 * nodesize aligned.
	 * In that case, we only require sectorsize alignment.
	 */
	if (!IS_ALIGNED(btrfs_super_root(sb), sectorsize)) {
		error("tree_root block unaligned: %llu", btrfs_super_root(sb));
		goto error_out;
	}
	if (!IS_ALIGNED(btrfs_super_chunk_root(sb), sectorsize)) {
		error("chunk_root block unaligned: %llu",
			btrfs_super_chunk_root(sb));
		goto error_out;
	}
	if (!IS_ALIGNED(btrfs_super_log_root(sb), sectorsize)) {
		error("log_root block unaligned: %llu",
			btrfs_super_log_root(sb));
		goto error_out;
	}

	/* Basic size check */
	if (btrfs_super_total_bytes(sb) == 0) {
		error("invalid total_bytes 0");
		goto error_out;
	}
	if (btrfs_super_bytes_used(sb) < 6 * btrfs_super_nodesize(sb)) {
		error("invalid bytes_used %llu", btrfs_super_bytes_used(sb));
		goto error_out;
	}

	if (memcmp(sb->fsid, sb->dev_item.fsid, BTRFS_FSID_SIZE) != 0) {
		char fsid[BTRFS_UUID_UNPARSED_SIZE];
		char dev_fsid[BTRFS_UUID_UNPARSED_SIZE];

		uuid_unparse(sb->fsid, fsid);
		uuid_unparse(sb->dev_item.fsid, dev_fsid);
		error("dev_item UUID does not match fsid: %s != %s",
				dev_fsid, fsid);
		goto error_out;
	}

	/*
	 * Hint to catch really bogus numbers, bitflips or so
	 */
	if (btrfs_super_num_devices(sb) > (1UL << 31)) {
		warning("suspicious number of devices: %llu",
			btrfs_super_num_devices(sb));
	}

	if (btrfs_super_num_devices(sb) == 0) {
		error("number of devices is 0");
		goto error_out;
	}

	/*
	 * Obvious sys_chunk_array corruptions, it must hold at least one key
	 * and one chunk
	 */
	if (btrfs_super_sys_array_size(sb) > BTRFS_SYSTEM_CHUNK_ARRAY_SIZE) {
		error("system chunk array too big %u > %u",
		      btrfs_super_sys_array_size(sb),
		      BTRFS_SYSTEM_CHUNK_ARRAY_SIZE);
		goto error_out;
	}
	if (btrfs_super_sys_array_size(sb) < sizeof(struct btrfs_disk_key)
			+ sizeof(struct btrfs_chunk)) {
		error("system chunk array too small %u < %zu",
		      btrfs_super_sys_array_size(sb),
		      sizeof(struct btrfs_disk_key) +
		      sizeof(struct btrfs_chunk));
		goto error_out;
	}

	return 0;

error_out:
	error("superblock checksum matches but it has invalid members");
	return -EIO;
}

static void free_root(struct btrfs_root *root)
{
	if (!root || IS_ERR(root))
		return;
	free_extent_buffer(root->node);
	free(root);
}

static void free_chunk_maps(struct btrfs_fs_info *fs_info)
{
	struct btrfs_chunk_map *map;
	struct btrfs_chunk_map *tmp;

	rbtree_postorder_for_each_entry_safe(map, tmp, &fs_info->mapping_root,
					     node)
		free(map);
}

void btrfs_unmount(struct btrfs_fs_info *fs_info)
{
	struct btrfs_root *root;
	struct btrfs_root *tmp;
	struct btrfs_device *dev;

	rbtree_postorder_for_each_entry_safe(root, tmp, &fs_info->subvols_root,
					     rb_node)
		free_root(root);

	free_root(fs_info->csum_root);
	free_root(fs_info->tree_root);
	free_root(fs_info->chunk_root);

	/*
	 * At this stage, all extent buffers should be free, just to catch
	 * unreleased ones.
	 */
	if (!RB_EMPTY_ROOT(&fs_info->eb_root)) {
		struct extent_buffer *eb;
		struct extent_buffer *tmp;
		warning("unreleased extent buffers detected");

		rbtree_postorder_for_each_entry_safe(eb, tmp, &fs_info->eb_root,
						     node) {
			warning("eb %llu unreleased", eb->start);
			free(eb);
		}
	}

	/* Now free the chunk maps */
	free_chunk_maps(fs_info);

	if (!fs_info->fs_devices)
		goto out;

	/* Finally close all devices */
	list_for_each_entry(dev, &fs_info->fs_devices->dev_list, list) {
		if (dev->fd >= 0) {
			close(dev->fd);
			dev->fd = -1;
		}
	}
out:
	free(fs_info);
}

static struct btrfs_root *read_default_root(struct btrfs_fs_info *fs_info)
{
	struct btrfs_key_range range;
	struct btrfs_dir_item *di;
	struct btrfs_path path;
	struct btrfs_key key;
	int ret;

	btrfs_init_path(&path);
	range.objectid = BTRFS_ROOT_TREE_DIR_OBJECTID;
	range.type_start = range.type_end = BTRFS_DIR_ITEM_KEY;
	range.offset_start = 0;
	range.offset_end = (u64)-1;

	ret = btrfs_search_keys_start(fs_info->tree_root, &path, &range);
	if (ret < 0)
		return ERR_PTR(ret);
	di = btrfs_item_ptr(path.nodes[0], path.slots[0], struct btrfs_dir_item);
	btrfs_dir_item_key_to_cpu(path.nodes[0], di, &key);
	btrfs_release_path(&path);

	ASSERT(is_fstree(key.objectid));
	return btrfs_read_root(fs_info, key.objectid);
}

struct btrfs_fs_info *btrfs_mount(const char *path)
{
	struct btrfs_fs_info *fs_info;
	int ret;

	fs_info = calloc(1, sizeof(*fs_info));
	if (!fs_info)
		return ERR_PTR(-ENOMEM);

	/* Check if there is btrfs on the device */
	ret = btrfs_scan_device(path, &fs_info->super_copy);
	if (ret < 0) {
		if (ret == -EINVAL)
			error("no btrfs found at %s", path);
		else
			error("failed to scan device %s: %d", path, ret);
		goto error;
	}
	fs_info->sectorsize = btrfs_super_sectorsize(&fs_info->super_copy);
	fs_info->nodesize = btrfs_super_nodesize(&fs_info->super_copy);
	fs_info->csum_type = btrfs_super_csum_type(&fs_info->super_copy);
	fs_info->csum_size = btrfs_super_csum_size(&fs_info->super_copy);
	memcpy(fs_info->fsid, fs_info->super_copy.fsid, BTRFS_UUID_SIZE);

	/* Now open all invovled devices of the fs */
	fs_info->fs_devices = btrfs_open_devices(fs_info);
	if (IS_ERR(fs_info->fs_devices)) {
		ret = PTR_ERR(fs_info->fs_devices);
		error("failed to grab fs_devs: %d", ret);
		goto error;
	}

	/* Then read the system chunk array */
	ret = btrfs_read_sys_chunk_array(fs_info);
	if (ret < 0) {
		error("failed to read system chunk array: %d", ret);
		goto error;
	}

	/* Now we can read the chunk tree */
	fs_info->chunk_root = btrfs_read_root(fs_info,
					      BTRFS_CHUNK_TREE_OBJECTID);
	if (IS_ERR(fs_info->chunk_root)) {
		ret = PTR_ERR(fs_info->chunk_root);
		error("failed to read chunk root: %d", ret);
		goto error;
	}

	/* Then read the chunk tree */
	ret = btrfs_read_chunk_tree(fs_info);
	if (ret < 0) {
		error("failed to iterate chunk tree: %d", ret);
		goto error;
	}

	/* Read the remaining trees */
	fs_info->tree_root = btrfs_read_root(fs_info, BTRFS_ROOT_TREE_OBJECTID);
	if (IS_ERR(fs_info->tree_root)) {
		ret = PTR_ERR(fs_info->tree_root);
		error("failed to read tree root: %d", ret);
		goto error;
	}
	fs_info->csum_root = btrfs_read_root(fs_info, BTRFS_CSUM_TREE_OBJECTID);
	if (IS_ERR(fs_info->csum_root)) {
		ret = PTR_ERR(fs_info->csum_root);
		error("failed to read csum root: %d", ret);
		goto error;
	}
	fs_info->default_root = read_default_root(fs_info);
	if (IS_ERR(fs_info->default_root)) {
		ret = PTR_ERR(fs_info->default_root);
		error("failed to read default root: %d", ret);
		goto error;
	}
	return fs_info;
error:
	btrfs_unmount(fs_info);
	return ERR_PTR(ret);
}
