// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_INODE_H
#define BTRFS_FUSE_INODE_H

#include <btrfs/kerncompat.h>
#include <asm-generic/types.h>
#include "ondisk_format.h"
#include "ctree.h"
#include "metadata.h"

/*
 * Represent one inode in a btrfs.
 *
 * Since each subvolume is a separate inode space, we have can same inode
 * numbers in different subvolumes.
 *
 * Thus in btrfs to locate one inode, we need (subvolid, inode), not just inode
 * number.
 */
struct btrfs_inode {
	struct btrfs_root *root;
	u64 ino;

	/* File type, indicated using BTRFS_FT_* numbers */
	u8 file_type;
};

/*
 * Lookup one name for @dir.
 *
 * NOTE: @name should not contain '/', thus it's really just one name, not
 * a complete path.
 *
 * The result will be put into @inode_ret, which can be either on-stack or
 * allocated memory. (This applies to all @inode_ret in the header)
 */
int btrfs_lookup_one_name(struct btrfs_fs_info *fs_info,
			  struct btrfs_inode *dir, const char *name,
			  size_t name_len, struct btrfs_inode *inode_ret);

/*
 * Resolve a full path.
 *
 * NOTE: the path should not contain soft link (or ".." or "."), and should be
 * absolute path (starts with '/').
 * This is ensured by FUSE already.
 */
int btrfs_resolve_path(struct btrfs_fs_info *fs_info,
		       const char *path, size_t path_len,
		       struct btrfs_inode *inode_ret);

/*
 * Read the softlink destination into @output.
 *
 * @inode must be a soft link.
 *
 * Return >0 for the size of the content read (not including
 * the tailing '\0')
 * Return <0 for error.
 * Under no case it would return 0.
 */
int btrfs_read_link(struct btrfs_fs_info *fs_info,
		    struct btrfs_inode *inode, char *output,
		    size_t output_size);

struct btrfs_iterate_dir_ctrl {
	struct btrfs_path path;
	struct btrfs_inode dir;
	struct btrfs_key_range range;
};

/*
 * Interafaces to iterate one dir.
 *
 * The common usage would be:
 *
 * struct btrfs_iterate_dir_ctrl ctrl = {};
 * int ret;
 *
 * ret = btrfs_iterate_dir_start(fs_info, &ctrl, dir, 0); // start from index 0
 *
 * while (ret == 0) {
 * 	struct btrfs_inode found_entry;
 *	char name_buf[NAME_MAX] = {};
 *	size_t name_len;
 *
 *	ret = btrfs_iterate_dir_get_inode(fs_info, &ctrl,
 *			&found_entry, name_buf, &name_len);
 *	// Do something using found_entry/name_buf.
 *
 *	ret = btrfs_iterate_dir_next(fs_info, &ctrl);
 * }
 * btrfs_iterate_dir_end(fs_info, &ctrl);
 */
int btrfs_iterate_dir_start(struct btrfs_fs_info *fs_info,
			    struct btrfs_iterate_dir_ctrl *ctrl,
			    const struct btrfs_inode *dir, u64 start_index);

int btrfs_iterate_dir_get_inode(struct btrfs_fs_info *fs_info,
				struct btrfs_iterate_dir_ctrl *ctrl,
				struct btrfs_inode *entry,
				u64 *index_ret, char *name, size_t *name_len);

static inline int btrfs_iterate_dir_next(struct btrfs_fs_info *fs_info,
					 struct btrfs_iterate_dir_ctrl *ctrl)
{
	return btrfs_search_keys_next(&ctrl->path, &ctrl->range);
}

static inline void btrfs_iterate_dir_end(struct btrfs_fs_info *fs_info,
					 struct btrfs_iterate_dir_ctrl *ctrl)
{
	btrfs_release_path(&ctrl->path);
}

#endif
