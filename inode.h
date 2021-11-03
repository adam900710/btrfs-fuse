// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_INODE_H
#define BTRFS_FUSE_INODE_H

#include <btrfs/kerncompat.h>
#include <asm-generic/types.h>
#include "ondisk_format.h"
#include "ctree.h"

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
 * allocated memory.
 */
int btrfs_lookup_one_name(struct btrfs_fs_info *fs_info,
			  struct btrfs_inode *dir, const char *name,
			  size_t name_len, struct btrfs_inode *inode_ret);

#endif
