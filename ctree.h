// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_CTREE_H
#define BTRFS_FUSE_CTREE_H

#include "accessors.h"
#include "libs/rbtree.h"
#include "libs/list.h"

struct btrfs_root {
	struct extent_buffer *node;
	struct btrfs_root_item root_item;
	struct btrfs_key root_key;
	struct btrfs_fs_info *fs_info;

	/* the dirty list is only used by non-reference counted roots */
	struct list_head dirty_list;
	struct rb_node rb_node;

	int refs;
};

struct btrfs_device {
	struct list_head list;
	struct btrfs_fs_info *fs_info;

	u64 type;
	u64 devid;
	u8 uuid[BTRFS_UUID_SIZE];

	int fd;
};

/* Represents a btrfs filesystem */
struct btrfs_fs_info {
	u8 chunk_tree_uuid[BTRFS_UUID_SIZE];
	u8 fsid[BTRFS_UUID_SIZE];

	struct btrfs_root *tree_root;
	struct btrfs_root *default_root;
	struct btrfs_root *chunk_root;
	struct btrfs_root *csum_root;

	/* Records all subvolume trees that are in use */
	struct rb_root subvols_root;

	/* Records logical->physical mappings */
	struct rb_root mapping_root;

	/* Cached generation, the same as superblock::generation */
	u64 generation;

	/* Cached basic sizes */
	u32 nodesize;
	u32 sectorsize;
	struct list_head fs_devices;
	struct btrfs_super_block super_copy;
};

#endif