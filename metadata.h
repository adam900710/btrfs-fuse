// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_METADATA_H
#define BTRFS_FUSE_METADATA_H

#include "ctree.h"

struct btrfs_path {
	struct extent_buffer *nodes[BTRFS_MAX_LEVEL];
	int slots[BTRFS_MAX_LEVEL];
};

void btrfs_init_path(struct btrfs_path *path);
void btrfs_release_path(struct btrfs_path *path);
static inline int btrfs_comp_cpu_keys(const struct btrfs_key *key1,
				      const struct btrfs_key *key2)
{
	if (key1->objectid > key2->objectid)
		return 1;
	if (key1->objectid < key2->objectid)
		return -1;
	if (key1->type > key2->type)
		return 1;
	if (key1->type < key2->type)
		return -1;
	if (key1->offset > key2->offset)
		return 1;
	if (key1->offset < key2->offset)
		return -1;
	return 0;
}

static inline struct extent_buffer *extent_buffer_get(struct extent_buffer *eb)
{
	eb->refs++;
	return eb;
}

void free_extent_buffer(struct extent_buffer *eb);

/*
 * Read a tree block at logical bytenr @logical.
 *
 * @logical:	The logical bytenr where the tree block should be.
 * @level:	The level the tree block should have.
 * @transid:	The transid the tree block should have.
 * @first_key:	The first key the tree block should have.
 * 		(optional, NULL to skip this check)
 *
 * Return ERR_PTR for error.
 * Return eb if read succeeded.
 */
struct extent_buffer *btrfs_read_tree_block(struct btrfs_fs_info *fs_info,
					    u64 logical, u8 level, u64 transid,
					    struct btrfs_key *first_key);

#endif
