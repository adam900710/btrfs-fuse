// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_METADATA_H
#define BTRFS_FUSE_METADATA_H

#include <stdbool.h>
#include "ctree.h"

struct btrfs_path {
	struct extent_buffer *nodes[BTRFS_MAX_LEVEL];
	int slots[BTRFS_MAX_LEVEL];
};

/* Specify a key range to search */
struct btrfs_key_range {
	/* The search range must have the same objectid */
	u64 objectid;

	/* Result slots will have @type_start <= key.type <= @type_end */
	u8 type_start;
	u8 type_end;

	/* Result slots will have @offset_start <= key.offset <= @offset_end */
	u64 offset_start;
	u64 offset_end;
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

static inline bool is_fstree(u64 rootid)
{
	return (rootid == BTRFS_FS_TREE_OBJECTID) ||
		(rootid >= BTRFS_FIRST_FREE_OBJECTID &&
		 rootid < BTRFS_LAST_FREE_OBJECTID);
}

struct btrfs_root *btrfs_read_root(struct btrfs_fs_info *fs_info, u64 rootid);

/*
 * Go to next sibling leaf
 *
 * Return 0 if next sibling leaf found and update @path.
 * Return >0 if no more next leaf.
 * Return <0 for error.
 */
int btrfs_next_leaf(struct btrfs_path *path);

/*
 * This is the equivalent of kernel/progs btrfs_search_slot(), without the CoW
 * part.
 *
 * Return 0 if an exact match is found.
 * Return <0 if an error occurred.
 * Return >0 if no exact match is found, and @path will point to the slot where
 * the new key should be inserted into.
 *
 * The >0 behavior has several pitfalls:
 *
 * - It may return an unused slot
 *   This means path->slots[0] >= btrfs_header_nritems(path->nodes[0]).
 *
 * - path->slots[0] can be 0 if the tree only has one leaf.
 *   Otherwise, path->slots[0] will never be zero.
 *
 * Thus it's recommened to call btrfs_search_key() and btrfs_search_key_range()
 * wrappers.
 */
int __btrfs_search_slot(struct btrfs_root *root, struct btrfs_path *path,
			struct btrfs_key *key);
/*
 * Search a single key to find an exact match
 *
 * Return 0 if an exact match is found and @path will point to the slot.
 * Return -ENOENT if no exact is found.
 * Return <0 for error.
 */
int btrfs_search_key(struct btrfs_root *root, struct btrfs_path *path,
		     struct btrfs_key *key);

/*
 * Initial a search for a range of keys
 *
 * Return 0 if we found any key matching the range, and @path will point
 * to the slot.
 * Caller then need to call btrfs_search_keys_next() to continue.
 *
 * Return -ENOENT if we can't find any key matching the range
 * Return <0 for error.
 */
int btrfs_search_keys_start(struct btrfs_root *root, struct btrfs_path *path,
			    struct btrfs_key_range *range);

/*
 * Continue the search for a range of keys
 *
 * Return 0 if there is still a key matching the range, and update @path.
 * Return >0 if there is no more such key, @path will still be updated
 * return <0 for error, and @path will be released.
 */
int btrfs_search_keys_next(struct btrfs_path *path,
			   struct btrfs_key_range *range);

#endif
