// SPDX-License-Identifier: MIT

#include <stdlib.h>
#include "metadata.h"
#include "volumes.h"
#include "messages.h"
#include "hash.h"

void free_extent_buffer(struct extent_buffer *eb)
{
	if (!eb)
		return;
	ASSERT(eb->refs > 0);

	eb->refs--;
	if (eb->refs == 0) {
		rb_erase(&eb->node, &eb->fs_info->eb_root);
		free(eb);
	}
}


void btrfs_init_path(struct btrfs_path *path)
{
	memset(path, 0, sizeof(*path));
}

void btrfs_release_path(struct btrfs_path *path)
{
	int i;

	for (i = BTRFS_MAX_LEVEL - 1; i >= 0; i--) {
		free_extent_buffer(path->nodes[i]);
		path->nodes[i] = NULL;
		path->slots[i] = 0;
	}
}

/* Check the sanity of the tree block, before doing the csum check */
static int verify_tree_block(struct extent_buffer *eb, u8 level,
			     u64 transid, struct btrfs_key *first_key)
{
	if (btrfs_header_bytenr(eb) != eb->start) {
		error("tree block %llu bad bytenr, has %llu expect %llu",
			eb->start, btrfs_header_bytenr(eb), eb->start);
		return -EIO;
	}
	if (btrfs_header_level(eb) != level) {
		error("tree block %llu bad level, has %u expect %u",
			eb->start, btrfs_header_level(eb), level);
		return -EIO;
	}
	if (btrfs_header_generation(eb) != transid) {
		error("tree block %llu bad trasid, has %llu expect %llu",
			eb->start, btrfs_header_generation(eb), transid);
		return -EIO;
	}
	if (first_key) {
		struct btrfs_key found_key;

		if (btrfs_header_level(eb))
			btrfs_node_key_to_cpu(eb, &found_key, 0);
		else
			btrfs_item_key_to_cpu(eb, &found_key, 0);
		if (btrfs_comp_cpu_keys(first_key, &found_key)) {
			error(
	"tree block %llu key mismatch, has (%llu %u %llu) want (%llu %u %llu)",
			      eb->start, found_key.objectid, found_key.type,
			      found_key.offset, first_key->objectid,
			      first_key->type, first_key->offset);
			return -EIO;
		}
	}
	return 0;
}

struct extent_buffer *btrfs_read_tree_block(struct btrfs_fs_info *fs_info,
					    u64 logical, u8 level, u64 transid,
					    struct btrfs_key *first_key)
{
	struct rb_node **p = &fs_info->eb_root.rb_node;
	struct rb_node *parent = NULL;
	struct extent_buffer *eb;
	int mirror_nr;
	int max_mirror;
	int ret = 0;

	while (*p) {
		parent = *p;
		eb = rb_entry(parent, struct extent_buffer, node);
		if (logical < eb->start) {
			p = &(*p)->rb_left;
		} else if (logical > eb->start) {
			p = &(*p)->rb_right;
		} else {
			/*
			 * Even for cached tree block, we still need to verify
			 * it in case of bad level/transid/first_key.
			 */
			ret = verify_tree_block(eb, level, transid, first_key);
			if (ret < 0)
				return ERR_PTR(ret);

			eb->refs++;
			return eb;
		}
	}

	max_mirror = btrfs_num_copies(fs_info, logical);
	if (max_mirror < 0)
		return ERR_PTR(max_mirror);

	eb = calloc(1, sizeof(*eb) + fs_info->nodesize);
	if (!eb)
		return ERR_PTR(-ENOMEM);
	eb->start = logical;
	eb->len = fs_info->nodesize;
	eb->refs = 0;
	eb->fs_info = fs_info;
	for (mirror_nr = 1; mirror_nr <= max_mirror; mirror_nr++) {
		u8 csum[BTRFS_CSUM_SIZE];

		ret = btrfs_read_logical(fs_info, eb->data,
					 fs_info->nodesize, logical, mirror_nr);
		/* Btrfs metadata should be read out in one go. */
		if (ret < fs_info->nodesize)
			continue;
		ret = verify_tree_block(eb, level, transid, first_key);
		if (ret < 0)
			continue;
		btrfs_csum_data(fs_info->csum_type,
				(u8 *)eb->data + BTRFS_CSUM_SIZE, csum,
				fs_info->nodesize - BTRFS_CSUM_SIZE);
		if (memcmp(csum, eb->data, fs_info->csum_size))
			continue;
		/* TODO: Add extra sanity check on the tree block contents */
		eb->refs++;
		rb_link_node(&eb->node, parent, p);
		rb_insert_color(&eb->node, &fs_info->eb_root);
		return eb;
	}

	free(eb);
	return ERR_PTR(-EIO);
}

/*
 * Binary search inside an extent buffer.
 *
 * Since btrfs extent buffer has all its items/nodes put together sequentially,
 * we can do a binary search here.
 */
static int generic_bin_search(struct extent_buffer *eb, unsigned long p,
			      int item_size, const struct btrfs_key *key,
			      int max, int *slot)
{
	int low = 0;
	int high = max;
	int mid;
	int ret;
	unsigned long offset;

	while(low < high) {
		struct btrfs_disk_key *tmp;
		struct btrfs_key tmp_cpu_key;

		mid = (low + high) / 2;
		offset = p + mid * item_size;

		tmp = (struct btrfs_disk_key *)(eb->data + offset);
		btrfs_disk_key_to_cpu(&tmp_cpu_key, tmp);
		ret = btrfs_comp_cpu_keys(&tmp_cpu_key, key);

		if (ret < 0)
			low = mid + 1;
		else if (ret > 0)
			high = mid;
		else {
			*slot = mid;
			return 0;
		}
	}
	*slot = low;
	return 1;
}

/* Locate the slot inside the extent buffer */
static int search_slot_in_eb(struct extent_buffer *eb,
			     const struct btrfs_key *key, int *slot)
{
	if (btrfs_header_level(eb) == 0)
		return generic_bin_search(eb,
					  offsetof(struct btrfs_leaf, items),
					  sizeof(struct btrfs_item),
					  key, btrfs_header_nritems(eb),
					  slot);
	else
		return generic_bin_search(eb,
					  offsetof(struct btrfs_node, ptrs),
					  sizeof(struct btrfs_key_ptr),
					  key, btrfs_header_nritems(eb),
					  slot);
}

static struct extent_buffer *read_node_child(struct extent_buffer *parent,
					     int slot)
{
	struct btrfs_key first_key;
	u64 bytenr;
	u64 gen;

	ASSERT(btrfs_header_level(parent) > 0);
	ASSERT(slot < btrfs_header_nritems(parent));

	bytenr = btrfs_node_blockptr(parent, slot);
	gen = btrfs_node_ptr_generation(parent, slot);
	btrfs_node_key_to_cpu(parent, &first_key, slot);

	return btrfs_read_tree_block(parent->fs_info, bytenr,
			btrfs_header_level(parent) - 1, gen, &first_key);
}

int __btrfs_search_slot(struct btrfs_root *root, struct btrfs_path *path,
			struct btrfs_key *key)
{
	int level;
	int ret = 0;

	/* The path must not hold any tree blocks, or we will leak some eb */
	ASSERT(path->nodes[0] == NULL);
	level = btrfs_header_level(root->node);
	path->nodes[level] = extent_buffer_get(root->node);

	for (; level >= 0; level--) {
		int slot;

		ASSERT(path->nodes[level]);
		ret = search_slot_in_eb(path->nodes[level], key, &slot);
		/*
		 * For nodes if we didn't found a match, we should go previous
		 * slot.
		 * As the current slot has key value larger than our target,
		 * continue search will never hit our target, like this example:
		 *
		 * key = (1, 1, 1)
		 *
		 * 	(1, 1, 0)		(1, 2, 0)
		 * 	    /			    \
		 * (1, 1, 0), (1, 1, 1)		(1, 2, 0), (1, 2, 1)
		 *
		 * In above example, we should go through the child of (1, 1, 0)
		 * other than the slot returned (1, 2, 0).
		 * Not to mention returned slot may be unused.
		 */
		if (level && ret && slot > 0)
			slot--;
		path->slots[level] = slot;

		/* Now read the node for next level */
		if (level > 0) {
			struct extent_buffer *eb;

			eb = read_node_child(path->nodes[level], slot);
			if (IS_ERR(eb)) {
				ret = PTR_ERR(eb);
				goto error;
			}
			path->nodes[level - 1] = eb;
		}
	}
	return ret;
error:
	btrfs_release_path(path);
	return ret;
}

int btrfs_next_leaf(struct btrfs_path *path)
{
	int slot;
	int level;

	for (level = 1; level < BTRFS_MAX_LEVEL; level++) {
		/* No more parent */
		if (!path->nodes[level])
			return 1;

		slot = path->slots[level] + 1;
		/* Parent has next slot, continue to next step */
		if (slot < btrfs_header_nritems(path->nodes[level])) {
			path->slots[level] = slot;
			break;
		}
		/* Parent has no next slot, continue to higher level */
	}
	if (level >= BTRFS_MAX_LEVEL)
		return 1;

	/* Now we're at @slot of @level, go to the left most path */
	for (; level; level--) {
		struct extent_buffer *eb;

		slot = path->slots[level];
		eb = read_node_child(path->nodes[level], slot);
		if (IS_ERR(eb)) {
			btrfs_release_path(path);
			return PTR_ERR(eb);
		}
		free_extent_buffer(path->nodes[level - 1]);
		path->nodes[level - 1] = eb;
		path->slots[level - 1] = 0;
	}
	return 0;
}

int btrfs_search_key(struct btrfs_root *root, struct btrfs_path *path,
		     struct btrfs_key *key)
{
	int ret;

	ret = __btrfs_search_slot(root, path, key);
	if (ret > 0)
		ret = -ENOENT;
	if (ret < 0)
		btrfs_release_path(path);
	return ret;
}

static int key_in_range(struct btrfs_key *key,
			struct btrfs_key_range *range)
{
	struct btrfs_key range_key1;
	struct btrfs_key range_key2;

	range_key1.objectid = range->objectid;
	range_key1.type = range->type_start;
	range_key1.offset = range->offset_start;

	range_key2.objectid = range->objectid;
	range_key2.type = range->type_end;
	range_key2.offset = range->offset_end;

	return (btrfs_comp_cpu_keys(&range_key1, key) <= 0 &&
		btrfs_comp_cpu_keys(key, &range_key2) <= 0);
}

int btrfs_search_keys_start(struct btrfs_root *root, struct btrfs_path *path,
			    struct btrfs_key_range *range)
{
	struct btrfs_key key;
	int ret;

	key.objectid = range->objectid;
	key.type = range->type_start;
	key.offset = range->offset_start;

	ret = __btrfs_search_slot(root, path, &key);
	/* Either found or error */
	if (ret <= 0)
		return ret;

	/* Check if current slot is used first */
	if (path->slots[0] >= btrfs_header_nritems(path->nodes[0])) {
		ret = btrfs_next_leaf(path);
		if (ret > 0)
			ret = -ENOENT;
		if (ret < 0) {
			btrfs_release_path(path);
			return ret;
		}
	}

	/* Check if the found key is in the target range */
	btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
	if (!key_in_range(&key, range)) {
		btrfs_release_path(path);
		return -ENOENT;
	}
	return 0;
}

int btrfs_search_keys_next(struct btrfs_path *path,
			   struct btrfs_key_range *range)
{
	struct btrfs_key key;
	int ret;

	ASSERT(path->nodes[0]);

	path->slots[0]++;
	if (path->slots[0] >= btrfs_header_nritems(path->nodes[0])) {
		ret = btrfs_next_leaf(path);
		if (ret)
			return ret;
	}

	btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
	if (key_in_range(&key, range))
		return 0;
	return 1;
}

static struct btrfs_root *find_cached_subvol_root(struct btrfs_fs_info *fs_info,
						  u64 rootid)
{
	struct rb_node *node = fs_info->subvols_root.rb_node;
	struct btrfs_root *root;

	while (node) {
		root = rb_entry(node, struct btrfs_root, rb_node);

		if (rootid < root->root_key.objectid)
			node = node->rb_left;
		else if (rootid > root->root_key.objectid)
			node = node->rb_right;
		else
			return root;
	}
	return NULL;
}

static int search_root_item(struct btrfs_fs_info *fs_info, u64 rootid,
			    struct btrfs_key *found_key,
			    struct btrfs_root_item *ri)
{
	struct btrfs_key_range key_range;
	struct btrfs_path path;
	int ret;

	/* At this stage, root tree must be initialized */
	ASSERT(fs_info->tree_root);

	btrfs_init_path(&path);
	key_range.objectid = rootid;
	key_range.type_start = key_range.type_end = BTRFS_ROOT_ITEM_KEY;
	key_range.offset_start = 0;
	key_range.offset_end = (u64)-1;

	ret = btrfs_search_keys_start(fs_info->tree_root, &path, &key_range);
	if (ret < 0)
		return ret;

	memset(ri, 0, sizeof(*ri));
	read_extent_buffer(path.nodes[0], ri,
			btrfs_item_ptr_offset(path.nodes[0], path.slots[0]),
			btrfs_item_size_nr(path.nodes[0], path.slots[0]));
	btrfs_item_key_to_cpu(path.nodes[0], found_key, path.slots[0]);
	btrfs_release_path(&path);
	return 0;
}

struct btrfs_root *btrfs_read_root(struct btrfs_fs_info *fs_info, u64 rootid)
{
	struct btrfs_super_block *sb = &fs_info->super_copy;
	struct btrfs_root *root;
	struct btrfs_key root_key = {};
	u64 gen;
	u64 bytenr;
	u8 level;
	int ret;

	/* For non-subvolume trees, return cached result */
	if (rootid == BTRFS_CHUNK_TREE_OBJECTID && fs_info->chunk_root)
		return fs_info->chunk_root;
	if (rootid == BTRFS_ROOT_TREE_OBJECTID && fs_info->tree_root)
		return fs_info->tree_root;
	if (rootid == BTRFS_CSUM_TREE_OBJECTID && fs_info->csum_root)
		return fs_info->csum_root;

	root = find_cached_subvol_root(fs_info, rootid);
	if (root)
		return root;

	root = calloc(1, sizeof(*root));
	if (!root)
		return ERR_PTR(-ENOMEM);

	RB_CLEAR_NODE(&root->rb_node);
	root->fs_info = fs_info;

	root_key.type = BTRFS_ROOT_ITEM_KEY;
	root_key.offset = 0;
	/*
	 * Allocate a new root and read from disk, we need to grab the info for
	 * the root tree block.
	 *
	 * For chunk and root tree, they need to be grabbed from superblock, all
	 * other trees needs to be grabed from tree root.
	 */
	if (rootid == BTRFS_CHUNK_TREE_OBJECTID) {
		gen = btrfs_super_chunk_root_generation(sb);
		level = btrfs_super_chunk_root_level(sb);
		bytenr = btrfs_super_chunk_root(sb);
		root_key.objectid = rootid;
		root_key.type = BTRFS_ROOT_ITEM_KEY;
		root_key.offset = 0;
	} else if (rootid == BTRFS_ROOT_TREE_OBJECTID){
		gen = btrfs_super_generation(sb);
		level = btrfs_super_root_level(sb);
		bytenr = btrfs_super_root(sb);
		root_key.objectid = rootid;
	} else {
		struct btrfs_root_item ri;

		ret = search_root_item(fs_info, rootid, &root_key, &ri);
		if (ret < 0)
			return ERR_PTR(ret);
		gen = btrfs_root_generation(&ri);
		level = btrfs_root_level(&ri);
		bytenr = btrfs_root_bytenr(&ri);
		root->root_dirid = btrfs_root_dirid(&ri);
	}

	memcpy(&root->root_key, &root_key, sizeof(root_key));
	root->node = btrfs_read_tree_block(fs_info, bytenr, level, gen, NULL);
	if (IS_ERR(root->node)) {
		ret = PTR_ERR(root->node);
		free(root);
		return ERR_PTR(ret);
	}

	/* If it's a subvolume tree, also add it to subvols_root rb tree */
	if (is_fstree(rootid)) {
		struct rb_node **p = &fs_info->subvols_root.rb_node;
		struct rb_node *parent = NULL;
		struct btrfs_root *entry;

		while (*p) {
			parent = *p;
			entry = rb_entry(parent, struct btrfs_root, rb_node);

			if (rootid < entry->root_key.objectid) {
				p = &(*p)->rb_left;
			} else if (rootid > entry->root_key.objectid) {
				p = &(*p)->rb_right;
			} else {
				free_extent_buffer(root->node);
				free(root);
				return ERR_PTR(-EEXIST);
			}
		}
		rb_link_node(&root->rb_node, parent, p);
		rb_insert_color(&root->rb_node, &fs_info->subvols_root);
	}
	return root;
}
