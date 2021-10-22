// SPDX-License-Identifier: MIT

#include "metadata.h"
#include "messages.h"

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

	eb = calloc(1, sizeof(*eb) + fs_info->nodesize);
	if (!eb)
		return ERR_PTR(-ENOMEM);
	eb->start = logical;
	eb->len = fs_info->nodesize;
	eb->refs = 1;
	eb->fs_info = fs_info;
	rb_link_node(&eb->node, parent, p);
	rb_insert_color(&eb->node, &fs_info->eb_root);

	/*
	 * TODO: need to co-operate with volumes.c to grab the chunk
	 * map and read from disk and verify them.
	 */

	return eb;
}
