// SPDX-License-Identifier: MIT

#include "metadata.h"
#include "volumes.h"
#include "messages.h"
#include "hash.h"
#include "data.h"

struct btrfs_csum_item *btrfs_lookup_csum(struct btrfs_fs_info *fs_info,
					  struct btrfs_path *path,
					  u64 bytenr)
{
	struct btrfs_key key;
	struct btrfs_csum_item *ci;
	u32 item_size;
	int ret;

	ASSERT(IS_ALIGNED(bytenr, fs_info->sectorsize));
	key.objectid = BTRFS_EXTENT_CSUM_OBJECTID;
	key.type = BTRFS_EXTENT_CSUM_KEY;
	key.offset = bytenr;

	ret = __btrfs_search_slot(fs_info->csum_root, path, &key);
	if (ret < 0) {
		btrfs_release_path(path);
		return ERR_PTR(ret);
	}

	/* The csum we're looking for is at the offset 0 of the item */
	if (ret == 0)
		return btrfs_item_ptr(path->nodes[0], path->slots[0],
				      struct btrfs_csum_item);

	/*
	 * The only time we got slot[0] == 0 without an exact match is when the
	 * tree only has one leaf, and since we didn't get an exact match, it's
	 * no longer possible to find an csum item before us.
	 *
	 * But we don't want to release @path, as caller may use @path to locate
	 * where the next csum starts at.
	 */
	if (path->slots[0] == 0) {
		ASSERT(path->nodes[1] == NULL);
		return ERR_PTR(-ENOENT);
	}

	/*
	 * Now we don't have an exact match, but we have one previous item,
	 * which may contain the bytenr.
	 */
	path->slots[0]--;
	btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
	item_size = btrfs_item_size_nr(path->nodes[0], path->slots[0]);

	/*
	 * Current item doesn't cover our bytenr, step forward to next item so
	 * caller can know where next csum starts.
	 */
	if (key.offset + item_size / fs_info->csum_size * fs_info->sectorsize >=
	    bytenr) {
		path->slots[0]++;
		if (path->slots[0] >= btrfs_header_nritems(path->nodes[0])) {
			ret = btrfs_next_leaf(path);
			if (ret < 0) {
				btrfs_release_path(path);
				return ERR_PTR(ret);
			}
		}
		return ERR_PTR(-ENOENT);
	}

	/* Now current item covers the bytenr, adjust the pointer */
	ci = btrfs_item_ptr(path->nodes[0], path->slots[0],
			    struct btrfs_csum_item);

	ci = (struct btrfs_csum_item *)((char *)ci +
			(bytenr - key.offset) / fs_info->sectorsize *
			fs_info->csum_size);
	return ci;
}
