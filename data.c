// SPDX-License-Identifier: MIT

#include <sys/param.h>
#include "metadata.h"
#include "volumes.h"
#include "messages.h"
#include "hash.h"
#include "inode.h"
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

static inline u32 bytes_to_csum_size(struct btrfs_fs_info *fs_info, u32 bytes)
{
	return bytes / fs_info->sectorsize * fs_info->csum_size;
}

static inline u32 csum_size_to_bytes(struct btrfs_fs_info *fs_info,
				     u32 csum_size)
{
	return csum_size / fs_info->csum_size * fs_info->sectorsize;
}

/*
 * Verify the data checksum.
 *
 * Return >=0 for how many bytes passed the data checksum.
 */
static u32 check_data_csum(struct btrfs_fs_info *fs_info,
			   const char *buf, size_t buf_bytes,
			   const char *csum)
{
	u8 result[BTRFS_CSUM_SIZE];
	u32 cur;

	ASSERT(IS_ALIGNED(buf_bytes, fs_info->sectorsize));

	for (cur = 0; cur < buf_bytes; cur += fs_info->sectorsize) {
		btrfs_csum_data(fs_info->csum_type, (u8 *)buf + cur, result,
				fs_info->sectorsize);
		if (memcmp(result, csum + bytes_to_csum_size(fs_info, cur),
			   fs_info->csum_size))
			break;
	}
	return cur;
}

/* The maximum size that we read from disk for one batch. */
#define	BTRFS_CACHE_SIZE	(SZ_128K)

ssize_t btrfs_read_data(struct btrfs_fs_info *fs_info, char *buf,
			size_t num_bytes, u64 logical)
{
	struct btrfs_csum_item *ci;
	struct btrfs_path path;
	struct btrfs_key key;
	char *csum_buf;
	bool has_csum;
	u32 bytes_to_read;
	u64 next_range_start;
	int ret;
	int mirror_nr;
	int max_mirror;

	ASSERT(IS_ALIGNED(logical, fs_info->sectorsize) &&
		IS_ALIGNED(num_bytes, fs_info->sectorsize));

	num_bytes = MIN(num_bytes, BTRFS_CACHE_SIZE);

	max_mirror = btrfs_num_copies(fs_info, logical);
	if (max_mirror < 0)
		return max_mirror;

	btrfs_init_path(&path);
	ci = btrfs_lookup_csum(fs_info, &path, logical);
	if (IS_ERR(ci)) {
		has_csum = false;
		ret = PTR_ERR(ci);
		/*
		 * We may still have path pointing to the next item, get the
		 * start bytenr of the next item, so we know how many bytes
		 * don't have csum.
		 */
		if (ret == -ENOENT && path.nodes[0] &&
		    path.slots[0] < btrfs_header_nritems(path.nodes[0])) {
			btrfs_item_key_to_cpu(path.nodes[0], &key,
					      path.slots[0]);
			next_range_start = key.offset;
		} else {
			next_range_start = logical + num_bytes;
		}
		csum_buf = NULL;
		bytes_to_read = MIN(next_range_start, logical + num_bytes) -
				logical;
	} else {
		u32 item_size;

		has_csum = true;
		/*
		 * We got an csum item covering the starting bytenr, thus
		 * @next_range_start should be the end of the csum item.
		 */
		btrfs_item_key_to_cpu(path.nodes[0], &key, path.slots[0]);
		item_size = btrfs_item_size_nr(path.nodes[0], path.slots[0]);

		next_range_start = csum_size_to_bytes(fs_info, item_size) +
				   key.offset;
		bytes_to_read = MIN(next_range_start, logical + num_bytes) -
				logical;
		csum_buf = malloc(bytes_to_csum_size(fs_info, bytes_to_read));
		if (!csum_buf) {
			btrfs_release_path(&path);
			return -ENOMEM;
		}
		read_extent_buffer(path.nodes[0], csum_buf, (unsigned long)ci,
				   bytes_to_csum_size(fs_info, bytes_to_read));
	}
	btrfs_release_path(&path);

	/*
	 * Now we have @has_csum, @csum_buf, @bytes_to_read setup,
	 * we can read the data from disk.
	 */
	for (mirror_nr = 1; mirror_nr <= max_mirror; mirror_nr++) {
		u32 bytes_csum_ok;

		ret = btrfs_read_logical(fs_info, buf, bytes_to_read, logical,
					 mirror_nr);
		/* Read completely failed, mostly missing dev, go next copy */
		if (ret < 0)
			continue;
		if (has_csum)
			bytes_csum_ok = check_data_csum(fs_info, buf, ret,
							csum_buf);
		else
			bytes_csum_ok = ret;
		/* Got some csum match, return the read bytes */
		if (bytes_csum_ok > 0) {
			ret = bytes_csum_ok;
			break;
		}
	}
	free(csum_buf);
	return ret;
}

/*
 * Lookup the file extent for file_offset
 *
 * Return 0 if we find an file extent which covers @file_offset, and @path
 * will point to it.
 *
 * Return >0 if we can't find an file extent, and @next_file_offset_ret
 * will be updated to indicate the next file offset where we can find the next
 * file extent. This behavior can be very handy for NO_HOLES cases to skip
 * to next non-hole extent.
 *
 * Return <0 for error.
 */
static int lookup_file_extent(struct btrfs_fs_info *fs_info,
			      struct btrfs_path *path,
			      struct btrfs_inode *inode, u64 file_offset,
			      u64 *next_file_offset_ret)
{
	struct btrfs_file_extent_item *fi;
	struct btrfs_key key;
	u64 next_offset = (u64)-1;
	u64 extent_len;
	u8 type;
	int ret;

	ASSERT(IS_ALIGNED(file_offset, fs_info->sectorsize));
	key.objectid = inode->ino;
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = file_offset;

	ret = __btrfs_search_slot(inode->root, path, &key);
	/* Either we fond an exact match or error */
	if (ret <= 0)
		return ret;

	/*
	 * Check btrfs_lookup_csum() for reason why path->slots[0] == 0 case
	 * means no match at all.
	 */
	if (path->slots[0] == 0)
		goto not_found;

	/* Check if previous item covers @file_offset. */
	path->slots[0]--;
	btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);

	/* Previous item doesn't even belong to this inode, no found */
	if (key.objectid != inode->ino)
		goto not_found;

	/*
	 * Previous item is not an file extent, but belongs to the same inode,
	 * this means we may be before the first file extent, still need to
	 * check next item.
	 */
	if (key.type != BTRFS_EXTENT_DATA_KEY)
		goto next_item;

	/* Now we're at previous file extent which belonds to this inode */
	fi = btrfs_item_ptr(path->nodes[0], path->slots[0],
			    struct btrfs_file_extent_item);

	type = btrfs_file_extent_type(path->nodes[0], fi);
	if (type == BTRFS_FILE_EXTENT_INLINE && key.offset != 0) {
		error("unexpected inline extent at inode %llu file offset %llu",
		      inode->ino, key.offset);
		btrfs_release_path(path);
		return -EUCLEAN;
	}
	if (type == BTRFS_FILE_EXTENT_INLINE)
		extent_len = fs_info->sectorsize;
	else
		extent_len = btrfs_file_extent_num_bytes(path->nodes[0], fi);

	/* The extent covers the range, found */
	if (key.offset + extent_len > file_offset)
		return 0;

next_item:
	/* No found, go next slot to grab next file_offset */
	path->slots[0]++;
	if (path->slots[0] >= btrfs_header_nritems(path->nodes[0])) {
		ret = btrfs_next_leaf(path);
		if (ret)
			goto not_found;
	}
	btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
	if (key.objectid != inode->ino || key.type != BTRFS_EXTENT_DATA_KEY)
		goto not_found;
	next_offset = key.offset;

not_found:
	if (next_file_offset_ret)
		*next_file_offset_ret = next_offset;
	btrfs_release_path(path);
	return 1;
}
