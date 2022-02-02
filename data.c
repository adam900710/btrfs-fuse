// SPDX-License-Identifier: MIT

#include <sys/param.h>
#include "metadata.h"
#include "volumes.h"
#include "messages.h"
#include "hash.h"
#include "inode.h"
#include "data.h"
#include "compression.h"

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
	if (key.offset + item_size / fs_info->csum_size * fs_info->sectorsize <=
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
#define	BTRFS_CACHE_SIZE	(128 * 1024)

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
	int ret = 0;
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
		} else {
			warning(
			"checksum mismatch for logical bytenr %llu mirror %d",
				logical, mirror_nr);
			ret = -EIO;
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

static ssize_t read_compressed_inline(struct btrfs_fs_info *fs_info,
				      struct btrfs_path *path,
				      struct btrfs_file_extent_item *fi,
				      char *buf)
{
	u32 csize = btrfs_file_extent_inline_item_len(path->nodes[0],
						btrfs_item_nr(path->slots[0]));
	u32 dsize = btrfs_file_extent_ram_bytes(path->nodes[0], fi);
	u8 compression = btrfs_file_extent_type(path->nodes[0], fi);
	char *cbuf;
	int ret;

	ASSERT(dsize <= fs_info->sectorsize);

	cbuf = malloc(csize);
	if (!cbuf)
		return -ENOMEM;

	read_extent_buffer(path->nodes[0], cbuf,
			   btrfs_file_extent_inline_start(fi), csize);

	ret = btrfs_decompress(fs_info, cbuf, csize, buf,
			       dsize, compression);
	memset(buf + dsize, 0, fs_info->sectorsize - dsize);
	if (ret < 0)
		return ret;
	return fs_info->sectorsize;
}

static ssize_t read_compressed_file_extent(struct btrfs_fs_info *fs_info,
					   struct btrfs_path *path,
					   struct btrfs_inode *inode,
					   u64 file_offset, char *buf,
					   u32 num_bytes)
{
	struct btrfs_file_extent_item *fi;
	struct btrfs_key key;
	char *cbuf;	/* Compressed data buffer */
	char *dbuf;	/* Uncompressed data buffer */
	u64 csize;	/* Compressed data size */
	u64 dsize;	/* Uncompressed data size */
	u64 disk_bytenr;
	u64 fi_offset;
	u64 fi_num_bytes;
	u32 cur_off = 0;
	u8 compress;
	u8 type;
	int ret;

	fi = btrfs_item_ptr(path->nodes[0], path->slots[0],
			    struct btrfs_file_extent_item);
	type = btrfs_file_extent_type(path->nodes[0], fi);
	compress = btrfs_file_extent_compression(path->nodes[0], fi);

	/* Prealloc is never compressed */
	ASSERT(type == BTRFS_FILE_EXTENT_INLINE ||
	       type == BTRFS_FILE_EXTENT_REG);

	if (type == BTRFS_FILE_EXTENT_INLINE) {
		ASSERT(file_offset == 0);
		return read_compressed_inline(fs_info, path, fi, buf);
	}

	/* Regular compressed extent */
	csize = btrfs_file_extent_disk_num_bytes(path->nodes[0], fi);
	dsize = btrfs_file_extent_ram_bytes(path->nodes[0], fi);
	disk_bytenr = btrfs_file_extent_disk_bytenr(path->nodes[0], fi);

	/* No hole extent should be compressed */
	ASSERT(disk_bytenr);

	cbuf = malloc(csize);
	dbuf = malloc(dsize);
	if (!cbuf || !dbuf) {
		free(dbuf);
		free(cbuf);
		return -ENOMEM;
	}

	/* Read compressed data */
	while (cur_off < csize) {
		ret = btrfs_read_data(fs_info, cbuf + cur_off, csize - cur_off,
				      disk_bytenr + cur_off);
		if (ret < 0)
			goto out;
		cur_off += ret;
	}

	ret = btrfs_decompress(fs_info, cbuf, csize, dbuf, dsize, compress);
	if (ret < 0)
		goto out;

	/* Now copy the part the file extent item refers to */
	btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);
	fi_offset = btrfs_file_extent_offset(path->nodes[0], fi);
	fi_num_bytes = btrfs_file_extent_num_bytes(path->nodes[0], fi);
	ret = MIN(file_offset + num_bytes, key.offset + fi_num_bytes) - file_offset;
	memcpy(buf, dbuf + (file_offset - key.offset + fi_offset), ret);

out:
	free(cbuf);
	free(dbuf);
	return ret;
}

/* Read a file extent specified by @path into @buf. */
static ssize_t read_file_extent(struct btrfs_fs_info *fs_info,
				struct btrfs_path *path,
				struct btrfs_inode *inode, u64 file_offset,
				char *buf, u32 num_bytes)
{
	struct btrfs_file_extent_item *fi;
	struct btrfs_key key;
	u64 disk_bytenr;
	u64 nr_bytes;
	u32 read_bytes;
	u32 cur_off = 0;
	u8 type;
	int ret;

	ASSERT(path->nodes[0]);
	ASSERT(path->slots[0] < btrfs_header_nritems(path->nodes[0]));
	ASSERT(IS_ALIGNED(file_offset, fs_info->sectorsize) &&
		IS_ALIGNED(num_bytes, fs_info->sectorsize));
	btrfs_item_key_to_cpu(path->nodes[0], &key, path->slots[0]);

	ASSERT(key.objectid == inode->ino && key.type == BTRFS_EXTENT_DATA_KEY);
	fi = btrfs_item_ptr(path->nodes[0], path->slots[0],
			    struct btrfs_file_extent_item);
	type = btrfs_file_extent_type(path->nodes[0], fi);

	if (btrfs_file_extent_compression(path->nodes[0], fi) !=
	    BTRFS_COMPRESS_NONE)
		return read_compressed_file_extent(fs_info, path, inode,
						   file_offset, buf, num_bytes);

	if (type == BTRFS_FILE_EXTENT_INLINE) {
		read_bytes = btrfs_file_extent_ram_bytes(path->nodes[0], fi);
		ASSERT(file_offset == 0 && read_bytes <= fs_info->sectorsize);
		read_extent_buffer(path->nodes[0], buf,
				btrfs_file_extent_inline_start(fi), read_bytes);
		memset(buf + read_bytes, 0, fs_info->sectorsize - read_bytes);
		return fs_info->sectorsize;
	}

	nr_bytes = btrfs_file_extent_num_bytes(path->nodes[0], fi);

	read_bytes = MIN(key.offset + nr_bytes, file_offset + BTRFS_CACHE_SIZE);
	read_bytes = MIN(read_bytes, file_offset + num_bytes);
	read_bytes -= file_offset;

	if (type == BTRFS_FILE_EXTENT_PREALLOC) {
		memset(buf, 0, read_bytes);
		return read_bytes;
	}
	/* A hole extent */
	if (btrfs_file_extent_disk_bytenr(path->nodes[0], fi) == 0) {
		memset(buf, 0, read_bytes);
		return read_bytes;
	}

	/* Regular type */
	disk_bytenr = btrfs_file_extent_disk_bytenr(path->nodes[0], fi) +
		      btrfs_file_extent_offset(path->nodes[0], fi) +
		      file_offset - key.offset;
	while (cur_off < read_bytes) {
		ret = btrfs_read_data(fs_info, buf + cur_off, read_bytes - cur_off,
				      disk_bytenr + cur_off);
		if (ret < 0)
			break;
		cur_off += ret;
	}
	if (ret < 0 && cur_off == 0)
		return ret;
	return cur_off;
}

ssize_t btrfs_read_file(struct btrfs_fs_info *fs_info,
			struct btrfs_inode *inode, u64 file_offset,
			char *buf, u32 num_bytes)
{
	struct btrfs_path path;
	u32 cur_off = 0;
	int ret;

	ASSERT(IS_ALIGNED(file_offset, fs_info->sectorsize) &&
		IS_ALIGNED(num_bytes, fs_info->sectorsize));
	btrfs_init_path(&path);

	while (cur_off < num_bytes) {
		u64 next_offset;

		btrfs_release_path(&path);
		ret = lookup_file_extent(fs_info, &path, inode,
					 file_offset + cur_off, &next_offset);
		if (ret < 0)
			goto out;
		/* No file extent found, mostly NO_HOLES case */
		if (ret > 0) {
			u32 read_bytes;

			read_bytes = MIN(next_offset - file_offset, num_bytes) -
				     cur_off;
			memset(buf + cur_off, 0, read_bytes);
			cur_off += read_bytes;
			continue;
		}

		ret = read_file_extent(fs_info, &path, inode,
				file_offset + cur_off, buf + cur_off,
				num_bytes - cur_off);
		if (ret < 0)
			break;
		cur_off += ret;
	}
out:
	btrfs_release_path(&path);
	if (ret < 0 && cur_off == 0)
		return ret;
	return cur_off;
}
