// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_DATA_H
#define BTRFS_FUSE_DATA_H

#include "metadata.h"

/*
 * Try to locate one csum item for @bytenr.
 *
 * Return btrfs_csum_item pointer to the csum item (must be used with
 * path->nodes[0]).
 * Return ERR_PTR() for error (including no csum found).
 * For ERR_PTR(-ENOENT) case, path will point to the nearest item after
 * @bytenr, in case caller want to know where the next csum starts.
 *
 * Thus caller should check path->nodes[0] and release the path accordingly.
 */
struct btrfs_csum_item *btrfs_lookup_csum(struct btrfs_fs_info *fs_info,
					  struct btrfs_path *path,
					  u64 bytenr);

/*
 * Read data from btrfs logical address @logical.
 *
 * Will do csum check and try to find the copy which pass checksum (if has).
 *
 * Return >0 for the number of bytes read from disk and pass the checksum
 * (if has).
 * Return <0 for error.
 *
 * Thus if we have the following on-disk data layout:
 *
 * 		X	X+4K	X+8K
 * Mirror 1	|XXXXXXX|	|
 * Mirror 2	|	|XXXXXXX|
 *
 * Where X means corrupted data.
 *
 * Then we call btrfs_read_data(fs_info, buf, SZ_8K, X);
 *
 * We will get the return value SZ_4K, with correct data from mirror 2,
 * then we still need to call btrfs_read_data(fs_info, buf + SZ_4K, SZ_4K,
 * X + SZ_4K) to read the next 4K correctly from mirror 1.
 */
ssize_t btrfs_read_data(struct btrfs_fs_info *fs_info, char *buf,
			size_t num_bytes, u64 logical);

#endif
