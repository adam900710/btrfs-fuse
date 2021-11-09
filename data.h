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

#endif
