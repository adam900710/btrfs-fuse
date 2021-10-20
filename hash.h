// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_HASH_H
#define BTRFS_FUSE_HASH_H

#include <btrfs/kerncompat.h>

int btrfs_csum_data(u16 csum_type, const u8 *data, u8 *out, size_t len);

#endif
