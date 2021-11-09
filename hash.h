// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_HASH_H
#define BTRFS_FUSE_HASH_H

#include "compat.h"
#include "libs/crc32c.h"

int btrfs_csum_data(u16 csum_type, const u8 *data, u8 *out, size_t len);

static inline u64 btrfs_name_hash(const char *name, int len)
{
	return crc32c((u32)~1, name, len);
}

#endif
