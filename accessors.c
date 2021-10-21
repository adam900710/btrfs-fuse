// SPDX-License-Identifier: MIT

#include "accessors.h"

static const struct btrfs_csum {
	u16 size;
} btrfs_csums[] = {
	[BTRFS_CSUM_TYPE_CRC32] = { 4 },
	[BTRFS_CSUM_TYPE_XXHASH] = { 8 },
	[BTRFS_CSUM_TYPE_SHA256] = { 32 },
	[BTRFS_CSUM_TYPE_BLAKE2] = { 32 },
};

u16 btrfs_super_csum_size(const struct btrfs_super_block *sb)
{
	const u16 csum_type = btrfs_super_csum_type(sb);

	return btrfs_csums[csum_type].size;
}

size_t btrfs_super_num_csums(void)
{
	return ARRAY_SIZE(btrfs_csums);
}
