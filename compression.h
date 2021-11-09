// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_COMPRESSION_H
#define BTRFS_FUSE_COMPRESSION_H

#include "compat.h"
#include "ctree.h"

int btrfs_decompress(const struct btrfs_fs_info *fs_info,
		     char *input, u32 input_len,
		     char *output, u32 output_len, u8 compression);

#endif
