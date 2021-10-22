// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_DISK_IO_H
#define BTRFS_FUSE_DISK_IO_H

#include "ctree.h"

/*
 * Read directly from physical @offset from disk.
 *
 * This is only used by superblock which is not chunk mapped.
 */
int btrfs_read_from_disk(int fd, char *buf, u64 offset, u32 len);

int btrfs_check_super(struct btrfs_super_block *sb);

#endif