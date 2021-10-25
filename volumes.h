// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_VOLUMES_H
#define BTRFS_FUSE_VOLUMES_H

#include <btrfs/kerncompat.h>
#include "libs/list.h"
#include "libs/rbtree.h"
#include "ondisk_format.h"

/*
 * Describe one single device which has btrfs super block.
 *
 * All involved devices need to be scanned so btrfs can assemble all its
 * devices belonging to one fs.
 */
struct btrfs_device {
	struct list_head list;
	struct btrfs_fs_info *fs_info;

	u64 devid;
	u8 uuid[BTRFS_UUID_SIZE];

	int fd;
	char *path;
};


/* Describe all devices belonging to one btrfs filesystem. */
struct btrfs_fs_devices {
	/* TODO: Find a better way to put seed devices into this list */
	struct list_head dev_list;

	/*
	 * We can have multiple btrfs specified, thus we need to record them
	 * all.
	 */
	struct list_head fs_list;

	u8 fsid[BTRFS_UUID_SIZE];
	int num_devices;

};

struct btrfs_io_stripe {
	struct btrfs_device *dev;
	u64 physical;
};

struct btrfs_chunk_map {
	struct rb_node node;

	u64 logical;
	u64 length;
	u64 flags;

	int num_stripes;
	struct btrfs_io_stripe stripes[];
};

static int inline btrfs_chunk_map_size(int num_stripes)
{
	return sizeof(struct btrfs_chunk_map) +
		num_stripes * sizeof(struct btrfs_io_stripe);
}
/*
 * Try to scan one device for btrfs.
 *
 * Return 0 if it's a btrfs and @sb will be populated.
 * Return <0 if it's not a btrfs.
 */
int btrfs_scan_device(const char *path, struct btrfs_super_block *sb);

/*
 * Open all devices belonging to the fs with @fsid
 *
 * At this stage, @fs_info should be pretty empty with just superblock and
 * fsid populated.
 */
struct btrfs_fs_devices *btrfs_open_devices(struct btrfs_fs_info *fs_info);

#endif
