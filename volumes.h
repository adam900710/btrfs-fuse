// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_VOLUMES_H
#define BTRFS_FUSE_VOLUMES_H

#include "compat.h"
#include "libs/list.h"
#include "libs/rbtree.h"
#include "ondisk_format.h"

/*
 * Here we use ilog2(BTRFS_BLOCK_GROUP_*) to convert the profile bits to
 * an index.
 * We reserve 0 for BTRFS_RAID_SINGLE, while the lowest profile, ilog2(RAID0),
 * is 3, thus we need this shift to make all index numbers sequential.
 */
#define BTRFS_RAID_SHIFT	(const_ilog2(BTRFS_BLOCK_GROUP_RAID0) - 1)

enum btrfs_raid_types {
	BTRFS_RAID_SINGLE  = 0,
	BTRFS_RAID_RAID0   = const_ilog2(BTRFS_BLOCK_GROUP_RAID0 >> BTRFS_RAID_SHIFT),
	BTRFS_RAID_RAID1   = const_ilog2(BTRFS_BLOCK_GROUP_RAID1 >> BTRFS_RAID_SHIFT),
	BTRFS_RAID_DUP     = const_ilog2(BTRFS_BLOCK_GROUP_DUP >> BTRFS_RAID_SHIFT),
	BTRFS_RAID_RAID10  = const_ilog2(BTRFS_BLOCK_GROUP_RAID10 >> BTRFS_RAID_SHIFT),
	BTRFS_RAID_RAID5   = const_ilog2(BTRFS_BLOCK_GROUP_RAID5 >> BTRFS_RAID_SHIFT),
	BTRFS_RAID_RAID6   = const_ilog2(BTRFS_BLOCK_GROUP_RAID6 >> BTRFS_RAID_SHIFT),
	BTRFS_RAID_RAID1C3 = const_ilog2(BTRFS_BLOCK_GROUP_RAID1C3 >> BTRFS_RAID_SHIFT),
	BTRFS_RAID_RAID1C4 = const_ilog2(BTRFS_BLOCK_GROUP_RAID1C4 >> BTRFS_RAID_SHIFT),
	BTRFS_NR_RAID_TYPES
};

/*
 * Convert block group flags (BTRFS_BLOCK_GROUP_*) to btrfs_raid_types, which
 * can be used as index to access btrfs_raid_array[].
 */
static inline enum btrfs_raid_types __attribute_const__
btrfs_bg_flags_to_raid_index(u64 flags)
{
	u64 profile = flags & BTRFS_BLOCK_GROUP_PROFILE_MASK;

	if (!profile)
		return BTRFS_RAID_SINGLE;

	return ilog2(profile >> BTRFS_RAID_SHIFT);
}

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
	u64 stripe_len;
	u64 flags;
	u16 sub_stripes;

	int num_stripes;
	struct btrfs_io_stripe stripes[];
};

static int inline btrfs_chunk_map_size(int num_stripes)
{
	return sizeof(struct btrfs_chunk_map) +
		num_stripes * sizeof(struct btrfs_io_stripe);
}

/*
 * This is for each profile to provide their own read function.
 *
 * Return the number of bytes read. For striped profiles (RAID0/RAID10/RAID56)
 * we will read at most one stripe a time, thus caller must do the read in a
 * loop to fill all the data.
 *
 * Return <0 for error.
 */
typedef int (*btrfs_raid_read_t)(struct btrfs_fs_info *fs_info,
				  struct btrfs_chunk_map *map, char *buf,
				  size_t size, u64 logical, int mirror_nr);

struct btrfs_raid_attr {
	int max_mirror;
	btrfs_raid_read_t read_func;
};

extern const struct btrfs_raid_attr btrfs_raid_array[BTRFS_NR_RAID_TYPES];

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

int btrfs_read_sys_chunk_array(struct btrfs_fs_info *fs_info);
int btrfs_read_chunk_tree(struct btrfs_fs_info *fs_info);

/*
 * Return >0 for the max mirror number of the chunk containing @logical.
 * Return <0 for error.
 */
int btrfs_num_copies(struct btrfs_fs_info *fs_info, u64 logical);

/*
 * Read from logical bytenr @logical with @mirror_nr as mirror number.
 *
 * This doesn't have any validation like data checksum nor metadata checksum.
 *
 * Return the number of bytes read from @logical.
 * Return <0 for error.
 */
int btrfs_read_logical(struct btrfs_fs_info *fs_info, char *buf, size_t size,
			u64 logical, int mirror_nr);

/* The equivalent of btrfs_cleanup_fs_uuid() of kernel */
void btrfs_exit(void);

#endif
