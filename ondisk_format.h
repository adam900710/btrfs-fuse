// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_ONDISK_FORMAT_H
#define BTRFS_FUSE_ONDISK_FORMAT_H

#include <assert.h>
#include <asm-generic/types.h>
#include <btrfs/kerncompat.h>


/*
 * Supported sectorsize range in theory.
 *
 * This is the minimal IO unit for data.
 *
 * All supported sectorsize must be power of 2.
 * Kernel may only support sectorsize == PAGE_SIZE.
 * (Since v5.14 btrfs has experimental support for 4K sectorsize with 64K page
 *  size)
 */
#define BTRFS_SECTORSIZE_MIN	4096
#define BTRFS_SECTORSIZE_MAX	65536

/* Maximum filename length (without the tailing '\0') */
#define BTRFS_NAME_LEN		255

/*
 * Supported nodesize range.
 *
 * This is the minimal IO unit for metadata.
 *
 * All supported nodesize must be power of 2.
 * Kernel only supports nodesize >= sectorsize.
 */
#define BTRFS_NODESIZE_MIN	4096
#define BTRFS_NODESIZE_MAX	65536

/*
 * The maximum checksum size in bytes, not all checksum algorithms use all
 * available bytes.
 */
#define BTRFS_CSUM_SIZE	32

#define BTRFS_FSID_SIZE 16
#define BTRFS_UUID_SIZE 16

/* Supported checksum algorithms */
enum btrfs_csum_type {
	BTRFS_CSUM_TYPE_CRC32	= 0,
	BTRFS_CSUM_TYPE_XXHASH	= 1,
	BTRFS_CSUM_TYPE_SHA256	= 2,
	BTRFS_CSUM_TYPE_BLAKE2	= 3,
};

/* Location of btrfs super blocks, here we only care the primary superblock */
#define BTRFS_SUPER_INFO_OFFSET 65536

#define BTRFS_SUPER_INFO_SIZE 	4096

#define BTRFS_MAGIC 0x4D5F53665248425FULL /* ascii _BHRfS_M, no null */

/* A subset of needed key types for read-only operations */
#define BTRFS_INODE_ITEM_KEY		1
#define BTRFS_DIR_ITEM_KEY		84
#define BTRFS_DIR_INDEX_KEY		96
#define BTRFS_EXTENT_DATA_KEY		108
#define BTRFS_EXTENT_CSUM_KEY		128
#define BTRFS_ROOT_ITEM_KEY		132
#define BTRFS_DEV_ITEM_KEY		216
#define BTRFS_CHUNK_ITEM_KEY		228

#define BTRFS_ROOT_TREE_OBJECTID	1ULL
#define BTRFS_DEV_ITEMS_OBJECTID	1ULL
#define BTRFS_CHUNK_TREE_OBJECTID	3ULL
#define BTRFS_FS_TREE_OBJECTID		5ULL

/*
 * This is for a special dir inode in root tree to indicate which root is the
 * default subvolume (stored as a DIR_ITEM).
 */
#define BTRFS_ROOT_TREE_DIR_OBJECTID	6ULL
#define BTRFS_CSUM_TREE_OBJECTID	7ULL
#define BTRFS_FIRST_CHUNK_TREE_OBJECTID	256ULL
#define BTRFS_FIRST_FREE_OBJECTID	256ULL
#define BTRFS_LAST_FREE_OBJECTID	-256ULL
#define BTRFS_EXTENT_CSUM_OBJECTID	-10ULL

/*
 * Describes a device
 *
 * Key format:
 * (BTRFS_DEV_ITEMS_OBJECTID, BTRFS_DEV_ITEM_KEY, <devid>)
 *
 * Tree:
 * Chunk tree, btrfs_super_block::dev_item
 *
 * It provides a binding between (devid, UUID) and FSID , so btrfs can assemble
 * multi-device fs correctly.
 */
struct btrfs_dev_item {
	__le64 devid;
	__le64 total_bytes;

	/* We may want to check this value to ensure the dev item is sane */
	__le64 bytes_used;

	__le32 __unused1[5];

	__le64 generation;

	/*
	 * starting byte of this partition on the device,
	 * to allow for stripe alignment in the future
	 */
	__u8 __unused2[14];

	/* btrfs generated uuid for this device */
	__u8 uuid[BTRFS_UUID_SIZE];

	/* uuid of FS who owns this device */
	__u8 fsid[BTRFS_UUID_SIZE];
} __attribute__ ((__packed__));

#define BTRFS_SYSTEM_CHUNK_ARRAY_SIZE	2048

#define BTRFS_LABEL_SIZE 256

#define BTRFS_HEADER_FLAG_WRITTEN		(1ULL << 0)
#define BTRFS_HEADER_FLAG_RELOC			(1ULL << 0)
/*
 * We have extra BTRFS_SUPER_FLAG_* flags, but we don't want to support them
 * for now.
 */

#define BTRFS_FEATURE_COMPAT_SUPP		0ULL
#define BTRFS_FEATURE_COMPAT_SAFE_SET		0ULL
#define BTRFS_FEATURE_COMPAT_SAFE_CLEAR		0ULL

#define BTRFS_FEATURE_COMPAT_RO_SUPP			\
	(BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE |	\
	 BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE_VALID | \
	 BTRFS_FEATURE_COMPAT_RO_VERITY)

#define BTRFS_FEATURE_COMPAT_RO_SAFE_SET	0ULL
#define BTRFS_FEATURE_COMPAT_RO_SAFE_CLEAR	0ULL

#define BTRFS_FEATURE_INCOMPAT_SUPP			\
	(BTRFS_FEATURE_INCOMPAT_MIXED_BACKREF |		\
	 BTRFS_FEATURE_INCOMPAT_DEFAULT_SUBVOL |	\
	 BTRFS_FEATURE_INCOMPAT_MIXED_GROUPS |		\
	 BTRFS_FEATURE_INCOMPAT_BIG_METADATA |		\
	 BTRFS_FEATURE_INCOMPAT_COMPRESS_LZO |		\
	 BTRFS_FEATURE_INCOMPAT_COMPRESS_ZSTD |		\
	 BTRFS_FEATURE_INCOMPAT_RAID56 |		\
	 BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF |		\
	 BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA |	\
	 BTRFS_FEATURE_INCOMPAT_NO_HOLES	|	\
	 BTRFS_FEATURE_INCOMPAT_RAID1C34	|	\
	 BTRFS_FEATURE_INCOMPAT_ZONED)
/*
 * Decribes the essential info
 *
 * It contains the following types of info:
 * - Lowlevel info
 *   Like csum_type, sectorsize, nodesize, compatible flags, how many devices
 *   are in the fs.
 *
 * - Tree info
 *   Like where the essential trees are (tree root, chunk tree).
 *
 * - Device info
 *   This is for the block device containing this superblock, this is essential
 *   to assemble the devices of a multi-device btrfs.
 *
 * - System chunk array
 *   Most bytenr in btrfs are in btrfs logical address space, thus to bootstrap
 *   we need a subset of the logical address space mapping.
 *   We store all our SYSTEM type chunk mapping into super block, and with
 *   SYSTEM type chunks mapped, we can read the whole chunk tree, then map the
 *   rest of the filesystem.
 *
 * Unnecessary members for read-only operations will be skipped.
 */
struct btrfs_super_block {
	u8 csum[BTRFS_CSUM_SIZE];
	u8 fsid[BTRFS_FSID_SIZE];
	__le64 bytenr;
	__le64 flags;
	__le64 magic;
	__le64 generation;
	__le64 root;
	__le64 chunk_root;
	
	/*
	 * We may still want to check log tree so that one day we can provide
	 * the latest file content in log tree.
	 */
	__le64 log_root;
	__le64 log_root_transid;
	__le64 total_bytes;
	__le64 bytes_used;
	__le64 root_dir_objectid;
	__le64 num_devices;
	__le32 sectorsize;
	__le32 nodesize;
	__le32 __unused1[2];
	__le32 sys_chunk_array_size;
	__le64 chunk_root_generation;
	__le64 compat_flags;
	__le64 compat_ro_flags;
	__le64 incompat_flags;
	__le16 csum_type;
	u8 root_level;
	u8 chunk_root_level;
	u8 log_root_level;
	struct btrfs_dev_item dev_item;

	char label[BTRFS_LABEL_SIZE];

	__le64 __unused2[2];

	u8 __unused3[BTRFS_FSID_SIZE];

	__le64 __unused4[28];
	u8 sys_chunk_array[BTRFS_SYSTEM_CHUNK_ARRAY_SIZE];

	u8 __unused5[1237];
} __attribute__ ((__packed__));

static_assert(sizeof(struct btrfs_super_block) == BTRFS_SUPER_INFO_SIZE);

/*
 * Btrfs metadata blocks has two different types:
 * - leave
 *   Tree blocks at level 0 (lowest level).
 *   Contains both fixed keys and variable length data.
 *
 * - nodes
 *   Tree blocks at level 1~7
 *   Contains fixed keys and position of the child nodes/leaves for each key. 
 *
 * Both nodes and leave share the same header.
 */

#define BTRFS_MAX_LEVEL	8

struct btrfs_header {
	u8 csum[BTRFS_CSUM_SIZE];
	u8 fsid[BTRFS_FSID_SIZE];

	/* Logical bytenr of this tree block */
	__le64 bytenr;
	__le64 flags;

	u8 chunk_tree_uuid[BTRFS_UUID_SIZE];
	__le64 generation;
	__le64 owner;
	__le32 nritems;
	u8 level;
} __attribute__ ((__packed__));


/*
 * Btrfs uses a fixed key to organize all its metadata.
 * It can be considered as a U132 (64 + 8 + 64) value.
 *
 * Type determines the meaning of objectid and offset.
 * For full document on all meanings of different keys, check:
 * https://btrfs.wiki.kernel.org/index.php/On-disk_Format
 */
struct btrfs_disk_key {
	__le64 objectid;
	__u8 type;
	__le64 offset;
} __attribute__ ((__packed__));

/* While for most operation, we use btrfs_key, which is in cpu native endian */
struct btrfs_key {
	__u64 objectid;
	__u8 type;
	__u64 offset;
} __attribute__ ((__packed__));

/*
 * A btrfs leaf puts its data like this:
 *
 * [header][item 0][item 1]..[item n][free space][data n]...[data 0]
 *
 * Each item needs the offset/size inside the leaf to locate the corresponding
 * data.
 */
struct btrfs_item {
	struct btrfs_disk_key key;
	__le32 offset;
	__le32 size;
} __attribute__ ((__packed__));

struct btrfs_leaf {
	struct btrfs_header header;
	struct btrfs_item items[];
} __attribute__ ((__packed__));

/*
 * A btrfs node only contains all keys and locations (in btrfs logical address
 * space) of its children.
 *
 * Thus it doesn't need the offset/size pointer, only need a fixed key_ptr.
 */

struct btrfs_key_ptr {
	struct btrfs_disk_key key;
	__le64 blockptr;
	__le64 generation;
} __attribute__ ((__packed__));

struct btrfs_node {
	struct btrfs_header header;
	struct btrfs_key_ptr ptrs[];
} __attribute__ ((__packed__));


/*
 * Different types of block groups (and chunks).
 *
 * Btrfs has block_group_item::flags and btrfs_chunk_item::flags
 * sharing these flags.
 *
 * DATA|SYSTEM|METADATA indicates the type of the chunk.
 * DATA chunks contain data, while METADATA contains all tree blocks 
 * but chunk tree blocks.
 * SYSTEM chunks contain tree blocks for chunk tree only.
 *
 * DATA and METADATA can co-exist for MIXED_BLOCK_GROUP feature.
 *
 * The rest bits are the profile of the chunk.
 * If none of the profile bit is set, it means SINGLE profile.
 */
#define BTRFS_BLOCK_GROUP_DATA		(1ULL << 0)
#define BTRFS_BLOCK_GROUP_SYSTEM	(1ULL << 1)
#define BTRFS_BLOCK_GROUP_METADATA	(1ULL << 2)

#define BTRFS_BLOCK_GROUP_RAID0		(1ULL << 3)
#define BTRFS_BLOCK_GROUP_RAID1		(1ULL << 4)
#define BTRFS_BLOCK_GROUP_DUP		(1ULL << 5)
#define BTRFS_BLOCK_GROUP_RAID10	(1ULL << 6)
#define BTRFS_BLOCK_GROUP_RAID5         (1ULL << 7)
#define BTRFS_BLOCK_GROUP_RAID6         (1ULL << 8)
#define BTRFS_BLOCK_GROUP_RAID1C3       (1ULL << 9)
#define BTRFS_BLOCK_GROUP_RAID1C4       (1ULL << 10)

#define BTRFS_BLOCK_GROUP_PROFILE_MASK	(BTRFS_BLOCK_GROUP_RAID0 |\
					 BTRFS_BLOCK_GROUP_RAID1 |\
					 BTRFS_BLOCK_GROUP_DUP |\
					 BTRFS_BLOCK_GROUP_RAID10 |\
					 BTRFS_BLOCK_GROUP_RAID5 |\
					 BTRFS_BLOCK_GROUP_RAID6 |\
					 BTRFS_BLOCK_GROUP_RAID1C3 |\
					 BTRFS_BLOCK_GROUP_RAID1C4)

struct btrfs_stripe {
	__le64 devid;

	/* The offset is in physical device bytenr */
	__le64 offset;
	__u8 dev_uuid[BTRFS_UUID_SIZE];
} __attribute__ ((__packed__));

/*
 * Describe a chunk, mapping a logical bytenr range to a physical device range
 *
 * Key format:
 * (BTRFS_CHUNK_TREE_OBJECTID, BTRFS_CHUNK_ITEM_KEY, <logical bytenr>)
 *
 * Tree:
 * Chunk tree
 */
struct btrfs_chunk {
	/* size of this chunk in bytes */
	__le64 length;

	/* objectid of the root referencing this chunk */
	__le64 __unused1;

	/*
	 * The stripe length for stripe based profiles
	 * (RAID0/RAID10/RAID5/RAID6).
	 * Currently it should be fixed to 64K.
	 */
	__le64 stripe_len;
	__le64 type;

	__le32 __unused2[3];

	__le16 num_stripes;

	/* Only for RAID10, and for RAID10, it's fixed to 2 */
	__le16 sub_stripes;

	/* One chunk must have as least one stripe */
	struct btrfs_stripe stripes[];
} __attribute__ ((__packed__));

struct btrfs_timespec {
	__le64 sec;
	__le32 nsec;
} __attribute__ ((__packed__));

/*
 * Describes an inode in btrfs
 *
 * Key format:
 * (<ino>, BTRFS_INODE_ITEM_KEY, 0)
 *
 * Tree:
 * Fs and subvolume tree, root tree (for v1 space cache and default root),
 * log tree.
 */
struct btrfs_inode_item {
	/* At which generation the inode is created */
	__le64 generation;

	/* At which generation the inode is updated */
	__le64 transid;

	/* Total file size in bytes */
	__le64 size;

	/* Real space took in bytes, doesn't take RAID into consideration  */
	__le64 nbytes;

	__le64 __unused1;

	/*
	 * How many hard link the inode has
	 *
	 * For directory it should be at most 1.
	 */
	__le32 nlink;
	__le32 uid;
	__le32 gid;

	/* File type and owner/group/other permission bits */
	__le32 mode;
	__le64 __unused2;

	/* Btrfs specific flags like NODATASUM|NODATACOW */
	__le64 flags;

	__le64 __unused3[5];
	struct btrfs_timespec atime;
	struct btrfs_timespec ctime;
	struct btrfs_timespec mtime;
	struct btrfs_timespec otime;
} __attribute__ ((__packed__));

/*
 * Describe a tree root
 *
 * Key format:
 * (<rootid> BTRFS_ROOT_ITEM_KEY <transid|0>)
 *
 * Tree:
 * Root tree
 *
 * For non-snapshot root, their key::offset will always be 0.
 * For snapshot root, their key::offset will be the generation when the
 * snapshot is created.
 */
struct btrfs_root_item {
	struct btrfs_inode_item inode;
	__le64 generation;
	__le64 root_dirid;
	__le64 bytenr;
	__le64 __unused2[3];
	__le64 flags;
	__le32 __unused3;
	struct btrfs_disk_key __unused4;
	__u8 __unused5;
	__u8 level;

	/*
	 * The following fields appear after subvol_uuids+subvol_times
	 * were introduced. They don't make much difference for read-only,
	 * but we need to make the root item size on-disk, or it will not
	 * be stack safe if we want to read more data into on-disk
	 * btrfs_root_item.
	 */
	__u8 __unused6[200];
} __attribute__ ((__packed__));

#define BTRFS_FT_UNKNOWN	0
#define BTRFS_FT_REG_FILE	1
#define BTRFS_FT_DIR		2
#define BTRFS_FT_CHRDEV		3
#define BTRFS_FT_BLKDEV		4
#define BTRFS_FT_FIFO		5
#define BTRFS_FT_SOCK		6
#define BTRFS_FT_SYMLINK	7
#define BTRFS_FT_XATTR		8

/*
 * Extra info to bind an child inode to its parent inode
 *
 * Key format:
 * (<parent ino>, BTRFS_DIR_(ITEM|INDEX)_KEY, <hash/index>)
 *
 * Tree:
 * Fs and subvolume tree, root tree (for default subvolume), log tree
 *
 * Both BTRFS_DIR_ITEM and BTRFS_DIR_INDEX share the same btrfs_dir_item,
 * just for different purpose.
 *
 * BTRFS_DIR_ITEM stores hash of the filename in its key::offset, while
 * BTRFS_DIR_INDEX stores the index number of the inode.
 *
 * This also means, BTRFS_DIR_ITEM can have hash conflicts and have several
 * different btrfs_dir_item stored in sequence.
 */
struct btrfs_dir_item {
	/*
	 * Where to find the child inode
	 *
	 * It can be either:
	 *
	 * - (<ino>, BTRFS_INODE_KEY, 0)
	 *   Pointing to the inode item inside the same subvolume
	 *
	 * - (<root_id>, BTRFS_ROOT_ITEM, -1)
	 *   Pointing to another subvolume
	 */
	struct btrfs_disk_key location;
	__le64 transid;

	/*
	 * For BTRFS_DIR_ITEM/BTRFS_DIR_INDEX, data_len is always 0.
	 * Only BTRFS_XATTR_ITEM uses this value.
	 */
	__le16 data_len;

	/* The length of the dir/file name, no tailing '\0' */
	__le16 name_len;

	/* Indicate the type of the child inode, using above BTRFS_FT_* number */
	__u8 type;
} __attribute__ ((__packed__));

enum {
	BTRFS_FILE_EXTENT_INLINE   = 0,
	BTRFS_FILE_EXTENT_REG      = 1,
	BTRFS_FILE_EXTENT_PREALLOC = 2,
	BTRFS_NR_FILE_EXTENT_TYPES = 3,
};

enum {
	BTRFS_COMPRESS_NONE	= 0,
	BTRFS_COMPRESS_ZLIB	= 1,
	BTRFS_COMPRESS_LZO	= 2,
	BTRFS_COMPRESS_ZSTD	= 3,
	BTRFS_COMPRESS_LAST	= 4,
};

/*
 * Describe a file extent
 *
 * Key format:
 * (<ino>, BTRFS_EXTENT_DATA_KEY, <file offset>)
 */
struct btrfs_file_extent_item {
	/* At which transaction the file extent is created */
	__le64 generation;

	/* Uncompressed size of the whole file extent*/
	__le64 ram_bytes;

	/* The compression algorithm */
	__u8 compression;
	__u8 __unused1[3];

	/* Whether the file extent is INLINE or REGular or PREALLOCated */
	__u8 type;

	/*
	 * Logical bytenr where the data is.
	 *
	 * At this offset in the structure, the __inline__ extent data start.
	 *
	 * For REGULAR file extent, if this is 0, it means this file extent is
	 * a hole, all its content is 0, and takes no space on disk.
	 */
	__le64 disk_bytenr;

	/*
	 * Logical size it takes in logical address space
	 * (aka compressed size for compressed extent).
	 */
	__le64 disk_num_bytes;

	/*
	 * Offset inside the uncompressed data we read from.
	 *
	 * In btrfs we can refer to only part of the whole file extent.
	 */
	__le64 offset;

	/* How many bytes we're really referring to the uncompressed extent  */
	__le64 num_bytes;

} __attribute__ ((__packed__));

/*
 * Describe data checksum.
 *
 * Key format:
 * (BTRFS_EXTENT_CSUM_OBJECTID, BTRFS_EXTENT_CSUM_KEY, <logical>)
 *
 * The csum item can be merged to save space, and the data length of one csum
 * item covers can be calculated using its item size.
 * (item_size / csum_size * sectorsize).
 *
 * The csum is for any data extent lies in btrfs logical address space, this
 * also means, for compressed file extent, it's the csum of the compressed data,
 * not the uncompressed data.
 */
struct btrfs_csum_item {
	__u8 csum;
} __attribute__ ((__packed__));

#endif
