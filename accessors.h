// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_ACCESSORS_H
#define BTRFS_FUSE_ACCESSORS_H

#include <byteswap.h>
#include <string.h>
#include "ondisk_format.h"

/*
 * Various helpers to access the on-disk tree blocks
 *
 * We have extent_buffer structure to represent one tree block.
 * But callers shouldn't just access extent_buffer::data[] directly,
 * as we still need to do endian converts.
 *
 * To access one named structure, like btrfs_root_item, we need to either:
 *
 * - Get offset inside an tree block, then use accessors
 *
 *   struct btrfs_root_item *ri;
 *   u64 generation;
 *
 *   ri = btrfs_item_ptr(extent_buffer, slot, struct btrfs_root_item);
 *   generation = btrfs_disk_root_generation(tree_block, ri);
 *
 * - Copy the item into a memory, then use accessors on the memory directly
 *   This is also calle the "STACK" way.
 *
 *   u8 buf[sizeof(struct btrfs_root_item)];
 *   u64 generation;
 *
 *   read_extent_buffer(extent_buffer, btrfs_item_ptr_nr(extent_buffer, slot),
 *			buffer, sizeof(struct btrfs_root_item));
 *
 * Even in this project we don't need the complex page opeartions in the kernel,
 * the accessors interface is kept the same as kernel intentionally, to allow
 * btrfs developers to quickly switch between this and Linux kernel.
 */

struct extent_buffer {
	/* Cached result of btrfs_header::bytenr */
	u64 start;

	/* The same value as the nodesize of the fs */
	u32 len;

	/* Extra runtime flags */
	u32 flags;
	struct btrfs_fs_info *fs_info;
	int refs;
	char data[];
};

static inline void read_extent_buffer(const struct extent_buffer *eb,
				      void *dst, unsigned start, unsigned len)
{
	memcpy(dst, eb->data + start, len);
}

static inline int memcmp_extent_buffer(const struct extent_buffer *eb,
				       const void *src, unsigned start,
				       unsigned len)
{
	return memcmp(eb->data + start, src, len);
}

#define BTRFS_GET_HEADER_FUNCS(name, type, member, bits)		\
static inline u##bits btrfs_##name(const struct extent_buffer *eb)	\
{									\
	const struct btrfs_header *h = (struct btrfs_header *)eb->data;	\
	return le##bits##_to_cpu(h->member);				\
}

#define BTRFS_GET_FUNCS(name, type, member, bits)			\
static inline u##bits btrfs_##name(const struct extent_buffer *eb,	\
				   const type *s)			\
{									\
	unsigned long offset = (unsigned long)s;			\
	const type *p = (type *) (eb->data + offset);			\
	return get_unaligned_le##bits(&p->member);			\
}

#define BTRFS_GET_STACK_FUNCS(name, type, member, bits)			\
static inline u##bits btrfs_##name(const type *s)			\
{									\
	return le##bits##_to_cpu(s->member);				\
}

#define read_eb_member(eb, ptr, type, member, result) (			\
	read_extent_buffer(eb, (char *)(result),			\
			   ((unsigned long)(ptr)) +			\
			    offsetof(type, member),			\
			   sizeof(((type *)0)->member)))

/* struct btrfs_dev_item */
BTRFS_GET_FUNCS(device_total_bytes, struct btrfs_dev_item, total_bytes, 64);
BTRFS_GET_FUNCS(device_bytes_used, struct btrfs_dev_item, bytes_used, 64);
BTRFS_GET_FUNCS(device_id, struct btrfs_dev_item, devid, 64);
BTRFS_GET_FUNCS(device_generation, struct btrfs_dev_item, generation, 64);

BTRFS_GET_STACK_FUNCS(stack_device_total_bytes, struct btrfs_dev_item,
             	 total_bytes, 64);
BTRFS_GET_STACK_FUNCS(stack_device_bytes_used, struct btrfs_dev_item,
             	 bytes_used, 64);
BTRFS_GET_STACK_FUNCS(stack_device_id, struct btrfs_dev_item, devid, 64);
BTRFS_GET_STACK_FUNCS(stack_device_generation, struct btrfs_dev_item,
			 generation, 64);

static inline char *btrfs_device_uuid(struct btrfs_dev_item *d)
{
	return (char *)d + offsetof(struct btrfs_dev_item, uuid);
}

static inline char *btrfs_device_fsid(struct btrfs_dev_item *d)
{
	return (char *)d + offsetof(struct btrfs_dev_item, fsid);
}

/* struct btrfs_chunk */
BTRFS_GET_FUNCS(chunk_length, struct btrfs_chunk, length, 64);
BTRFS_GET_FUNCS(chunk_stripe_len, struct btrfs_chunk, stripe_len, 64);
BTRFS_GET_FUNCS(chunk_type, struct btrfs_chunk, type, 64);
BTRFS_GET_FUNCS(chunk_num_stripes, struct btrfs_chunk, num_stripes, 16);
BTRFS_GET_FUNCS(chunk_sub_stripes, struct btrfs_chunk, sub_stripes, 16);
BTRFS_GET_FUNCS(stripe_devid, struct btrfs_stripe, devid, 64);
BTRFS_GET_FUNCS(stripe_offset, struct btrfs_stripe, offset, 64);

static inline char *btrfs_stripe_dev_uuid(struct btrfs_stripe *s)
{
	return (char *)s + offsetof(struct btrfs_stripe, dev_uuid);
}

BTRFS_GET_STACK_FUNCS(stack_chunk_length, struct btrfs_chunk, length, 64);
BTRFS_GET_STACK_FUNCS(stack_chunk_stripe_len, struct btrfs_chunk,
             	 stripe_len, 64);
BTRFS_GET_STACK_FUNCS(stack_chunk_type, struct btrfs_chunk, type, 64);
BTRFS_GET_STACK_FUNCS(stack_chunk_num_stripes, struct btrfs_chunk,
             	 num_stripes, 16);
BTRFS_GET_STACK_FUNCS(stack_chunk_sub_stripes, struct btrfs_chunk,
             	 sub_stripes, 16);
BTRFS_GET_STACK_FUNCS(stack_stripe_devid, struct btrfs_stripe, devid, 64);
BTRFS_GET_STACK_FUNCS(stack_stripe_offset, struct btrfs_stripe, offset, 64);

static inline struct btrfs_stripe *btrfs_stripe_nr(struct btrfs_chunk *c,
						   int nr)
{
	unsigned long offset = (unsigned long)c;
	offset += offsetof(struct btrfs_chunk, stripes);
	offset += nr * sizeof(struct btrfs_stripe);
	return (struct btrfs_stripe *)offset;
}

static inline char *btrfs_stripe_dev_uuid_nr(struct btrfs_chunk *c, int nr)
{
	return btrfs_stripe_dev_uuid(btrfs_stripe_nr(c, nr));
}

static inline u64 btrfs_stripe_offset_nr(struct extent_buffer *eb,
					 struct btrfs_chunk *c, int nr)
{
	return btrfs_stripe_offset(eb, btrfs_stripe_nr(c, nr));
}

static inline u64 btrfs_stripe_devid_nr(struct extent_buffer *eb,
					 struct btrfs_chunk *c, int nr)
{
	return btrfs_stripe_devid(eb, btrfs_stripe_nr(c, nr));
}

/* struct btrfs_inode_item */
BTRFS_GET_FUNCS(inode_generation, struct btrfs_inode_item, generation, 64);
BTRFS_GET_FUNCS(inode_transid, struct btrfs_inode_item, transid, 64);
BTRFS_GET_FUNCS(inode_size, struct btrfs_inode_item, size, 64);
BTRFS_GET_FUNCS(inode_nbytes, struct btrfs_inode_item, nbytes, 64);
BTRFS_GET_FUNCS(inode_nlink, struct btrfs_inode_item, nlink, 32);
BTRFS_GET_FUNCS(inode_uid, struct btrfs_inode_item, uid, 32);
BTRFS_GET_FUNCS(inode_gid, struct btrfs_inode_item, gid, 32);
BTRFS_GET_FUNCS(inode_mode, struct btrfs_inode_item, mode, 32);
BTRFS_GET_FUNCS(inode_flags, struct btrfs_inode_item, flags, 64);

BTRFS_GET_STACK_FUNCS(stack_inode_generation,
		      struct btrfs_inode_item, generation, 64);
BTRFS_GET_STACK_FUNCS(stack_inode_transid,
		      struct btrfs_inode_item, transid, 64);
BTRFS_GET_STACK_FUNCS(stack_inode_size,
		      struct btrfs_inode_item, size, 64);
BTRFS_GET_STACK_FUNCS(stack_inode_nbytes,
		      struct btrfs_inode_item, nbytes, 64);
BTRFS_GET_STACK_FUNCS(stack_inode_nlink,
		      struct btrfs_inode_item, nlink, 32);
BTRFS_GET_STACK_FUNCS(stack_inode_uid,
		      struct btrfs_inode_item, uid, 32);
BTRFS_GET_STACK_FUNCS(stack_inode_gid,
		      struct btrfs_inode_item, gid, 32);
BTRFS_GET_STACK_FUNCS(stack_inode_mode,
		      struct btrfs_inode_item, mode, 32);
BTRFS_GET_STACK_FUNCS(stack_inode_flags,
		      struct btrfs_inode_item, flags, 64);

static inline struct btrfs_timespec *
btrfs_inode_atime(struct btrfs_inode_item *inode_item)
{
	unsigned long ptr = (unsigned long)inode_item;
	ptr += offsetof(struct btrfs_inode_item, atime);
	return (struct btrfs_timespec *)ptr;
}

static inline struct btrfs_timespec *
btrfs_inode_mtime(struct btrfs_inode_item *inode_item)
{
	unsigned long ptr = (unsigned long)inode_item;
	ptr += offsetof(struct btrfs_inode_item, mtime);
	return (struct btrfs_timespec *)ptr;
}

static inline struct btrfs_timespec *
btrfs_inode_ctime(struct btrfs_inode_item *inode_item)
{
	unsigned long ptr = (unsigned long)inode_item;
	ptr += offsetof(struct btrfs_inode_item, ctime);
	return (struct btrfs_timespec *)ptr;
}

static inline struct btrfs_timespec *
btrfs_inode_otime(struct btrfs_inode_item *inode_item)
{
	unsigned long ptr = (unsigned long)inode_item;
	ptr += offsetof(struct btrfs_inode_item, otime);
	return (struct btrfs_timespec *)ptr;
}

BTRFS_GET_FUNCS(timespec_sec, struct btrfs_timespec, sec, 64);
BTRFS_GET_FUNCS(timespec_nsec, struct btrfs_timespec, nsec, 32);
BTRFS_GET_STACK_FUNCS(stack_timespec_sec, struct btrfs_timespec, sec, 64);
BTRFS_GET_STACK_FUNCS(stack_timespec_nsec, struct btrfs_timespec, nsec, 32);

/* struct btrfs_node */
BTRFS_GET_FUNCS(key_blockptr, struct btrfs_key_ptr, blockptr, 64);
BTRFS_GET_FUNCS(key_generation, struct btrfs_key_ptr, generation, 64);

static inline u64 btrfs_node_blockptr(struct extent_buffer *eb, int nr)
{
	unsigned long ptr;
	ptr = offsetof(struct btrfs_node, ptrs) +
		sizeof(struct btrfs_key_ptr) * nr;
	return btrfs_key_blockptr(eb, (struct btrfs_key_ptr *)ptr);
}

static inline u64 btrfs_node_ptr_generation(struct extent_buffer *eb, int nr)
{
	unsigned long ptr;
	ptr = offsetof(struct btrfs_node, ptrs) +
		sizeof(struct btrfs_key_ptr) * nr;
	return btrfs_key_generation(eb, (struct btrfs_key_ptr *)ptr);
}
static inline unsigned long btrfs_node_key_ptr_offset(int nr)
{
	return offsetof(struct btrfs_node, ptrs) +
		sizeof(struct btrfs_key_ptr) * nr;
}

static inline void btrfs_node_key(struct extent_buffer *eb,
				  struct btrfs_disk_key *disk_key, int nr)
{
	unsigned long ptr;
	ptr = btrfs_node_key_ptr_offset(nr);
	read_eb_member(eb, (struct btrfs_key_ptr *)ptr,
		       struct btrfs_key_ptr, key, disk_key);
}

/* struct btrfs_item */
BTRFS_GET_FUNCS(item_offset, struct btrfs_item, offset, 32);
BTRFS_GET_FUNCS(item_size, struct btrfs_item, size, 32);

static inline unsigned long btrfs_item_nr_offset(int nr)
{
	return offsetof(struct btrfs_leaf, items) +
		sizeof(struct btrfs_item) * nr;
}

static inline struct btrfs_item *btrfs_item_nr(int nr)
{
	return (struct btrfs_item *)btrfs_item_nr_offset(nr);
}

static inline u32 btrfs_item_end(struct extent_buffer *eb,
				 struct btrfs_item *item)
{
	return btrfs_item_offset(eb, item) + btrfs_item_size(eb, item);
}

static inline u32 btrfs_item_end_nr(struct extent_buffer *eb, int nr)
{
	return btrfs_item_end(eb, btrfs_item_nr(nr));
}

static inline u32 btrfs_item_offset_nr(const struct extent_buffer *eb, int nr)
{
	return btrfs_item_offset(eb, btrfs_item_nr(nr));
}

static inline u32 btrfs_item_size_nr(struct extent_buffer *eb, int nr)
{
	return btrfs_item_size(eb, btrfs_item_nr(nr));
}

static inline void btrfs_item_key(struct extent_buffer *eb,
			   struct btrfs_disk_key *disk_key, int nr)
{
	struct btrfs_item *item = btrfs_item_nr(nr);
	read_eb_member(eb, item, struct btrfs_item, key, disk_key);
}

#define btrfs_item_ptr(leaf, slot, type)	\
	((type *)(btrfs_leaf_data(leaf) + btrfs_item_offset_nr(leaf, slot)))

#define btrfs_item_ptr_offset(leaf, slot)	\
	((u32)(btrfs_leaf_data(leaf) + btrfs_item_offset_nr(leaf, slot)))

/* struct btrfs_dir_item */
BTRFS_GET_FUNCS(dir_data_len, struct btrfs_dir_item, data_len, 16);
BTRFS_GET_FUNCS(dir_type, struct btrfs_dir_item, type, 8);
BTRFS_GET_FUNCS(dir_name_len, struct btrfs_dir_item, name_len, 16);
BTRFS_GET_FUNCS(dir_transid, struct btrfs_dir_item, transid, 64);

BTRFS_GET_STACK_FUNCS(stack_dir_data_len, struct btrfs_dir_item, data_len, 16);
BTRFS_GET_STACK_FUNCS(stack_dir_type, struct btrfs_dir_item, type, 8);
BTRFS_GET_STACK_FUNCS(stack_dir_name_len, struct btrfs_dir_item, name_len, 16);
BTRFS_GET_STACK_FUNCS(stack_dir_transid, struct btrfs_dir_item, transid, 64);

static inline void btrfs_dir_item_key(struct extent_buffer *eb,
				      struct btrfs_dir_item *item,
				      struct btrfs_disk_key *key)
{
	read_eb_member(eb, item, struct btrfs_dir_item, location, key);
}

/* struct btrfs_disk_key */
BTRFS_GET_STACK_FUNCS(disk_key_objectid, struct btrfs_disk_key,
			 objectid, 64);
BTRFS_GET_STACK_FUNCS(disk_key_offset, struct btrfs_disk_key, offset, 64);
BTRFS_GET_STACK_FUNCS(disk_key_type, struct btrfs_disk_key, type, 8);

static inline void btrfs_disk_key_to_cpu(struct btrfs_key *cpu,
					 struct btrfs_disk_key *disk)
{
	cpu->offset = le64_to_cpu(disk->offset);
	cpu->type = disk->type;
	cpu->objectid = le64_to_cpu(disk->objectid);
}

static inline void btrfs_cpu_key_to_disk(struct btrfs_disk_key *disk,
					 const struct btrfs_key *cpu)
{
	disk->offset = cpu_to_le64(cpu->offset);
	disk->type = cpu->type;
	disk->objectid = cpu_to_le64(cpu->objectid);
}

static inline void btrfs_node_key_to_cpu(struct extent_buffer *eb,
				  struct btrfs_key *key, int nr)
{
	struct btrfs_disk_key disk_key;
	btrfs_node_key(eb, &disk_key, nr);
	btrfs_disk_key_to_cpu(key, &disk_key);
}

static inline void btrfs_item_key_to_cpu(struct extent_buffer *eb,
				  struct btrfs_key *key, int nr)
{
	struct btrfs_disk_key disk_key;
	btrfs_item_key(eb, &disk_key, nr);
	btrfs_disk_key_to_cpu(key, &disk_key);
}

static inline void btrfs_dir_item_key_to_cpu(struct extent_buffer *eb,
				      struct btrfs_dir_item *item,
				      struct btrfs_key *key)
{
	struct btrfs_disk_key disk_key;
	btrfs_dir_item_key(eb, item, &disk_key);
	btrfs_disk_key_to_cpu(key, &disk_key);
}

/* struct btrfs_header */
BTRFS_GET_HEADER_FUNCS(header_bytenr, struct btrfs_header, bytenr, 64);
BTRFS_GET_HEADER_FUNCS(header_generation, struct btrfs_header,
             	  generation, 64);
BTRFS_GET_HEADER_FUNCS(header_owner, struct btrfs_header, owner, 64);
BTRFS_GET_HEADER_FUNCS(header_nritems, struct btrfs_header, nritems, 32);
BTRFS_GET_HEADER_FUNCS(header_flags, struct btrfs_header, flags, 64);
BTRFS_GET_HEADER_FUNCS(header_level, struct btrfs_header, level, 8);
BTRFS_GET_STACK_FUNCS(stack_header_bytenr, struct btrfs_header, bytenr, 64);
BTRFS_GET_STACK_FUNCS(stack_header_nritems, struct btrfs_header, nritems,
             	 32);
BTRFS_GET_STACK_FUNCS(stack_header_owner, struct btrfs_header, owner, 64);
BTRFS_GET_STACK_FUNCS(stack_header_generation, struct btrfs_header,
			 generation, 64);

static inline int btrfs_header_flag(struct extent_buffer *eb, u64 flag)
{
	return (btrfs_header_flags(eb) & flag) == flag;
}

static inline unsigned long btrfs_header_fsid(void)
{
	return offsetof(struct btrfs_header, fsid);
}

static inline unsigned long btrfs_header_chunk_tree_uuid(struct extent_buffer *eb)
{
	return offsetof(struct btrfs_header, chunk_tree_uuid);
}

static inline u8 *btrfs_header_csum(struct extent_buffer *eb)
{
	unsigned long ptr = offsetof(struct btrfs_header, csum);
	return (u8 *)ptr;
}

static inline int btrfs_is_leaf(struct extent_buffer *eb)
{
	return (btrfs_header_level(eb) == 0);
}

/* struct btrfs_root_item */
BTRFS_GET_FUNCS(disk_root_generation, struct btrfs_root_item,
		generation, 64);
BTRFS_GET_FUNCS(disk_root_bytenr, struct btrfs_root_item, bytenr, 64);
BTRFS_GET_FUNCS(disk_root_level, struct btrfs_root_item, level, 8);

BTRFS_GET_STACK_FUNCS(root_generation, struct btrfs_root_item,
		      generation, 64);
BTRFS_GET_STACK_FUNCS(root_bytenr, struct btrfs_root_item, bytenr, 64);
BTRFS_GET_STACK_FUNCS(root_level, struct btrfs_root_item, level, 8);
BTRFS_GET_STACK_FUNCS(root_flags, struct btrfs_root_item, flags, 64);

/*
 * struct btrfs_super_block
 *
 * Since super block is not accessed inside an extent_buffer, thus only
 * stack version accessors are provided.
 */
BTRFS_GET_STACK_FUNCS(super_bytenr, struct btrfs_super_block, bytenr, 64);
BTRFS_GET_STACK_FUNCS(super_flags, struct btrfs_super_block, flags, 64);
BTRFS_GET_STACK_FUNCS(super_generation, struct btrfs_super_block,
		      generation, 64);
BTRFS_GET_STACK_FUNCS(super_root, struct btrfs_super_block, root, 64);
BTRFS_GET_STACK_FUNCS(super_sys_array_size, struct btrfs_super_block,
		      sys_chunk_array_size, 32);
BTRFS_GET_STACK_FUNCS(super_chunk_root_generation, struct btrfs_super_block,
		      chunk_root_generation, 64);
BTRFS_GET_STACK_FUNCS(super_root_level, struct btrfs_super_block, root_level,
		      8);
BTRFS_GET_STACK_FUNCS(super_chunk_root, struct btrfs_super_block, chunk_root,
		      64);
BTRFS_GET_STACK_FUNCS(super_chunk_root_level, struct btrfs_super_block,
		      chunk_root_level, 8);
BTRFS_GET_STACK_FUNCS(super_log_root, struct btrfs_super_block, log_root, 64);
BTRFS_GET_STACK_FUNCS(super_log_root_transid, struct btrfs_super_block,
		      log_root_transid, 64);
BTRFS_GET_STACK_FUNCS(super_log_root_level, struct btrfs_super_block,
		      log_root_level, 8);
BTRFS_GET_STACK_FUNCS(super_total_bytes, struct btrfs_super_block, total_bytes,
		      64);
BTRFS_GET_STACK_FUNCS(super_bytes_used, struct btrfs_super_block, bytes_used,
		      64);
BTRFS_GET_STACK_FUNCS(super_sectorsize, struct btrfs_super_block, sectorsize,
		      32);
BTRFS_GET_STACK_FUNCS(super_nodesize, struct btrfs_super_block, nodesize, 32);
BTRFS_GET_STACK_FUNCS(super_num_devices, struct btrfs_super_block, num_devices,
		      64);
BTRFS_GET_STACK_FUNCS(super_compat_flags, struct btrfs_super_block,
		      compat_flags, 64);
BTRFS_GET_STACK_FUNCS(super_compat_ro_flags, struct btrfs_super_block,
		      compat_ro_flags, 64);
BTRFS_GET_STACK_FUNCS(super_incompat_flags, struct btrfs_super_block,
		      incompat_flags, 64);
BTRFS_GET_STACK_FUNCS(super_csum_type, struct btrfs_super_block, csum_type, 16);
BTRFS_GET_STACK_FUNCS(super_magic, struct btrfs_super_block, magic, 64);

static inline unsigned long btrfs_leaf_data(struct extent_buffer *l)
{
	return offsetof(struct btrfs_leaf, items);
}

#endif
