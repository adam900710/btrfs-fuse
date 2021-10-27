// SPDX-License-Identifier: MIT

#include <unistd.h>
#include <errno.h>
#include <uuid.h>
#include "ondisk_format.h"
#include "super.h"
#include "messages.h"
#include "hash.h"
#include "volumes.h"

int btrfs_read_from_disk(int fd, char *buf, u64 offset, u32 len)
{
	int cur = 0;

	while (cur < len) {
		int ret;

		ret = pread(fd, buf + cur, len - cur, offset + cur);
		if (ret < 0) {
			ret = -errno;
			return ret;
		}
		cur += ret;
	}
	return len;
}

int btrfs_check_super(struct btrfs_super_block *sb)
{
	u8 result[BTRFS_CSUM_SIZE];
	u32 sectorsize;
	u32 nodesize;
	u16 csum_type;
	int csum_size;

	if (btrfs_super_magic(sb) != BTRFS_MAGIC)
		return -EIO;

	csum_type = btrfs_super_csum_type(sb);
	if (csum_type >= btrfs_super_num_csums()) {
		error("unsupported checksum algorithm %u", csum_type);
		return -EIO;
	}
	csum_size = btrfs_super_csum_size(sb);

	btrfs_csum_data(csum_type, (u8 *)sb + BTRFS_CSUM_SIZE,
			result, BTRFS_SUPER_INFO_SIZE - BTRFS_CSUM_SIZE);

	if (memcmp(result, sb->csum, csum_size)) {
		error("superblock checksum mismatch");
		return -EIO;
	}

	/* We don't support seed/dumps/FSID change yet */
	if (btrfs_super_flags(sb) & ~BTRFS_HEADER_FLAG_WRITTEN) {
		error("unsupported super flags: %llx", btrfs_super_flags(sb));
		goto error_out;
	}

	/* Root level checks */
	if (btrfs_super_root_level(sb) >= BTRFS_MAX_LEVEL) {
		error("tree_root level too big: %d >= %d",
			btrfs_super_root_level(sb), BTRFS_MAX_LEVEL);
		goto error_out;
	}
	if (btrfs_super_chunk_root_level(sb) >= BTRFS_MAX_LEVEL) {
		error("chunk_root level too big: %d >= %d",
			btrfs_super_chunk_root_level(sb), BTRFS_MAX_LEVEL);
		goto error_out;
	}
	if (btrfs_super_log_root_level(sb) >= BTRFS_MAX_LEVEL) {
		error("log_root level too big: %d >= %d",
			btrfs_super_log_root_level(sb), BTRFS_MAX_LEVEL);
		goto error_out;
	}

	/* Sectorsize/nodesize checks */
	sectorsize = btrfs_super_sectorsize(sb);
	nodesize = btrfs_super_nodesize(sb);

	if (!is_power_of_2(sectorsize) || sectorsize > BTRFS_SECTORSIZE_MAX ||
	    sectorsize < BTRFS_SECTORSIZE_MIN) {
		error("invalid sectorsize: %u", sectorsize);
		goto error_out;
	}
	if (!is_power_of_2(nodesize) || nodesize> BTRFS_NODESIZE_MAX ||
	    nodesize < BTRFS_NODESIZE_MIN || nodesize < sectorsize) {
		error("invalid nodesize: %u", nodesize);
		goto error_out;
	}

	/*
	 * Root alignment check
	 *
	 * We may have rare case where chunk is sectorsize aligned but not
	 * nodesize aligned.
	 * In that case, we only require sectorsize alignment.
	 */
	if (!IS_ALIGNED(btrfs_super_root(sb), sectorsize)) {
		error("tree_root block unaligned: %llu", btrfs_super_root(sb));
		goto error_out;
	}
	if (!IS_ALIGNED(btrfs_super_chunk_root(sb), sectorsize)) {
		error("chunk_root block unaligned: %llu",
			btrfs_super_chunk_root(sb));
		goto error_out;
	}
	if (!IS_ALIGNED(btrfs_super_log_root(sb), sectorsize)) {
		error("log_root block unaligned: %llu",
			btrfs_super_log_root(sb));
		goto error_out;
	}

	/* Basic size check */
	if (btrfs_super_total_bytes(sb) == 0) {
		error("invalid total_bytes 0");
		goto error_out;
	}
	if (btrfs_super_bytes_used(sb) < 6 * btrfs_super_nodesize(sb)) {
		error("invalid bytes_used %llu", btrfs_super_bytes_used(sb));
		goto error_out;
	}

	if (memcmp(sb->fsid, sb->dev_item.fsid, BTRFS_FSID_SIZE) != 0) {
		char fsid[BTRFS_UUID_UNPARSED_SIZE];
		char dev_fsid[BTRFS_UUID_UNPARSED_SIZE];

		uuid_unparse(sb->fsid, fsid);
		uuid_unparse(sb->dev_item.fsid, dev_fsid);
		error("dev_item UUID does not match fsid: %s != %s",
				dev_fsid, fsid);
		goto error_out;
	}

	/*
	 * Hint to catch really bogus numbers, bitflips or so
	 */
	if (btrfs_super_num_devices(sb) > (1UL << 31)) {
		warning("suspicious number of devices: %llu",
			btrfs_super_num_devices(sb));
	}

	if (btrfs_super_num_devices(sb) == 0) {
		error("number of devices is 0");
		goto error_out;
	}

	/*
	 * Obvious sys_chunk_array corruptions, it must hold at least one key
	 * and one chunk
	 */
	if (btrfs_super_sys_array_size(sb) > BTRFS_SYSTEM_CHUNK_ARRAY_SIZE) {
		error("system chunk array too big %u > %u",
		      btrfs_super_sys_array_size(sb),
		      BTRFS_SYSTEM_CHUNK_ARRAY_SIZE);
		goto error_out;
	}
	if (btrfs_super_sys_array_size(sb) < sizeof(struct btrfs_disk_key)
			+ sizeof(struct btrfs_chunk)) {
		error("system chunk array too small %u < %zu",
		      btrfs_super_sys_array_size(sb),
		      sizeof(struct btrfs_disk_key) +
		      sizeof(struct btrfs_chunk));
		goto error_out;
	}

	return 0;

error_out:
	error("superblock checksum matches but it has invalid members");
	return -EIO;
}
