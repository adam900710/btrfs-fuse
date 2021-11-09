// SPDX-License-Identifier: MIT

#include <lzo/lzoconf.h>
#include <lzo/lzo1x.h>
#include <zlib.h>
#include <zstd.h>
#include <sys/param.h>
#include "compression.h"
#include "messages.h"

static int decompress_zlib(char *input, u32 input_len, char *output,
			   u32 output_len)
{
	z_stream strm;
	int ret;

	memset(&strm, 0, sizeof(strm));
	ret = inflateInit(&strm);
	if (ret != Z_OK) {
		error("zlib init failed: %d", ret);
		return -EIO;
	}

	strm.avail_in = input_len;
	strm.next_in = (unsigned char *)input;
	strm.avail_out = output_len;
	strm.next_out = (unsigned char *)output;
	ret = inflate(&strm, Z_NO_FLUSH);
	inflateEnd(&strm);
	if (ret != Z_STREAM_END) {
		error("zlib infalte failed: %d", ret);
		return -EIO;
	}
	return 0;
}

static int decompress_zstd(char *input, u32 input_len, char *output,
			   u32 output_len)
{
	ZSTD_DStream *strm;
	ZSTD_inBuffer in = {
		.src	= input,
		.size	= input_len,
		.pos	= 0,
	};
	ZSTD_outBuffer out = {
		.dst	= output,
		.size	= output_len,
		.pos	= 0,
	};
	size_t zret;
	int ret = 0;

	strm = ZSTD_createDStream();
	if (!strm) {
		error("failed to alloc zstd");
		return -ENOMEM;
	}

	zret = ZSTD_initDStream(strm);
	if (ZSTD_isError(zret)) {
		error("zstd init failed: %s", ZSTD_getErrorName(zret));
		ret = -EIO;
		goto out;
	}

	zret = ZSTD_decompressStream(strm, &out, &in);
	if (ZSTD_isError(zret)) {
		error("zstd decompress failed: %s", ZSTD_getErrorName(zret));
		ret = -EIO;
		goto out;
	}
	if (zret != 0) {
		error("zstd frame incomplete");
		ret = -EIO;
	}
out:
	ZSTD_freeDStream(strm);
	return ret;
}

#define LZO_LEN		(4)

static inline u32 read_compress_length(const char *buf)
{
	__le32 dlen;

	memcpy(&dlen, buf, LZO_LEN);
	return le32_to_cpu(dlen);
}

/* Worst lzo compressed size */
static inline u32 lzo1x_worst_compress(u32 size)
{
	return (size + size / 16) + 64 + 3 + 2;
}

/*
 * Unlike zlib/zstd, lzo doesn't have its embedded stream format, thus
 * it relies on btrfs defined segment headers:
 *
 * 1.  Header
 *     Fixed size. LZO_LEN (4) bytes long, LE32.
 *     Records the total size (including the header) of compressed data.
 *
 * 2.  Segment(s)
 *     Variable size. Each segment includes one segment header, followed by data
 *     payload.
 *     One regular LZO compressed extent can have one or more segments.
 *     For inlined LZO compressed extent, only one segment is allowed.
 *     One segment represents at most one sector of uncompressed data.
 *
 * 2.1 Segment header
 *     Fixed size. LZO_LEN (4) bytes long, LE32.
 *     Records the total size of the segment (not including the header).
 *     Segment header never crosses sector boundary, thus it's possible to
 *     have at most 3 padding zeros at the end of the sector.
 *
 * 2.2 Data Payload
 *     Variable size. Size up limit should be lzo1x_worst_compress(sectorsize)
 *     which is 4419 for a 4KiB sectorsize.
 *
 * Example with 4K sectorsize:
 * Page 1:
 *          0     0x2   0x4   0x6   0x8   0xa   0xc   0xe     0x10
 * 0x0000   |  Header   | SegHdr 01 | Data payload 01 ...     |
 * ...
 * 0x0ff0   | SegHdr  N | Data payload  N     ...          |00|
 *                                                          ^^ padding zeros
 * Page 2:
 * 0x1000   | SegHdr N+1| Data payload N+1 ...                |
 */
static int decompress_lzo(const struct btrfs_fs_info *fs_info, char *input,
			  u32 input_len, char *output, u32 output_len)
{
	const u32 sectorsize = fs_info->sectorsize;
	int ret = 0;
	u32 len_in;
	u32 cur_in = 0;	/* Current offset inside @input */
	u32 cur_out = 0; /* current oiffset inside @output */

	len_in = read_compress_length(input);
	cur_in += LZO_LEN;

	/* Basic lzo header checks */
	if (len_in > MIN(BTRFS_MAX_COMPRESSED, input_len) ||
	    round_up(input_len, sectorsize) < input_len) {
		error("invalid lzo header, lzo len %u compressed len %u",
			len_in, input_len);
		return -EUCLEAN;
	}

	while (cur_in < input_len) {
		u32 seg_len;	/* length of the compressed segment */
		u32 sector_bytes_left;
		unsigned long out_len = lzo1x_worst_compress(sectorsize);

		/*
		 * We should always have enough space for one segment header
		 * inside current sector.
		 */
		ASSERT(cur_in / sectorsize ==
		       (cur_in + LZO_LEN - 1) / sectorsize);
		seg_len = read_compress_length(input + cur_in);
		cur_in += LZO_LEN;
		cur_in += seg_len;

		ret = lzo1x_decompress_safe((unsigned char *)input + cur_in,
				seg_len, (unsigned char *)output + cur_out,
				&out_len, NULL);
		if (ret != LZO_E_OK) {
			error("lzo decompress failed: %d", ret);
			ret = -EIO;
			return ret;
		}
		cur_out += out_len;

		sector_bytes_left = sectorsize - (cur_in % sectorsize);
		if (sector_bytes_left >= LZO_LEN)
			continue;

		/* Skip the padding zeros */
		cur_in += sector_bytes_left;
	}
	if (!ret)
		memset(output + cur_out, 0, output_len - cur_out);
	return 0;
}

int btrfs_decompress(const struct btrfs_fs_info *fs_info,
		     char *input, u32 input_len,
		     char *output, u32 output_len, u8 compression)
{
	switch (compression) {
	case BTRFS_COMPRESS_ZLIB:
		return decompress_zlib(input, input_len, output, output_len);
	case BTRFS_COMPRESS_LZO:
		return decompress_lzo(fs_info, input, input_len, output,
				      output_len);
	case BTRFS_COMPRESS_ZSTD:
		return decompress_zstd(input, input_len, output, output_len);
	}

	error("invalid compression algorithm: %d", compression);
	return -EUCLEAN;
}
