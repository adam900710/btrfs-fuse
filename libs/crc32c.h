// SPDX-License-Identifier: GPL-2.0-or-later
//
#ifndef __CRC32C__
#define __CRC32C__

#include "compat.h"

u32 crc32c_le(u32 seed, unsigned char const *data, size_t length);
void crc32c_optimization_init(void);

#define crc32c(seed, data, length) crc32c_le(seed, (unsigned char const *)data, length)

#endif
