// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
 
#ifndef GLOBAL_H
#define GLOBAL_H

#ifdef HAVE_XFS_XFS_H
#include <xfs/xfs.h>
#endif

#ifdef HAVE_XFS_LIBXFS_H
#include <xfs/libxfs.h>
#endif

#ifdef HAVE_XFS_JDM_H
#include <xfs/jdm.h>
#endif

#include <attr/attributes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/param.h>
#include <libgen.h>
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <strings.h>
#include <sys/param.h>
#include <linux/falloc.h>

#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE		0x01
#endif

#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE		0x02
#endif

#ifndef FALLOC_FL_NO_HIDE_STALE
#define FALLOC_FL_NO_HIDE_STALE		0x04
#endif

#ifndef FALLOC_FL_COLLAPSE_RANGE
#define FALLOC_FL_COLLAPSE_RANGE	0x08
#endif

#ifndef FALLOC_FL_ZERO_RANGE
#define FALLOC_FL_ZERO_RANGE		0x10
#endif

#ifndef FALLOC_FL_INSERT_RANGE
#define FALLOC_FL_INSERT_RANGE		0x20
#endif

#include <sys/mman.h>

static inline unsigned long long
rounddown_64(unsigned long long x, unsigned int y)
{
	x /= y;
	return x * y;
}

static inline unsigned long long
roundup_64(unsigned long long x, unsigned int y)
{
	return rounddown_64(x + y - 1, y);
}

#endif /* GLOBAL_H */
