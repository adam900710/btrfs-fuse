// SPDX-License-Identifier: MIT

#ifndef BTRFS_FUSE_MESSAGES_H
#define BTRFS_FUSE_MESSAGES_H

__attribute__ ((format (printf, 1, 2)))
void error(const char *fmt, ...);

__attribute__ ((format (printf, 1, 2)))
void warning(const char *fmt, ...);

__attribute__ ((format (printf, 1, 2)))
void info(const char *fmt, ...);

__attribute__ ((format (printf, 1, 2)))
void debug(const char *fmt, ...);

#endif
