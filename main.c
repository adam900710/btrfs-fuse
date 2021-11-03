// SPDX-License-Identifier: MIT

#define FUSE_USE_VERSION 31

#include <fuse.h>
#include "accessors.h"
#include "ctree.h"
#include "messages.h"
#include "super.h"

static struct btrfs_fs_info *global_info = NULL;

static int btrfs_fuse_statfs(const char *path, struct statvfs *stbuf)
{
	ASSERT(global_info);

	stbuf->f_bsize = global_info->sectorsize;
	stbuf->f_frsize = global_info->sectorsize;
	stbuf->f_blocks = btrfs_super_total_bytes(&global_info->super_copy) /
			  global_info->sectorsize;
	/*
	 * Btrfs avaiable space calculation is already complex due to dyanmic
	 * allocation.
	 * Since our implementation is read-only, no need to populate those
		* available values.
	 */
	stbuf->f_bavail = 0;
	stbuf->f_bfree = 0;
	stbuf->f_favail = 0;
	stbuf->f_files = 0;
	stbuf->f_namemax = BTRFS_NAME_LEN;
	return 0;
}

static const struct fuse_operations btrfs_fuse_ops = {
	.statfs		= btrfs_fuse_statfs,
};

int main(int argc, char *argv[])
{
	struct btrfs_fs_info *fs_info;
	char *path = argv[1];

	if (argc != 2) {
		error("needs exact one parameter, have %d", argc - 1);
		return 1;
	}

	info("btrfs-fuse selftest for bootstrap on %s", path);
	/* Just a simple tester for single-device btrfs bootstrap */
	fs_info = btrfs_mount(path);
	if (IS_ERR(fs_info)) {
		error("failed to open %s", path);
		return 1;
	}
	btrfs_unmount(fs_info);

	info("test ran fine for %s", path);
	btrfs_exit();
	return 0;
}
