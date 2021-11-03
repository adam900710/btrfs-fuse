// SPDX-License-Identifier: MIT

#define FUSE_USE_VERSION 31

#include <fuse.h>
#include "accessors.h"
#include "ctree.h"
#include "messages.h"
#include "super.h"

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
