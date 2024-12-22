// SPDX-License-Identifier: MIT

#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <fuse_common.h>
#include "accessors.h"
#include "ctree.h"
#include "messages.h"
#include "super.h"
#include "inode.h"
#include "data.h"

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

static int btrfs_fuse_getattr(const char *path, struct stat *stbuf,
			      struct fuse_file_info *fi)
{
	struct btrfs_fs_info *fs_info = global_info;
	struct btrfs_inode inode = {};
	int ret;

	ret = btrfs_resolve_path(fs_info, path, strlen(path), &inode);
	if (ret < 0)
		return ret;

	ret = btrfs_stat(fs_info, &inode, stbuf);
	return ret;
}

static int btrfs_fuse_read_link(const char *path, char *output, size_t output_len)
{
	struct btrfs_fs_info *fs_info = global_info;
	struct btrfs_inode inode = {};
	int ret;

	ret = btrfs_resolve_path(fs_info, path, strlen(path), &inode);
	if (ret < 0)
		return ret;

	if (inode.file_type != BTRFS_FT_SYMLINK)
		return -EINVAL;
	ret = btrfs_read_link(fs_info, &inode, output, output_len);
	if (ret < 0)
		return ret;
	return 0;
}

/* Just do basic path resolve and type check */
static int btrfs_fuse_open(const char *path, struct fuse_file_info *fi)
{
	struct btrfs_fs_info *fs_info = global_info;
	struct btrfs_inode inode = {};
	int ret;

	ret = btrfs_resolve_path(fs_info, path, strlen(path), &inode);
	if (ret < 0)
		return ret;

	if (inode.file_type == BTRFS_FT_DIR)
		return -EISDIR;
	return 0;
}

static int btrfs_fuse_read(const char *path, char *output, size_t size,
			   off_t offset, struct fuse_file_info *fi)
{
	struct btrfs_fs_info *fs_info = global_info;
	struct btrfs_inode inode = {};
	int ret;

	if (!IS_ALIGNED(offset, fs_info->sectorsize) ||
	    !IS_ALIGNED(size, fs_info->sectorsize)) {
		error("unaligned read range, size=%zu offset=%tu path=%s",
			size, offset, path);
		return -EINVAL;
	}

	ret = btrfs_resolve_path(fs_info, path, strlen(path), &inode);
	if (ret < 0)
		return ret;

	if (inode.file_type == BTRFS_FT_DIR)
		return -EISDIR;

	return btrfs_read_file(fs_info, &inode, offset, output, size);
}

static int btrfs_fuse_release(const char *path, struct fuse_file_info *fi)
{
	return 0;
}

static void *btrfs_fuse_init(struct fuse_conn_info *conn,
			     struct fuse_config *cfg)
{
	cfg->use_ino = 1;
	cfg->intr = 1;
	cfg->nullpath_ok = 0;
	return NULL;
}

static int btrfs_fuse_opendir(const char *path, struct fuse_file_info *fi)
{
	struct btrfs_fs_info *fs_info = global_info;
	struct btrfs_inode inode = {};
	int ret;

	ret = btrfs_resolve_path(fs_info, path, strlen(path), &inode);
	if (ret < 0)
		return ret;

	if (inode.file_type != BTRFS_FT_DIR)
		return -ENOTDIR;
	return 0;
}

static int btrfs_fuse_readdir(const char *path, void *buf,
			      fuse_fill_dir_t filler, off_t offset,
			      struct fuse_file_info *fi,
			      enum fuse_readdir_flags flags)
{
	struct btrfs_fs_info *fs_info = global_info;
	struct btrfs_iterate_dir_ctrl ctrl = {};
	struct btrfs_inode dir = {};
	int ret;

	ret = btrfs_resolve_path(fs_info, path, strlen(path), &dir);
	if (ret < 0)
		return ret;

	if (dir.file_type != BTRFS_FT_DIR)
		return -ENOTDIR;

	/*
	 * The @offset is the last returned found index. So we should start
	 * from the next one.
	 */
	ret = btrfs_iterate_dir_start(fs_info, &ctrl, &dir, offset + 1);
	if (ret < 0)
		return ret;

	while (ret == 0) {
		u64 found_index;
		char name_buf[BTRFS_NAME_LEN + 1] = {};
		size_t name_len;
		struct btrfs_inode entry = {};
		struct stat st = {};

		ret = btrfs_iterate_dir_get_inode(fs_info, &ctrl, &entry,
				&found_index, name_buf, &name_len);
		if (ret < 0)
			break;

		st.st_ino = entry.ino;
		st.st_mode = btrfs_type_to_imode(entry.file_type);
		if (filler(buf, name_buf, &st, found_index, 0))
			break;
		ret = btrfs_iterate_dir_next(fs_info, &ctrl);
	}
	btrfs_iterate_dir_end(fs_info, &ctrl);
	if (ret > 0)
		ret = 0;
	return ret;
}

static void btrfs_fuse_destroy(void *private_data)
{
	struct btrfs_fs_info *fs_info = global_info;

	global_info = NULL;
	btrfs_unmount(fs_info);
	btrfs_exit();
}

static const struct fuse_operations btrfs_fuse_ops = {
	.statfs		= btrfs_fuse_statfs,
	.getattr	= btrfs_fuse_getattr,
	.readlink	= btrfs_fuse_read_link,
	.open		= btrfs_fuse_open,
	.read		= btrfs_fuse_read,
	.release	= btrfs_fuse_release,
	.opendir	= btrfs_fuse_opendir,
	.readdir	= btrfs_fuse_readdir,
	.init		= btrfs_fuse_init,
	.destroy	= btrfs_fuse_destroy,
};

void usage(void)
{
	fprintf(stderr, "usage: btrfs-fuse [<fuse options>] <device> [<device>...] <mnt>\n");
}

int main(int argc, char *argv[])
{
	enum { MAX_ARGS = 32 };
	struct btrfs_fs_info *fs_info;
	int nargc = 0;
	char *nargv[MAX_ARGS] = {};
	char *paras[2] = {};
	int i;

	/*
	 * We pass all parameters to fuse directly, but we want to scan btrfs
	 * on all parameters except the last one.
	 */
	for (i = 0; i < argc && nargc < MAX_ARGS; i++) {
		int ret;

		if (i == 0)
			goto pass;

		if (argv[i][0] == '-')
			goto pass;

		/*
		 * This parameter can be a device or a mount point.
		 *
		 * If it's the last parameter, it will be added to nargv[]
		 * after the loop.
		 * So we don't need to pass current parameter to fuse.
		 */
		paras[1] = paras[0];
		paras[0] = argv[i];
		if (!paras[1])
			continue;
		/*
		 * paras[1] is definitely not the last parameter,
		 * thus it should be a btrfs device.
		 *
		 * Do the device scan and don't pass it to fuse.
		 * Fuse only needs to handle all options and mount point.
		 */
		ret = btrfs_scan_device(paras[1], NULL);
		if (ret < 0) {
			error("failed to scan device %s: %d", paras[1], ret);
			btrfs_exit();
			return 1;
		}
		continue;
pass:
		nargv[nargc] = argv[i];
		nargc++;
	}
	if (paras[0]) {
		nargv[nargc] = paras[0];
		nargc++;
	} else {
		usage();
	}

	if (nargc + 1 >= MAX_ARGS) {
		error("too many args for FUSE, max supported args is %u", MAX_ARGS);
		return 1;
	}

	if (paras[1]) {
		fs_info = btrfs_mount(paras[1]);
		if (IS_ERR(fs_info)) {
			error("failed to open btrfs on device %s", paras[1]);
			btrfs_exit();
			return 1;
		}
		global_info = fs_info;
	}

	/* Either run FUSE or let FUSE handle "--help" output */
	return fuse_main(nargc, nargv, &btrfs_fuse_ops, NULL);
}
