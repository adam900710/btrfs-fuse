// SPDX-License-Identifier: MIT

#include <strings.h>
#include <sys/param.h>
#include <sys/stat.h>
#include "inode.h"
#include "ctree.h"
#include "metadata.h"
#include "hash.h"
#include "messages.h"

int btrfs_lookup_one_name(struct btrfs_fs_info *fs_info,
			  struct btrfs_inode *dir, const char *name,
			  size_t name_len, struct btrfs_inode *inode_ret)
{
	struct btrfs_dir_item *di;
	struct btrfs_root *root;
	struct btrfs_key key;
	struct btrfs_path path;
	u64 ino;
	u32 cur;
	u32 item_start;
	u32 item_len;
	u8 file_type;
	bool found = false;
	int ret;

	if (dir->file_type != BTRFS_FT_DIR)
		return -ENOTDIR;

	btrfs_init_path(&path);
	key.objectid = dir->ino;
	key.type = BTRFS_DIR_ITEM_KEY;
	key.offset = btrfs_name_hash(name, name_len);

	ret = btrfs_search_key(dir->root, &path, &key);
	if (ret < 0) {
		btrfs_release_path(&path);
		return ret;
	}

	item_start = btrfs_item_ptr_offset(path.nodes[0], path.slots[0]);
	item_len = btrfs_item_size_nr(path.nodes[0], path.slots[0]);
	cur = item_start;
	/*
	 * We can have name hash conflicts, thus still need to verify the
	 * found dir_item one by one.
	 */
	while (cur < item_start + item_len) {
		u32 name_ptr;
		u32 this_item_size;

		di = (struct btrfs_dir_item *)(long)cur;
		this_item_size = sizeof(*di) +
			btrfs_dir_data_len(path.nodes[0], di) +
			btrfs_dir_name_len(path.nodes[0], di);

		if (cur + this_item_size > item_start + item_len) {
			error(
"invalid dir item size, cur=%u dir_item size=%u item start=%u item len=%u",
				cur, this_item_size, item_start, item_len);
			return -EUCLEAN;
		}

		cur = (u32)(long)(di + 1);
		name_ptr = cur;

		if (btrfs_dir_name_len(path.nodes[0], di) == name_len &&
		    !memcmp_extent_buffer(path.nodes[0], name, name_ptr, name_len)) {
			found = true;
			break;
		}
		cur += btrfs_dir_name_len(path.nodes[0], di);
	}
	if (!found) {
		btrfs_release_path(&path);
		return -ENOENT;
	}

	/* Found the dir item we want, extract root/ino from it */
	btrfs_dir_item_key_to_cpu(path.nodes[0], di, &key);
	if (key.type == BTRFS_ROOT_ITEM_KEY) {
		root = btrfs_read_root(fs_info, key.objectid);
		if (IS_ERR(root)) {
			ret = PTR_ERR(root);
			btrfs_release_path(&path);
			return ret;
		}
		ino = root->root_dirid;
		file_type = BTRFS_FT_DIR;
	} else if (key.type == BTRFS_INODE_ITEM_KEY){
		root = dir->root;
		ino = key.objectid;
		file_type = btrfs_dir_type(path.nodes[0], di);
	} else {
		error("invalid dir item key found: (%llu %u %llu)",
			key.objectid, key.type, key.offset);
		btrfs_release_path(&path);
		return -EUCLEAN;
	}
	btrfs_release_path(&path);

	inode_ret->root = root;
	inode_ret->ino = ino;
	inode_ret->file_type = file_type;
	return 0;
}

int btrfs_resolve_path(struct btrfs_fs_info *fs_info,
		       const char *path, size_t path_len,
		       struct btrfs_inode *inode_ret)
{
	struct btrfs_inode cur_inode;
	struct btrfs_inode next_inode;
	size_t offset = 0;
	char *slash_char;
	int ret;

	cur_inode.root = fs_info->default_root;
	cur_inode.ino = fs_info->default_root->root_dirid;
	cur_inode.file_type = BTRFS_FT_DIR;

	while (offset < path_len) {
		u32 name_len;

		/* Skip any '/' in the path*/
		if (path[offset] == '/') {
			offset++;
			continue;
		}

		/* Extract the next filename to resolve */
		slash_char = memchr(path + offset, '/', path_len - offset);
		if (slash_char) {
			name_len = slash_char - (path + offset);
		} else {
			/* Last name, no more '/' */
			name_len = path_len - offset;
		}

		ret = btrfs_lookup_one_name(fs_info, &cur_inode, path + offset,
					    name_len, &next_inode);
		if (ret < 0)
			return ret;

		memcpy(&cur_inode, &next_inode, sizeof(next_inode));
		offset += name_len;
	}

	memcpy(inode_ret, &cur_inode, sizeof(cur_inode));
	return 0;
}

int btrfs_read_link(struct btrfs_fs_info *fs_info,
		    struct btrfs_inode *inode, char *output,
		    size_t output_size)
{
	struct btrfs_file_extent_item *fi;
	struct btrfs_path path;
	struct btrfs_key key;
	u32 read_size;
	int ret;

	ASSERT(inode->file_type == BTRFS_FT_SYMLINK);

	btrfs_init_path(&path);
	key.objectid = inode->ino;
	key.type = BTRFS_EXTENT_DATA_KEY;
	key.offset = 0;

	ret = btrfs_search_key(inode->root, &path, &key);
	if (ret < 0) {
		btrfs_release_path(&path);
		return ret;
	}

	fi = btrfs_item_ptr(path.nodes[0], path.slots[0],
			    struct btrfs_file_extent_item);
	if (btrfs_file_extent_type(path.nodes[0], fi) !=
	    BTRFS_FILE_EXTENT_INLINE) {
		error("invalid file extent type, has %u expect %u",
			btrfs_file_extent_type(path.nodes[0], fi),
			BTRFS_FILE_EXTENT_INLINE);
		btrfs_release_path(&path);
		return -EUCLEAN;
	}
	if (btrfs_file_extent_compression(path.nodes[0], fi) !=
	    BTRFS_COMPRESS_NONE) {
		error("invalid file extent compression, has %u expect %u",
			btrfs_file_extent_compression(path.nodes[0], fi),
			BTRFS_COMPRESS_NONE);
		btrfs_release_path(&path);
		return -EUCLEAN;
	}
	if (btrfs_file_extent_ram_bytes(path.nodes[0], fi) == 0) {
		error("empty link length");
		btrfs_release_path(&path);
		return -EUCLEAN;
	}
	if (btrfs_file_extent_ram_bytes(path.nodes[0], fi) >= PATH_MAX) {
		error("invalid link length, has %llu max %u",
			btrfs_file_extent_ram_bytes(path.nodes[0], fi),
			PATH_MAX);
		btrfs_release_path(&path);
		return -ENAMETOOLONG;
	}
	read_size = MIN(btrfs_file_extent_ram_bytes(path.nodes[0], fi),
			output_size - 1);
	read_extent_buffer(path.nodes[0], output,
			   btrfs_file_extent_inline_start(fi),
			   read_size);
	output[read_size] = '\0';
	btrfs_release_path(&path);
	return read_size;
}

int btrfs_iterate_dir_start(struct btrfs_fs_info *fs_info,
			    struct btrfs_iterate_dir_ctrl *ctrl,
			    const struct btrfs_inode *dir, u64 start_index)
{
	struct btrfs_key_range *range = &ctrl->range;

	ASSERT(dir->file_type == BTRFS_FT_DIR);

	range->objectid = dir->ino;
	range->type_start = range->type_end = BTRFS_DIR_INDEX_KEY;
	range->offset_start = start_index;
	range->offset_end = (u64)-1;

	ctrl->dir.ino = dir->ino;
	ctrl->dir.root = dir->root;
	ctrl->dir.file_type = dir->file_type;
	btrfs_init_path(&ctrl->path);

	return btrfs_search_keys_start(ctrl->dir.root, &ctrl->path, &ctrl->range);
}

int btrfs_iterate_dir_get_inode(struct btrfs_fs_info *fs_info,
				struct btrfs_iterate_dir_ctrl *ctrl,
				struct btrfs_inode *entry,
				u64 *index_ret, char *name, size_t *name_len)
{
	struct btrfs_dir_item *di;
	struct btrfs_key key;

	btrfs_item_key_to_cpu(ctrl->path.nodes[0], &key, ctrl->path.slots[0]);
	ASSERT(key.type == BTRFS_DIR_INDEX_KEY);

	if (index_ret)
		*index_ret = key.offset;

	di = btrfs_item_ptr(ctrl->path.nodes[0], ctrl->path.slots[0],
			    struct btrfs_dir_item);
	btrfs_dir_item_key_to_cpu(ctrl->path.nodes[0], di, &key);

	if (key.type == BTRFS_INODE_ITEM_KEY) {
		entry->root = ctrl->dir.root;
		entry->ino = key.objectid;
	} else {
		struct btrfs_root *root;
		root = btrfs_read_root(fs_info, key.objectid);
		if (IS_ERR(root))
			return PTR_ERR(root);

		entry->root = root;
		entry->ino = root->root_dirid;
	}
	entry->file_type = btrfs_dir_type(ctrl->path.nodes[0], di);

	*name_len = btrfs_dir_name_len(ctrl->path.nodes[0], di);
	read_extent_buffer(ctrl->path.nodes[0], name, (unsigned long)(di + 1),
			   *name_len);
	return 0;
}

int btrfs_stat(struct btrfs_fs_info *fs_info, struct btrfs_inode *inode,
	       struct stat *stbuf)
{
	struct btrfs_inode_item *ii;
	struct extent_buffer *leaf;
	struct btrfs_path path;
	struct btrfs_key key;
	int ret;

	btrfs_init_path(&path);
	key.objectid = inode->ino;
	key.type = BTRFS_INODE_ITEM_KEY;
	key.offset = 0;

	ret = btrfs_search_key(inode->root, &path, &key);
	if (ret < 0)
		return ret;

	leaf = path.nodes[0];
	ii = btrfs_item_ptr(leaf, path.slots[0], struct btrfs_inode_item);
	stbuf->st_blksize = fs_info->sectorsize;
	stbuf->st_blocks = btrfs_inode_nbytes(leaf, ii) >> SECTOR_SHIFT;
	stbuf->st_size = btrfs_inode_size(leaf, ii);
	stbuf->st_gid = btrfs_inode_gid(leaf, ii);
	stbuf->st_uid = btrfs_inode_uid(leaf, ii);
	stbuf->st_mode = btrfs_inode_gid(leaf, ii);
	stbuf->st_ino = inode->ino;
	stbuf->st_nlink = btrfs_inode_nlink(leaf, ii);
	stbuf->st_mode = btrfs_inode_mode(leaf, ii);
	stbuf->st_atim.tv_sec = btrfs_timespec_sec(leaf, btrfs_inode_atime(ii));
	stbuf->st_atim.tv_nsec = btrfs_timespec_nsec(leaf, btrfs_inode_atime(ii));
	stbuf->st_ctim.tv_sec = btrfs_timespec_sec(leaf, btrfs_inode_ctime(ii));
	stbuf->st_ctim.tv_nsec = btrfs_timespec_nsec(leaf, btrfs_inode_ctime(ii));
	stbuf->st_mtim.tv_sec = btrfs_timespec_sec(leaf, btrfs_inode_mtime(ii));
	stbuf->st_mtim.tv_nsec = btrfs_timespec_nsec(leaf, btrfs_inode_mtime(ii));
	/*
	 * We don't have a good way to emulate the same anonymous device
	 * numbers in kernel. Thus here we just use subvolid id.
	 */
	stbuf->st_dev = inode->root->root_key.objectid;
	btrfs_release_path(&path);
	return 0;
}
