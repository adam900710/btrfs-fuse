// SPDX-License-Identifier: MIT

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
