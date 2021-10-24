// SPDX-License-Identifier: MIT

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>
#include "volumes.h"
#include "disk-io.h"
#include "messages.h"

static LIST_HEAD(global_fs_list);

static struct btrfs_device *global_add_device(const char* path, const u8 *fsid,
					      const u8 *dev_uuid, u64 devid)
{
	struct btrfs_fs_devices *fs_devs;
	struct btrfs_fs_devices *found_fs_devs = NULL;
	struct btrfs_device *dev;
	struct btrfs_device *found_dev = NULL;

	list_for_each_entry(fs_devs, &global_fs_list, fs_list) {
		if (memcmp(fsid, fs_devs->fsid, BTRFS_UUID_SIZE) == 0) {
			found_fs_devs = fs_devs;
			break;
		}
	}
	/* Allocate a new fs_devs */
	if (!found_fs_devs) {
		found_fs_devs = malloc(sizeof(*found_fs_devs));
		if (!found_fs_devs)
			return ERR_PTR(-ENOMEM);
		INIT_LIST_HEAD(&found_fs_devs->dev_list);
		found_fs_devs->num_devices = 0;
		memcpy(found_fs_devs->fsid, fsid, BTRFS_UUID_SIZE);
		list_add_tail(&found_fs_devs->fs_list, &global_fs_list);
	}

	list_for_each_entry(dev, &found_fs_devs->dev_list, list) {
		/* Conflicts found */
		if (dev->devid == devid &&
		    memcmp(dev_uuid, dev->uuid, BTRFS_UUID_SIZE)) {
			error("conflicting device found for devid %llu",
				devid);
			return ERR_PTR(-EEXIST);
		}
		if (dev->devid == devid &&
		    !memcmp(dev_uuid, dev->uuid, BTRFS_UUID_SIZE)) {
			found_dev = dev;
			break;
		}
	}
	if (!found_dev) {
		found_dev = malloc(sizeof(*found_dev));
		/*
		 * Here we can exit directly, for worst case we just added an empty
		 * btrfs_fs_dev, can be easily cleaned up.
		 */
		if (!found_dev) {
			if (found_fs_devs->num_devices == 0) {
				list_del(&found_fs_devs->fs_list);
				free(found_fs_devs);
			}
			return ERR_PTR(-ENOMEM);
		}
		found_dev->path = strndup(path, PATH_MAX);
		if (!found_dev->path) {
			if (found_fs_devs->num_devices == 0) {
				list_del(&found_fs_devs->fs_list);
				free(found_fs_devs);
			}
			free(found_dev);
			return ERR_PTR(-ENOMEM);
		}

		found_dev->devid = devid;
		memcpy(found_dev->uuid, dev_uuid, BTRFS_UUID_SIZE);
		

		/* fd and fs_info will be set when we mount the fs */
		found_dev->fd = -1;
		found_dev->fs_info = NULL;

		/* Add the new device to corresponding fs_devs */
		list_add_tail(&found_dev->list, &found_fs_devs->dev_list);
		found_fs_devs->num_devices++;
	}
	return 0;
}

int btrfs_scan_device(const char *path, struct btrfs_super_block *sb)
{
	struct btrfs_super_block buf;
	u64 devid;
	int ret = 0;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	ret = btrfs_read_from_disk(fd, (char *)&buf, BTRFS_SUPER_INFO_OFFSET,
				   BTRFS_SUPER_INFO_SIZE);
	if (ret < BTRFS_SUPER_INFO_SIZE) {
		if (ret > 0)
			ret = -EIO;
		goto out;
	}

	ret = btrfs_check_super(&buf);
	if (ret < 0)
		goto out;
	devid = btrfs_stack_device_id(&buf.dev_item);

	if (IS_ERR(global_add_device(path, buf.fsid, buf.dev_item.uuid, devid)))
		goto out;
	if (sb)
		memcpy(sb, &buf, BTRFS_SUPER_INFO_SIZE);
out:
	close(fd);
	return ret;
}

struct btrfs_fs_devices *btrfs_open_devices(struct btrfs_fs_info *fs_info)
{
	struct btrfs_fs_devices *fs_dev;
	struct btrfs_fs_devices *found_fs_dev = NULL;
	struct btrfs_device *device;
	u8 *fsid = fs_info->fsid;

	list_for_each_entry(fs_dev, &global_fs_list, fs_list) {
		if (!memcmp(fsid, fs_dev->fsid, BTRFS_UUID_SIZE)) {
			found_fs_dev = fs_dev;
			break;
		}
	}
	if (!found_fs_dev)
		return ERR_PTR(-ENOENT);

	list_for_each_entry(device, &found_fs_dev->dev_list, list) {
		/* Already opened */
		if (device->fd >= 0) {
			ASSERT(device->fs_info);
			continue;
		}

		device->fs_info = fs_info;

		/* We allow missing devices (aka, degraded by default) */
		if (!device->path) {
			warning("devid %llu missing", device->devid);
			continue;
		}
		device->fd = open(device->path, O_RDONLY);
		if (device->fd < 0)
			warning("failed to open devid %llu path %s", device->devid,
				device->path);
	}
	return found_fs_dev;
}
