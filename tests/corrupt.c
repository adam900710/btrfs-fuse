#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

static void usage(const char *name)
{
	printf("usage: %s <file>\n", name);
	exit(1);
}

#define BUF_SIZE	8
int main(int argc, char *argv[])
{
	struct stat stat_buf;
	char *path;
	char data_buf[BUF_SIZE];
	off_t size;
	int i;
	int fd;
	int ret;

	if (argc != 2)
		usage(argv[0]);

	path = argv[1];
	fd = open(path, O_RDWR);
	if (fd < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open file %s: %d\n", path, ret);
		return 1;
	}
	ret = fstat(fd, &stat_buf);
	if (ret < 0) {
		ret = -errno;
		fprintf(stderr, "failed to open file %s: %d\n", path, ret);
		goto out;
	}
	if (S_ISREG(stat_buf.st_mode)) {
		size = stat_buf.st_size;
	} else if (S_ISBLK(stat_buf.st_mode)) {
		ret = ioctl(fd, BLKGETSIZE64, &size);
		if (ret < 0) {
			ret = -errno;
			fprintf(stderr, "failed to get block dev size %s: %d\n",
				path, ret);
			goto out;
		}
	} else {
		ret = -EINVAL;
		fprintf(stderr, "%s is not a regular file or block device\n",
			path);
		goto out;
	}
	if (size <= 1024 * 1024) {
		ret = -EINVAL;
		fprintf(stderr, "file %s is too small\n", path);
		goto out;
	}
	srand(time(NULL));

	/* Corrupted 1/16 of the file */
	for (i = 0; i < (size / 16); i+= BUF_SIZE) {
		off_t dest_off = rand() % (size - 1024 * 1024);
		int j;

		/* Now dest_off is always beyond the first 1MB */
		dest_off += 1024 * 1024;

		for (j = 0; j < BUF_SIZE; j++)
			data_buf[j] = rand() % 256;

		ret = pwrite(fd, data_buf, BUF_SIZE, dest_off);
		if (ret != BUF_SIZE) {
			ret = -EIO;
			fprintf(stderr, "failed to write data into %s\n", path);
			goto out;
		}
	}
out:
	close(fd);
	if (ret < 0)
		return 1;
	printf("%s is corrupted with %u bytes\n", path, i);
	return 0;
}
