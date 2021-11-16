btrfs-fuse
==========

About
-----

This is a read-only btrfs implementation using FUSE (Filesystem in Userspace).

Although btrfs is already in mainline Linux kernel, there are still use-cases
for such read-only btrfs implementation:

* Educational purpose

  Let new developers get a quick way to learn how a complex and modern
  filesystem works.

* For certain bootloaders

  Certain bootloaders need code base compatible with their license.

* As a last resort method for subpage/multipage support

  Currently (v5.16-rc) Linux kernel can only support sectorsize == pagesize , and
  4K sectorsize with 64K page size.

  Thus this project can act as a last resort method to read data from filesystem
  with unsupported sectorsize.


Build
-----

This project uses meson build system.

```
$ cd btrfs-fuse
$ meson setup build
$ cd build
$ ninja
```

This project has the following dependency:

- uuid

  For uuid parsing

- libb2

  For BLAKE2 checksum support

- libcrypto

  For SHA256 checksum support

- libxxhash

  For XXHASH checksum support

- zlib

  For zlib decompression support

- lzo2

  For lzo decompression support

- libzstd

  For zstd decompression support

- fuse3

  For FUSE interface.


There are some extra dependency for self-test tools:

- xfsprogs
- btrfs-progs
- aio (optional)
- liburing (optional)

Above dependencies are all for `fsstress` program.

Limitation
----------

Currently `btrfs-fuse` has the following btrfs features missing:

- xattr/fattr support

Above features are still under active development.

When such missing features is hit, `btrfs-fuse` would return -EOPNOTSUPP.


While there are still some other FUSE related feature missing:

- Proper subvolume inode address space

  This is due to FUSE limitation, that one FUSE must has the same `stat::st_dev`.
  In kernel btrfs returns different `stat::st_dev` for different subvolumes,
  but in FUSE we don't have the ability do the same thing.


Usage
-----

```
$ btrfs-fuse [<fuse options>] <device> [<extra devs> ...] <mnt>
```

Please note that, if multiple devices are passed into `btrfs-fuse` and contains
different file systems, `btrfs-fuse` will use the last device to initialize the
mount.

That's to say, for the following example:

```
$ mkfs.btrfs -f /dev/test/scratch1
$ mkfs.btrfs -f /dev/test/scratch2
$ btrfs-fuse /dev/test/scratch1 /dev/test/scratch2 /tmp/mount
```

Then only btrfs on `/dev/test/scratch2` will be mounted onto `/tmp/mount`.


License
-------

All files at the root directory is under MIT license.

Files under `libs` and `tests` directories are under their own licenses.
Mostly GPL-2.0+ or GPL-2.0-only.

Those external libs include:

- crc32c.[ch]

  For CRC32C checksum support.

  Cross-ported from btrfs-progs, which is cross-ported from older kernel, which
  is still under GPL-2.0+ license.

- list.h

  For kernel style list implementation.

  Cross-ported from btrfs-progs, which is cross-ported from kernel, and under
  GPL-2.0-only license.

- rbtree.[ch] and rbtree_augmented.h

  For kernel style rb-tree implementation.

  Cross-ported from btrfs-progs, which is cross-ported from kernel, and under
  GPL-2.0+ license.

- raid56.[ch] and tables.c

  For RAID56 rebuild.

  Cross-ported from btrfs-progs, which is cross-ported from kernel, and under
  GPL-2.0-only license.

- fsstress.c

  For populating the test mount point.

  Cross-ported from fstests, which is cross-ported from LTP, and under
  GPL-2.0-only license.

- fssum.c and md5.[ch]

  For verifying the content of the test filesystem.

  Cross-ported from fstests, under GPL-2.0-only license.

For projects which want to have btrfs read-only support, and already has a
FUSE-like interface (like GRUB), those files should not be cross-ported to the
project as above licenses are not compatible with the target project.

Instead either use wrappers around the interfaces provided by the target
project, or start from scratch and follow the license of the target project.
