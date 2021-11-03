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

Usage
-----

For now, the generated binary `btrfs-fuse` only does selftest for
`btrfs_mount()` function to make sure the bootstrap and metadata reading is
working.

Example:

```
# mkfs.btrfs /dev/test/test
$ ./build/btrfs-fuse /dev/test/test
INFO: btrfs-fuse test for bootstrap on /dev/test/test
INFO: test ran fine for /dev/test/test
```

License
-------

All files at the root directory is under MIT license.

Files under `libs` directory is under their own licenses.
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
