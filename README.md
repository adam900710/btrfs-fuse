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
