project('btrfs-fuse', 'c')
src = ['accessors.c', 'hash.c', 'main.c', 'messages.c', 'metadata.c',
       'super.c', 'volumes.c', 'inode.c', 'libs/crc32c.c', 'libs/rbtree.c']

uuid_dep = dependency('uuid')
blake2_dep = dependency('libb2')
crypto_dep = dependency('libcrypto')
xxhash_dep = dependency('libxxhash')

deps = [uuid_dep, blake2_dep, crypto_dep, xxhash_dep ]
executable('btrfs-fuse', src, dependencies: deps)
