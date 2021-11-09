project('btrfs-fuse', 'c')

if get_option('buildtype').startswith('debug')
  add_project_arguments('-DDEBUG', language : ['c'])
endif
src = ['accessors.c', 'hash.c', 'main.c', 'messages.c', 'metadata.c',
       'super.c', 'volumes.c', 'inode.c', 'data.c', 'compression.c',
       'libs/crc32c.c', 'libs/rbtree.c']

uuid_dep = dependency('uuid')

# Hash dependency
blake2_dep = dependency('libb2')
crypto_dep = dependency('libcrypto')
xxhash_dep = dependency('libxxhash')
hash_deps = [blake2_dep, crypto_dep, xxhash_dep]

# Compression dependency
zlib_dep = dependency('zlib')
lzo_dep = dependency('lzo2')
zstd_dep = dependency('libzstd')
compression_deps = [zlib_dep, lzo_dep, zstd_dep]

fuse_dep = dependency('fuse3')

deps = [uuid_dep, hash_deps, compression_deps, fuse_dep]
executable('btrfs-fuse', src, dependencies: deps)
