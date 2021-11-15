project('btrfs-fuse', 'c')

if get_option('buildtype').startswith('debug')
  add_project_arguments('-DDEBUG', language : ['c'])
endif
src = ['accessors.c', 'hash.c', 'main.c', 'messages.c', 'metadata.c',
       'super.c', 'volumes.c', 'inode.c', 'data.c', 'compression.c',
       'libs/crc32c.c', 'libs/rbtree.c', 'libs/raid56.c', 'libs/tables.c']

cc = meson.get_compiler('c')

uuid_dep = dependency('uuid')

# Hash dependency
blake2_dep = dependency('libb2')
crypto_dep = dependency('libcrypto')
xxhash_dep = dependency('libxxhash')
hash_deps = [blake2_dep, crypto_dep, xxhash_dep]

# Compression dependency
zlib_dep = dependency('zlib')
# not using pkgconfig for lzo as older versions do not ship a definition
lzo_dep = cc.find_library('lzo2', has_headers: ['lzo/lzo2a.h'])
zstd_dep = dependency('libzstd')
compression_deps = [zlib_dep, lzo_dep, zstd_dep]

fuse_dep = dependency('fuse3')

deps = [uuid_dep, hash_deps, compression_deps, fuse_dep]
executable('btrfs-fuse', src, dependencies: deps, install: true)
