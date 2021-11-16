project('btrfs-fuse', 'c')

if get_option('buildtype').startswith('debug')
  add_project_arguments('-DDEBUG', language : ['c'])
endif
btrfs_fuse_src = ['accessors.c', 'hash.c', 'main.c', 'messages.c', 'metadata.c',
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

btrfs_fuse_deps = [uuid_dep, hash_deps, compression_deps, fuse_dep]
executable('btrfs-fuse', btrfs_fuse_src, dependencies: btrfs_fuse_deps,
           install: true)

# The rest are all for selftests
#
# Btrfs-progs is a hard-requirement so that fsstress can create subvolumes and
# snapshots. Without that we can't test the name resolve for subvolumes.
btrfs_dep = dependency('libbtrfsutil')
test_args = ['-D_GNU_SOURCE', '-D_FILE_OFFSET_BITS=64']
if btrfs_dep.found()
  test_args += ['-DHAVE_BTRFSUTIL_H']
endif

if cc.has_header('linux/fiemap.h')
  test_args += ['-DHAVE_LINUX_FIEMAP_H']
endif

if cc.has_header('sys/prctl.h')
  test_args += ['-DHAVE_SYS_PRCTL_H']
endif

aio_dep = cc.find_library('aio', has_headers: ['libaio.h'], required: false)
if aio_dep.found()
  test_args += ['-DAIO']
endif

uring_dep = dependency('liburing', required: false)
if aio_dep.found()
  test_args += ['-DURING']
endif

if cc.has_function('renameat2')
  test_args += ['-DHAVE_RENAMEAT2']
endif

if cc.has_header('xfs/xfs.h')
  test_args += ['-DHAVE_XFS_XFS_H']
endif
if cc.has_header('xfs/jdm.h')
  test_args += ['-DHAVE_XFS_JDM_H']
endif

test_deps = [btrfs_dep, aio_dep, uring_dep ]
executable('fsstress', 'tests/fsstress.c', c_args: test_args,
           dependencies: test_deps, install: false)
