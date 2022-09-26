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

# For PPC64/MIPS64 which has u64 defined as unsigned long, and can
# cause warning for print formats.
# Use this marco to use more common u64 == unsigned long long.
if host_machine.cpu_family() == 'ppc64' or host_machine.cpu_family() == 'mips64'
  add_project_arguments('-D__SANE_USERSPACE_TYPES__', language : ['c'])
endif

btrfs_fuse_deps = [uuid_dep, hash_deps, compression_deps, fuse_dep]
executable('btrfs-fuse', btrfs_fuse_src, dependencies: btrfs_fuse_deps,
           install: true)

want_tests =  get_option('tests')

# The rest are all for selftests
#
# Btrfs-progs is a hard-requirement so that fsstress can create subvolumes and
# snapshots. Without that we can't test the name resolve for subvolumes.
btrfs_dep = dependency('libbtrfsutil', required: want_tests)
test_args = ['-D_GNU_SOURCE', '-D_FILE_OFFSET_BITS=64']
if btrfs_dep.found()
  test_args += ['-DHAVE_BTRFSUTIL_H']
endif

if cc.has_header('linux/fiemap.h', required: want_tests)
  test_args += ['-DHAVE_LINUX_FIEMAP_H']
endif

if cc.has_header('sys/prctl.h', required: want_tests)
  test_args += ['-DHAVE_SYS_PRCTL_H']
endif

aio_dep = cc.find_library('aio', has_headers: ['libaio.h'], required: want_tests)
if aio_dep.found()
  test_args += ['-DAIO']
endif

uring_dep = dependency('liburing', required: want_tests)
if uring_dep.found()
  test_args += ['-DURING']
endif

if cc.has_function('renameat2')
  test_args += ['-DHAVE_RENAMEAT2']
endif

if cc.has_header('xfs/xfs.h', required: want_tests)
  test_args += ['-DHAVE_XFS_XFS_H']
endif
if cc.has_header('xfs/jdm.h', required: want_tests)
  test_args += ['-DHAVE_XFS_JDM_H']
endif

test_deps = [btrfs_dep, aio_dep, uring_dep]
executable('fsstress', 'tests/fsstress.c', c_args: test_args,
           dependencies: test_deps, install: false)
executable('fssum', 'tests/fssum.c', c_args: test_args,
           dependencies: [test_deps, crypto_dep], install: false)
executable('corrupt', 'tests/corrupt.c', c_args: test_args,
           dependencies: [test_deps, crypto_dep], install: false)
