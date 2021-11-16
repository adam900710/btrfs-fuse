#!/bin/bash

build_dir=$1

usage()
{
	echo "usage:"
	echo "  $0: <build dir>"
	exit 1
}

if [ -z $build_dir ]; then
	usage
fi


if  [ $(whoami) != "root" ]; then
	echo "need root privilege"
	exit 1;
fi

declare -a devs
for (( i = 0; i < 4; i++ )); do
	devs[$i]="${build_dir}/dev${i}"
done

for dev in ${devs[@]}; do
	truncate -s 1G "$dev"
done

fsstress="$build_dir/fsstress"
fssum="$build_dir/fssum"
fuse="$build_dir/btrfs-fuse"
mnt="$build_dir/mnt"
log="$build_dir/log"
tmp=$(mktemp --tmpdir btrfs-fuse-tests.XXXXXX)
nr_ops=1024

cleanup()
{
	umount "$mnt" &> /dev/null
	if [ -f "$tmp.fssum_kernel" ]; then
		cp "$tmp.fssum_kernel" "$build_dir/fssum_kernel"
	fi
	rm -rf - "$tmp*"
}

fail()
{
	echo "$*" | tee -a "$log"
	cleanup
	exit 1
}

require_command()
{
	type -p "$1" &> /dev/null
	if [ $? -ne 0 ]; then
		fail "command '$1' not found"
	fi
}

fssum_generate()
{
	dir=$1

	if [ -z "$dir" ]; then
		fail "need a path"
	fi

	# Don't create snapshot, as due to FUSE ino/st_dev limit, fssum has no
	# way to detect snapshot boundary 
	"$fsstress" -f snapshot=0 -w -n "$nr_ops" -d "$mnt" >> "$log" ||\
	       	fail "fsstress failed"

	mount -o ro,remount "$mnt" || fail "remount failed"

	# No XATTR support yet, thus don't take xattr into fssum
	"$fssum" -T -f -w "$tmp.fssum_kernel" "$mnt" ||\
		fail "fssum generation failed"
}

test_default()
{
	echo "=== test default mkfs profile ===" | tee -a "$log"
	mkfs.btrfs -f "${devs[0]}" > /dev/null
	mount "${devs[0]}" "$mnt" || fail "mount failed"
	fssum_generate "$mnt"
	umount "$mnt"

	"$fuse" "${devs[0]}" "$mnt" || fail "fuse mount failed"
	"$fssum" -r "$tmp.fssum_kernel" "$mnt" >> "$log" || fail "fssum verification failed"
	fusermount -u "$mnt" || fail "fuse unmount failed"
}

mkdir -p $mnt

require_command mkfs.btrfs
require_command fusermount

test_default
