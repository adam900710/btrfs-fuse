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
	file="${build_dir}/dev${i}"
	truncate -s 1G "$file"
	devs[$i]=$(losetup -f --show $file)
done

fsstress="$build_dir/fsstress"
fssum="$build_dir/fssum"
fuse="$build_dir/btrfs-fuse"
corrupt="$build_dir/corrupt"
mnt="$build_dir/mnt"
log="$build_dir/test-log"
tmp=$(mktemp --tmpdir btrfs-fuse-tests.XXXXXX)
nr_ops=1024

rm -rf "$log"

cleanup()
{
	umount "$mnt" &> /dev/null
	for ((i = 0; i < 4; i++)); do
		losetup -d "${devs[i]}"
	done
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

test_raid0()
{
	echo "=== test raid0 mkfs profile ===" | tee -a "$log"
	mkfs.btrfs -f "${devs[0]}" "${devs[1]}" -m raid0 -d raid0 > /dev/null
	mount "${devs[0]}" "$mnt" || fail "mount failed"
	fssum_generate "$mnt"
	umount "$mnt"

	"$fuse" "${devs[0]}" "${devs[1]}" "$mnt" || fail "fuse mount failed"
	"$fssum" -r "$tmp.fssum_kernel" "$mnt" >> "$log" || fail "fssum verification failed"
	fusermount -u "$mnt" || fail "fuse unmount failed"
}

test_raid1()
{
	echo "=== test raid1 mkfs profile ===" | tee -a "$log"
	mkfs.btrfs -f "${devs[0]}" "${devs[1]}" -m raid1 -d raid1 > /dev/null
	mount "${devs[0]}" "$mnt" || fail "mount failed"
	fssum_generate "$mnt"
	umount "$mnt"

	"$fuse" "${devs[0]}" "${devs[1]}" "$mnt" || fail "fuse mount failed"
	"$fssum" -r "$tmp.fssum_kernel" "$mnt" >> "$log" || fail "fssum verification failed"
	fusermount -u "$mnt" || fail "fuse unmount failed"

	echo "=== test raid1 with one missing dev ===" | tee -a "$log"
	"$fuse" "${devs[0]}" "$mnt" >> "$log" || fail "fuse mount failed"
	"$fssum" -r "$tmp.fssum_kernel" "$mnt" >> "$log" || fail "fssum verification failed"
	fusermount -u "$mnt" || fail "fuse unmount failed"

	echo "=== test raid1 with one corrupted dev ===" | tee -a "$log"
	"$corrupt" "${devs[0]}" >> "$log" || fail "file corruption failed"
	"$fuse" "${devs[0]}" "${devs[1]}" "$mnt" || fail "fuse mount failed"
	"$fssum" -r "$tmp.fssum_kernel" "$mnt" >> "$log" || fail "fssum verification failed"
	fusermount -u "$mnt" || fail "fuse unmount failed"
}

test_raid10()
{
	echo "=== test raid10 mkfs profile ===" | tee -a "$log"
	mkfs.btrfs -f "${devs[0]}" "${devs[1]}" "${devs[2]}" "${devs[3]}" \
		-m raid10 -d raid10 > /dev/null
	mount "${devs[0]}" "$mnt" || fail "mount failed"
	fssum_generate "$mnt"
	umount "$mnt"

	"$fuse" "${devs[0]}" "${devs[1]}" "${devs[2]}" "${devs[3]}" "$mnt" >> "$log" ||\
		fail "fuse mount failed"
	"$fssum" -r "$tmp.fssum_kernel" "$mnt" >> "$log" || fail "fssum verification failed"
	fusermount -u "$mnt" || fail "fuse unmount failed"

	# In theory we can handle two missing devices in different sub groups,
	# but that requires very strict device rotation during mkfs.
	echo "=== test raid10 with one missing devs ===" | tee -a "$log"
	"$fuse" "${devs[0]}" "${devs[1]}" "${devs[3]}" "$mnt" >> "$log" || fail "fuse mount failed"
	"$fssum" -r "$tmp.fssum_kernel" "$mnt" >> "$log" || fail "fssum verification failed"
	fusermount -u "$mnt" || fail "fuse unmount failed"

	echo "=== test raid10 with one corrupted dev ===" | tee -a "$log"
	"$corrupt" "${devs[0]}" >> "$log" || fail "file corruption failed"
	"$fuse" "${devs[0]}" "${devs[1]}" "${devs[2]}" "${devs[3]}" "$mnt" ||\
		fail "fuse mount failed"
	"$fssum" -r "$tmp.fssum_kernel" "$mnt" >> "$log" || fail "fssum verification failed"
	fusermount -u "$mnt" || fail "fuse unmount failed"
}

test_raid5()
{
	echo "=== test raid5 mkfs profile ===" | tee -a "$log"
	mkfs.btrfs -f "${devs[0]}" "${devs[1]}" "${devs[2]}" \
		-m raid5 -d raid5 &> /dev/null
	mount "${devs[0]}" "$mnt" || fail "mount failed"
	fssum_generate "$mnt"
	umount "$mnt"

	"$fuse" "${devs[0]}" "${devs[1]}" "${devs[2]}" "$mnt" >> "$log" ||\
		fail "fuse mount failed"
	"$fssum" -r "$tmp.fssum_kernel" "$mnt" >> "$log" || fail "fssum verification failed"
	fusermount -u "$mnt" || fail "fuse unmount failed"

	echo "=== test raid5 with one missing dev ===" | tee -a "$log"
	"$fuse" "${devs[0]}" "${devs[1]}" "$mnt" >> "$log" || fail "fuse mount failed"
	"$fssum" -r "$tmp.fssum_kernel" "$mnt" >> "$log" || fail "fssum verification failed"
	fusermount -u "$mnt" || fail "fuse unmount failed"

	echo "=== test raid5 with one corrupted dev ===" | tee -a "$log"
	"$corrupt" "${devs[0]}" >> "$log" || fail "file corruption failed"
	"$fuse" "${devs[0]}" "${devs[1]}" "${devs[2]}" "$mnt" >> "$log" ||\
		fail "fuse mount failed"
	"$fssum" -r "$tmp.fssum_kernel" "$mnt" >> "$log" || fail "fssum verification failed"
	fusermount -u "$mnt" || fail "fuse unmount failed"
}

test_raid6()
{
	echo "=== test raid6 mkfs profile ===" | tee -a "$log"
	mkfs.btrfs -f "${devs[0]}" "${devs[1]}" "${devs[2]}" "${devs[3]}"\
		-m raid6 -d raid6 &> /dev/null
	mount "${devs[0]}" "$mnt" || fail "mount failed"
	fssum_generate "$mnt"
	umount "$mnt"

	"$fuse" "${devs[0]}" "${devs[1]}" "${devs[2]}" "${devs[3]}" "$mnt" \
		>> "$log" || fail "fuse mount failed"
	"$fssum" -r "$tmp.fssum_kernel" "$mnt" >> "$log" || fail "fssum verification failed"
	fusermount -u "$mnt" || fail "fuse unmount failed"

	# RAID6 recovery with mixed corruption and missing is not handled well
	# in kernel/progs/btrfs-fuse.
	# Thus here we only test missing devices case.

	echo "=== test raid6 with two missing dev ===" | tee -a "$log"
	"$fuse" "${devs[0]}" "${devs[1]}" "$mnt" >> "$log" || fail "fuse mount failed"
	"$fssum" -r "$tmp.fssum_kernel" "$mnt" >> "$log" || fail "fssum verification failed"
	fusermount -u "$mnt" || fail "fuse unmount failed"
}
mkdir -p $mnt

require_command mkfs.btrfs
require_command fusermount
require_command losetup

test_default
test_raid0
test_raid1
test_raid10
test_raid5
test_raid6
cleanup
