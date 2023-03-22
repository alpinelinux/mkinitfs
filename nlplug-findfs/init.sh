#!/bin/sh

# initramfs for testing nlplug-findfs
# Copyright (c) 2022-2023 Kaarle Ritvanen

export PATH=/usr/bin:/bin:/usr/sbin:/sbin

busybox mount -t proc none /proc
busybox mount -t sysfs none /sys
busybox mkdir /usr/bin /usr/sbin
/bin/busybox --install

param() {
	sed -E "s/^.* nlpffs_$1"'=([^ ]*)( .*)?/\1/;ta;d;:a' < /proc/cmdline
}

MODE=$(param mode)
TEST_PATH=$(param path)

APKOVL=foo.apkovl.tar.gz
BOOT_REPO=bar/.boot_repository

_mkfs() {
	local dev=/dev/$1
	shift

	mkfs.vfat $dev
	mkdir -p /mnt
	mount -t vfat $dev /mnt

	local path
	for path; do
		mkdir -p /mnt/$(dirname $path)
		: > /mnt/$path
	done

	umount /mnt
}

luks() {
	local args="-d $TEST_PATH/build/key ${3:+--header /dev/$3} /dev/$2"
	cryptsetup luksFormat $args < /dev/null
	cryptsetup open --type luks $args $1
}

luksfs() {
	local dev=$1
	local files=$2
	shift 2

	luks fs $dev $*
	_mkfs mapper/fs $files
	cryptsetup close fs
}

nlpffs() {
	local path=$1
	shift
	$path/nlplug-findfs -p /sbin/mdev "$@"
}

if [ "$MODE" = build ]; then
	nlpffs /sbin

	for disk in a b c d e f; do
		(
			for part in $(seq 3); do
				cat <<-EOF
					n
					p
					$part

					+32M
				EOF
			done
			echo w
		) | fdisk /dev/vd$disk
	done

	mdev -s

	set -ex
	_mkfs vda1 $APKOVL $BOOT_REPO
	_mkfs vdb1 $APKOVL
	
	luks pv vdc1
	lvm pvcreate /dev/mapper/pv
	lvm vgcreate vg /dev/mapper/pv
	lvm lvcreate -L 1M -n lv vg
	_mkfs vg/lv $APKOVL
	lvm vgchange -a n
	cryptsetup close pv
	_mkfs vdc2 $BOOT_REPO

	luksfs vdd1 "$APKOVL $BOOT_REPO"

	luksfs vde1 $BOOT_REPO vde2
	mdadm -C /dev/md0 -l 1 -n 2 --assume-clean --metadata 1.2 \
		/dev/vde3 /dev/vdf1
	_mkfs md0 $APKOVL
	mdadm -S /dev/md0
else
	set -x
	cd "$TEST_PATH"
	mkdir output
	cd output
	nlpffs .. $(param args | base64 -d)
	echo $? > status

	if [ "$MODE" = debug ]; then
		cd ..
		sh
	elif [ "$MODE" = test ]; then
		set +x
		echo -n "TEST RESULT:"
		for file in *; do
			echo -n " $file="
			sed ':a;N;s/\n/:/;ta' $file | tr -d $'\n'
		done
		echo
	fi
fi

poweroff -f
