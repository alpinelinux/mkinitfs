#!/bin/sh -e

# Test utility for nlplug-findfs
# Copyright (c) 2022-2023 Kaarle Ritvanen

cd "${0%/*}"
BINARY=$PWD/nlplug-findfs
BUILD_DIR=$PWD/build
mkdir -p "$BUILD_DIR"
KEY_FILE=$BUILD_DIR/key
INITRAMFS=$BUILD_DIR/initramfs

split_chars() {
	local s=$1
	while [ "$s" ]; do
		echo ${s:0:1}
		s=${s:1}
	done
}


disk_img() {
	echo "$BUILD_DIR/disk$1.img"
}

run_in_vm() {
	[ -f "$BINARY" ]
	[ -f "$KEY_FILE" ] || dd if=/dev/urandom of="$KEY_FILE" bs=32 count=1
	[ -f "$INITRAMFS" ] || custom_files="$BINARY $KEY_FILE" \
		mkinitfs -i init.sh -o "$INITRAMFS" \
		-F "base cryptsetup lvm raid usb virtio"

	local args=
	local disk
	for disk in $(split_chars $2); do
		args="$args -drive file=$(disk_img $disk),format=raw,if=virtio"
	done

	qemu-system-x86_64 -m 256 -nographic \
		-kernel /boot/vmlinuz-lts -initrd "$INITRAMFS" \
		-append "console=ttyS0 nlpffs_path=$PWD nlpffs_mode=$1 ${3:+nlpffs_args=$3}" \
		$args
}

build() {
	local disks=$(seq -s "" 0 5)
	local disk
	for disk in $(split_chars $disks); do
		qemu-img create $(disk_img $disk) 128M
	done
	run_in_vm build $disks < /dev/null
}

run_case_in_vm() {
	local mode=$1
	local case=$2
	shift 2

	local disks=
	local args=
	local opt
	for opt in $(split_chars "$case"); do
		case "$opt" in
		[0-9])
			[ -f $(disk_img $opt) ] || build > /dev/null
			disks="$disks$opt"
			;;
		[a-zA-Z])
			local arg
			for arg in \
				a:apkovl \
				b:bootrepo \
				c:vda1 \
				k:$KEY_FILE \
				m:cryptdev \
				H:vda2; do

				if [ ${arg%:*} = $opt ]; then
					opt="$opt ${arg#*:}"
					break
				fi
			done
			args="$args -$opt"
			;;
		esac
	done
	run_in_vm $mode $disks $(printf %s "$args $*" | base64 -w 0)
}


if [ $# -eq 0 ]; then
	MODE=run
else
	MODE=$1
	shift
fi

TEST=$1
ARGS=
case "$MODE" in
	build)
		build
		exit
		;;
	debug)
		run_case_in_vm debug "$@"
		exit
		;;
	custom)
		shift
		ARGS=$*
		;;
	update)
		TEST=
		;;
	run)
		;;
	*)
		exit 1
		;;
esac


expected() {
	if [ "$1" ]; then
		grep "^$1 " expected
	else
		cat expected
	fi
}

: > actual
run() {
	[ $MODE != run ] || expected "$1" > /dev/null

	(
		echo -n "$1 "
		local result=$(run_case_in_vm test "$@" < /dev/null | \
			sed "s/^TEST RESULT: //;ta;d;:a" | tr -d '\r\n')
		[ "$result" ] || result=FAILED
		echo "$result"
	) | tee -a actual
}

if [ "$TEST" ]; then
	run "$TEST" $ARGS
else
	for disks in 0 05 1 12 2 3 45; do
		for ab in a b ab; do
			for n in "" n; do
				for ckmH in "" ckm ckmH; do
					run $disks-$ab$n$ckmH
				done
			done
		done
	done
fi

if [ $MODE = update ]; then
	mv actual expected
elif [ $MODE = run ]; then
	expected $TEST | diff /dev/stdin actual
fi
