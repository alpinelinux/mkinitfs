#!/bin/sh

set -e
set -u

# Defaults
operation=full
noconfirm=0
clean_all=0
retcode=0
flags=""
clean=1

usage () {
	cat >&2 <<-EOF
	$0 [flags] [operation]

	operation:
	  full (default)
	  clean
	  help (this help)

	flags:
	  -h: help (this help)
	  -d: turn on nlplug-findfs debug output
	  -y: skip confirmation at program start
	  -x: clean all (including produced binaries)
	  -k: keep devices (dont clean up)
	EOF
	exit 1
}

while [ $# -gt 0 ]
do
	case "$1" in
		"-d") flags="-d $flags"; shift;;
		"-y") noconfirm=1; shift;;
		"-x") clean_all=1; shift;;
		"-h"|"--help") usage; shift;;
		"-k") clean=""; shift;;
		"-"*) shift;; # Ignore erroneous flags
		*) break;;
	esac
done

[ $# -eq 1 ] && operation=$1

[ $noconfirm -eq 0 ] && echo \
"Warning: this script is going to de-setup all your existing /dev/loop* devices
at exit. Press enter to continue, or ^C to cancel." >&2
[ $noconfirm -eq 0 ] && read dummy

if [ "$operation" != "clean" ]
then
	passphrase=foobar
	mkdir -p local-mount

	if [ ! -f ./nlplug-findfs ]; then
		echo "> Creating nlplug-findfs"
		make
	fi

	echo "> Creating images"
	dd if=/dev/zero of=block count=10 bs=1M 2>&1 | sed 's/^/\t/g'
	[ "$operation" = "header" ] && dd if=/dev/zero of=header count=1024 bs=65536 2>&1 | sed 's/^/\t/g'

	echo "> Setting up the loop devices"
	block="$(sudo losetup -f)"
	echo "> Setting up block as $block"
	sudo losetup $block block 2>&1 | sed 's/^/\t/g'
	[ "$operation" = "header" ] && header="$(sudo losetup -f)"
	[ "$operation" = "header" ] && echo "> Setting up header as $header"
	[ "$operation" = "header" ] && sudo losetup $header header 2>&1 | sed 's/^/\t/g'

	[ "$operation" != "header" ] && echo "> Formatting '$block' with passphrase '$passphrase'."
	[ "$operation" = "header" ] && echo "> Formatting '$block' with header '$header' and passphrase '$passphrase'."
	[ "$operation" != "header" ] && printf "%s" "$passphrase" | sudo cryptsetup luksFormat -q $block - 2>&1 | sed 's/^/\t/g'
	[ "$operation" = "header" ] && printf "%s" "$passphrase" | sudo cryptsetup luksFormat -q --header $header $block - 2>&1 | sed 's/^/\t/g'
	echo "> Opening the device '$block' as /dev/mapper/temp-test"
	[ "$operation" != "header" ] && printf "%s" "$passphrase" | sudo cryptsetup luksOpen -q $block temp-test - 2>&1 | sed 's/^/\t/g'
	[ "$operation" = "header" ] && printf "%s" "$passphrase" | sudo cryptsetup luksOpen -q --header $header $block temp-test - 2>&1 | sed 's/^/\t/g'
	echo "> Creating a filesystem on '/dev/mapper/temp-test'"
	sudo mkfs.ext2 /dev/mapper/temp-test
	echo "> Mounting the fs"
	sudo mount -t ext2 /dev/mapper/temp-test local-mount
	echo "> Creating proof in the mounted fs"
	sudo sh -c 'date "+proof:%s" > local-mount/proof'
	proof=$(cat local-mount/proof)
	echo "> Proof is: '$proof'"
	echo "> Unmounting the fs"
	sudo umount local-mount
	echo "> Closing the device '/dev/mapper/temp-test'"
	sudo cryptsetup luksClose temp-test

	echo "> Testing nlplug-findfs on $block (passphrase was '$passphrase')"
	[ "$operation" != "header" ] && { echo "$passphrase" | sudo ./nlplug-findfs -p /sbin/mdev ${flags} -c $block -m 'test-device' /dev/mapper/test-device || retcode=1; }
	[ "$operation" = "header" ] && { echo "$passphrase" | sudo ./nlplug-findfs -p /sbin/mdev ${flags} -H $header -c $block -m 'test-device' /dev/mapper/test-device || retcode=1; }

	if [ $retcode -eq 0 ]; then
		echo "> Mounting the device"
		sudo mount /dev/mapper/test-device local-mount
		echo "> Getting proof"
		check=$(cat local-mount/proof)
		echo "Retrieved proof is: $check"
		if [ "$check" != "$proof" ]; then
			retcode=1
		fi
	fi
	[ $retcode -eq 0 ] && echo "Operation succeeded, proofs match" || echo "Operation failed, proofs don't match"
fi

if [ -z  "$clean" ]; then
	exit
fi
echo "> Cleaning up"
mountpoint local-mount && sudo umount local-mount
[ -b /dev/mapper/test-device ] && sudo cryptsetup luksClose test-device
for i in $(seq 0 $(($(sudo losetup -f | sed 's:^[a-z/]*\([0-9]*\)$:\1:; s/$/-1/')))); do
	sudo losetup -d /dev/loop$i
done
[ -d local-mount ] && rmdir local-mount
[ -f block ] && rm block
[ -f header ] && rm header
[ $clean_all -eq 1 ] && ( make clean; rm -f nlplug-findfs nlplug-findfs.o )
exit $retcode
# vim: ts=4:sw=4
