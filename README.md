# mkinitfs

This is the initramfs generator for Alpine Linux, including support for apk and 
Alpine Diskless boot.

## Dependencies

To compile manually, you need to have the following build tools available:

- make
- gcc with musl and kernel-headers

nlplug-findfs will link against the following libraries (runtime deps):

- libkmod
- libblkid (from util-linux)
- libcryptsetup

## Installation

Build mkinitfs via `make` and install it via `make install`.
The installation honours the `DESTDIR` parameter to overwrite the sysroot path.

For testing, its not necessary to install `mkinitfs` into your root file system.

## Tweaking

The Makefile is kept slim and debuggable.
