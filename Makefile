
VERSION		:= $(shell awk -F= '$$1=="VERSION" {print($$2)}' mkinitfs)


SBIN_FILES	:= mkinitfs bootchartd
SHARE_FILES	:= initramfs-init
CONF_FILES	:= mkinitfs.conf \
		modules.d/ata \
		modules.d/ide \
		modules.d/base \
		modules.d/raid \
		modules.d/scsi \
		modules.d/cdrom \
		modules.d/usb \
		modules.d/cramfs \
		files.d/bootchart \
		files.d/base

DISTFILES	:= $(SBIN_FILES) $(CONF_FILES) $(SHARE_FILES) Makefile

INSTALL		:= install

help:
	@echo mkinitfs $(VERSION)
	@echo "usage: make install [DESTDIR=]"

install:
	for i in $(SBIN_FILES); do \
		$(INSTALL) -Dm755 $$i $(DESTDIR)/sbin/$$i || exit 1;\
	done
	for i in $(CONF_FILES); do \
		$(INSTALL) -Dm644 $$i $(DESTDIR)/etc/mkinitfs/$$i || exit 1;\
	done
	for i in $(SHARE_FILES); do \
		$(INSTALL) -D $$i $(DESTDIR)/usr/share/mkinitfs/$$i || exit 1;\
	done

