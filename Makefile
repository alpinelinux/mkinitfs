
VERSION		:= 2.0_rc7

sysconfdir	?= /etc/mkinitfs
datarootdir	?= /usr/share
datadir		?= $(datarootdir)/mkinitfs

SBIN_FILES	:= mkinitfs bootchartd
SHARE_FILES	:= initramfs-init fstab passwd group
CONF_FILES	:= mkinitfs.conf \
		modules.d/ata \
		modules.d/base \
		modules.d/cdrom \
		modules.d/cramfs \
		modules.d/ext2 \
		modules.d/ext3 \
		modules.d/ext4 \
		modules.d/floppy \
		modules.d/raid \
		modules.d/reiserfs \
		modules.d/scsi \
		modules.d/ubifs \
		modules.d/usb \
		modules.d/xfs \
		files.d/bootchart \
		files.d/base

SCRIPTS		:= $(SBIN_FILES) initramfs-init 
IN_FILES	:= $(addsuffix .in,$(SCRIPTS))

GIT_REV := $(shell test -d .git && git describe || echo exported)
ifneq ($(GIT_REV), exported)
FULL_VERSION    := $(patsubst $(PACKAGE)-%,%,$(GIT_REV))
FULL_VERSION    := $(patsubst v%,%,$(FULL_VERSION))
else
FULL_VERSION    := $(VERSION)
endif


DISTFILES	:= $(IN_FILES) $(CONF_FILES) Makefile

INSTALL		:= install
SED		:= sed
SED_REPLACE	:= -e 's:@VERSION@:$(FULL_VERSION):g' \
		-e 's:@sysconfdir@:$(sysconfdir):g' \
		-e 's:@datadir@:$(datadir):g'


all:	$(SCRIPTS)

clean:
	rm -f $(SCRIPTS)

help:
	@echo mkinitfs $(VERSION)
	@echo "usage: make install [DESTDIR=]"

.SUFFIXES:	.in
.in:
	${SED} ${SED_REPLACE} ${SED_EXTRA} $< > $@

install: $(SBIN_FILES) $(SHARE_FILES) $(CONF_FILES)
	for i in $(SBIN_FILES); do \
		$(INSTALL) -Dm755 $$i $(DESTDIR)/sbin/$$i;\
	done
	for i in $(CONF_FILES); do \
		$(INSTALL) -Dm644 $$i $(DESTDIR)/etc/mkinitfs/$$i;\
	done
	for i in $(SHARE_FILES); do \
		$(INSTALL) -D $$i $(DESTDIR)/usr/share/mkinitfs/$$i;\
	done

