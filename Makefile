# Hey Emacs this is a -*- makefile-*-

PACKAGE_NAME	= kexec-tools
PACKAGE_VERSION	= 2.0.13.git

prefix		= /usr/local
exec_prefix	= ${prefix}

bindir		= ${exec_prefix}/bin
sbindir		= ${exec_prefix}/sbin
libexecdir	= ${exec_prefix}/libexec
datadir		= ${datarootdir}
datarootdir	= ${prefix}/share
sysconfdir	= ${prefix}/etc
sharedstatedir	= ${prefix}/com
localstatedir	= ${prefix}/var
libdir		= ${exec_prefix}/lib
infodir		= ${datarootdir}/info
mandir		= ${datarootdir}/man
includedir	= ${prefix}/include


# The target architecture
ARCH		= x86_64
SUBARCH		= 
OBJDIR		= /home/bhsharma/code/upstream/kexec-tools/objdir
target		= x86_64-unknown-linux-gnu
host		= x86_64-unknown-linux-gnu

# Compiler for building kexec
CC		= gcc
CPP		= gcc -E
LD		= ld
AS		= as
OBJCOPY		= objcopy
AR		= ar

# C compiler for binaries to run during the build
BUILD_CC	= gcc
BUILD_CFLAGS	= -O2 -Wall
TARGET_CC	= gcc
TARGET_LD	= ld
TARGET_CFLAGS	= -O2 -Wall


# Base compiler flags. These are extended by the subcomponent-Makefiles
# where necessary.
CPPFLAGS	=  -I$(srcdir)/include -I$(srcdir)/util_lib/include \
			-Iinclude/ $($(ARCH)_CPPFLAGS)
CFLAGS		= -g -O2 -fno-strict-aliasing -Wall -Wstrict-prototypes
PURGATORY_EXTRA_CFLAGS = -fno-zero-initialized-in-bss
ASFLAGS		=  $($(ARCH)_ASFLAGS)
LDFLAGS		= 
LIBS		= 

# Utilities called by the makefiles
INSTALL		= /usr/bin/install -c
MKDIR		= mkdir
RM		= rm
CP		= cp
LN		= ln
TAR		= tar
RPMBUILD	= no
SED		= sed
FIND		= find
XARGS		= xargs
DIRNAME		= dirname
STRIP		= strip


pkgdatadir = $(datadir)/$(PACKAGE_NAME)
pkglibdir = $(libdir)/$(PACKAGE_NAME)
pkgincludedir = $(includedir)/$(PACKAGE_NAME)

# You can specify DESTDIR on the command line to do a add
# a prefix to the install so it doesn't really happen
# Useful for building binary packages
DESTDIR =

srcdir		= .
VPATH		= .

# install paths
BUILD_PREFIX:=build
SBINDIR=$(BUILD_PREFIX)/sbin
BINDIR=$(BUILD_PREFIX)/bin
LIBEXECDIR=$(BUILD_PREFIX)/libexec
DATADIR=$(BUILD_PREFIX)/share
SYSCONFDIR=$(BUILD_PREFIX)/etc
SHAREDSTATEDIR=$(BUILD_PREFIX)/com
LOCALSTATEDIR=$(BUILD_PREFIX)/var
LIBDIR=$(BUILD_PREFIX)/lib
INFODIR=$(BUILD_PREFIX)/info
MANDIR=$(BUILD_PREFIX)/man
MAN1DIR=$(MANDIR)/man1
MAN2DIR=$(MANDIR)/man2
MAN3DIR=$(MANDIR)/man3
MAN4DIR=$(MANDIR)/man4
MAN5DIR=$(MANDIR)/man5
MAN6DIR=$(MANDIR)/man6
MAN7DIR=$(MANDIR)/man7
MAN8DIR=$(MANDIR)/man8
INCLUDEDIR=$(BUILD_PREFIX)/include

PKGDATADIR=$(DATADIR)/$(PACKAGE_NAME)
PKGLIBDIR=$(LIBDIR)/$(PACKAGE_NAME)
PKGINCLUDEIR=$(INCLUDEDIR)/$(PACKAGE_NAME)

all: targets

# generic build rules
%.o: %.c
	@$(MKDIR) -p $(@D)
	$(COMPILE.c) -MD -o $@ $<

%.o: %.S
	@$(MKDIR) -p $(@D)
	$(COMPILE.S) -MD -o $@ $<

# collect objects to be removed in 'make clean'
clean =

dist =	AUTHORS COPYING INSTALL News TODO Makefile.in configure.ac configure \
	kexec-tools.spec.in config/

# utility function for converting a list of files (with extension) to
# file.o (or file.d) format.
objify = $(addsuffix .o, $(basename $(1)))
depify = $(addsuffix .d, $(basename $(1)))

# Documentation
#
include $(srcdir)/doc/Makefile

# Headers
#
include $(srcdir)/include/Makefile

# Utility function library
#
include $(srcdir)/util_lib/Makefile

#
# Stand alone utilities
#
include $(srcdir)/util/Makefile

#
# purgatory (code between kernels)
#
include $(srcdir)/purgatory/Makefile

#
# kexec (linux booting linux)
#
include $(srcdir)/kexec/Makefile

# vmcore-dmesg (read dmesg from a vmcore)
#
include $(srcdir)/vmcore-dmesg/Makefile

#
# kexec_test (test program)
#
include $(srcdir)/kexec_test/Makefile

SPEC=$(PACKAGE_NAME).spec
GENERATED_SRCS:= $(SPEC)
TARBALL=$(PACKAGE_NAME)-$(PACKAGE_VERSION).tar
TARBALL.gz=$(TARBALL).gz
SRCS:= $(dist)
PSRCS:=$(foreach s, $(SRCS), $(PACKAGE_NAME)-$(PACKAGE_VERSION)/$(s))
PGSRCS:=$(foreach s, $(GENERATED_SRCS), $(PACKAGE_NAME)-$(PACKAGE_VERSION)/$(s))

MAN_PAGES:=$(KEXEC_MANPAGE) $(VMCORE_DMESG_MANPAGE)
BINARIES_i386:=$(KEXEC_TEST)
BINARIES_x86_64:=$(KEXEC_TEST)
BINARIES:=$(KEXEC) $(VMCORE_DMESG) $(BINARIES_$(ARCH))

TARGETS:=$(BINARIES) $(MAN_PAGES)

targets: $(TARGETS)

Makefile: Makefile.in config.status
	./config.status

configure: configure.ac
	cd $(srcdir) && autoheader && autoconf && rm -rf autom4te.cache

tarball: $(TARBALL.gz)

$(TARBALL): $(SRCS) $(GENERATED_SRCS)
	$(RM) -f $(PACKAGE_NAME)-$(PACKAGE_VERSION)
	$(LN) -s $(srcdir) $(PACKAGE_NAME)-$(PACKAGE_VERSION)
	$(TAR) -cf $@ $(PSRCS)
	$(RM) -f $(PACKAGE_NAME)-$(PACKAGE_VERSION)
	$(LN) -sf . $(PACKAGE_NAME)-$(PACKAGE_VERSION)
	$(TAR) -rf $@ $(PGSRCS)
	$(RM) -f $(PACKAGE_NAME)-$(PACKAGE_VERSION)
	@echo $(dist)

$(TARBALL.gz): $(TARBALL)
	gzip -c < $^ > $@

rpm: $(TARBALL.gz)
	unset MAKEFLAGS MAKELEVEL;
	$(RPMBUILD) -ta $(TARBALL.gz)

$(SPEC): kexec-tools.spec.in Makefile
	$(SED) -e 's,^Version: $$,Version: $(PACKAGE_VERSION),' $< > $@

echo::
	@echo ARCH=$(ARCH)
	@echo BINARIES=$(BINARIES)
	@echo TARGETS=$(TARGETS)
	@echo CC=$(CC)
	@echo AR=$(AR)
	@echo LD=$(LD)
	@echo STRIP=$(STRIP)

clean:
	$(RM) -f $(clean)
	$(RM) -rf build
	$(RM) -f $(TARBALL) $(TARBALL.gz)

distclean: dist-clean

dist-clean: clean
	$(RM) -f config.log config.status config.cache Makefile include/config.h
	$(RM) -f include/config.h.in configure $(SPEC)
	$(RM) -rf autom4te.cache

install: $(TARGETS)
	for file in $(TARGETS) ; do \
		if test `$(DIRNAME) $$file` =     "$(SBINDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(sbindir)/; \
			$(INSTALL) -m 755  $$file $(DESTDIR)/$(sbindir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(BINDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(bindir)/; \
			$(INSTALL) -m 755 $$file $(DESTDIR)/$(bindir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(LIBEXECDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(libexecdir)/; \
			$(INSTALL) -m 755 $$file $(DESTDIR)/$(libexecdir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(DATADIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(datadir)/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(datadir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(SYSCONFDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(sysconfdir)/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(sysconfdir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(SHAREDSTATEDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(sharedstatedir)/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(sharedstatedir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(LOCALSTATEDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(localstatedir)/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(localstatedir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(LIBDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(libdir)/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(libdir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(INFODIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(infodir)/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(infodir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN1DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man1; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(mandir)/man1; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN2DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man2; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(mandir)/man2; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN3DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man3/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(mandir)/man3/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN4DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man4/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(mandir)/man4/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN5DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man5/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(mandir)/man5/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN6DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man6/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(mandir)/man6/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN7DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man7/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(mandir)/man7/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(MAN8DIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(mandir)/man8/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(mandir)/man8/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(INCLUDEDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(includedir)/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(includedir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(PKGDATADIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(pkgdatadir)/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(pkgdatadir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(PKGLIBDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(pkglibdir)/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(pkglibdir)/; \
		fi; \
		if test `$(DIRNAME) $$file` =     "$(PKGINCLUDEDIR)" ; then \
			$(MKDIR) -p     $(DESTDIR)/$(pkgincludedir)/; \
			$(INSTALL) -m 644 $$file $(DESTDIR)/$(pkgincludedir)/; \
		fi; \
	done

.PHONY: echo install all targets clean dist-clean distclean \
	maintainer-clean maintainerclean tarball rpm
