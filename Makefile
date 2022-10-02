#
# moauth top-level makefile
#
# Copyright © 2017-2022 by Michael R Sweet
#
# Licensed under Apache License v2.0.  See the file "LICENSE" for more
# information.
#

# Include common stuff...
include Makedefs


# Subdirectories...
SUBDIRS	=	libcups/cups moauth moauthd


# Make everything...
all:
	echo "CC=$(CC)"
	echo "CFLAGS=$(CFLAGS)"
	echo "CODESIGN_IDENTITY=$(CODESIGN_IDENTITY)"
	echo "LDFLAGS=$(LDFLAGS)"
	echo "LIBS=$(LIBS)"
	for dir in $(SUBDIRS); do \
		echo "======== all in $$dir ========"; \
		(cd $$dir; $(MAKE) $(MFLAGS) all || exit 1); \
	done


# Clean everything...
clean:
	for dir in $(SUBDIRS); do \
		echo "======== clean in $$dir ========"; \
		(cd $$dir; $(MAKE) $(MFLAGS) clean || exit 1); \
	done


# Really clean everything...
distclean:	clean
	$(RM) config.h config.log config.status Makedefs


# Install everything...
install:	all
	for dir in $(SUBDIRS); do \
		echo "======== install in $$dir ========"; \
		(cd $$dir; $(MAKE) $(MFLAGS) install || exit 1); \
	done


# Test everything...
.PHONY:	test
test:
	for dir in moauth moauthd; do \
		echo "======== test in $$dir ========"; \
		(cd $$dir; $(MAKE) $(MFLAGS) test || exit 1); \
	done


#
# Don't run top-level build targets in parallel...
#

.NOTPARALLEL:
