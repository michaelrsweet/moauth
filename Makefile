#
# moauth top-level makefile
#
# Copyright © 2017 by Michael R Sweet
#
# Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
#

# Include common stuff...
include Makedefs


# Subdirectories...
SUBDIRS	=	moauth moauthd


# Make everything...
all:
	for dir in $(SUBDIRS); do \
		(cd $$dir; $(MAKE) $(MFLAGS) all || exit 1); \
	done

# Clean everything...
clean:
	for dir in $(SUBDIRS); do \
		(cd $$dir; $(MAKE) $(MFLAGS) clean || exit 1); \
	done


# Install everything...
install:	all
	for dir in $(SUBDIRS); do \
		(cd $$dir; $(MAKE) $(MFLAGS) install || exit 1); \
	done


# Test everything...
test:
	for dir in $(SUBDIRS); do \
		(cd $$dir; $(MAKE) $(MFLAGS) test || exit 1); \
	done
