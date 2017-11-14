#
# moauth library makefile
#
# Copyright © 2017 by Michael R Sweet
#
# Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
#

# Include common stuff...
include ../Makedefs


# Library targets...
LIBOBJS	=	form.o

OBJS	=	$(LIBOBJS) testmoauth.o

HEADERS	=	moauth.h

TARGETS	=	libmoauth.a testmoauth


# Make everything...
all:	$(TARGETS)


# Clean everything...
clean:
	$(RM) $(TARGETS) $(OBJS)


# Install everything...
install:	all


# Test everything...
test:	testmoauth
	./testmoauth


# Unit test program...
testmoauth:	testmoauth.o libmoauth.a
	$(CC) $(LDFLAGS) -o $@ testmoauth.o libmoauth.a $(LIBS)


# moauth library...
libmoauth.a:	$(LIBOBJS)
	$(RM) $@
	$(AR) $(ARFLAGS) $@ $(LIBOBJS)
	$(RANLIB) $@


# Dependencies...
$(OBJS):	moauth.h
