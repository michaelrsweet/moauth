#
# mOAuth library makefile
#
# Copyright © 2017-2024 by Michael R Sweet
#
# Licensed under Apache License v2.0.  See the file "LICENSE" for more
# information.
#

# Include common stuff...
include ../Makedefs


# Library targets...
LIBOBJS	=	\
		authorize.o \
		connect.o \
		post.o \
		random.o \
		register.o \
		token.o

OBJS	=	\
		$(LIBOBJS) \
		testmoauth.o

HEADERS	=	moauth.h

TARGETS	=	\
		libmoauth.a \
		testmoauth


# Make everything...
all:	$(TARGETS)


# Clean everything...
clean:
	$(RM) $(TARGETS) $(OBJS)


# Make documentation using codedoc (https://www.msweet.org/codedoc)
CODEDOC_OPTIONS = \
		libmoauth.xml \
		--author "Michael R Sweet" \
		--copyright "Copyright (c) 2017-2024" \
		--docversion "$(MOAUTH_VERSION)" \
		--title "mOAuth API Reference" \
		--body libmoauth-body.md

doc:
	echo Generating documentation...
	$(RM) libmoauth.xml
	codedoc $(CODEDOC_OPTIONS) $(LIBOBJS:.o=.c) $(HEADERS) >libmoauth.html
	codedoc $(CODEDOC_OPTIONS) --man libmoauth >libmoauth.3
	$(RM) libmoauth.xml


# Install everything...
install:	all
	$(INSTALL_DIR) $(BUILDROOT)$(includedir)
	$(INSTALL_DATA) moauth.h $(BUILDROOT)$(includedir)
	$(INSTALL_DIR) $(BUILDROOT)$(mandir)/man3
	$(INSTALL_MAN) libmoauth.3 $(BUILDROOT)$(mandir)/man3


# Test everything...
test:	testmoauth
	./testmoauth


# Unit test program...
testmoauth:	testmoauth.o libmoauth.a
	echo Linking $@...
	$(CC) $(LDFLAGS) -o $@ testmoauth.o libmoauth.a $(LIBS)
	$(CODE_SIGN) $(CSFLAGS) $@


# moauth library...
libmoauth.a:	$(LIBOBJS)
	echo Creating static library $@...
	$(RM) $@
	$(AR) $(ARFLAGS) $@ $(LIBOBJS)
	$(RANLIB) $@


# Dependencies...
$(OBJS):	moauth.h moauth-private.h
