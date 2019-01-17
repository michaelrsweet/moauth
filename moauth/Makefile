#
# moauth library makefile
#
# Copyright © 2017-2019 by Michael R Sweet
#
# Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
#

# Include common stuff...
include ../Makedefs


# Library targets...
LIBOBJS	=	authorize.o connect.o form.o json.o post.o random.o token.o

OBJS	=	$(LIBOBJS) testmoauth.o

HEADERS	=	moauth.h

TARGETS	=	libmoauth.a testmoauth


# Make everything...
all:	$(TARGETS)


# Clean everything...
clean:
	$(RM) $(TARGETS) $(OBJS)


# Make documentation using codedoc (https://www.msweet.org/codedoc)
CODEDOC_OPTIONS = \
		libmoauth.xml \
		--author "Michael R Sweet" \
		--copyright "Copyright (c) 2017-2019" \
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
	$(INSTALL) -d -m 755 $(BUILDROOT)$(includedir)
	$(INSTALL) -c -m 644 moauth.h $(BUILDROOT)$(includedir)
	$(INSTALL) -d -m 755 $(BUILDROOT)$(mandir)/man3
	$(INSTALL) -c -m 644 libmoauth.3 $(BUILDROOT)$(mandir)/man3


# Test everything...
test:	testmoauth
	./testmoauth


# Unit test program...
testmoauth:	testmoauth.o libmoauth.a
	echo Linking $@...
	$(CC) $(LDFLAGS) -o $@ testmoauth.o libmoauth.a $(LIBS)


# moauth library...
libmoauth.a:	$(LIBOBJS)
	echo Creating static library $@...
	$(RM) $@
	$(AR) $(ARFLAGS) $@ $(LIBOBJS)
	$(RANLIB) $@


# Dependencies...
$(OBJS):	moauth.h moauth-private.h
