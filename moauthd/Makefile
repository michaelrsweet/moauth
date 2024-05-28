#
# mOAuth daemon makefile
#
# Copyright © 2017-2024 by Michael R Sweet
#
# Licensed under Apache License v2.0.  See the file "LICENSE" for more
# information.
#

# Include common stuff...
include ../Makedefs


# Daemon targets...
MOAUTHD_OBJS	=	\
			auth.o \
			client.o \
			log.o \
			main.o \
			mmd.o \
			resource.o \
			server.o \
			token.o \
			web.o
OBJS		=	\
			$(MOAUTHD_OBJS) \
			testmoauthd.o
TARGETS		=	\
			moauthd \
			testmoauthd


# Make everything...
all:	$(TARGETS)


# Clean everything...
clean:
	$(RM) $(TARGETS) $(OBJS)


# Install everything...
install:	all
	$(INSTALL_DIR) $(BUILDROOT)$(sbindir)
	$(INSTALL_BIN) moauthd $(BUILDROOT)$(sbindir)
	$(INSTALL_DIR) $(BUILDROOT)$(mandir)/man5
	$(INSTALL_MAN) moauthd.conf.5 $(BUILDROOT)$(mandir)/man5
	$(INSTALL_DIR) $(BUILDROOT)$(mandir)/man8
	$(INSTALL_MAN) moauthd.8 $(BUILDROOT)$(mandir)/man8
	$(INSTALL_DIR) $(BUILDROOT)$(sysconfdir)
	$(INSTALL_DATA) moauthd.conf.default $(BUILDROOT)$(sysconfdir)


# Test everything...
test:	$(TARGETS)
	./testmoauthd -v


# Daemon program...
moauthd:	$(MOAUTHD_OBJS) ../moauth/libmoauth.a
	echo Linking $@...
	$(CC) $(LDFLAGS) -o $@ $(MOAUTHD_OBJS) ../moauth/libmoauth.a \
		$(PAMLIBS) $(LIBS)
	$(CODE_SIGN) $(CSFLAGS) $@


# Daemon test program...
testmoauthd:	testmoauthd.o ../moauth/libmoauth.a
	echo Linking $@...
	$(CC) $(LDFLAGS) -o $@ testmoauthd.o ../moauth/libmoauth.a $(LIBS)
	$(CODE_SIGN) $(CSFLAGS) $@


# Default resource files for daemon web UI
index-md.h:	index.md Makefile
	echo "Generating index-md.h from index.md..."
	echo "static const char *index_md =" >index-md.h
	sed -e '1,$$s/"/\\"/g' <index.md | awk '{printf("\n  \"%s\\n\"", $$0);}' >>index-md.h
	echo ";" >>index-md.h

moauth-png.h:	../moauth.png Makefile
	echo "Generating moauth-png.h from moauth.png..."
	echo "static const unsigned char moauth_png[] =" >moauth-png.h
	echo "{" >>moauth-png.h
	od -t x1 ../moauth.png | cut -b12- | awk '{printf("  "); for (i = 1; i <= NF; i ++) printf("0x%s,", $$i); print "";}' >>moauth-png.h
	echo "};" >>moauth-png.h

style-css.h:	style.css Makefile
	echo "Generating style-css.h from style.css..."
	echo "static const char *style_css =" >style-css.h
	sed -e '1,$$s/"/\\"/g' <style.css | awk '{printf("\n  \"%s\\n\"", $$0);}' >>style-css.h
	echo ";" >>style-css.h


# Dependencies...
$(MOAUTHD_OBJS): moauthd.h
$(OBJS):	../moauth/moauth.h
mmd.o:		mmd.h
resource.o:	mmd.h
server.o:	index-md.h moauth-png.h style-css.h
