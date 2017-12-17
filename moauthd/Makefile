#
# moauth daemon makefile
#
# Copyright © 2017 by Michael R Sweet
#
# Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
#

# Include common stuff...
include ../Makedefs


# Daemon targets...
MOAUTHD_OBJS	=	auth.o client.o log.o main.o mmd.o resource.o server.o token.o web.o
OBJS		=	$(MOAUTHD_OBJS) testmoauthd.o
TARGETS		=	moauthd testmoauthd


# Make everything...
all:	$(TARGETS)


# Clean everything...
clean:
	$(RM) $(TARGETS) $(OBJS)


# Install everything...
install:	all


# Test everything...
test:	$(TARGETS)
	./testmoauthd


# Daemon program...
moauthd:	$(MOAUTHD_OBJS) ../moauth/libmoauth.a
	echo Linking $@...
	$(CC) $(LDFLAGS) -o $@ $(MOAUTHD_OBJS) ../moauth/libmoauth.a $(LIBS)


# Daemon test program...
testmoauthd:	testmoauthd.o ../moauth/libmoauth.a
	echo Linking $@...
	if test `uname` = Darwin; then \
		$(CC) $(LDFLAGS) -o $@ testmoauthd.o ../moauth/libmoauth.a $(LIBS) -framework CoreServices; \
	else \
		$(CC) $(LDFLAGS) -o $@ testmoauthd.o ../moauth/libmoauth.a $(LIBS); \
	fi


# Default resource files for daemon web UI
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
server.o:	moauth-png.h style-css.h
