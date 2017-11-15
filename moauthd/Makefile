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
OBJS	=	client.o conf.o log.o main.o resource.o server.o token.o

TARGETS	=	moauthd


# Make everything...
all:	$(TARGETS)


# Clean everything...
clean:
	$(RM) $(TARGETS) $(OBJS)


# Install everything...
install:	all


# Test everything...
test:	moauthd
	echo "Sorry, moauthd test not yet written..."


# Daemon program...
moauthd:	$(OBJS) ../moauth/libmoauth.a
	echo Linking $@...
	$(CC) $(LDFLAGS) -o $@ $(OBJS) ../moauth/libmoauth.a $(LIBS)


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
$(OBJS):	moauthd.h ../moauth/moauth.h
resource.o:	moauth-png.h style-css.h
