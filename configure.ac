dnl
dnl moauth configuration script
dnl
dnl Copyright © 2017-2019 by Michael R Sweet
dnl
dnl Licensed under Apache License v2.0.  See the file "LICENSE" for more
dnl information.
dnl

dnl We need at least autoconf 2.70 for --runstatedir...
AC_PREREQ([2.70])


dnl Package name and version...
AC_INIT([moauth], [1.1], [https://github.com/michaelrsweet/moauth/issues], [moauth], [https://www.msweet.org/moauth])
AC_CONFIG_HEADERS(config.h)

dnl This line is provided to ensure that you don't run the autoheader program
dnl against this project.  Doing so is completely unsupported and WILL cause
dnl problems!
AH_TOP([#error "Somebody ran autoheader on this project which is unsupported and WILL cause problems."])


dnl Define the version number...
MOAUTH_VERSION="AC_PACKAGE_VERSION"
AC_SUBST(MOAUTH_VERSION)
AC_DEFINE_UNQUOTED(MOAUTH_VERSION, "$MOAUTH_VERSION")

dnl Standard programs...
AC_PROG_CC(clang cc gcc)
AC_PROG_RANLIB
AC_PATH_PROG(AR,ar)
AC_MSG_CHECKING(for install-sh script)
INSTALL="`pwd`/install-sh"
AC_SUBST(INSTALL)
AC_MSG_RESULT(using $INSTALL)
AC_PATH_PROG(MKDIR,mkdir)
AC_PATH_PROG(RM,rm)
AC_PATH_TOOL(CUPSCONFIG, cups-config)

if test "x$CUPSCONFIG" = x; then
    AC_MSG_ERROR([Sorry, this software requires CUPS.])
fi

dnl Figure out the correct "ar" command flags...
if test "$ac_cv_prog_ranlib" = ":"; then
    ARFLAGS="crs"
else
    ARFLAGS="cr"
fi
AC_SUBST(ARFLAGS)

dnl Compiler options...
CFLAGS="${CFLAGS:=}"
CXXFLAGS="${CXXFLAGS:=}"
LDFLAGS="${LDFLAGS:=}"
LIBS="${LIBS:=}"
WARNINGS="${WARNINGS:=}"
AC_SUBST([WARNINGS])


dnl Options...
AC_ARG_WITH([optim], AS_HELP_STRING([--with-optim], [set additional optimization flags, default=none]), [
    OPTIM="$withval"
], [
    OPTIM=""
])
AC_SUBST([OPTIM])

AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug], [turn on debugging, default=no]))
AC_ARG_ENABLE([maintainer], AS_HELP_STRING([--enable-maintainer], [turn on maintainer mode, default=no]))
AC_ARG_ENABLE([sanitizer], AS_HELP_STRING([--enable-sanitizer], [build with AddressSanitizer, default=no]))

AS_IF([test -n "$GCC"], [
    CFLAGS="-D_GNU_SOURCE $CFLAGS"

    AS_IF([test "x$OPTIM" = x], [
	AS_IF([test x$enable_debug = xyes], [
	    OPTIM="-g"
	], [
	    OPTIM="-g -Os"
	])
    ], [test x$enable_debug = xyes], [
	OPTIM="$OPTIM -g"
    ])

    AS_IF([test x$enable_sanitizer = xyes], [
	# Use -fsanitize=address with debugging...
	OPTIM="$OPTIM -fsanitize=address"
    ], [
	# Otherwise use the Fortify enhancements to catch any unbounded
	# string operations...
	CPPFLAGS="$CPPFLAGS -D_FORTIFY_SOURCE=2"
    ])

    dnl Show all standard warnings + unused variables when compiling...
    WARNINGS="$WARNINGS -Wall -Wunused"

    dnl Drop some not-useful/unreliable warnings...
    for warning in char-subscripts format-truncation format-y2k switch unused-result; do
	AC_MSG_CHECKING([whether compiler supports -Wno-$warning])

	OLDCFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS -Wno-$warning -Werror"

	AC_COMPILE_IFELSE([AC_LANG_PROGRAM()], [
	    AC_MSG_RESULT(yes)
	    WARNINGS="$WARNINGS -Wno-$warning"
        ], [
	    AC_MSG_RESULT(no)
	])

	CFLAGS="$OLDCFLAGS"
    done

    dnl Maintainer mode enables -Werror...
    AS_IF([test x$enable_maintainer = xyes], [
	WARNINGS="$WARNINGS -Werror"
    ])
], [
    AS_IF([test "x$OPTIM" = x], [
	AS_IF([test x$enable_debug = xyes], [
	    OPTIM="-g"
	], [
	    OPTIM="-O"
	])
    ])
])

dnl CUPS library...
AC_ARG_ENABLE(static_cups, [  --enable-static-cups    use static CUPS libraries, default=no])

if test x$enable_static_cups = xyes; then
	CFLAGS="$CFLAGS `cups-config --static --cflags`"
	LDFLAGS="$LDFLAGS `cups-config --static --ldflags`"
	LIBS="$LIBS `cups-config --static --libs`"
else
	CFLAGS="$CFLAGS `cups-config --cflags`"
	LDFLAGS="$LDFLAGS `cups-config --ldflags`"
	LIBS="$LIBS `cups-config --libs`"
fi

dnl POSIX threads...
AC_CHECK_HEADER(pthread.h, AC_DEFINE(HAVE_PTHREAD_H))

if test x$ac_cv_header_pthread_h != xyes; then
    AC_MSG_ERROR([Sorry, this software requires POSIX threading support.])
fi

dnl Check various threading options for the platforms we support
for flag in -lpthreads -lpthread -pthread; do
    AC_MSG_CHECKING([for pthread_create using $flag])
    SAVELIBS="$LIBS"
    LIBS="$flag $LIBS"
    AC_LANG([C])
    AC_LINK_IFELSE([
        AC_LANG_PROGRAM([#include <pthread.h>],[pthread_create(0, 0, 0, 0);])],
        [have_pthread=yes],
	[LIBS="$SAVELIBS"])

    if test x$have_pthread = xyes; then
        AC_MSG_RESULT([yes])
        CFLAGS="$CFLAGS -D_THREAD_SAFE -D_REENTRANT"
        break
    else
        AC_MSG_RESULT([no])
    fi
done

dnl PAM support...
AC_ARG_ENABLE(pam, [  --disable-pam           disable PAM support])

PAMLIBS=""

if test x$enable_pam != xno; then
    SAVELIBS="$LIBS"

    AC_CHECK_LIB(dl,dlopen)
    AC_CHECK_LIB(pam,pam_start)
    AC_CHECK_HEADER(security/pam_appl.h, AC_DEFINE(HAVE_SECURITY_PAM_APPL_H))
    AC_CHECK_HEADER(pam/pam_appl.h, AC_DEFINE(HAVE_PAM_PAM_APPL_H))

    if test x$ac_cv_lib_pam_pam_start != xno; then
	# Set the necessary libraries for PAM...
	if test x$ac_cv_lib_dl_dlopen != xno; then
	    PAMLIBS="-lpam -ldl"
	else
	    PAMLIBS="-lpam"
	fi
    fi

    LIBS="$SAVELIBS"
fi

AC_SUBST(PAMLIBS)

dnl Random number support...
AC_CHECK_HEADER(sys/random.h, AC_DEFINE(HAVE_SYS_RANDOM_H))
AC_CHECK_FUNC(arc4random, AC_DEFINE(HAVE_ARC4RANDOM))

dnl Generate the Makedefs file...
AC_CONFIG_FILES([Makedefs])
AC_OUTPUT
