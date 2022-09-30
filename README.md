mOAuth - A Basic OAuth 2.0 Client/Server Implementation
=======================================================

![Version](https://img.shields.io/github/v/release/michaelrsweet/moauth?include_prereleases)
![Apache 2.0](https://img.shields.io/github/license/michaelrsweet/moauth)
![Build](https://github.com/michaelrsweet/moauth/workflows/Build/badge.svg)
[![Coverity Scan Status](https://img.shields.io/coverity/scan/22388.svg)](https://scan.coverity.com/projects/michaelrsweet-moauth)
[![LGTM Grade](https://img.shields.io/lgtm/grade/cpp/github/michaelrsweet/moauth)](https://lgtm.com/projects/g/michaelrsweet/moauth/context:cpp)
[![LGTM Alerts](https://img.shields.io/lgtm/alerts/github/michaelrsweet/moauth)](https://lgtm.com/projects/g/michaelrsweet/moauth/)

mOAuth is a basic OAuth 2.0 client/server implementation designed for testing
and development of OAuth-based services.  The client library supports
authorization of native macOS, iOS, and Linux applications with PKCE.  The
server is both an Authorization Server and a Resource Server that supports:

- User account authentication/authorization using PAM
- Traditional web-based authorization grants with redirection as well as
  resource owner password credentials grants
- Token introspection for services
- Basic Resource Server functionality with implicit and explicit ACLs
- Customizable web interface


Requirements
------------

mOAuth requires CUPS 2.2 or later for its HTTPS support.  If you are compiling
from source you'll need a C compiler (GCC and clang are fine) and a make
program that supports the "include" directive (like GNU make).


Standards Implemented
---------------------

The specific standards mOAuth currently implements are:

- [The OAuth2 Authentication Framework (RFC6749)](https://tools.ietf.org/html/rfc6749)
- [The OAuth2 Bearer Token (RFC6750)](https://tools.ietf.org/html/rfc6750)
- [OAuth 2.0 Dynamic Client Registration Protocol (RFC7591)](https://tools.ietf.org/html/rfc7591)
- [Proof Key for Code Exchange by OAuth Public Clients (RFC7636)](https://tools.ietf.org/html/rfc7636)
- [OAuth 2.0 Token Introspection (RFC7662)](https://tools.ietf.org/html/rfc7662)
- [OAuth 2.0 for Native Apps (RFC8252)](https://tools.ietf.org/html/rfc8252)
- [OAuth 2.0 Authorization Server Metadata (RFC8414)](https://tools.ietf.org/html/rfc8414)


Using mOAuth
------------

The simplest way to use mOAuth on Linux is to install the moauth snap with:

    sudo snap install moauth

You can also build and install from source (see commands below) and then run
`moauthd` by hand.


Building mOAuth from Source
---------------------------

mOAuth uses the typical configure script and makefile build system and requires
a recent version of CUPS (2.2 or later) to provide the necessary HTTPS support.
On Ubuntu 18.04 and later you'll want to install the "libcups2-dev" package to
satisfy that requirement.

Assuming everything in in the normal locations the following commands will
build and install mOAuth on your system to "/usr/local":

    ./configure
    make
    make install

The `--prefix` option can be used to override the default installation prefix,
for example:

    ./configure --prefix=/opt/moauth


Change History
--------------

Changes in v1.1:

- Now support dynamic client registration (Issue #8)
- Now support PAM-based authentication backends (Issue #9)
- Now install libmoauth, the `<moauth.h>` header, and a man page for the
  library.
- Updated `moauthd` to look for "/etc/moauthd.conf" and
  "/usr/local/etc/moauthd.conf" as the default configuration file, and install
  a "moauthd.conf.default" file as a template (Issue #10)


Legal Stuff
-----------

Copyright © 2017-2022 by Michael R Sweet.

mOAuth is licensed under the Apache License Version 2.0 with an exception to
allow linking against GPL2/LGPL2 software (like older versions of CUPS).  See
the files "LICENSE" and "NOTICE" for more information.
