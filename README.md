mOAuth - A Basic OAuth 2.0 Client/Server Implementation
=======================================================

![Version](https://img.shields.io/github/v/release/michaelrsweet/moauth?include_prereleases)
![Apache 2.0](https://img.shields.io/github/license/michaelrsweet/moauth)
![Build Status](https://img.shields.io/github/actions/workflow/status/michaelrsweet/moauth/build.yml?branch=master)
![Coverity Scan Status](https://img.shields.io/coverity/scan/22388.svg)

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

mOAuth requires libcups v3 for its HTTPS and JWT support.  If you are compiling
from source you'll need a C compiler (GCC and clang are fine) and a POSIX make
program (GNU make works).


Standards Implemented
---------------------

The specific standards mOAuth currently implements are:

- [The OAuth2 Authentication Framework (RFC6749)](https://datatracker.ietf.org/doc/html/rfc6749)
- [The OAuth2 Bearer Token (RFC6750)](https://datatracker.ietf.org/doc/html/rfc6750)
- [OAuth 2.0 Dynamic Client Registration Protocol (RFC7591)](https://datatracker.ietf.org/doc/html/rfc7591)
- [Proof Key for Code Exchange by OAuth Public Clients (RFC7636)](https://datatracker.ietf.org/doc/html/rfc7636)
- [OAuth 2.0 Token Introspection (RFC7662)](https://datatracker.ietf.org/doc/html/rfc7662)
- [OAuth 2.0 for Native Apps (RFC8252)](https://datatracker.ietf.org/doc/html/rfc8252)
- [OAuth 2.0 Authorization Server Metadata (RFC8414)](https://datatracker.ietf.org/doc/html/rfc8414)


Using mOAuth
------------

The simplest way to use mOAuth on Linux is to install the moauth snap with:

    sudo snap install moauth

You can also build and install from source (see commands below) and then run
`moauthd` by hand.


Building mOAuth from Source
---------------------------

mOAuth uses the typical configure script and makefile build system and requires
a recent version of libcups v3 to provide the necessary HTTPS support.

Assuming everything in in the normal locations the following commands will
build and install mOAuth on your system to "/usr/local":

    ./configure
    make
    make install

The `--prefix` option can be used to override the default installation prefix,
for example:

    ./configure --prefix=/opt/moauth


Legal Stuff
-----------

Copyright © 2017-2024 by Michael R Sweet.

mOAuth is licensed under the Apache License Version 2.0 with an exception to
allow linking against GPL2/LGPL2 software (like older versions of CUPS).  See
the files "LICENSE" and "NOTICE" for more information.
