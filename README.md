mOAuth - A Basic OAuth 2.0 Client/Server Implementation
=======================================================

mOAuth is a basic OAuth 2.0 client/server implementation that is geared towards
testing and development of OAuth-based services.  The client library supports
authorization of native macOS, iOS, and Linux applications with PKCE.

The server is both an Authorization Server and a Resource Server that supports:

- User account authentication/authorization using PAM
- Traditional web-based authorization grants with redirection as well as
  resource owner password credentials grants
- Token introspection for services
- Basic Resource Server functionality with implicit and explicit ACLs
- Customizable web interface

mOAuth currently requires CUPS for its HTTPS support.


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

- Updated `moauthd` to look for "/etc/moauthd.conf" and
  "/usr/local/etc/moauthd.conf" as the default configuration file.
- Now install libmoauth and the `<moauth.h>` header.


Legal Stuff
-----------

Copyright © 2017-2019 by Michael R Sweet.

mOAuth is licensed under the Apache License Version 2.0 with an exception to
allow linking against GPL2/LGPL2 software (like older versions of CUPS).  See
the files "LICENSE" and "NOTICE" for more information.
