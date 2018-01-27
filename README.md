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

mOAuth is licensed under the Apache License Version 2.0 with an exception to
allow linking against GPL2/LGPL2 software (like older versions of CUPS).  See
the files "LICENSE" and "NOTICE" for more information.
