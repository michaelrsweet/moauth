---
title: mOAuth Test Server
---

# mOAuth Test Server

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

mOAuth is licensed under the Apache License Version 2.0.  See the file
["LICENSE"](LICENSE.md) for more information.

Documentation can be found in the file ["DOCUMENTATION.md"](DOCUMENTATION.md).

Shared resources are [here](shared).

Private resources are [here](private).
