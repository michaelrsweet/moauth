mOAuth Documentation
====================

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

mOAuth currently requires libcups v3 for its HTTPS and JWT support.

Copyright © 2017-2024 by Michael R Sweet.

mOAuth is licensed under the Apache License Version 2.0 with an exception to
allow linking against GPL2/LGPL2 software (like older versions of CUPS).  See
the files "LICENSE" and "NOTICE" for more information.

> Note: Please use the Github issue tracker to report issues or request
> features/improvements in mOAuth and/or this documentation:
>
> <https://github.com/michaelrsweet/moauth/issues>


Using libmoauth
---------------

`libmoauth` is an OAuth 2.0 client library you can use in C/C++ applications to
interact with an OAuth 2.0 authorization server.  To use the library you just
include the `<moauth.h>` header file in your source code and the `moauth` and
`cups` libraries when you link your application, for example:

    gcc -o myprogram myprogram.c -lmoauth -lcups3

The library uses the `moauth_t` type to keep track of the state of and
connection to an OAuth 2.0 authorization server.  You connect to a server using
the `moauthConnect` function:

    moauth_t *server = moauthConnect("https://oauth.example.com");

The returned value is then used to authorize access and get access (Bearer)
tokens:

    /* Request authorization using the default web browser */
    int moauthAuthorize(moauth_t *server, const char *redirect_uri, const char *client_id, const char *state, const char *code_verifier, const char *scope);

    /* Get an access token with the grant token provided by the server */
    char *moauthGetToken(moauth_t *server, const char *redirect_uri, const char *client_id, const char *grant, const char *code_verifier, char *token, size_t tokensize, char *refresh, size_t refreshsize, time_t *expires);

    /* Get an access token with a username and password */
    char *moauthPasswordToken(moauth_t *server, const char *username, const char *password, const char *scope, char *token, size_t tokensize, char *refresh, size_t refreshsize, time_t *expires);

    /* Get an access token with the refresh token provided by the server */
    char *moauthRefreshToken(moauth_t *server, const char *refresh, char *token, size_t tokensize, char *new_refresh, size_t new_refreshsize, time_t *expires);

When errors occur, the `moauthErrorString` function can be used to get a
human-readable error message, for example:

    printf("Request failed: %s\n", moauthErrorString(server));

Finally, when you are done using the authorization server you can close the
connection and free any memory used with `moauthClose`:

    moauthClose(server);


Using moauthd
-------------

`moauthd` is the OAuth 2.0 authorization and resource server program.  When run
with no arguments, it binds to port 9nnn where 'nnn' is the bottom three digits
of your user ID and is accessible on all addresses associated with your system's
hostname.  Log messages are written to the standard error file by default.

The `-v` option increases the verbosity of the logging, with multiple v's making
the logging progressively more verbose.  (Currently there are three levels of
verbosity, so anything past `-vvv` is silently ignored...)

The `-c` option specifies a plain text configuration file that consists of
blank, comment, or "directive" lines, for example:

```
# This is a comment
ServerName oauth.example.com:9443

# This is another comment
LogLevel debug
LogFile /var/log/moauthd.log
```

If no configuration file is specified, `moauthd` will look for a "moauthd.conf"
file in "/etc" or "/usr/local/etc".

The following directives are currently recognized:

- `Application`: Specifies a client ID and redirect URI pair to allow when
  authorizing.
- `AuthService`: Specifies a PAM authorization service to use.  The default is
  "login".
- `IntrospectGroup`: Specifies the group used for authenticating access to the
  token introspection endpoint.  The default is no group/authentication.
- `LogFile`: Specifies the file for log messages.  The filename can be "stderr"
  to send messages to the standard error file, "syslog" to send messages to the
  syslog daemon, or "none" to disable logging.
- `LogLevel`: Specifies the logging level - "error", "info", or "debug".  The
  default level is "error" so that only errors are logged.
- `MaxGrantLife`: Specifies the maximum life of grants in seconds ("42"),
  minutes ("42m"), hours ("42h"), days ("42d"), or weeks ("42w").  The default
  is five minutes.
- `MaxTokenLife`: Specifies the maximum life of issued tokens in seconds ("42"),
  minutes ("42m"), hours ("42h"), days ("42d"), or weeks ("42w").  The default
  is one week.
- `Option`: Specifies a server option to enable.  Currently only "BasicAuth" is
  supported, which allows access to resources using HTTP Basic authentication
  in addition to HTTP Bearer tokens.
- `RegisterGroup`: Specifies the group used for authenticating access to the
  dynamic client registration endpoint.  The default is no group/
  authentication.
- `Resource`: Specifies a remotely accessible file or directory resource.  [See
  below](#resources) for examples and details.
- `ServerName`: Specifies the host name and (optionally) port number to bind to,
  separated by a colon.  For example, "oauth.example.com:9443" specifies a host
  name of "oauth.example.com" and a port number of 9443.  The default host name
  is the configured host name of the system.  The default port number is 9nnn
  where 'nnn' is the bottom three digits of your user ID.
- `TestPassword`: Specifies a test password to use for all accounts, rather than
  using PAM to authenticate the supplied username and password.

The log level specified in the configuration file is also affected by the `-v`
option, so if the configuration file specifies `LogLevel info` but you run
`moauthd` with:

    moauthd -c /path/to/config/file -v

then the log level will actually be set to "debug".


### Resources

Resources are specified using the `Resource` directive and allow remote access
to a file or directory:

```
Resource scope /remote/path /local/path
```

The *scope* is "public" for resources that require no authentication, "private"
for resources that can only be accessed by the resource owner or group (as
defined by the local path permissions), "shared" for resources that can be
accessed by any valid user, or a named Unix group to limit access to members of
that group.

The */remote/path* is the URL path that matches the resource, while the
*/local/path* is the local path corresponding to it.

For example, the following directives setup a public web site directory under
"/", a private directory under "/private", and a shared directory under
"/shared":

```
Resource public / public_files
Resource private /private private_files
Resource shared /shared shared_files
```

Resources are matched using the longest matching remote path.  Directory
resources use the "index.md" or "index.html" file for viewing, while Markdown
resources are automatically converted to HTML.
