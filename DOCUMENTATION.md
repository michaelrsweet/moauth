mOAuth Documentation
====================

> Note: mOAuth is still in early development.  I will try to keep this
> documentation in sync with the code - please file issues if you find
> something that needs correction or clarification.  Thanks!

moauthd
-------

`moauthd` is the OAuth 2.0 authentication/resource server program.  When run
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

The following directives are currently recognized:

- `Application`: Specifies a client ID and redirect URI pair to allow when
  authorizing.
- `LogFile`: Specifies the file for log messages.  The filename can be "stderr"
  to send messages to the standard error file, "syslog" to send messages to the
  syslog daemon, or "none" to disable logging.
- `LogLevel`: Specifies the logging level - "error", "info", or "debug".  The
  default level is "error" so that only errors are logged.
- `MaxTokenLife`: Specifies the maximum life of issued tokens in seconds ("42"),
  minutes ("42m"), hours ("42h"), days ("42d"), or weeks ("42w").  The default
  is one week.
- `Resource`: Specifies a remotely accessible file or directory resource.  See
  below for examples and details.
- `ServerName`: Specifies the host name and (optionally) port number to bind to,
  separated by a colon.  For example, "oauth.example.com:9443" specifies a host
  name of "oauth.example.com" and a port number of 9443.  The default host name
  is the configured host name of the system.  The default port number is 9nnn
  where 'nnn' is the bottom three digits of your user UI.
- `TestPassword`: Specifies a test password to use for all accounts.

The log level specified in the configuration file is also affected by the `-v`
option, so if the configuration file specifies `LogLevel info` but you run
`moauthd` with:

    moauthd -c /path/to/config/file -v

then the log level will actually be set to "debug".

Resources are specified using the `Resource` directive and allow remote access
to a file or directory:

```
Resource scope /remote/path /local/path
```

The *scope* is "public" for resources that require no authentication, "private"
for resources that can only be accessed by the resource owner or group (as
defined by the local path permissions), or "shared" for resources that can be
accessed by any valid user.

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
