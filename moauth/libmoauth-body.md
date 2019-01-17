Introduction
============

The "moauth" library provides a simple API for performing OAuth 2.0
authorization.  A single `<moauth.h>` header file needs to be included in your
code:

    #include <moauth.h>

When linking your program, include both the "moauth" and "cups" libraries, for
example:

    gcc -o myprogram myprogram.c -lmoauth -lcups


Getting Started
===============

The connection to the OAuth Authorization Server is represented by a `moauth_t`
pointer.  Provide the URI for the server to the `moauthConnect` function to
create a connection to the server:

    moauth_t *server = moauthConnect("https://oauth.example.net");

When you are done communicating with the server, use the `moauthClose` function
to close the connection to the server:

    moauthClose(server);

To authorize access, call the `moauthAuthorize` function, which handles opening
a web browser as needed:

    extern int
    moauthAuthorize(moauth_t *server,
                    const char *redirect_uri,
                    const char *client_id,
                    const char *state,
                    const char *code_verifier,
                    const char *scope);

Typically the `redirect_uri` will use a scheme related to your program name, for
example "myprogram://authorize" - these URI schemes must be registered with the
local operating system.  You can also use "https" URIs pointing to the local
system, assuming that you have a local service running, however registering
clients using local addresses and port numbers can be tricky - most "native"
applications use a custom URI scheme.

> TODO: Add example registration process/links for Linux and macOS/iOS.

The `client_id` string is an identifier that is provided when you register your
application with the OAuth provider, for example
"5C87D618-A5AE-4A48-B04B-E1BCE501ED75".

The `state` string is some data you provide for local state tracking, for
example "Snoopy".

The `code_verifier` string is used to prevent man-in-the-middle attacks and
should be a random string, for example "aBrh14x01-fjh552".

The `scope` string is used to request specific privileges.  If `NULL` the
authorization server will grant the default privileges.

Putting that all together yields the following example code:

    if (!moauthAuthorize(server, "myprogram://authorize",
                         "5C87D618-A5AE-4A48-B04B-E1BCE501ED75", "Snoopy",
                         "aBrh14x01-fjh552", NULL))
        fprintf(stderr, "Unable to authorize access: %s\n", moauthErrorString(server));

Once authorization is complete your program will be notified using the
redirect URI followed by several form variables, for example:

    myprogram://authorize?code=ABCDEFG0123456789&state=Snoopy

Your program needs to verify the state string matches what you used in the
initial authorization request ("Snoopy") and then uses the code value to
request an access token using the `moauthGetToken` function:

    extern char *
    moauthGetToken(moauth_t *server,
                   const char *redirect_uri,
                   const char *client_id,
                   const char *grant,
                   const char *code_verifier,
                   char *token,
                   size_t tokensize,
                   char *refresh,
                   size_t refreshsize,
                   time_t *expires);

The `server`, `redirect_uri`, `client_id`, and `code_verifier` arguments are
the same as before.

The `grant` string is the "code" value from the redirect URI your program
received.

The `token` argument is a pointer to a character buffer of `tokensize` bytes and
will be filled with the access token.

The `refresh` argument is a pointer to a character buffer of `refreshsize` bytes
and will be filled with a refresh token, if any.  If you don't care about the
refresh token you can pass `NULL` and `0` for these arguments.

The `expires` argument is a pointer to a `time_t` variable and will be filled
with the expiration date/time for the access token.  If you don't care about the
expiration date/time you can pass `NULL`.

For example:

    char access_token[1024];

    if (!moauthGetToken(server, "myprogram://authorize",
                        "5C87D618-A5AE-4A48-B04B-E1BCE501ED75",
                        "ABCDEFG0123456789", "aBrh14x01-fjh552",
                        access_token, sizeof(access_token),
                        NULL, 0, NULL))
        fprintf(stderr, "Unable to get access token: %s\n", moauthErrorString(server));
    else
        printf("Access token is \"%s\".\n", access_token);
