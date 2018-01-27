/*
 * Connection support for moauth library
 *
 * Copyright © 2017-2018 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include <config.h>
#include "moauth-private.h"


/*
 * 'moauthClose()' - Close an OAuth server connection.
 */

void
moauthClose(moauth_t *server)		/* I - OAuth server connection */
{
  if (server)
  {
    httpClose(server->http);
    free(server);
  }
}


/*
 * 'moauthConnect()' - Open a connection to an OAuth server.
 */

moauth_t *				/* O - OAuth server connection or @code NULL@ */
moauthConnect(
    const char *oauth_uri,		/* I - Authorization URI */
    int        msec,			/* I - Connection timeout in milliseconds */
    int        *cancel)			/* I - Pointer to a "cancel" variable or @code NULL@ */
{
  char		scheme[32],		/* URI scheme */
		userpass[256],		/* Username:password (unused) */
		host[256],		/* Host */
		resource[256];		/* Resource path (unused) */
  int		port;			/* Port number */
  moauth_t	*server;		/* OAuth server connection */


  if (httpSeparateURI(HTTP_URI_CODING_ALL, oauth_uri, scheme, sizeof(scheme), userpass, sizeof(userpass), host, sizeof(host), &port, resource, sizeof(resource)) < HTTP_URI_STATUS_OK)
    return (NULL);			/* Bad authorization URI */

  if (strcmp(scheme, "https"))
    return (NULL);			/* Only connect to HTTPS servers */

  if ((server = calloc(1, sizeof(moauth_t))) == NULL)
    return (NULL);			/* Unable to allocate server structure */

  if ((server->http = httpConnect2(host, port, NULL, AF_UNSPEC, HTTP_ENCRYPTION_ALWAYS, 1, msec, cancel)) == NULL)
  {
    free(server);

    return (NULL);
  }

  strncpy(server->host, host, sizeof(server->host) - 1);
  server->port = port;

 /*
  * TODO:
  *
  * - Recognize common domains and override the resource to point to the
  *   right endpoint - OAuth has no standard endpoint for authorization...
  * - Support IndieAuth Profile URL links - basically do a GET of the URI
  *   and then extract the authorization and token URIs.
  */

  strncpy(server->authorize_resource, "/authorize", sizeof(server->authorize_resource) - 1);
  strncpy(server->token_resource, "/token", sizeof(server->token_resource) - 1);

  return (server);
}


/*
 * 'moauthErrorString()' - Return a description of the last error that occurred,
 *                         if any.
 */

const char *				/* O - Last error description or @code NULL@ if none */
moauthErrorString(moauth_t *server)	/* I - OAuth server connection */
{
  return ((server && server->error[0]) ? server->error : NULL);
}
