/*
 * Connection support for moauth library
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include <config.h>
#include "moauth.h"

/*
 * 'moauthConnect()' - Open a connection to an OAuth server.
 */

http_t *				/* O - HTTP connection or @code NULL@ */
moauthConnect(
    const char *oauth_uri,		/* I - Authorization URI */
    int        msec,			/* I - Connection timeout in milliseconds */
    int        *cancel)			/* I - Pointer to a "cancel" variable or @code NULL@ */
{
  char	scheme[32],			/* URI scheme */
	userpass[256],			/* Username:password (unused) */
	host[256],			/* Host */
	resource[256];			/* Resource path (unused) */
  int	port;				/* Port number */


  if (httpSeparateURI(HTTP_URI_CODING_ALL, oauth_uri, scheme, sizeof(scheme), userpass, sizeof(userpass), host, sizeof(host), &port, resource, sizeof(resource)) < HTTP_URI_STATUS_OK)
    return (NULL);			/* Bad authorization URI */

  if (strcmp(scheme, "https"))
    return (NULL);			/* Only connect to HTTPS servers */

  return (httpConnect2(host, port, NULL, AF_UNSPEC, HTTP_ENCRYPTION_ALWAYS, 1, msec, cancel));
}
