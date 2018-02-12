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
    cupsFreeOptions(server->num_metadata, server->metadata);
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

  /**** TODO: enforce trust settings ****/

  strncpy(server->host, host, sizeof(server->host) - 1);
  server->port = port;

 /*
  * Get the metadata from the specified URL.  If the resource is "/" (default)
  * then grab the well-known OpenID configuration path.
  */

  if (!strcmp(resource, "/"))
  {
    strncpy(resource, "/.well-known/openid-configuration", sizeof(resource) - 1);
    resource[sizeof(resource) - 1] = '\0';
  }

  httpClearFields(server->http);

  if (!httpGet(server->http, resource))
  {
   /*
    * GET succeeded, grab the response...
    */

    http_status_t	status;		/* HTTP GET response status */
    const char		*content_type;	/* Message body format */
    char		*body;		/* HTTP message body */

    while ((status = httpUpdate(server->http)) == HTTP_STATUS_CONTINUE);

    content_type = httpGetField(server->http, HTTP_FIELD_CONTENT_TYPE);
    body         = _moauthCopyMessageBody(server->http);

    if (content_type && body && !strcmp(content_type, "text/json"))
    {
     /*
      * OpenID JSON metadata...
      */

      const char *uri;			/* Authorization/token URI */

      server->num_metadata = _moauthJSONDecode(body, &server->metadata);

      if ((uri = cupsGetOption("authorization_endpoint", server->num_metadata, server->metadata)) != NULL)
      {
	if (httpSeparateURI(HTTP_URI_CODING_ALL, uri, scheme, sizeof(scheme), userpass, sizeof(userpass), host, sizeof(host), &port, resource, sizeof(resource)) < HTTP_URI_STATUS_OK || strcmp(scheme, "https") || strcmp(host, server->host) || port != server->port)
        {
         /*
          * Bad authorization URI...
	  */

          moauthClose(server);
	  return (NULL);
	}

        strncpy(server->authorize_resource, resource, sizeof(server->authorize_resource) - 1);
      }

      if ((uri = cupsGetOption("token_endpoint", server->num_metadata, server->metadata)) != NULL)
      {
	if (httpSeparateURI(HTTP_URI_CODING_ALL, uri, scheme, sizeof(scheme), userpass, sizeof(userpass), host, sizeof(host), &port, resource, sizeof(resource)) < HTTP_URI_STATUS_OK || strcmp(scheme, "https") || strcmp(host, server->host) || port != server->port)
        {
         /*
          * Bad authorization URI...
	  */

          moauthClose(server);
	  return (NULL);
	}

        strncpy(server->token_resource, resource, sizeof(server->token_resource) - 1);
      }
    }

    if (body)
      free(body);
  }

  if (!server->authorize_resource[0] || !server->token_resource[0])
  {
   /*
    * Use the default values appropriate for mOAuth...
    */

    strncpy(server->authorize_resource, "/authorize", sizeof(server->authorize_resource) - 1);
    strncpy(server->token_resource, "/token", sizeof(server->token_resource) - 1);
  }

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
