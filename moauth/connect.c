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
    cupsFreeOptions(server->num_metadata, server->metadata);
    free(server);
  }
}


/*
 * '_moauthConnect()' - Connect to the server for the provided URI and return
 *                      the associated resource.
 */

http_t *				/* O - HTTP connection or @code NULL@ */
_moauthConnect(const char *uri,		/* I - URI to connect to */
               char       *resource,	/* I - Resource buffer */
               size_t     resourcelen)	/* I - Size of resource buffer */
{
  char		scheme[32],		/* URI scheme */
		userpass[256],		/* Username:password (unused) */
		host[256];		/* Host */
  int		port;			/* Port number */
  http_t	*http;			/* HTTP connection */


  if (httpSeparateURI(HTTP_URI_CODING_ALL, uri, scheme, sizeof(scheme), userpass, sizeof(userpass), host, sizeof(host), &port, resource, (int)resourcelen) < HTTP_URI_STATUS_OK || strcmp(scheme, "https"))
    return (NULL);			/* Bad URI */

  http = httpConnect2(host, port, NULL, AF_UNSPEC, HTTP_ENCRYPTION_ALWAYS, 1, 30000, NULL);

  /**** TODO: enforce trust settings ****/

  return (http);
}


/*
 * 'moauthConnect()' - Open a connection to an OAuth server.
 */

moauth_t *				/* O - OAuth server connection or @code NULL@ */
moauthConnect(
    const char *oauth_uri)		/* I - Authorization URI */
{
  http_t	*http;			/* Connection to OAuth server */
  char		resource[256];		/* Resource path */
  moauth_t	*server;		/* OAuth server connection */


 /*
  * Connect to the OAuth URI...
  */

  if ((http = _moauthConnect(oauth_uri, resource, sizeof(resource))) == NULL)
    return (NULL);			/* Unable to connect to server */

  if ((server = calloc(1, sizeof(moauth_t))) == NULL)
    return (NULL);			/* Unable to allocate server structure */

 /*
  * Get the metadata from the specified URL.  If the resource is "/" (default)
  * then grab the well-known OpenID configuration path.
  */

  if (!strcmp(resource, "/"))
  {
    strncpy(resource, "/.well-known/openid-configuration", sizeof(resource) - 1);
    resource[sizeof(resource) - 1] = '\0';
  }

  httpClearFields(http);

  if (!httpGet(http, resource))
  {
   /*
    * GET succeeded, grab the response...
    */

    http_status_t	status;		/* HTTP GET response status */
    const char		*content_type;	/* Message body format */
    char		*body;		/* HTTP message body */
    char		scheme[32],	/* URI scheme */
			userpass[256],	/* Username:password (unused) */
			host[256];	/* Host */
    int			port;		/* Port number */

    while ((status = httpUpdate(http)) == HTTP_STATUS_CONTINUE);

    content_type = httpGetField(http, HTTP_FIELD_CONTENT_TYPE);
    body         = _moauthCopyMessageBody(http);

    httpClose(http);

    if (content_type && body && (!*content_type || !strcmp(content_type, "text/json")))
    {
     /*
      * OpenID JSON metadata...
      */

      const char *uri;			/* Authorization/token URI */

      server->num_metadata = _moauthJSONDecode(body, &server->metadata);

      if ((uri = cupsGetOption("authorization_endpoint", server->num_metadata, server->metadata)) != NULL)
      {
	if (httpSeparateURI(HTTP_URI_CODING_ALL, uri, scheme, sizeof(scheme), userpass, sizeof(userpass), host, sizeof(host), &port, resource, sizeof(resource)) < HTTP_URI_STATUS_OK || strcmp(scheme, "https"))
        {
         /*
          * Bad authorization URI...
	  */

          moauthClose(server);
	  return (NULL);
	}

        server->authorization_endpoint = uri;
      }

      if ((uri = cupsGetOption("token_endpoint", server->num_metadata, server->metadata)) != NULL)
      {
	if (httpSeparateURI(HTTP_URI_CODING_ALL, uri, scheme, sizeof(scheme), userpass, sizeof(userpass), host, sizeof(host), &port, resource, sizeof(resource)) < HTTP_URI_STATUS_OK || strcmp(scheme, "https"))
        {
         /*
          * Bad token URI...
	  */

          moauthClose(server);
	  return (NULL);
	}

        server->token_endpoint = uri;
      }
    }

    if (body)
      free(body);
  }

  if (!server->authorization_endpoint || !server->token_endpoint)
  {
   /*
    * OAuth server does not provide endpoints, unable to support it!
    */

    moauthClose(server);
    return (NULL);
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
