/*
 * Client support for moauth daemon
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include "moauthd.h"
#include "moauth-png.h"
#include "style-css.h"


/*
 * Local functions...
 */

static int	respond(moauthd_client_t *client, http_status_t code, const char *type, size_t length);


/*
 * 'moauthdCreateClient()' - Accept a connection and create a client object.
 */

moauthd_client_t *			/* O - New client object */
moauthdCreateClient(
    moauthd_server_t *server,		/* I - Server object */
    int              fd)		/* I - Listening socket */
{
  moauthd_client_t *client;		/* Client object */


  if ((client = calloc(1, sizeof(moauthd_client_t))) == NULL)
  {
    moauthdLogs(server, MOAUTHD_LOGLEVEL_ERROR, "Unable to allocate memory for client: %s", strerror(errno));

    return (NULL);
  }

  client->number = ++ server->num_clients;
  client->server = server;

  if ((client->http = httpAcceptConnection(fd, 0)) == NULL)
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to accept client connection: %s", cupsLastErrorString());
    free(client);

    return (NULL);
  }

  httpGetHostname(client->http, client->remote_host, sizeof(client->remote_host));

  moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "Accepted connection from \"%s\".", client->remote_host);

  if (httpEncryption(client->http, HTTP_ENCRYPTION_ALWAYS))
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to establish TLS session: %s", cupsLastErrorString());
    httpClose(client->http);
    free(client);

    return (NULL);
  }

  httpBlocking(client->http, 1);

  moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "TLS session established.");

  return (client);
}


/*
 * 'moauthdDeleteClient()' - Close a connection and delete a client object.
 */

void
moauthdDeleteClient(
    moauthd_client_t *client)		/* I - Client object */
{
  httpClose(client->http);

  moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "Connection closed.");

  free(client);
}


/*
 * 'moauthdRunClient()' - Process requests from a client object.
 */

void *					/* O - Thread return status (ignored) */
moauthdRunClient(
    moauthd_client_t *client)		/* I - Client object */
{
  int			done = 0;	/* Are we done yet? */
  http_state_t		state;		/* HTTP state */
  http_status_t		status;		/* HTTP status */
  char			host_value[300];/* Expected Host: header value */
  char			uri_prefix[300];/* URI prefix for server */
  size_t		uri_prefix_len;	/* Length of URI prefix */
  static const char * const states[] =
  {					/* Strings for logging HTTP method */
    "WAITING",
    "OPTIONS",
    "GET",
    "GET_SEND",
    "HEAD",
    "POST",
    "POST_RECV",
    "POST_SEND",
    "PUT",
    "PUT_RECV",
    "DELETE",
    "TRACE",
    "CONNECT",
    "STATUS",
    "UNKNOWN_METHOD",
    "UNKNOWN_VERSION"
  };


  snprintf(host_value, sizeof(host_value), "%s:%d", client->server->name, client->server->port);
  snprintf(uri_prefix, sizeof(uri_prefix), "https://%s:%d", client->server->name, client->server->port);
  uri_prefix_len = strlen(uri_prefix);

  while (!done)
  {
   /*
    * Get a request line...
    */

    while ((state = httpReadRequest(client->http, client->path_info, sizeof(client->path_info))) == HTTP_STATE_WAITING)
      usleep(1);

    if (state == HTTP_STATE_ERROR)
    {
      if (httpError(client->http) == EPIPE || httpError(client->http) == 0)
	moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Client closed connection.");
      else
	moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad request line (%s).", strerror(httpError(client->http)));

      break;
    }
    else if (state == HTTP_STATE_UNKNOWN_METHOD)
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad/unknown operation.");
      respond(client, HTTP_STATUS_BAD_REQUEST, NULL, 0);
      break;
    }
    else if (state == HTTP_STATE_UNKNOWN_VERSION)
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad HTTP version.");
      respond(client, HTTP_STATUS_BAD_REQUEST, NULL, 0);
      break;
    }

    moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "%s %s", states[state], client->path_info);

    if (client->path_info[0] != '/' && !strncmp(client->path_info, uri_prefix, uri_prefix_len) && client->path_info[uri_prefix_len] == '/')
    {
     /*
      * Full URL, trim off "https://name:port" part...
      */

      size_t path_info_len = strlen(client->path_info);

      memmove(client->path_info, client->path_info + uri_prefix_len, path_info_len - uri_prefix_len + 1);
    }

    if ((client->query_string = strchr(client->path_info, '?')) != NULL)
    {
     /*
      * Chop the query string off the end...
      */

      *(client->query_string)++ = '\0';
    }

    if ((client->path_info[0] != '/' || strstr(client->path_info, "/../")) && (strcmp(client->path_info, "*") || client->request_method != HTTP_STATE_OPTIONS))
    {
     /*
      * Not a supported path or URI...
      */

      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad request URI \"%s\".", client->path_info);
      respond(client, HTTP_STATUS_BAD_REQUEST, NULL, 0);
      break;
    }

    while ((status = httpUpdate(client->http)) == HTTP_STATUS_CONTINUE);

    moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "status=%d", status);

    if (status != HTTP_STATUS_OK)
    {
     /*
      * Unable to get the request headers...
      */

      respond(client, HTTP_STATUS_BAD_REQUEST, NULL, 0);
      break;
    }

    if (strcasecmp(httpGetField(client->http, HTTP_FIELD_HOST), host_value))
    {
     /*
      * Bad "Host:" field...
      */

      respond(client, HTTP_STATUS_BAD_REQUEST, NULL, 0);
      break;
    }

    if (httpGetExpect(client->http) && client->request_method == HTTP_STATE_POST)
    {
     /*
      * Handle Expect: nnn
      */

      if (httpGetExpect(client->http) == HTTP_STATUS_CONTINUE)
      {
       /*
	* Send 100-continue header...
	*/

	if (!respond(client, HTTP_STATUS_CONTINUE, NULL, 0))
	  break;
      }
      else
      {
       /*
	* Send 417-expectation-failed header...
	*/

	if (!respond(client, HTTP_STATUS_EXPECTATION_FAILED, NULL, 0))
	  break;
      }
    }

    switch (client->request_method)
    {
      case HTTP_STATE_OPTIONS :
	 /*
	  * Do OPTIONS command...
	  */

	  if (!respond(client, HTTP_STATUS_OK, NULL, 0))
	    done = 1;
	  break;

      case HTTP_STATE_HEAD :
	  if (!strcmp(client->path_info, "/"))
	  {
	    if (!respond(client, HTTP_STATUS_OK, "text/html", 0))
	      done = 1;
	  }
	  else if (!strcmp(client->path_info, "/moauth.png"))
	  {
	    if (!respond(client, HTTP_STATUS_OK, "image/png", sizeof(moauth_png)))
	      done = 1;
	  }
	  else if (!strcmp(client->path_info, "/style.css"))
	  {
	    if (!respond(client, HTTP_STATUS_OK, "text/css", sizeof(style_css)))
	      done = 1;
	  }
	  else
	  {
	    respond(client, HTTP_STATUS_NOT_FOUND, NULL, 0);
	    done = 1;
	  }
	  break;

      case HTTP_STATE_GET :
	  if (!strcmp(client->path_info, "/"))
	  {
	    if (!respond(client, HTTP_STATUS_OK, "text/html", 0))
	      done = 1;

            httpPrintf(client->http,
                       "<!DOCTYPE html>\n"
                       "<html>\n"
                       "  <head>\n"
                       "    <link rel=\"stylesheet\" type=\"text/css\" href=\"/style.css\">\n"
                       "    <title>%s</title>\n"
                       "  </head>\n"
                       "  <body>\n"
                       "    <h1><img src=\"/moauth.png\" align=\"left\" width=\"64\" height=\"64\">%s</h1>\n"
                       "  </body>\n"
                       "</html>\n", "mOAuth " MOAUTH_VERSION, "mOAuth " MOAUTH_VERSION);
            httpWrite2(client->http, (void *)"", 0);
            httpFlushWrite(client->http);
	  }
	  else if (!strcmp(client->path_info, "/moauth.png"))
	  {
	    if (!respond(client, HTTP_STATUS_OK, "image/png", sizeof(moauth_png)))
	      done = 1;

	    httpWrite2(client->http, (void *)moauth_png, sizeof(moauth_png));
	    httpFlushWrite(client->http);
	  }
	  else if (!strcmp(client->path_info, "/style.css"))
	  {
	    if (!respond(client, HTTP_STATUS_OK, "text/css", sizeof(style_css)))
	      done = 1;

	    httpWrite2(client->http, (void *)style_css, sizeof(style_css));
	    httpFlushWrite(client->http);
	  }
	  else
	  {
	    respond(client, HTTP_STATUS_NOT_FOUND, NULL, 0);
	    done = 1;
	  }
	  break;

      case HTTP_STATE_POST :
	  respond(client, HTTP_STATUS_NOT_FOUND, NULL, 0);
          done = 1;
          break;

      default :
	  respond(client, HTTP_STATUS_BAD_REQUEST, NULL, 0);
          done = 1;
	  break;
    }
  }

  moauthdDeleteClient(client);

  return (NULL);
}


/*
 * 'respond()' - Send a HTTP response.
 */

int					/* O - 1 on success, 0 on failure */
respond(
    moauthd_client_t *client,		/* I - Client */
    http_status_t    code,		/* I - HTTP status of response */
    const char       *type,		/* I - MIME media type of response */
    size_t           length)		/* I - Length of response or 0 for chunked */
{
  char	message[1024];			/* Text message */


  moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "%s", httpStatus(code));

  if (code == HTTP_STATUS_CONTINUE)
  {
   /*
    * 100-continue doesn't send any headers...
    */

    return (httpWriteResponse(client->http, HTTP_STATUS_CONTINUE) == 0);
  }

 /*
  * Format an error message...
  */

  if (!type && !length && code != HTTP_STATUS_OK && code != HTTP_STATUS_SWITCHING_PROTOCOLS)
  {
    snprintf(message, sizeof(message), "%d - %s\n", code, httpStatus(code));

    type   = "text/plain";
    length = strlen(message);
  }
  else
    message[0] = '\0';

 /*
  * Send the HTTP response header...
  */

  httpClearFields(client->http);

  if (code == HTTP_STATUS_METHOD_NOT_ALLOWED || client->request_method == HTTP_STATE_OPTIONS)
    httpSetField(client->http, HTTP_FIELD_ALLOW, "GET, HEAD, OPTIONS, POST");

  if (type)
  {
    if (!strcmp(type, "text/html"))
      httpSetField(client->http, HTTP_FIELD_CONTENT_TYPE, "text/html; charset=utf-8");
    else
      httpSetField(client->http, HTTP_FIELD_CONTENT_TYPE, type);
  }

  httpSetLength(client->http, length);

  if (httpWriteResponse(client->http, code) < 0)
    return (0);

 /*
  * Send the response data...
  */

  if (message[0])
  {
   /*
    * Send a plain text message.
    */

    if (httpPrintf(client->http, "%s", message) < 0)
      return (0);
  }

  httpFlushWrite(client->http);

  return (1);
}
