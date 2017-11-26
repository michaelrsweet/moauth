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

static void	html_escape(moauthd_client_t *client, const char *s, size_t slen);
static void	html_footer(moauthd_client_t *client);
static void	html_header(moauthd_client_t *client, const char *title);
static void	html_printf(moauthd_client_t *client, const char *format, ...) __attribute__((__format__(__printf__, 2, 3)));
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

    client->request_method = state;

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

      moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Problem getting request headers.");
      respond(client, HTTP_STATUS_BAD_REQUEST, NULL, 0);
      break;
    }

    if (strcasecmp(httpGetField(client->http, HTTP_FIELD_HOST), host_value))
    {
     /*
      * Bad "Host:" field...
      */

      moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Bad Host: header value \"%s\" (expected \"%s\").", httpGetField(client->http, HTTP_FIELD_HOST), host_value);
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
	    if (!respond(client, HTTP_STATUS_OK, "text/css", strlen(style_css)))
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
	    moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Sending home page.");

	    if (!respond(client, HTTP_STATUS_OK, "text/html", 0))
	      done = 1;

            html_header(client, "Home");
            html_printf(client, "      <h1><img src=\"/moauth.png\" width=\"32\" height=\"32\"> mOAuth " MOAUTH_VERSION "</h1>\n");
            html_footer(client);

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
	    if (!respond(client, HTTP_STATUS_OK, "text/css", strlen(style_css)))
	      done = 1;

	    httpWrite2(client->http, (void *)style_css, strlen(style_css));
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
	  moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Unexpected HTTP state %d.", client->request_method);
	  respond(client, HTTP_STATUS_BAD_REQUEST, NULL, 0);
          done = 1;
	  break;
    }
  }

  moauthdDeleteClient(client);

  return (NULL);
}


/*
 * 'html_escape()' - Write a HTML-safe string.
 */

static void
html_escape(moauthd_client_t *client,	/* I - Client */
	    const char       *s,	/* I - String to write */
	    size_t           slen)	/* I - Number of characters to write */
{
  const char	*start,			/* Start of segment */
		*end;			/* End of string */


  start = s;
  end   = s + (slen > 0 ? slen : strlen(s));

  while (*s && s < end)
  {
    if (*s == '&' || *s == '<')
    {
      if (s > start)
        httpWrite2(client->http, start, (size_t)(s - start));

      if (*s == '&')
        httpWrite2(client->http, "&amp;", 5);
      else
        httpWrite2(client->http, "&lt;", 4);

      start = s + 1;
    }

    s ++;
  }

  if (s > start)
    httpWrite2(client->http, start, (size_t)(s - start));
}


/*
 * 'html_footer()' - Show the web interface footer.
 *
 * This function also writes the trailing 0-length chunk.
 */

static void
html_footer(moauthd_client_t *client)	/* I - Client */
{
  html_printf(client,
	      "    </div>\n"
	      "  </body>\n"
	      "</html>\n");
  httpWrite2(client->http, "", 0);
}


/*
 * 'html_header()' - Show the web interface header and title.
 */

static void
html_header(moauthd_client_t *client,	/* I - Client */
            const char       *title)	/* I - Title */
{
  html_printf(client,
	      "<!DOCTYPE html>\n"
	      "<html>\n"
	      "  <head>\n"
	      "    <link rel=\"stylesheet\" type=\"text/css\" href=\"/style.css\">\n"
	      "    <link rel=\"shortcut icon\" type=\"image/png\" href=\"/moauth.png\">\n"
	      "    <title>%s (mOAuth " MOAUTH_VERSION ")</title>\n"
	      "  </head>\n"
	      "  <body>\n"
	      "    <div class=\"body\">\n", title);
}


/*
 * 'html_printf()' - Send formatted text to the client, quoting as needed.
 */

static void
html_printf(moauthd_client_t *client,	/* I - Client */
	    const char       *format,	/* I - Printf-style format string */
	    ...)			/* I - Additional arguments as needed */
{
  va_list	ap;			/* Pointer to arguments */
  const char	*start;			/* Start of string */
  char		size,			/* Size character (h, l, L) */
		type;			/* Format type character */
  int		width,			/* Width of field */
		prec;			/* Number of characters of precision */
  char		tformat[100],		/* Temporary format string for sprintf() */
		*tptr,			/* Pointer into temporary format */
		temp[1024];		/* Buffer for formatted numbers */
  char		*s;			/* Pointer to string */


 /*
  * Loop through the format string, formatting as needed...
  */

  va_start(ap, format);
  start = format;

  while (*format)
  {
    if (*format == '%')
    {
      if (format > start)
        httpWrite2(client->http, start, (size_t)(format - start));

      tptr    = tformat;
      *tptr++ = *format++;

      if (*format == '%')
      {
        httpWrite2(client->http, "%", 1);
        format ++;
	start = format;
	continue;
      }
      else if (strchr(" -+#\'", *format))
        *tptr++ = *format++;

      if (*format == '*')
      {
       /*
        * Get width from argument...
	*/

	format ++;
	width = va_arg(ap, int);

	snprintf(tptr, sizeof(tformat) - (size_t)(tptr - tformat), "%d", width);
	tptr += strlen(tptr);
      }
      else
      {
	width = 0;

	while (isdigit(*format & 255))
	{
	  if (tptr < (tformat + sizeof(tformat) - 1))
	    *tptr++ = *format;

	  width = width * 10 + *format++ - '0';
	}
      }

      if (*format == '.')
      {
	if (tptr < (tformat + sizeof(tformat) - 1))
	  *tptr++ = *format;

        format ++;

        if (*format == '*')
	{
         /*
	  * Get precision from argument...
	  */

	  format ++;
	  prec = va_arg(ap, int);

	  snprintf(tptr, sizeof(tformat) - (size_t)(tptr - tformat), "%d", prec);
	  tptr += strlen(tptr);
	}
	else
	{
	  prec = 0;

	  while (isdigit(*format & 255))
	  {
	    if (tptr < (tformat + sizeof(tformat) - 1))
	      *tptr++ = *format;

	    prec = prec * 10 + *format++ - '0';
	  }
	}
      }

      if (*format == 'l' && format[1] == 'l')
      {
        size = 'L';

	if (tptr < (tformat + sizeof(tformat) - 2))
	{
	  *tptr++ = 'l';
	  *tptr++ = 'l';
	}

	format += 2;
      }
      else if (*format == 'h' || *format == 'l' || *format == 'L')
      {
	if (tptr < (tformat + sizeof(tformat) - 1))
	  *tptr++ = *format;

        size = *format++;
      }
      else
        size = 0;


      if (!*format)
      {
        start = format;
        break;
      }

      if (tptr < (tformat + sizeof(tformat) - 1))
        *tptr++ = *format;

      type  = *format++;
      *tptr = '\0';
      start = format;

      switch (type)
      {
	case 'E' : /* Floating point formats */
	case 'G' :
	case 'e' :
	case 'f' :
	case 'g' :
	    if ((size_t)(width + 2) > sizeof(temp))
	      break;

	    sprintf(temp, tformat, va_arg(ap, double));

            httpWrite2(client->http, temp, strlen(temp));
	    break;

        case 'B' : /* Integer formats */
	case 'X' :
	case 'b' :
        case 'd' :
	case 'i' :
	case 'o' :
	case 'u' :
	case 'x' :
	    if ((size_t)(width + 2) > sizeof(temp))
	      break;

            if (size == 'l')
	      sprintf(temp, tformat, va_arg(ap, long));
	    else
	      sprintf(temp, tformat, va_arg(ap, int));

            httpWrite2(client->http, temp, strlen(temp));
	    break;

	case 's' : /* String */
	    if ((s = va_arg(ap, char *)) == NULL)
	      s = "(null)";

            html_escape(client, s, strlen(s));
	    break;
      }
    }
    else
      format ++;
  }

  if (format > start)
    httpWrite2(client->http, start, (size_t)(format - start));

  va_end(ap);
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
