//
// Web support for moauth daemon
//
// Copyright © 2017-2022 by Michael R Sweet
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//

#include "moauthd.h"


//
// Local functions...
//

static void	html_escape(moauthd_client_t *client, const char *s, size_t slen);


//
// 'moauthdHTMLFooter()' - Show the web interface footer.
//
// This function also writes the trailing 0-length chunk.
//

void
moauthdHTMLFooter(moauthd_client_t *client)	// I - Client
{
  moauthdHTMLPrintf(client,
      "    </div>\n"
      "  </body>\n"
      "</html>\n");
  httpWrite(client->http, "", 0);
}


//
// 'moauthdHTMLHeader()' - Show the web interface header and title.
//

void
moauthdHTMLHeader(
    moauthd_client_t *client,		// I - Client
    const char       *title)		// I - Title
{
  moauthdHTMLPrintf(client,
      "<!DOCTYPE html>\n"
      "<html>\n"
      "  <head>\n"
      "    <link rel=\"stylesheet\" type=\"text/css\" href=\"/style.css\">\n"
      "    <link rel=\"shortcut icon\" type=\"image/png\" href=\"/moauth.png\">\n"
      "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
      "    <title>%s (mOAuth " MOAUTH_VERSION ")</title>\n"
      "  </head>\n"
      "  <body>\n"
      "    <div class=\"body\">\n", title);
}


//
// 'moauthdHTMLPrintf()' - Send formatted text to the client, quoting as needed.
//

void
moauthdHTMLPrintf(
    moauthd_client_t *client,		// I - Client
    const char       *format,		// I - Printf-style format string
    ...)				// I - Additional arguments as needed
{
  va_list	ap;			// Pointer to arguments
  const char	*start;			// Start of string
  char		size,			// Size character (h, l, L)
		type;			// Format type character
  int		width,			// Width of field
		prec;			// Number of characters of precision
  char		tformat[100],		// Temporary format string for sprintf()
		*tptr,			// Pointer into temporary format
		temp[1024];		// Buffer for formatted numbers
  char		*s;			// Pointer to string


  // Loop through the format string, formatting as needed...
  va_start(ap, format);
  start = format;

  while (*format)
  {
    if (*format == '%')
    {
      if (format > start)
        httpWrite(client->http, start, (size_t)(format - start));

      tptr    = tformat;
      *tptr++ = *format++;

      if (*format == '%')
      {
        httpWrite(client->http, "%", 1);
        format ++;
	start = format;
	continue;
      }
      else if (strchr(" -+#\'", *format))
        *tptr++ = *format++;

      if (*format == '*')
      {
        // Get width from argument...
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
          // Get precision from argument...
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
	case 'E' : // Floating point formats
	case 'G' :
	case 'e' :
	case 'f' :
	case 'g' :
	    if ((size_t)(width + 2) > sizeof(temp))
	      break;

	    sprintf(temp, tformat, va_arg(ap, double));

            httpWrite(client->http, temp, strlen(temp));
	    break;

        case 'B' : // Integer formats
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

            httpWrite(client->http, temp, strlen(temp));
	    break;

	case 's' : // String
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
    httpWrite(client->http, start, (size_t)(format - start));

  va_end(ap);
}


//
// 'moauthdRespondClient()' - Send a HTTP response.
//

bool					// O - `true` on success, `false` on failure
moauthdRespondClient(
    moauthd_client_t *client,		// I - Client
    http_status_t    code,		// I - HTTP status of response
    const char       *type,		// I - MIME media type
    const char       *uri,		// I - URI of response
    time_t           mtime,		// I - Last modified date and time
    size_t           length)		// I - Length of response or 0 for chunked
{
  char	message[1024];			// Text message


  moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "HTTP/1.1 %d %s", code, httpStatusString(code));

  if (code == HTTP_STATUS_CONTINUE)
  {
    // 100-continue doesn't send any headers...
    return (httpWriteResponse(client->http, HTTP_STATUS_CONTINUE));
  }

  // Format an error message...
  if (!type && !length && code != HTTP_STATUS_OK && code != HTTP_STATUS_SWITCHING_PROTOCOLS)
  {
    snprintf(message, sizeof(message), "%d - %s\n", code, httpStatusString(code));

    type   = "text/plain";
    length = strlen(message);
  }
  else
  {
    message[0] = '\0';
  }

  // Send the HTTP response header...
  httpClearFields(client->http);

  if (code == HTTP_STATUS_METHOD_NOT_ALLOWED || client->request_method == HTTP_STATE_OPTIONS)
    httpSetField(client->http, HTTP_FIELD_ALLOW, "GET, HEAD, OPTIONS, POST");

  if (code == HTTP_STATUS_UNAUTHORIZED || code == HTTP_STATUS_FORBIDDEN)
  {
    if (client->server->options & MOAUTHD_OPTION_BASIC_AUTH)
      httpSetField(client->http, HTTP_FIELD_WWW_AUTHENTICATE, "Bearer realm=\"mOAuth\", Basic realm=\"mOAuth\"");
    else
      httpSetField(client->http, HTTP_FIELD_WWW_AUTHENTICATE, "Bearer realm=\"mOAuth\"");
  }

  if (mtime)
  {
    char temp[256];			// Temporary string

    httpSetField(client->http, HTTP_FIELD_LAST_MODIFIED, httpGetDateString(mtime, temp, sizeof(temp)));
  }

  if (code == HTTP_STATUS_MOVED_PERMANENTLY || code == HTTP_STATUS_FOUND)
  {
    httpSetField(client->http, HTTP_FIELD_LOCATION, uri);
    moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Location: %s", uri);
  }
  else if (uri)
  {
    httpSetField(client->http, HTTP_FIELD_CONTENT_LOCATION, uri);
  }

  if (type)
  {
    if (!strcmp(type, "text/html"))
      httpSetField(client->http, HTTP_FIELD_CONTENT_TYPE, "text/html; charset=utf-8");
    else
      httpSetField(client->http, HTTP_FIELD_CONTENT_TYPE, type);
  }

  httpSetLength(client->http, length);

  if (!httpWriteResponse(client->http, code))
    return (false);

  // Send the response data...
  if (message[0])
  {
    // Send a plain text message.
    if (httpWrite(client->http, message, length) < 0)
      return (false);
  }

  httpFlushWrite(client->http);

  return (true);
}


//
// 'html_escape()' - Write a HTML-safe string.
//

static void
html_escape(moauthd_client_t *client,	// I - Client
	    const char       *s,	// I - String to write
	    size_t           slen)	// I - Number of characters to write
{
  const char	*start,			// Start of segment
		*end;			// End of string


  start = s;
  end   = s + (slen > 0 ? slen : strlen(s));

  while (*s && s < end)
  {
    if (*s == '&' || *s == '<')
    {
      if (s > start)
        httpWrite(client->http, start, (size_t)(s - start));

      if (*s == '&')
        httpWrite(client->http, "&amp;", 5);
      else
        httpWrite(client->http, "&lt;", 4);

      start = s + 1;
    }

    s ++;
  }

  if (s > start)
    httpWrite(client->http, start, (size_t)(s - start));
}
