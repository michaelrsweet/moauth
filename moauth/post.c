//
// POST support for moauth library
//
// Copyright © 2017-2022 by Michael R Sweet
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
//

#include <config.h>
#include "moauth-private.h"


//
// '_moauthCopyMessageBody()' - Copy the HTTP message body data to a string.
//

char *					// O - Message body string or `NULL` on error
_moauthCopyMessageBody(http_t *http)	// I - HTTP connection
{
  char		*body,			// Message body data string
		*end,			// End of data
		*ptr;			// Pointer into string
  size_t	bodylen;		// Allocated length of string
  ssize_t	bytes;			// Bytes read
  http_state_t	initial_state;		// Initial HTTP state


  // Allocate memory for string...
  initial_state = httpGetState(http);

  if ((bodylen = httpGetLength(http)) == 0 || bodylen > 65536)
    bodylen = 65536;			// Accept up to 64k for POSTs

  if ((body = calloc(1, bodylen + 1)) != NULL)
  {
    for (ptr = body, end = body + bodylen; ptr < end; ptr += bytes)
    {
      if ((bytes = httpRead(http, ptr, end - ptr)) <= 0)
        break;
    }
  }

  if (httpGetState(http) == initial_state)
    httpFlush(http);

  return (body);
}
