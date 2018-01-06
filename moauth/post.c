/*
 * POST support for moauth library
 *
 * Copyright © 2017-2018 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include <config.h>
#include "moauth-private.h"


/*
 * '_moauthGetPostData()' - Get POST form data.
 */

char *					/* O - Form data string or @code NULL@ on error */
_moauthGetPostData(http_t *http)	/* I - HTTP connection */
{
  char		*data,			/* Form data string */
		*end,			/* End of data */
		*ptr;			/* Pointer into string */
  size_t	datalen;		/* Allocated length of string */
  ssize_t	bytes;			/* Bytes read */
  http_state_t	initial_state;		/* Initial HTTP state */


 /*
  * Allocate memory for string...
  */

  initial_state = httpGetState(http);

  if ((datalen = httpGetLength2(http)) == 0 || datalen > 65536)
    datalen = 65536;			/* Accept up to 64k for POSTs */

  if ((data = calloc(1, datalen + 1)) != NULL)
  {
    for (ptr = data, end = data + datalen; ptr < end; ptr += bytes)
      if ((bytes = httpRead2(http, ptr, end - ptr)) <= 0)
        break;
  }

  if (httpGetState(http) == initial_state)
    httpFlush(http);

  return (data);
}
