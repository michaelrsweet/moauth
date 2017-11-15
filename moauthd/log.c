/*
 * Logging support for moauth daemon
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include "moauthd.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>


/*
 * 'moauthdLog()' - Log a message.
 */

void
moauthdLog(moauthd_loglevel_t level,	/* I - Log level */
           moauthd_server_t   *server,	/* I - Server object */
           const char         *message,	/* I - Printf-style message */
           ...)				/* I - Additional arguments as needed */
{
  char		buffer[8192],		/* Message buffer */
		*bufptr;		/* Pointer into buffer */
  va_list	ap;			/* Argument pointer */


  if (level > server->log_level || server->log_file < 0)
    return;

  va_start(ap, message);
  vsnprintf(buffer, sizeof(buffer) - 1, message, ap);
  va_end(ap);

  bufptr = buffer + strlen(buffer);
  if (bufptr[-1] != '\n')
    *bufptr++ = '\n';

  write(server->log_file, buffer, bufptr - buffer);
}
