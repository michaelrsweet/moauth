/*
 * Logging support for moauth daemon
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include "moauthd.h"
#include <stdarg.h>
#include <syslog.h>


/*
 * Local globals...
 */

static const int priorities[] = { LOG_ERR, LOG_INFO, LOG_DEBUG };


/*
 * Local functions...
 */

static void	file_log(int fd, const char *message, va_list ap);


/*
 * 'moauthdLogc()' - Log a client message.
 */

void
moauthdLogc(moauthd_client_t   *client,	/* I - Client object */
            moauthd_loglevel_t level,	/* I - Log level */
            const char         *message,/* I - Printf-style message */
            ...)			/* I - Additional arguments as needed */
{
  moauthd_server_t *server = client->server;
					/* Server object */
  char		cmessage[1024];		/* Client message */
  va_list	ap;			/* Argument pointer */


  if (level > server->log_level || server->log_file < 0)
    return;

  snprintf(cmessage, sizeof(cmessage), "[Client %d] %s", client->number, message);
  va_start(ap, message);

  if (server->log_file == 0)
    vsyslog(priorities[level], cmessage, ap);
  else
    file_log(server->log_file, cmessage, ap);

  va_end(ap);
}


/*
 * 'moauthdLogs()' - Log a server message.
 */

void
moauthdLogs(moauthd_server_t   *server,	/* I - Server object */
            moauthd_loglevel_t level,	/* I - Log level */
            const char         *message,/* I - Printf-style message */
            ...)			/* I - Additional arguments as needed */
{
  va_list	ap;			/* Argument pointer */


  if (level > server->log_level || server->log_file < 0)
    return;

  va_start(ap, message);

  if (server->log_file == 0)
    vsyslog(priorities[level], message, ap);
  else
    file_log(server->log_file, message, ap);

  va_end(ap);
}


/*
 * "file_log()" - Log a message to a file.
 */

static void
file_log(int        fd,			/* I - File to write to */
         const char *message,		/* I - Printf-style message */
         va_list    ap)			/* I - Argument pointer */
{
  char		buffer[8192],		/* Message buffer */
		*bufptr;		/* Pointer into buffer */


  vsnprintf(buffer, sizeof(buffer) - 1, message, ap);
  bufptr = buffer + strlen(buffer);
  if (bufptr[-1] != '\n')
    *bufptr++ = '\n';

  write(fd, buffer, bufptr - buffer);
}
