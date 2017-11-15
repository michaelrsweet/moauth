/*
 * Server support for moauth daemon
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include "moauthd.h"


/*
 * 'moauthdCreateServer()' - Create a new server object and load the specified config file.
 */

moauthd_server_t *			/* O - New server object */
moauthdCreateServer(
    const char *configfile)		/* I - Configuration file to load */
{
  (void)configfile;

  return (NULL);
}


/*
 * 'moauthdDeleteServer()' - Delete a server object.
 */

void
moauthdDeleteServer(
    moauthd_server_t *server)		/* I - Server object */
{
  (void)server;
}


/*
 * 'moauthdRunServer()' - Listen for client connections and process requests.
 */

void
moauthdRunServer(
    moauthd_server_t *server)		/* I - Server object */
{
  (void)server;
}
