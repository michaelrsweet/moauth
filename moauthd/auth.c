/*
 * Authentication support for moauth daemon
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include "moauthd.h"


/*
 * 'moauthdAuthenticateUser()' - Validate a username + password combination.
 */

int					/* O - 1 if correct, 0 otherwise */
moauthdAuthenticateUser(
    moauthd_server_t *server,		/* I - Server object */
    const char       *username,		/* I - Username string */
    const char       *password)		/* I - Password string */
{
  (void)username;

  if (server->test_password && !strcmp(server->test_password, password))
    return (1);

  return (0);
}
