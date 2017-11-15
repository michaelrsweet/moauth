/*
 * Resource handling for moauth daemon
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include "moauthd.h"
#include "moauth-png.h"
#include "style-css.h"


/*
 * 'moauthdGetFile()' - Get the named resource file.
 *
 * This function is responsible for authorizing client access to the named resource.
 */

int					/* O - HTTP status */
moauthdGetFile(moauthd_client_t *client)/* I - Client object */
{
  (void)client;

  return (HTTP_STATUS_NOT_FOUND);
}
