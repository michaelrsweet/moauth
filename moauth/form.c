/*
 * Form variable support for moauth library
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include <config.h>
#include "moauth.h"


/*
 * 'moauthFormDecode()' - Decode x-www-form-urlencoded variables.
 */

int					/* O - Number of form variables or 0 on error */
moauthFormDecode(const char    *data,	/* I - Form data */
                 cups_option_t **vars)	/* O - Form variables or @code NULL@ on error */
{
  (void)data;

  *vars = NULL;

  return (0);
}


/*
 * 'moauthFormEncode()' - Encode variables in the x-www-form-urlencoded format.
 *
 * The caller is responsible for calling @code free@ on the returned string.
 */

char *					/* O - Encoded data or @code NULL@ on error */
moauthFormEncode(int           num_vars,/* I - Number of form variables */
                 cups_option_t *vars)	/* I - Form variables */
{
  (void)num_vars;
  (void)vars;

  return (NULL);
}
