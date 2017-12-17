/*
 * Header file for moauth library
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#ifndef _MOAUTH_H_
#  define _MOAUTH_H_

/*
 * Include necessary headers...
 */

#  include <cups/cups.h>


/*
 * Functions...
 */

extern int	moauthFormDecode(const char *data, cups_option_t **vars);
extern char	*moauthFormEncode(int num_vars, cups_option_t *vars);

extern char	*moauthGetPostData(http_t *http);

#endif /* !_MOAUTH_H_ */
