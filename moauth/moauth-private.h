/*
 * Private header file for moauth library
 *
 * Copyright © 2017-2018 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#ifndef _MOAUTH_PRIVATE_H_
#  define _MOAUTH_PRIVATE_H_

/*
 * Include necessary headers...
 */

#  include <cups/cups.h>
#  include "moauth.h"


/*
 * Private types...
 */

struct _moauth_s			/* OAuth server connection data */
{
  http_t	*http;			/* HTTP connection */
  char		host[256];		/* Hostname */
  int		port;			/* Port number */
  char		authorize_resource[256],/* Resource path for authorization requests */
		token_resource[256];	/* Resource path for token requests */
};


/*
 * Private functions...
 */

extern int	_moauthFormDecode(const char *data, cups_option_t **vars);
extern char	*_moauthFormEncode(int num_vars, cups_option_t *vars);

extern char	*_moauthGetPostData(http_t *http);

extern int	_moauthJSONDecode(const char *data, cups_option_t **vars);
extern char	*_moauthJSONEncode(int num_vars, cups_option_t *vars);

#endif /* !_MOAUTH_PRIVATE_H_ */
