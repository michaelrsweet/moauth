/*
 * Private header file for moauth library
 *
 * Copyright © 2018 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#ifndef _MOAUTH_PRIVATE_H_
#  define _MOAUTH_PRIVATE_H_

/*
 * Include necessary headers...
 */

#  include "moauth.h"


/*
 * Private types...
 */

struct _moauth_s			/* OAuth server connection data */
{
  http_t	*http;			/* HTTP connection */
  int		port;			/* Port number */
  char		host[256],		/* Hostname */
		authorize_resource[256],/* Resource path for authorization requests */
		token_resource[256];	/* Resource path for token requests */
};


/*
 * Private functions...
 */

extern char	*_moauthGetPostData(http_t *http);

#endif /* !_MOAUTH_PRIVATE_H_ */
