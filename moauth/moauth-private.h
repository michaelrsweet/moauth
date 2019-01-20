/*
 * Private header file for moauth library
 *
 * Copyright © 2017-2019 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#ifndef _MOAUTH_PRIVATE_H_
#  define _MOAUTH_PRIVATE_H_

/*
 * Include necessary headers...
 */

#  include <stdio.h>
#  include <cups/cups.h>
#  include "moauth.h"


/*
 * Private types...
 */

struct _moauth_s			/* OAuth server connection data */
{
  char		error[1024];		/* Last error message, if any */
  const char	*authorization_endpoint,/* Authorization endpoint */
		*introspection_endpoint,/* Introspection endpoint */
		*registration_endpoint,	/* Registration endpoint */
		*token_endpoint;	/* Token endpoint */
  int		num_metadata;		/* Number of metadata values */
  cups_option_t	*metadata;		/* Metadata values */
};


/*
 * Private functions...
 */

extern http_t	*_moauthConnect(const char *uri, char *resource, size_t resourcelen);
extern int	_moauthFormDecode(const char *data, cups_option_t **vars);
extern char	*_moauthFormEncode(int num_vars, cups_option_t *vars);

extern char	*_moauthCopyMessageBody(http_t *http);

extern void	_moauthGetRandomBytes(void *data, size_t bytes);

extern int	_moauthJSONDecode(const char *data, cups_option_t **vars);
extern char	*_moauthJSONEncode(int num_vars, cups_option_t *vars);

#endif /* !_MOAUTH_PRIVATE_H_ */
