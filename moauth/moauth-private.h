//
// Private header file for moauth library
//
// Copyright © 2017-2022 by Michael R Sweet
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
//

#ifndef MOAUTH_PRIVATE_H
#  define MOAUTH_PRIVATE_H

//
// Include necessary headers...
//

#  include <stdio.h>
#  include <cups/cups.h>
#  include <cups/json.h>
#  include "moauth.h"


//
// Private types...
//

struct _moauth_s			// OAuth server connection data
{
  char		error[1024];		// Last error message, if any
  const char	*authorization_endpoint,// Authorization endpoint
		*introspection_endpoint,// Introspection endpoint
		*registration_endpoint,	// Registration endpoint
		*token_endpoint;	// Token endpoint
  cups_json_t	*metadata;		// Metadata values
};


//
// Private functions...
//

extern http_t	*_moauthConnect(const char *uri, char *resource, size_t resourcelen);
extern char	*_moauthCopyMessageBody(http_t *http);

extern void	_moauthGetRandomBytes(void *data, size_t bytes);


#endif // !MOAUTH_PRIVATE_H
