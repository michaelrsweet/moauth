/*
 * Header file for moauth library
 *
 * Copyright © 2017-2018 by Michael R Sweet
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
 * Types...
 */

typedef struct _moauth_s moauth_t;	/* OAuth server connection */


/*
 * Functions...
 */

extern int	moauthAuthorize(moauth_t *server, const char *redirect_uri, const char *client_id, const char *state);

extern void	moauthClose(moauth_t *server);
extern moauth_t	*moauthConnect(const char *oauth_uri, int msec, int *cancel);

extern int	moauthFormDecode(const char *data, cups_option_t **vars);
extern char	*moauthFormEncode(int num_vars, cups_option_t *vars);

extern http_t	*moauthGetHTTP(moauth_t *server);

extern char	*moauthGetToken(moauth_t *server, const char *redirect_uri, const char *client_id, const char *grant, char *token, size_t tokensize, char *refresh, size_t refreshsize, time_t *expires);

extern int	moauthJSONDecode(const char *data, cups_option_t **vars);
extern char	*moauthJSONEncode(int num_vars, cups_option_t *vars);

extern char	*moauthRefreshToken(moauth_t *server, const char *refresh, char *token, size_t tokensize, char *new_refresh, size_t new_refreshsize, time_t *expires);


#endif /* !_MOAUTH_H_ */
