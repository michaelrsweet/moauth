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

extern int	moauthAuthorize(const char *oauth_uri, const char *redirect_uri, const char *client_id, const char *state);

extern http_t	*moauthConnect(const char *oauth_uri, int msec, int *cancel);

extern int	moauthFormDecode(const char *data, cups_option_t **vars);
extern char	*moauthFormEncode(int num_vars, cups_option_t *vars);

extern char	*moauthGetPostData(http_t *http);

extern char	*moauthGetToken(const char *oauth_uri, const char *redirect_uri, const char *client_id, const char *grant, char *token, size_t tokensize, char *refresh, size_t refreshsize, time_t *expires);

extern int	moauthJSONDecode(const char *data, cups_option_t **vars);
extern char	*moauthJSONEncode(int num_vars, cups_option_t *vars);

extern char	*moauthRefreshToken(const char *oauth_uri, const char *refresh, char *token, size_t tokensize, char *new_refresh, size_t new_refreshsize, time_t *expires);


#endif /* !_MOAUTH_H_ */
