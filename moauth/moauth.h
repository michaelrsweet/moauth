//
// Header file for moauth library
//
// Copyright © 2017-2022 by Michael R Sweet
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//

#ifndef MOAUTH_H
#  define MOAUTH_H


//
// Types...
//

typedef struct _moauth_s moauth_t;	// OAuth server connection


//
// Functions...
//

extern bool	moauthAuthorize(moauth_t *server, const char *redirect_uri, const char *client_id, const char *state, const char *code_verifier, const char *scope);

extern void	moauthClose(moauth_t *server);
extern moauth_t	*moauthConnect(const char *oauth_uri);

extern const char *moauthErrorString(moauth_t *server);

extern char	*moauthGetToken(moauth_t *server, const char *redirect_uri, const char *client_id, const char *grant, const char *code_verifier, char *token, size_t tokensize, char *refresh, size_t refreshsize, time_t *expires);

extern bool	moauthIntrospectToken(moauth_t *server, const char *token, char *username, size_t username_size, char *scope, size_t scope_size, time_t *expires);

extern char	*moauthPasswordToken(moauth_t *server, const char *username, const char *password, const char *scope, char *token, size_t tokensize, char *refresh, size_t refreshsize, time_t *expires);

extern char	*moauthRefreshToken(moauth_t *server, const char *refresh, char *token, size_t tokensize, char *new_refresh, size_t new_refreshsize, time_t *expires);

extern char	*moauthRegisterClient(moauth_t *server, const char *redirect_uri, const char *client_name, const char *client_uri, const char *logo_uri, const char *tos_uri, char *client_id, size_t client_id_size);

#endif // !MOAUTH_H
