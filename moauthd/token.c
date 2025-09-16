//
// Token handling for moauth daemon
//
// Copyright © 2017-2025 by Michael R Sweet
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
//

#include "moauthd.h"
#include <cups/jwt.h>
#include <pwd.h>


//
// Local functions...
//

static int	compare_tokens(moauthd_token_t *a, moauthd_token_t *b, void *data);
static void	free_token(moauthd_token_t *token, void *data);


//
// 'moauthdCreateToken()' - Create an OAuth token.
//

moauthd_token_t *			// O - New token
moauthdCreateToken(
    moauthd_server_t      *server,	// I - Server object
    moauthd_toktype_t     type,		// I - Token type
    moauthd_application_t *application,	// I - Application
    const char            *user,	// I - Authenticated user
    const char            *scopes)	// I - Space-delimited list of scopes
{
  moauthd_token_t	*token;		// New token
  struct passwd		*passwd;	// User info
  cups_jwt_t		*jwt;		// JWT


  if (!scopes || !*scopes)
    scopes = "private shared";

  token = (moauthd_token_t *)calloc(1, sizeof(moauthd_token_t));

  token->type         = type;
  token->application  = application;
  token->user         = strdup(user);
  token->scopes       = strdup(scopes);
  token->scopes_array = cupsArrayNewStrings(scopes, ' ');

  if ((passwd = getpwnam(user)) != NULL)
  {
    token->uid = passwd->pw_uid;
    token->gid = passwd->pw_gid;
  }
  else
  {
    token->uid = (uid_t)-1;
    token->gid = (gid_t)-1;
  }

  token->created = time(NULL);

  if (type == MOAUTHD_TOKTYPE_GRANT)
    token->expires = token->created + server->max_grant_life;
  else
    token->expires = token->created + server->max_token_life;

  // Generate the JWT for the token...
  jwt = cupsJWTNew("JWT", /*claims*/NULL);
  cupsJWTSetClaimString(jwt, "iss", token->user);
  cupsJWTSetClaimString(jwt, "scope", token->scopes);
  cupsJWTSetClaimNumber(jwt, "iat", (double)token->created);
  cupsJWTSetClaimNumber(jwt, "exp", (double)token->expires);

  cupsJWTSign(jwt, CUPS_JWA_RS256, server->private_key);

  token->token = cupsJWTExportString(jwt, CUPS_JWS_FORMAT_COMPACT);
  cupsJWTDelete(jwt);

//  moauthdLogs(server, MOAUTHD_LOGLEVEL_DEBUG, "token->user=\"%s\", ->scopes=\"%s\", uid=%d, gid=%d, created=%ld, expires=%ld, token=\"%s\"", token->user, token->scopes, (int)token->uid, (int)token->gid, (long)token->created, (long)token->expires, token->token);

  cupsRWLockWrite(&server->tokens_lock);

  if (!server->tokens)
    server->tokens = cupsArrayNew((cups_array_cb_t)compare_tokens, NULL, NULL, 0, NULL, (cups_afree_cb_t)free_token);

  cupsArrayAdd(server->tokens, token);

  cupsRWUnlock(&server->tokens_lock);

  return (token);
}


//
// 'moauthdDeleteToken()' - Delete a token from the server...
//

void
moauthdDeleteToken(
    moauthd_server_t *server,		// I - Server object
    moauthd_token_t  *token)		// I - Token
{
  cupsRWLockWrite(&server->tokens_lock);

  cupsArrayRemove(server->tokens, token);

  cupsRWUnlock(&server->tokens_lock);
}


//
// 'moauthdFindToken()' - Find an OAuth token.
//

moauthd_token_t	*			// O - Matching token
moauthdFindToken(
    moauthd_server_t *server,		// I - Server object
    const char       *token_id)		// I - Token ID
{
  moauthd_token_t	*match,		// Matching token, if any
			key;		// Search key


//  moauthdLogs(server, MOAUTHD_LOGLEVEL_DEBUG, "FindToken(\"%s\")", token_id);

  key.token = (char *)token_id;

  cupsRWLockRead(&server->tokens_lock);

  match = cupsArrayFind(server->tokens, &key);

  cupsRWUnlock(&server->tokens_lock);

//  moauthdLogs(server, MOAUTHD_LOGLEVEL_DEBUG, "FindToken: match=%p(%s)", (void *)match, match ? match->user : "???");

  return (match);
}


//
// 'compare_token()' - Compare two tokens.
//

static int				// O - Result of comparison
compare_tokens(moauthd_token_t *a,	// I - First token
               moauthd_token_t *b,	// I - Second token
               void            *data)	// I - Callback data (unused)
{
  (void)data;

  return (strcmp(a->token, b->token));
}


//
// 'free_token()' - Free the memory used by a token.
//

static void
free_token(moauthd_token_t *token,	// I - Token to free
           void            *data)	// I - Callback data (unused)
{
  (void)data;

  if (token->challenge)
    free(token->challenge);
  free(token->token);
  free(token->user);
  free(token->scopes);
  cupsArrayDelete(token->scopes_array);
  free(token);
}
