//
// Token handling for moauth daemon
//
// Copyright © 2017-2022 by Michael R Sweet
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
//

#include "moauthd.h"
#include <pwd.h>


//
// Local functions...
//

static int	compare_tokens(moauthd_token_t *a, moauthd_token_t *b);
static void	free_token(moauthd_token_t *token);


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
  char			temp[1024],	// Temporary string
			*scope;		// Current scope


  if (!scopes || !*scopes)
    scopes = "private shared";

  token = (moauthd_token_t *)calloc(1, sizeof(moauthd_token_t));

  token->type        = type;
  token->application = application;
  token->user        = strdup(user);
  token->scopes      = strdup(scopes);

  strncpy(temp, scopes, sizeof(temp) - 1);
  temp[sizeof(temp) - 1] = '\0';

  token->scopes_array = cupsArrayNew((cups_array_cb_t)strcmp, NULL, NULL, 0, (cups_acopy_cb_t)strdup, (cups_afree_cb_t)free);
  if ((scope = strtok(temp, " \t")) != NULL)
    cupsArrayAdd(token->scopes_array, scope);
  while ((scope = strtok(NULL, " \t")) != NULL)
    cupsArrayAdd(token->scopes_array, scope);

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

  // Generate the token as a UUID using the server name, port, secret, and number
  // of tokens issued.
  httpAssembleUUID(server->name, server->port, server->secret, server->num_tokens ++, temp, sizeof(temp));

  token->token = strdup(temp + 9);	// Skip "urn:uuid:" prefix

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


  key.token = (char *)token_id;

  cupsRWLockRead(&server->tokens_lock);

  match = cupsArrayFind(server->tokens, &key);

  cupsRWUnlock(&server->tokens_lock);

  return (match);
}


//
// 'compare_token()' - Compare two tokens.
//

static int				// O - Result of comparison
compare_tokens(moauthd_token_t *a,	// I - First token
               moauthd_token_t *b)	// I - Second token
{
  return (strcmp(a->token, b->token));
}


//
// 'free_token()' - Free the memory used by a token.
//

static void
free_token(moauthd_token_t *token)	// I - Token to free
{
  if (token->challenge)
    free(token->challenge);
  free(token->token);
  free(token->user);
  free(token->scopes);
  cupsArrayDelete(token->scopes_array);
  free(token);
}
