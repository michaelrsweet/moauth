/*
 * Token handling for moauth daemon
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include "moauthd.h"
#include <pwd.h>


/*
 * Local functions...
 */

static int	compare_tokens(moauthd_token_t *a, moauthd_token_t *b);
static void	free_token(moauthd_token_t *token);


/*
 * 'moauthdCreateToken()' - Create an OAuth token.
 */

moauthd_token_t *			/* O - New token */
moauthdCreateToken(
    moauthd_server_t  *server,		/* I - Server object */
    moauthd_toktype_t type,		/* I - Token type */
    const char        *redirect_uri,	/* I - Redirect URI */
    const char        *user,		/* I - Authenticated user */
    const char        *scopes)		/* I - Space-delimited list of scopes */
{
  moauthd_token_t	*token;		/* New token */
  struct passwd		*passwd;	/* User info */
  char			temp[1024],	/* Temporary string */
			*scope;		/* Current scope */


  token = (moauthd_token_t *)calloc(1, sizeof(moauthd_token_t));

  token->type         = type;
  token->redirect_uri = strdup(redirect_uri);
  token->user         = strdup(user);

  strncpy(temp, scopes, sizeof(temp) - 1);
  temp[sizeof(temp) - 1] = '\0';

  token->scopes = cupsArrayNew3((cups_array_func_t)strcmp, NULL, NULL, 0, (cups_acopy_func_t)strdup, (cups_afree_func_t)free);
  if ((scope = strtok(temp, " \t")) != NULL)
    cupsArrayAdd(token->scopes, scope);
  while ((scope = strtok(NULL, " \t")) != NULL)
    cupsArrayAdd(token->scopes, scope);

  if ((passwd = getpwnam(user)) != NULL)
    token->uid = passwd->pw_uid;
  else
    token->uid = (uid_t)-1;

  token->expires = time(NULL) + server->max_token_life;

 /*
  * Generate the token as a UUID using the server name, port, secret, and number
  * of tokens issued.
  */

  httpAssembleUUID(server->name, server->port, server->secret, server->num_tokens ++, temp, sizeof(temp));

  token->token = strdup(temp + 9);	/* Skip "urn:uuid:" prefix */

  pthread_rwlock_wrlock(&server->tokens_lock);

  if (!server->tokens)
    server->tokens = cupsArrayNew3((cups_array_func_t)compare_tokens, NULL, NULL, 0, NULL, (cups_afree_func_t)free_token);

  cupsArrayAdd(server->tokens, token);

  pthread_rwlock_unlock(&server->tokens_lock);

  return (token);
}


/*
 * 'moauthdFindToken()' - Find an OAuth token.
 */

moauthd_token_t	*			/* O - Matching token */
moauthdFindToken(
    moauthd_server_t *server,		/* I - Server object */
    const char       *token_id)		/* I - Token ID */
{
  moauthd_token_t	*match,		/* Matching token, if any */
			key;		/* Search key */


  key.token = (char *)token_id;

  pthread_rwlock_rdlock(&server->tokens_lock);

  match = cupsArrayFind(server->tokens, &key);

  pthread_rwlock_unlock(&server->tokens_lock);

  return (match);
}


/*
 * 'compare_token()' - Compare two tokens.
 */

static int				/* O - Result of comparison */
compare_tokens(moauthd_token_t *a,	/* I - First token */
               moauthd_token_t *b)	/* I - Second token */
{
  return (strcmp(a->token, b->token));
}


/*
 * 'free_token()' - Free the memory used by a token.
 */

static void
free_token(moauthd_token_t *token)	/* I - Token to free */
{
  free(token->token);
  free(token->redirect_uri);
  free(token->user);
  cupsArrayDelete(token->scopes);
  free(token);
}
