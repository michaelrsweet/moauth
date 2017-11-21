/*
 * Header file for moauth daemon
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#ifndef _MOAUTHD_H_
#  define _MOAUTHD_H_

/*
 * Include necessary headers...
 */

#  include <config.h>
#  include <moauth/moauth.h>
#  include <stdio.h>
#  include <stdlib.h>
#  include <string.h>
#  include <ctype.h>
#  include <errno.h>
#  include <poll.h>
#  include <pthread.h>


/*
 * Constants...
 */

#  define MOAUTHD_MAX_LISTENERS	100	/* Maximum number of listener sockets */


/*
 * Types...
 */

typedef struct moauthd_user_s		/**** User ****/
{
  char		*email,			/* Email address */
		*username,		/* User name */
		*realname,		/* Real name */
		*password;		/* Hashed password */
  cups_array_t	*scopes;		/* Member scopes */
} moauthd_user_t;

typedef struct moauthd_client_id_s	/**** Client (Application) ID ****/
{
  char		*client_id;		/* Client identifier */
  cups_array_t	*redirect_uris;		/* Allowed redirection URIs */
} moauthd_client_id_t;


typedef enum moauthd_restype_e		/**** Resource Types ****/
{
  MOAUTHD_RESTYPE_DIR,			/* Explicit directory */
  MOAUTHD_RESTYPE_FILE,			/* Explicit file */
  MOAUTHD_RESTYPE_USERDIR		/* Wildcard user directory */
} moauthd_restype_t;


typedef struct moauthd_resource_s	/**** Resource ****/
{
  moauthd_restype_t	type;		/* Resource type */
  char			*remote_path,	/* Remote path */
			*local_path,	/* Local path */
			*scope;		/* Access scope */
  moauthd_user_t	*owner;		/* Owning user (not used for MOAUTHD_RESTYPE_USERDIR) */
} moauthd_resource_t;


typedef enum moauthd_toktype_e		/**** Token Type ****/
{
  MOAUTHD_TOKTYPE_ACCESS,		/* Access token */
  MOAUTHD_TOKTYPE_GRANT,		/* Grant token */
  MOAUTHD_TOKTYPE_RENEWAL		/* Renewal token */
} moauthd_toktype_t;


typedef struct moauthd_token_s		/**** Token ****/
{
  moauthd_toktype_t	type;		/* Type of token */
  char			*token,		/* Token string */
			*redirect_uri;	/* Redirection URI used */
  cups_array_t		*scopes;	/* Scopes */
  moauthd_user_t	*user;		/* Authenticated user */
} moauthd_token_t;


typedef enum moauthd_loglevel_e		/**** Log Levels ****/
{
  MOAUTHD_LOGLEVEL_ERROR,		/* Error messages only */
  MOAUTHD_LOGLEVEL_INFO,		/* Errors and informational messages */
  MOAUTHD_LOGLEVEL_DEBUG,		/* All messages */
} moauthd_loglevel_t;


typedef struct moauthd_server_s		/**** Server ****/
{
  char		*name;			/* Server hostname */
  int		port;			/* Server port */
  int		log_file;		/* Log file descriptor */
  moauthd_loglevel_t log_level;		/* Log level */
  int		num_clients;		/* Number of clients served */
  int		num_listeners;		/* Number of listener sockets */
  struct pollfd	listeners[MOAUTHD_MAX_LISTENERS];
					/* Listener sockets */
  cups_array_t	*resources;		/* Resources that are shared */
  cups_array_t	*scopes;		/* Scopes */
  cups_array_t	*tokens;		/* Tokens that have been issued */
  cups_array_t	*users;			/* Users */
} moauthd_server_t;


typedef struct moauthd_client_s		/**** Client Information ****/
{
  int		number;			/* Client number */
  moauthd_server_t *server;		/* Server */
  http_t	*http;			/* HTTP connection */
  http_state_t	request_method;		/* Request method */
  char		path_info[4096],	/* Request path/URI */
		*query_string;		/* Query string (if any) */
  char		remote_host[256],	/* Remote hostname */
		remote_user[256];	/* Authenticated username */
} moauthd_client_t;


/*
 * Functions...
 */

extern moauthd_client_t	*moauthdCreateClient(moauthd_server_t *server, int fd);
extern moauthd_server_t	*moauthdCreateServer(const char *configfile, int verbosity);
extern void		moauthdDeleteClient(moauthd_client_t *client);
extern void		moauthdDeleteServer(moauthd_server_t *server);
extern int		moauthdGetFile(moauthd_client_t *client);
extern void		moauthdLogc(moauthd_client_t *client, moauthd_loglevel_t level, const char *message, ...) __attribute__((__format__(__printf__, 3, 4)));
extern void		moauthdLogs(moauthd_server_t *server, moauthd_loglevel_t level, const char *message, ...) __attribute__((__format__(__printf__, 3, 4)));
extern void		*moauthdRunClient(moauthd_client_t *client);
extern int		moauthdRunServer(moauthd_server_t *server);

#endif /* !_MOAUTHD_H_ */
