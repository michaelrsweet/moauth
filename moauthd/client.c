/*
 * Client support for moauth daemon
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

static int	do_authorize(moauthd_client_t *client);
static int	do_token(moauthd_client_t *client);


/*
 * 'moauthdCreateClient()' - Accept a connection and create a client object.
 */

moauthd_client_t *			/* O - New client object */
moauthdCreateClient(
    moauthd_server_t *server,		/* I - Server object */
    int              fd)		/* I - Listening socket */
{
  moauthd_client_t *client;		/* Client object */


  if ((client = calloc(1, sizeof(moauthd_client_t))) == NULL)
  {
    moauthdLogs(server, MOAUTHD_LOGLEVEL_ERROR, "Unable to allocate memory for client: %s", strerror(errno));

    return (NULL);
  }

  client->number = ++ server->num_clients;
  client->server = server;

  if ((client->http = httpAcceptConnection(fd, 0)) == NULL)
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to accept client connection: %s", cupsLastErrorString());
    free(client);

    return (NULL);
  }

  httpGetHostname(client->http, client->remote_host, sizeof(client->remote_host));

  moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "Accepted connection from \"%s\".", client->remote_host);

  if (httpEncryption(client->http, HTTP_ENCRYPTION_ALWAYS))
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to establish TLS session: %s", cupsLastErrorString());
    httpClose(client->http);
    free(client);

    return (NULL);
  }

  httpBlocking(client->http, 1);

  moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "TLS session established.");

  return (client);
}


/*
 * 'moauthdDeleteClient()' - Close a connection and delete a client object.
 */

void
moauthdDeleteClient(
    moauthd_client_t *client)		/* I - Client object */
{
  httpClose(client->http);

  moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "Connection closed.");

  free(client);
}


/*
 * 'moauthdRunClient()' - Process requests from a client object.
 */

void *					/* O - Thread return status (ignored) */
moauthdRunClient(
    moauthd_client_t *client)		/* I - Client object */
{
  int			done = 0;	/* Are we done yet? */
  http_state_t		state;		/* HTTP state */
  http_status_t		status;		/* HTTP status */
  const char		*authorization;	/* Authorization: header value */
  char			host_value[300],/* Host: header value */
			*host_ptr;	/* Pointer into Host: header */
  char			uri_prefix[300];/* URI prefix for server */
  size_t		uri_prefix_len;	/* Length of URI prefix */
  static const char * const states[] =
  {					/* Strings for logging HTTP method */
    "WAITING",
    "OPTIONS",
    "GET",
    "GET_SEND",
    "HEAD",
    "POST",
    "POST_RECV",
    "POST_SEND",
    "PUT",
    "PUT_RECV",
    "DELETE",
    "TRACE",
    "CONNECT",
    "STATUS",
    "UNKNOWN_METHOD",
    "UNKNOWN_VERSION"
  };


  snprintf(host_value, sizeof(host_value), "%s:%d", client->server->name, client->server->port);
  snprintf(uri_prefix, sizeof(uri_prefix), "https://%s:%d", client->server->name, client->server->port);
  uri_prefix_len = strlen(uri_prefix);

  while (!done)
  {
   /*
    * Get a request line...
    */

    while ((state = httpReadRequest(client->http, client->path_info, sizeof(client->path_info))) == HTTP_STATE_WAITING)
      usleep(1);

    if (state == HTTP_STATE_ERROR)
    {
      if (httpError(client->http) == EPIPE || httpError(client->http) == ETIMEDOUT || httpError(client->http) == 0)
	moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Client closed connection.");
      else
	moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad request line (%s).", strerror(httpError(client->http)));

      break;
    }
    else if (state == HTTP_STATE_UNKNOWN_METHOD)
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad/unknown operation.");
      moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0);
      break;
    }
    else if (state == HTTP_STATE_UNKNOWN_VERSION)
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad HTTP version.");
      moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0);
      break;
    }

    client->request_method = state;

    moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "%s %s", states[state], client->path_info);

    if (client->path_info[0] != '/' && !strncmp(client->path_info, uri_prefix, uri_prefix_len) && client->path_info[uri_prefix_len] == '/')
    {
     /*
      * Full URL, trim off "https://name:port" part...
      */

      size_t path_info_len = strlen(client->path_info);

      memmove(client->path_info, client->path_info + uri_prefix_len, path_info_len - uri_prefix_len + 1);
    }

    if ((client->query_string = strchr(client->path_info, '?')) != NULL)
    {
     /*
      * Chop the query string off the end...
      */

      *(client->query_string)++ = '\0';
    }

    if ((client->path_info[0] != '/' || strstr(client->path_info, "/../")) && (strcmp(client->path_info, "*") || client->request_method != HTTP_STATE_OPTIONS))
    {
     /*
      * Not a supported path or URI...
      */

      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad request URI \"%s\".", client->path_info);
      moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0);
      break;
    }

    while ((status = httpUpdate(client->http)) == HTTP_STATUS_CONTINUE);

    if (status != HTTP_STATUS_OK)
    {
     /*
      * Unable to get the request headers...
      */

      moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Problem getting request headers.");
      moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0);
      break;
    }

   /*
    * Validate Host: header...
    */

    strncpy(host_value, httpGetField(client->http, HTTP_FIELD_HOST), sizeof(host_value) - 1);
    host_value[sizeof(host_value) - 1] = '\0';

    if ((host_ptr = strrchr(host_value, ':')) == NULL)
      host_ptr = host_value + strlen(host_value);
    if (host_ptr > host_value && host_ptr[-1] == '.')
      host_ptr --;			/* Also strip trailing dot */
    *host_ptr = '\0';

    if (strcasecmp(host_value, client->server->name))
    {
     /*
      * Bad "Host:" field...
      */

      moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Bad Host: header value \"%s\" (expected \"%s\").", httpGetField(client->http, HTTP_FIELD_HOST), host_value);
      moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0);
      break;
    }

    client->remote_user[0] = '\0';
    client->remote_uid     = (uid_t)-1;

    if ((authorization = httpGetField(client->http, HTTP_FIELD_AUTHORIZATION)) != NULL && *authorization)
    {
      if (!strncmp(authorization, "Basic ", 6))
      {
       /*
        * Basic authentication...
        */

	char	username[512],		/* Username value */
		*password;		/* Password value */
        int	userlen = sizeof(username);
					/* Length of username:password */
        struct passwd *user;		/* User information */


        for (authorization += 6; *authorization && isspace(*authorization & 255); authorization ++);

        httpDecode64_2(username, &userlen, authorization);
        if ((password = strchr(username, ':')) != NULL)
        {
          *password++ = '\0';

          if (moauthdAuthenticateUser(client->server, username, password))
          {
            if ((user = getpwnam(username)) != NULL)
	    {
	      moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "Authenticated as \"%s\" using Basic.", username);
	      strncpy(client->remote_user, username, sizeof(client->remote_user) - 1);
	      client->remote_uid = user->pw_uid;
	    }
	    else
	    {
	      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to lookup user \"%s\".", username);
	    }
	  }
	  else
	  {
	    moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "Basic authentication of \"%s\" failed.", username);
	  }
	}
	else
	{
	  moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad Basic Authorization value.");
	}
      }
      else if (!strncmp(authorization, "Bearer ", 7))
      {
       /*
        * Bearer (OAuth) token...
        */

        moauthd_token_t *token;		/* Access token */

        for (authorization += 7; *authorization && isspace(*authorization & 255); authorization ++);

        if ((token = moauthdFindToken(client->server, authorization)) != NULL)
        {
          if (token->expires <= time(NULL))
          {
	    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bearer token has expired.");

            pthread_rwlock_wrlock(&client->server->tokens_lock);
            cupsArrayRemove(client->server->tokens, token);
            pthread_rwlock_unlock(&client->server->tokens_lock);

            token = NULL;
          }
          else if (token->type != MOAUTHD_TOKTYPE_ACCESS)
          {
	    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bearer token is of the wrong type.");

            token = NULL;
	  }
	}

        if (token)
        {
	  moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "Authenticated as \"%s\" using Bearer.", token->user);
          client->remote_token = token;
          client->remote_uid   = token->uid;
          strncpy(client->remote_user, token->user, sizeof(client->remote_user) - 1);
        }
      }
      else
      {
       /*
        * Unsupported Authorization scheme...
        */

        char	scheme[32];		/* Scheme name */

        strncpy(scheme, authorization, sizeof(scheme) - 1);
        scheme[sizeof(scheme) - 1] = '\0';
        strtok(scheme, " \t");

	moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unsupported Authorization scheme \"%s\".", scheme);
      }

      if (!client->remote_user[0])
      {
	moauthdRespondClient(client, HTTP_STATUS_UNAUTHORIZED, NULL, NULL, 0, 0);
	break;
      }
    }

    if (httpGetExpect(client->http) && client->request_method == HTTP_STATE_POST)
    {
     /*
      * Handle Expect: nnn
      */

      if (httpGetExpect(client->http) == HTTP_STATUS_CONTINUE)
      {
       /*
	* Send 100-continue header...
	*
	* TODO: Update as needed based on the URL path - some endpoints need
	* authentication...
	*/

	if (!moauthdRespondClient(client, HTTP_STATUS_CONTINUE, NULL, NULL, 0, 0))
	  break;
      }
      else
      {
       /*
	* Send 417-expectation-failed header...
	*/

	if (!moauthdRespondClient(client, HTTP_STATUS_EXPECTATION_FAILED, NULL, NULL, 0, 0))
	  break;
      }
    }

    switch (client->request_method)
    {
      case HTTP_STATE_OPTIONS :
	 /*
	  * Do OPTIONS command...
	  */

	  if (!moauthdRespondClient(client, HTTP_STATUS_OK, NULL, NULL, 0, 0))
	    done = 1;
	  break;

      case HTTP_STATE_HEAD :
	  if (!strcmp(client->path_info, "/authorize"))
	    done = !do_authorize(client);
	  else if (moauthdGetFile(client) >= HTTP_STATUS_BAD_REQUEST)
	    done = 1;
	  break;

      case HTTP_STATE_GET :
	  if (!strcmp(client->path_info, "/authorize"))
	    done = !do_authorize(client);
	  else if (moauthdGetFile(client) >= HTTP_STATUS_BAD_REQUEST)
	    done = 1;
	  break;

      case HTTP_STATE_POST :
	  if (!strcmp(client->path_info, "/authorize"))
	    done = !do_authorize(client);
	  else if (!strcmp(client->path_info, "/token"))
	    done = !do_token(client);
	  else
	  {
	    moauthdRespondClient(client, HTTP_STATUS_NOT_FOUND, NULL, NULL, 0, 0);
            done = 1;
	  }
          break;

      default :
	  moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Unexpected HTTP state %d.", client->request_method);
	  moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0);
          done = 1;
	  break;
    }
  }

  moauthdDeleteClient(client);

  return (NULL);
}


/*
 * 'do_authorize()' - Process a request for the /authorize endpoint.
 */

static int				/* O - 1 on success, 0 on failure */
do_authorize(moauthd_client_t *client)	/* I - Client object */
{
  int		num_vars;		/* Number of form variables */
  cups_option_t	*vars;			/* Form variables */
  char		*data;			/* Form data */
  const char	*client_id,		/* client_id variable (REQUIRED) */
		*redirect_uri,		/* redirect_uri variable (OPTIONAL) */
		*response_type,		/* response_type variable (REQUIRED) */
		*scope,			/* scope variable (OPTIONAL) */
		*state,			/* state variable (RECOMMENDED) */
		*username,		/* username variable */
		*password;		/* password variable */
  moauthd_application_t *app;		/* Application */
  moauthd_token_t *token;		/* Token */
  char		uri[2048];		/* Redirect URI */
  const char	*prefix;		/* Prefix string */


  switch (client->request_method)
  {
    case HTTP_STATE_HEAD :
        return (moauthdRespondClient(client, HTTP_STATUS_OK, "text/html", NULL, 0, 0));

    case HTTP_STATE_GET :
       /*
        * Get form variable on the request line...
        */

        num_vars      = moauthFormDecode(client->query_string, &vars);
        client_id     = cupsGetOption("client_id", num_vars, vars);
        redirect_uri  = cupsGetOption("redirect_uri", num_vars, vars);
        response_type = cupsGetOption("response_type", num_vars, vars);
        scope         = cupsGetOption("scope", num_vars, vars);
        state         = cupsGetOption("state", num_vars, vars);

        if (!client_id || !response_type || strcmp(response_type, "code"))
        {
	 /*
	  * Missing required variables!
	  */

          if (!client_id)
            moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Missing client_id in authorize request.");
          if (!response_type)
            moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Missing response_type in authorize request.");
          else if (strcmp(response_type, "code"))
            moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad response_type in authorize request.");

	  moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Query string was \"%s\".", client->query_string);

          cupsFreeOptions(num_vars, vars);

          return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));
        }

        if ((app = moauthdFindApplication(client->server, client_id, redirect_uri)) == NULL)
        {
          if (redirect_uri)
            moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad client_id/redirect_uri in authorize request.");
	  else
            moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad client_id in authorize request.");

	  moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Query string was \"%s\".", client->query_string);

          cupsFreeOptions(num_vars, vars);

          return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));
        }

        if (!moauthdRespondClient(client, HTTP_STATUS_OK, "text/html", NULL, 0, 0))
        {
	  cupsFreeOptions(num_vars, vars);

          return (0);
	}

        moauthdHTMLHeader(client, "Authorization");
        moauthdHTMLPrintf(client,
            "<div class=\"form\">\n"
            "  <form action=\"/authorize\" method=\"POST\">\n"
            "    <h1>Authorization</h1>\n"
            "    <div class=\"form-group\">\n"
            "      <label for=\"username\">Username:</label>\n"
            "      <input type=\"text\" name=\"username\" size=\"16\">\n"
            "    </div>\n"
            "    <div class=\"form-group\">\n"
            "      <label for=\"password\">Password:</label>\n"
            "      <input type=\"password\" name=\"password\" size=\"16\">\n"
            "    </div>\n"
            "    <div class=\"form-group\">\n"
            "      <input type=\"submit\" value=\"Login\">\n"
            "    </div>\n"
            "    <input type=\"hidden\" name=\"client_id\" value=\"%s\">\n"
            "    <input type=\"hidden\" name=\"redirect_uri\" value=\"%s\">\n"
            "    <input type=\"hidden\" name=\"response_type\" value=\"%s\">\n"
            "    <input type=\"hidden\" name=\"scope\" value=\"%s\">\n",
            client_id, app->redirect_uri, response_type, scope ? scope : "private shared");
        if (state)
          moauthdHTMLPrintf(client, "    <input type=\"hidden\" name=\"state\" value=\"%s\">\n", state);
	moauthdHTMLPrintf(client,
            "  </form>\n"
            "</div>\n");
        moauthdHTMLFooter(client);

        cupsFreeOptions(num_vars, vars);
        break;

    case HTTP_STATE_POST :
        if ((data = moauthGetPostData(client->http)) == NULL)
          return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));

        num_vars      = moauthFormDecode(data, &vars);
        client_id     = cupsGetOption("client_id", num_vars, vars);
        redirect_uri  = cupsGetOption("redirect_uri", num_vars, vars);
        response_type = cupsGetOption("response_type", num_vars, vars);
        scope         = cupsGetOption("scope", num_vars, vars);
        state         = cupsGetOption("state", num_vars, vars);
        username      = cupsGetOption("username", num_vars, vars);
        password      = cupsGetOption("password", num_vars, vars);

        if (!client_id || !response_type || strcmp(response_type, "code"))
        {
	 /*
	  * Missing required variables!
	  */

          if (!client_id)
            moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Missing client_id in authorize request.");
          if (!response_type)
            moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Missing response_type in authorize request.");
          else if (strcmp(response_type, "code"))
            moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad response_type in authorize request.");

          cupsFreeOptions(num_vars, vars);

          return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));
        }

        if ((app = moauthdFindApplication(client->server, client_id, redirect_uri)) == NULL)
        {
          if (redirect_uri)
            moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad client_id/redirect_uri in authorize request.");
	  else
            moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad client_id in authorize request.");

	  moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Query string was \"%s\".", client->query_string);

          cupsFreeOptions(num_vars, vars);

          return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));
        }

        if (strchr(redirect_uri, '?'))
          prefix = "&";
	else
	  prefix = "?";

        if (!username || !password || !moauthdAuthenticateUser(client->server, username, password))
        {
          snprintf(uri, sizeof(uri), "%s%serror=access_denied&error_description=Bad+username+or+password.%s%s", redirect_uri, prefix, state ? "&state=" : "", state ? state : "");
        }
        else if ((token = moauthdCreateToken(client->server, MOAUTHD_TOKTYPE_GRANT, redirect_uri, username, scope)) == NULL)
        {
          snprintf(uri, sizeof(uri), "%s%serror=server_error&error_description=Unable+to+create+grant.%s%s", redirect_uri, prefix, state ? "&state=" : "", state ? state : "");
        }
        else
        {
          snprintf(uri, sizeof(uri), "%s%scode=%s%s%s", redirect_uri, prefix, token->token, state ? "&state=" : "", state ? state : "");
        }

        cupsFreeOptions(num_vars, vars);

        return (moauthdRespondClient(client, HTTP_STATUS_MOVED_TEMPORARILY, NULL, uri, 0, 0));

    default :
        return (0);
  }

  return (1);
}


/*
 * 'do_token()' - Process a request for the /token endpoint.
 */

static int				/* O - 1 on success, 0 on failure */
do_token(moauthd_client_t *client)	/* I - Client object */
{
  return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));
}

