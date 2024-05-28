//
// Client support for moauth daemon
//
// Copyright © 2017-2024 by Michael R Sweet
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//

#include "moauthd.h"
#include <cups/form.h>
#include <pwd.h>
#include <grp.h>


//
// Local functions...
//

static bool	do_authorize(moauthd_client_t *client);
static bool	do_introspect(moauthd_client_t *client);
static bool	do_register(moauthd_client_t *client);
static bool	do_token(moauthd_client_t *client);
static bool	do_userinfo(moauthd_client_t *client);
static bool	validate_uri(const char *uri, const char *urischeme);


//
// 'moauthdCreateClient()' - Accept a connection and create a client object.
//

moauthd_client_t *			// O - New client object
moauthdCreateClient(
    moauthd_server_t *server,		// I - Server object
    int              fd)		// I - Listening socket
{
  moauthd_client_t *client;		// Client object


  if ((client = calloc(1, sizeof(moauthd_client_t))) == NULL)
  {
    moauthdLogs(server, MOAUTHD_LOGLEVEL_ERROR, "Unable to allocate memory for client: %s", strerror(errno));

    return (NULL);
  }

  client->number = ++ server->num_clients;
  client->server = server;

  if ((client->http = httpAcceptConnection(fd, false)) == NULL)
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to accept client connection: %s", cupsGetErrorString());
    free(client);

    return (NULL);
  }

  httpGetHostname(client->http, client->remote_host, sizeof(client->remote_host));

  moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "Accepted connection from \"%s\".", client->remote_host);

  if (!httpSetEncryption(client->http, HTTP_ENCRYPTION_ALWAYS))
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to establish TLS session: %s", cupsGetErrorString());
    httpClose(client->http);
    free(client);

    return (NULL);
  }

  httpSetBlocking(client->http, true);

  moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "TLS session established.");

  return (client);
}


//
// 'moauthdDeleteClient()' - Close a connection and delete a client object.
//

void
moauthdDeleteClient(
    moauthd_client_t *client)		// I - Client object
{
  httpClose(client->http);

  moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "Connection closed.");

  free(client);
}


//
// 'moauthdRunClient()' - Process requests from a client object.
//

void *					// O - Thread return status (ignored)
moauthdRunClient(
    moauthd_client_t *client)		// I - Client object
{
  bool			done = false;	// Are we done yet?
  http_state_t		state;		// HTTP state
  http_status_t		status;		// HTTP status
  const char		*authorization;	// Authorization: header value
  char			host_value[300],// Host: header value
			*host_ptr;	// Pointer into Host: header
  int			host_port;	// Port number
  char			uri_prefix[300];// URI prefix for server
  size_t		uri_prefix_len;	// Length of URI prefix


  snprintf(host_value, sizeof(host_value), "%s:%d", client->server->name, client->server->port);
  snprintf(uri_prefix, sizeof(uri_prefix), "https://%s:%d", client->server->name, client->server->port);
  uri_prefix_len = strlen(uri_prefix);

  while (!done)
  {
    // Get a request line...
    while ((state = httpReadRequest(client->http, client->path_info, sizeof(client->path_info))) == HTTP_STATE_WAITING)
      usleep(1);

    if (state == HTTP_STATE_ERROR)
    {
      if (httpGetError(client->http) == EPIPE || httpGetError(client->http) == ETIMEDOUT || httpGetError(client->http) == 0)
	moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "Client closed connection.");
      else
	moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad request line (%s).", strerror(httpGetError(client->http)));

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

    moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "%s %s", httpStateString(state), client->path_info);

    if (client->path_info[0] != '/' && !strncmp(client->path_info, uri_prefix, uri_prefix_len) && client->path_info[uri_prefix_len] == '/')
    {
      // Full URL, trim off "https://name:port" part...
      size_t path_info_len = strlen(client->path_info);

      memmove(client->path_info, client->path_info + uri_prefix_len, path_info_len - uri_prefix_len + 1);
    }

    if ((client->query_string = strchr(client->path_info, '?')) != NULL)
    {
      // Chop the query string off the end...
      *(client->query_string)++ = '\0';
    }

    if ((client->path_info[0] != '/' || strstr(client->path_info, "/../")) && (strcmp(client->path_info, "*") || client->request_method != HTTP_STATE_OPTIONS))
    {
      // Not a supported path or URI...
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad request URI \"%s\".", client->path_info);
      moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0);
      break;
    }

    while ((status = httpUpdate(client->http)) == HTTP_STATUS_CONTINUE);

    if (status != HTTP_STATUS_OK)
    {
      // Unable to get the request headers...
      moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Problem getting request headers.");
      moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0);
      break;
    }

    // Validate Host: header...
    cupsCopyString(host_value, httpGetField(client->http, HTTP_FIELD_HOST), sizeof(host_value));

    if ((host_ptr = strrchr(host_value, ':')) != NULL)
    {
      host_port = atoi(host_ptr + 1);
    }
    else
    {
      host_port = 443;
      host_ptr  = host_value + strlen(host_value);
    }

    if (host_ptr > host_value && host_ptr[-1] == '.')
      host_ptr --;			// Also strip trailing dot
    *host_ptr = '\0';

    if (strcasecmp(host_value, client->server->name) || host_port != client->server->port)
    {
      // Bad "Host:" field...
      if (!strcasecmp(host_value, "localhost"))
      {
       /*
        * Redirect to the correct server name...
        */

        char uri[1024];			// Redirection URI

        httpAssembleURI(HTTP_URI_CODING_ALL, uri, sizeof(uri), "https", NULL, client->server->name, client->server->port, client->path_info);
        moauthdRespondClient(client, HTTP_STATUS_MOVED_PERMANENTLY, NULL, uri, 0, 0);
      }
      else
      {
        // Log it...
	moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Bad Host: header value \"%s\" (expected \"%s:%d\").", httpGetField(client->http, HTTP_FIELD_HOST), client->server->name, client->server->port);
	moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0);
	break;
      }
    }

    client->remote_user[0] = '\0';
    client->remote_uid     = (uid_t)-1;

    if ((authorization = httpGetField(client->http, HTTP_FIELD_AUTHORIZATION)) != NULL && *authorization)
    {
      if (!strncmp(authorization, "Basic ", 6))
      {
        // Basic authentication...
	char	username[512],		// Username value
		*password;		// Password value
        size_t	userlen = sizeof(username);
					// Length of username:password
        struct passwd *user;		// User information


        for (authorization += 6; *authorization && isspace(*authorization & 255); authorization ++);

        httpDecode64(username, &userlen, authorization, /*end*/NULL);
        if ((password = strchr(username, ':')) != NULL)
        {
          *password++ = '\0';

          if (moauthdAuthenticateUser(client, username, password))
          {
            if ((user = getpwnam(username)) != NULL)
	    {
	      moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "Authenticated as \"%s\" using Basic.", username);
	      cupsCopyString(client->remote_user, username, sizeof(client->remote_user));
	      client->remote_uid = user->pw_uid;

              client->num_remote_groups = (int)(sizeof(client->remote_groups) / sizeof(client->remote_groups[0]));

#ifdef __APPLE__
              if (getgrouplist(client->remote_user, (int)user->pw_gid, client->remote_groups, &client->num_remote_groups))
#else
              if (getgrouplist(client->remote_user, user->pw_gid, client->remote_groups, &client->num_remote_groups))
#endif // __APPLE__
              {
                moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to lookup groups for user \"%s\": %s", username, strerror(errno));
                client->num_remote_groups = 0;
	      }
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
        // Bearer (OAuth) token...
        moauthd_token_t *token;		// Access token

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
          cupsCopyString(client->remote_user, token->user, sizeof(client->remote_user));

	  client->num_remote_groups = (int)(sizeof(client->remote_groups) / sizeof(client->remote_groups[0]));

#ifdef __APPLE__
	  if (getgrouplist(token->user, (int)token->gid, client->remote_groups, &client->num_remote_groups))
#else
	  if (getgrouplist(token->user, token->gid, client->remote_groups, &client->num_remote_groups))
#endif // __APPLE__
	  {
	    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to lookup groups for user \"%s\": %s", token->user, strerror(errno));
	    client->num_remote_groups = 0;
	  }
        }
      }
      else
      {
        // Unsupported Authorization scheme...
        char	scheme[32];		// Scheme name

        cupsCopyString(scheme, authorization, sizeof(scheme));
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
      // Handle Expect: nnn
      if (httpGetExpect(client->http) == HTTP_STATUS_CONTINUE)
      {
        // Send 100-continue header...
	//
	// TODO: Update as needed based on the URL path - some endpoints need
	// authentication...
	if (!moauthdRespondClient(client, HTTP_STATUS_CONTINUE, NULL, NULL, 0, 0))
	  break;
      }
      else
      {
        // Send 417-expectation-failed header...
	if (!moauthdRespondClient(client, HTTP_STATUS_EXPECTATION_FAILED, NULL, NULL, 0, 0))
	  break;
      }
    }

    switch (client->request_method)
    {
      case HTTP_STATE_OPTIONS :
	  // Do OPTIONS command...
	  if (!moauthdRespondClient(client, HTTP_STATUS_OK, NULL, NULL, 0, 0))
	    done = true;
	  break;

      case HTTP_STATE_HEAD :
	  if (!strcmp(client->path_info, "/authorize"))
	    done = !do_authorize(client);
	  else if (moauthdGetFile(client) >= HTTP_STATUS_BAD_REQUEST)
	    done = true;
	  break;

      case HTTP_STATE_GET :
	  if (!strcmp(client->path_info, "/authorize"))
	    done = !do_authorize(client);
	  else if (!strcmp(client->path_info, "/userinfo"))
	    done = !do_userinfo(client);
	  else if (moauthdGetFile(client) >= HTTP_STATUS_BAD_REQUEST)
	    done = true;
	  break;

      case HTTP_STATE_POST :
	  if (!strcmp(client->path_info, "/authorize"))
	  {
	    done = !do_authorize(client);
	  }
	  else if (!strcmp(client->path_info, "/introspect"))
	  {
	    done = !do_introspect(client);
	  }
	  else if (!strcmp(client->path_info, "/register"))
	  {
	    done = !do_register(client);
	  }
	  else if (!strcmp(client->path_info, "/token"))
	  {
	    done = !do_token(client);
	  }
	  else if (!strcmp(client->path_info, "/userinfo"))
	  {
	    done = !do_userinfo(client);
	  }
	  else
	  {
	    moauthdRespondClient(client, HTTP_STATUS_NOT_FOUND, NULL, NULL, 0, 0);
            done = true;
	  }
          break;

      default :
	  moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Unexpected HTTP state %d.", client->request_method);
	  moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0);
          done = true;
	  break;
    }
  }

  moauthdDeleteClient(client);

  return (NULL);
}


//
// 'do_authorize()' - Process a request for the /authorize endpoint.
//

static bool				// O - `true` on success, `false` on failure
do_authorize(moauthd_client_t *client)	// I - Client object
{
  size_t	num_vars;		// Number of form variables
  cups_option_t	*vars;			// Form variables
  char		*data;			// Form data
  const char	*client_id,		// client_id variable (REQUIRED)
		*redirect_uri,		// redirect_uri variable (OPTIONAL)
		*response_type,		// response_type variable (REQUIRED)
		*scope,			// scope variable (OPTIONAL)
		*state,			// state variable (RECOMMENDED)
		*challenge,		// code_challenge variable (OPTIONAL)
		*method,		// code_challenge_method variable (OPTIONAL)
		*username,		// username variable
		*password;		// password variable
  moauthd_application_t *app;		// Application
  moauthd_token_t *token;		// Token
  char		uri[2048];		// Redirect URI
  const char	*prefix;		// Prefix string


  moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "httpGetState=%s", httpStateString(httpGetState(client->http)));

  switch (client->request_method)
  {
    case HTTP_STATE_HEAD :
        return (moauthdRespondClient(client, HTTP_STATUS_OK, "text/html", NULL, 0, 0));

    case HTTP_STATE_GET :
        // Get form variable on the request line...
        num_vars      = cupsFormDecode(client->query_string, &vars);
        client_id     = cupsGetOption("client_id", num_vars, vars);
        redirect_uri  = cupsGetOption("redirect_uri", num_vars, vars);
        response_type = cupsGetOption("response_type", num_vars, vars);
        scope         = cupsGetOption("scope", num_vars, vars);
        state         = cupsGetOption("state", num_vars, vars);
        challenge     = cupsGetOption("code_challenge", num_vars, vars);
        method        = cupsGetOption("code_challenge_method", num_vars, vars);

        {
          size_t i;
          moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "num_vars=%u", (unsigned)num_vars);
          for (i = 0; i < num_vars; i ++)
            moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "vars[%u].name=\"%s\", .value=\"%s\"", (unsigned)i, vars[i].name, vars[i].value);
        }

        if (!client_id || !response_type || strcmp(response_type, "code") || (method && strcmp(method, "S256")))
        {
	  // Missing required variables!
          if (!client_id)
            moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Missing client_id in authorize request.");
          if (!response_type)
            moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Missing response_type in authorize request.");
          else if (strcmp(response_type, "code"))
            moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad response_type in authorize request.");
	  else if (method && strcmp(method, "S256"))
            moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad code_challenge_method \"%s\" in authorize request.", method);

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

          return (false);
	}

        moauthdHTMLHeader(client, "Authorization");
        if (app->client_name)
	  moauthdHTMLPrintf(client,
	      "<div class=\"form\">\n"
	      "  <form action=\"/authorize\" method=\"POST\">\n"
	      "    <h1>%s Authorization</h1>\n", app->client_name);
        else
	  moauthdHTMLPrintf(client,
	      "<div class=\"form\">\n"
	      "  <form action=\"/authorize\" method=\"POST\">\n"
	      "    <h1>Authorization</h1>\n");

	if (app->client_uri || app->tos_uri)
	{
	  if (app->client_uri && app->tos_uri)
	    moauthdHTMLPrintf(client, "<p><a href=\"%s\">More Info</a> &middot; <a href=\"%s\">Terms of Service</a></p>\n", app->client_uri, app->tos_uri);
	  else if (app->client_uri)
	    moauthdHTMLPrintf(client, "<p><a href=\"%s\">More Info</a></p>\n", app->client_uri);
	  else
	    moauthdHTMLPrintf(client, "<p><a href=\"%s\">Terms of Service</a></p>\n", app->tos_uri);
	}

	moauthdHTMLPrintf(client,
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
        if (challenge)
          moauthdHTMLPrintf(client, "    <input type=\"hidden\" name=\"code_challenge\" value=\"%s\">\n", challenge);
	moauthdHTMLPrintf(client,
            "  </form>\n"
            "</div>\n");
        moauthdHTMLFooter(client);

        cupsFreeOptions(num_vars, vars);
        break;

    case HTTP_STATE_POST :
        if ((data = _moauthCopyMessageBody(client->http)) == NULL)
          return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));

        num_vars      = cupsFormDecode(data, &vars);
        client_id     = cupsGetOption("client_id", num_vars, vars);
        redirect_uri  = cupsGetOption("redirect_uri", num_vars, vars);
        response_type = cupsGetOption("response_type", num_vars, vars);
        scope         = cupsGetOption("scope", num_vars, vars);
        state         = cupsGetOption("state", num_vars, vars);
        username      = cupsGetOption("username", num_vars, vars);
        password      = cupsGetOption("password", num_vars, vars);
        challenge     = cupsGetOption("code_challenge", num_vars, vars);

        {
          size_t i;
          moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "num_vars=%u", (unsigned)num_vars);
          for (i = 0; i < num_vars; i ++)
            moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "vars[%u].name=\"%s\", .value=\"%s\"", (unsigned)i, vars[i].name, vars[i].value);
        }

	free(data);

        if (!client_id || !response_type || strcmp(response_type, "code"))
        {
	  // Missing required variables!
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

        if (!username || !password || !moauthdAuthenticateUser(client, username, password))
        {
          snprintf(uri, sizeof(uri), "%s%serror=access_denied&error_description=Bad+username+or+password.%s%s", redirect_uri, prefix, state ? "&state=" : "", state ? state : "");
        }
        else if ((token = moauthdCreateToken(client->server, MOAUTHD_TOKTYPE_GRANT, app, username, scope)) == NULL)
        {
          snprintf(uri, sizeof(uri), "%s%serror=server_error&error_description=Unable+to+create+grant.%s%s", redirect_uri, prefix, state ? "&state=" : "", state ? state : "");
        }
        else
        {
          if (challenge)
            token->challenge = strdup(challenge);

          snprintf(uri, sizeof(uri), "%s%scode=%s%s%s", redirect_uri, prefix, token->token, state ? "&state=" : "", state ? state : "");
        }

        cupsFreeOptions(num_vars, vars);

        return (moauthdRespondClient(client, HTTP_STATUS_FOUND, NULL, uri, 0, 0));

    default :
        return (false);
  }

  return (true);
}


//
// 'do_introspect()' - Process a request for the /introspect endpoint.
//

static bool				// O - `true` on success, `false` on failure
do_introspect(moauthd_client_t *client)	// I - Client object
{
  http_status_t	status = HTTP_STATUS_OK;// Response status
  size_t	num_vars;		// Number of form (request) variables
  cups_option_t	*vars;			// Form (request) variables
  char		*data;			// Form data
  const char	*token_var;		// token variable (REQUIRED)
  moauthd_token_t *token;		// Token
  cups_json_t	*json,			// JSON response
		*jarray;		// JSON array
  size_t	datalen;		// Length of JSON data
  static const char * const types[] =	// Token types
  {
    "access",
    "grant",
    "renewal"
  };


  if (client->server->introspect_group != (gid_t)-1)
  {
    // See if the authenticated user is in the specified group...
    if (!client->remote_user[0])
    {
      // Not yet authenticated...
      status = HTTP_STATUS_UNAUTHORIZED;
    }
    else
    {
      int i;				// Looping var

      for (i = 0; i < client->num_remote_groups; i ++)
	if (client->remote_groups[i] == client->server->introspect_group)
	  break;

      if (i >= client->num_remote_groups)
	status = HTTP_STATUS_FORBIDDEN;
    }
  }

  if (status != HTTP_STATUS_OK)
    return (moauthdRespondClient(client, status, NULL, NULL, 0, 0));

  if ((data = _moauthCopyMessageBody(client->http)) == NULL)
    return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));

  num_vars  = cupsFormDecode(data, &vars);
  token_var = cupsGetOption("token", num_vars, vars);

  free(data);

  if (!token_var)
  {
    // Missing required variables!
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Missing token in introspect request.");

    goto bad_request;
  }

  if ((token = moauthdFindToken(client->server, token_var)) == NULL)
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad token in introspect request.");

    goto bad_request;
  }

  json = cupsJSONNew(/*parent*/NULL, /*after*/NULL, CUPS_JTYPE_OBJECT);
  cupsJSONNew(json, cupsJSONNewKey(json, /*after*/NULL, "active"), token->expires > time(NULL) ? CUPS_JTYPE_TRUE : CUPS_JTYPE_FALSE);
  jarray = cupsJSONNew(json, cupsJSONNewKey(json, /*after*/NULL, "scope"), CUPS_JTYPE_ARRAY);
  cupsJSONNewString(jarray, /*after*/NULL, token->scopes);// TODO: Fix this
  cupsJSONNewString(json, cupsJSONNewKey(json, /*after*/NULL, "client_id"), token->application->client_id);
  cupsJSONNewString(json, cupsJSONNewKey(json, /*after*/NULL, "username"), token->user);
  cupsJSONNewString(json, cupsJSONNewKey(json, /*after*/NULL, "token_type"), types[token->type]);
  cupsJSONNewNumber(json, cupsJSONNewKey(json, /*after*/NULL, "exp"), (double)token->expires);
  cupsJSONNewNumber(json, cupsJSONNewKey(json, /*after*/NULL, "iat"), (double)token->created);

  data = cupsJSONExportString(json);
  cupsJSONDelete(json);

  if (!data)
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to create JSON response.");

    goto bad_request;
  }

  cupsFreeOptions(num_vars, vars);

  datalen = strlen(data);

  if (!moauthdRespondClient(client, HTTP_STATUS_OK, "application/json", NULL, 0, datalen))
  {
    free(data);
    return (false);
  }

  if (httpWrite(client->http, data, datalen) < datalen)
  {
    free(data);
    return (false);
  }

  free(data);

  return (true);

  // If we get here there was a bad request...
  bad_request:

  cupsFreeOptions(num_vars, vars);

  return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));
}


//
// 'do_register()' - Process a request for the /register endpoint.
//

static bool				// O - `true` on success, `false` on failure
do_register(moauthd_client_t *client)	// I - Client object
{
  http_status_t	status = HTTP_STATUS_CREATED;
					// Return status
  cups_json_t	*request = NULL,	// JSON request
		*response = NULL,	// JSON response
		*jarray;		// JSON array
  char		*data;			// Form data
  const char	*redirect_uris,		// redirect_uris variable (REQUIRED)
		*client_name,		// client_name variable (RECOMMENDED)
		*client_uri,		// client_uri variable (RECOMMENDED)
		*logo_uri,		// logo_uri variable (OPTIONAL)
		*tos_uri;		// tos_uri variable (OPTIONAL)
  size_t	datalen;		// Length of JSON data
  unsigned char	client_id_hash[32];	// SHA2-256 hash of client_name or redirect_uris
  char		client_id[65];		// client_id value
  const char	*error = NULL;		// Error code, if any
  char		error_message[1024];	// Error message, if any


  if (client->server->register_group != (gid_t)-1)
  {
    // See if the authenticated user is in the specified group...
    if (!client->remote_user[0])
    {
      // Not yet authenticated...
      status = HTTP_STATUS_UNAUTHORIZED;
    }
    else
    {
      int i;				// Looping var

      for (i = 0; i < client->num_remote_groups; i ++)
	if (client->remote_groups[i] == client->server->register_group)
	  break;

      if (i >= client->num_remote_groups)
	status = HTTP_STATUS_FORBIDDEN;
    }
  }

  if (status != HTTP_STATUS_CREATED)
    return (moauthdRespondClient(client, status, NULL, NULL, 0, 0));

  // Get request data...
  if ((data = _moauthCopyMessageBody(client->http)) == NULL)
    return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));

  request       = cupsJSONImportString(data);
  redirect_uris = cupsJSONGetString(cupsJSONGetChild(cupsJSONFind(request, "redirect_uris"), 0));
  client_name   = cupsJSONGetString(cupsJSONFind(request, "client_name"));
  client_uri    = cupsJSONGetString(cupsJSONFind(request, "client_uri"));
  logo_uri      = cupsJSONGetString(cupsJSONFind(request, "logo_uri"));
  tos_uri       = cupsJSONGetString(cupsJSONFind(request, "tos_uri"));

  free(data);

  if (!redirect_uris)
  {
    // Missing required variables!
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Missing redirect_uris in register request.");

    error = "invalid_redirect_uri";
    snprintf(error_message, sizeof(error_message), "Missing redirect_uris value.");

    goto bad_request;
  }
  else if (!validate_uri(redirect_uris, NULL))
  {
    error = "invalid_redirect_uri";
    snprintf(error_message, sizeof(error_message), "Bad redirect_uri \"%s\".", redirect_uris);

    goto bad_request;
  }
  else if (client_uri && !validate_uri(client_uri, "https"))
  {
    error = "invalid_client_metadata";
    snprintf(error_message, sizeof(error_message), "Bad client_uri \"%s\".", client_uri);

    goto bad_request;
  }
  else if (logo_uri && !validate_uri(logo_uri, "https"))
  {
    error = "invalid_client_metadata";
    snprintf(error_message, sizeof(error_message), "Bad logo_uri \"%s\".", logo_uri);

    goto bad_request;
  }
  else if (tos_uri && !validate_uri(tos_uri, "https"))
  {
    error = "invalid_client_metadata";
    snprintf(error_message, sizeof(error_message), "Bad tos_uri \"%s\".", tos_uri);

    goto bad_request;
  }

  // Parse redirect_uris to add application entries...
  if (client_name)
    cupsHashData("sha2-256", client_name, strlen(client_name), client_id_hash, sizeof(client_id_hash));
  else
    cupsHashData("sha2-256", redirect_uris, strlen(redirect_uris), client_id_hash, sizeof(client_id_hash));

  cupsHashString(client_id_hash, sizeof(client_id_hash), client_id, sizeof(client_id));
  client_id[16] = '\0';

  moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "Registering client \"%s\" with redirect URI \"%s\".", client_id, redirect_uris);

  if (moauthdFindApplication(client->server, client_id, redirect_uris))
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Client %s %s is already registered.", client_id, redirect_uris);
  }
  else if (moauthdAddApplication(client->server, client_id, redirect_uris, client_name, client_uri, logo_uri, tos_uri))
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Client %s %s registered.", client_id, redirect_uris);
  }
  else
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_DEBUG, "Unable to register client %s %s.", client_id, redirect_uris);
    // TODO: Return an error? Nothing defined in RFC 7591 for internal errors...
  }

  // Respond with the metadata and generated client_id...
  response = cupsJSONNew(/*parent*/NULL, /*after*/NULL, CUPS_JTYPE_OBJECT);
  cupsJSONNewString(response, cupsJSONNewKey(response, /*after*/NULL, "client_id"), client_id);
  if (redirect_uris)
  {
    jarray = cupsJSONNew(response, cupsJSONNewKey(response, /*after*/NULL, "redirect_uris"), CUPS_JTYPE_ARRAY);
    cupsJSONNewString(jarray, /*after*/NULL, redirect_uris);
  }
  if (client_name)
    cupsJSONNewString(response, cupsJSONNewKey(response, /*after*/NULL, "client_name"), client_name);
  if (client_uri)
    cupsJSONNewString(response, cupsJSONNewKey(response, /*after*/NULL, "client_uri"), client_uri);
  if (logo_uri)
    cupsJSONNewString(response, cupsJSONNewKey(response, /*after*/NULL, "logo_uri"), logo_uri);
  if (tos_uri)
    cupsJSONNewString(response, cupsJSONNewKey(response, /*after*/NULL, "tos_uri"), tos_uri);

  cupsJSONNewString(response, cupsJSONNewKey(response, /*after*/NULL, "token_endpoint_auth_method"), "none");

  jarray = cupsJSONNew(response, cupsJSONNewKey(response, /*after*/NULL, "grant_types"), CUPS_JTYPE_ARRAY);
  cupsJSONNewString(jarray, /*after*/NULL, "authorization_code");
  cupsJSONNewString(jarray, /*after*/NULL, "password");
  cupsJSONNewString(jarray, /*after*/NULL, "refresh_token");

  jarray = cupsJSONNew(response, cupsJSONNewKey(response, /*after*/NULL, "token_endpoint_auth_methods_supported"), CUPS_JTYPE_ARRAY);
  cupsJSONNewString(jarray, /*after*/NULL, "none");

  data = cupsJSONExportString(response);

  if (!data)
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to create JSON response.");

    goto bad_request;
  }

  cupsJSONDelete(request);
  cupsJSONDelete(response);

  datalen = strlen(data);

  if (!moauthdRespondClient(client, HTTP_STATUS_CREATED, "application/json", NULL, 0, datalen))
  {
    free(data);
    return (false);
  }

  if (httpWrite(client->http, data, datalen) < datalen)
  {
    free(data);
    return (false);
  }

  free(data);

  return (true);

  // If we get here there was a bad request...
  bad_request:

  cupsJSONDelete(request);
  cupsJSONDelete(response);

  if (error)
  {
    response = cupsJSONNew(/*parent*/NULL, /*after*/NULL, CUPS_JTYPE_OBJECT);
    cupsJSONNewString(response, cupsJSONNewKey(response, /*after*/NULL, "error"), error);
    cupsJSONNewString(response, cupsJSONNewKey(response, /*after*/NULL, "error_description"), error_message);

    data = cupsJSONExportString(response);
    cupsJSONDelete(response);

    if (data)
    {
      int status;			// Return status

      datalen = strlen(data);
      status  = moauthdRespondClient(client, HTTP_STATUS_CREATED, "application/json", NULL, 0, datalen);
      free(data);
      return (status);
    }
  }

  return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));
}


//
// 'do_token()' - Process a request for the /token endpoint.
//

static bool				// O - `true` on success, `false` on failure
do_token(moauthd_client_t *client)	// I - Client object
{
  size_t	num_vars;		// Number of form (request) variables
  cups_option_t	*vars;			// Form (request) variables
  char		*data;			// Form data
  const char	*client_id,		// client_id variable (REQUIRED)
		*code,			// code variable (REQUIRED)
		*grant_type,		// grant_type variable (REQUIRED)
		*password,		// password variable (REQURIED for Resource Owner Password Grant)
		*redirect_uri,		// redirect_uri variable (OPTIONAL)
		*scope,			// scope variable (OPTIONAL)
		*username,		// username variable (REQURIED for Resource Owner Password Grant)
		*verifier;		// code_verify variable (OPTIONAL)
  moauthd_application_t *app;		// Application
  moauthd_token_t *grant_token,		// Grant token
		*access_token;		// Access token
  cups_json_t	*response;		// JSON response
  size_t	datalen;		// Length of JSON data


  if ((data = _moauthCopyMessageBody(client->http)) == NULL)
    return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));

  num_vars      = cupsFormDecode(data, &vars);
  client_id     = cupsGetOption("client_id", num_vars, vars);
  code          = cupsGetOption("code", num_vars, vars);
  grant_type    = cupsGetOption("grant_type", num_vars, vars);
  password      = cupsGetOption("password", num_vars, vars);
  redirect_uri  = cupsGetOption("redirect_uri", num_vars, vars);
  username      = cupsGetOption("username", num_vars, vars);
  scope         = cupsGetOption("scope", num_vars, vars);
  verifier      = cupsGetOption("code_verifier", num_vars, vars);

  free(data);

  if (!grant_type || (strcmp(grant_type, "authorization_code") && strcmp(grant_type, "password")))
  {
    if (!grant_type)
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Missing grant_type in token request.");
    else
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad grant_type '%s' in token request.", grant_type);

    goto bad_request;
  }
  else if (!strcmp(grant_type, "password") && !username && !password)
  {
    if (!username)
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Missing username in token request.");
    if (!password)
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Missing password in token request.");

    goto bad_request;
  }
  else if (strcmp(grant_type, "password") && (!client_id || !code))
  {
    // Missing required variables!
    if (!client_id)
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Missing client_id in token request.");
    if (!code)
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Missing code in token request.");

    goto bad_request;
  }

  if (!strcmp(grant_type, "password"))
  {
    if (!moauthdAuthenticateUser(client, username, password))
      goto bad_request;

    access_token = moauthdCreateToken(client->server, MOAUTHD_TOKTYPE_ACCESS, NULL, username, scope);
  }
  else
  {
    if ((app = moauthdFindApplication(client->server, client_id, redirect_uri)) == NULL)
    {
      if (redirect_uri)
	moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad client_id/redirect_uri in token request.");
      else
	moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad client_id in token request.");

      goto bad_request;
    }

    if ((grant_token = moauthdFindToken(client->server, code)) == NULL)
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad code in token request.");

      goto bad_request;
    }

    if (grant_token->application != app)
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad client_id or redirect_uri in token request.");

      goto bad_request;
    }

    if (grant_token->expires <= time(NULL))
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Grant token has expired.");

      moauthdDeleteToken(client->server, grant_token);

      goto bad_request;
    }

    if (grant_token->challenge)
    {
      if (verifier)
      {
	unsigned char	sha256[32];	// SHA-256 hash of verifier
	char		challenge[45];	// Base64 version of hash

	cupsHashData("sha2-256", verifier, strlen(verifier), sha256, sizeof(sha256));
	httpEncode64(challenge, (int)sizeof(challenge), (char *)sha256, sizeof(sha256), true);

	if (strcmp(grant_token->challenge, challenge))
	{
	  moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Incorrect code_verifier in token request.");

	  goto bad_request;
	}
      }
      else
      {
	moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Missing code_verifier in token request.");

	goto bad_request;
      }
    }

    if ((access_token = moauthdCreateToken(client->server, MOAUTHD_TOKTYPE_ACCESS, app, grant_token->user, grant_token->scopes)) == NULL)
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to create access token.");

      goto bad_request;
    }

    moauthdDeleteToken(client->server, grant_token);
  }

  response = cupsJSONNew(/*parent*/NULL, /*after*/NULL, CUPS_JTYPE_OBJECT);
  cupsJSONNewString(response, cupsJSONNewKey(response, /*after*/NULL, "access_token"), access_token->token);
  cupsJSONNewString(response, cupsJSONNewKey(response, /*after*/NULL, "token_type"), "access");
  cupsJSONNewNumber(response, cupsJSONNewKey(response, /*after*/NULL, "expires_in"), client->server->max_token_life);

  data = cupsJSONExportString(response);
  cupsJSONDelete(response);

  if (!data)
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to create JSON response.");

    goto bad_request;
  }

  cupsFreeOptions(num_vars, vars);

  datalen = strlen(data);

  if (!moauthdRespondClient(client, HTTP_STATUS_OK, "application/json", NULL, 0, datalen))
  {
    free(data);
    return (false);
  }

  if (httpWrite(client->http, data, datalen) < datalen)
  {
    free(data);
    return (false);
  }

  free(data);

  return (true);

  // If we get here there was a bad request...

  // TODO: generate JSON error message body
  bad_request:

  cupsFreeOptions(num_vars, vars);

  return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));
}


//
// 'do_userinfo()' - Process a request for the /userinfo endpoint.
//

static bool				// O - `true` on success, `false` on error
do_userinfo(moauthd_client_t *client)	// I - Client
{
  bool		ret = false;		// Return value
  int		error;			// Error value
  const char	*authorization;		// Authorization header
  moauthd_token_t *token;		// Token
  struct passwd	pw,			// User info
		*pwresult = NULL;	// Matching result
  char		pwbuffer[16384];	// User info buffer
  cups_json_t	*json;			// JSON response
  char		*data;			// Form data
  size_t	datalen;		// Length of JSON data


  // Discard any POST data...
  if (httpGetState(client->http) == HTTP_STATE_POST_RECV)
    free(_moauthCopyMessageBody(client->http));

  // Get the Bearer token from the request...
  if ((authorization = httpGetField(client->http, HTTP_FIELD_AUTHORIZATION)) == NULL || strncmp(authorization, "Bearer ", 7))
    return (moauthdRespondClient(client, HTTP_STATUS_UNAUTHORIZED, NULL, NULL, 0, 0));

  authorization += 7;
  while (*authorization && isspace(*authorization & 255))
    authorization ++;

  if ((token = moauthdFindToken(client->server, authorization)) == NULL)
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Bad token in userinfo request.");

    return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));
  }

  if ((error = getpwnam_r(token->user, &pw, pwbuffer, sizeof(pwbuffer), &pwresult)) != 0)
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to lookup user '%s' information: %s", token->user, strerror(error));
    return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));
  }
  else if (!pwresult)
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to lookup user '%s' information: NULL result", token->user);
    return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));
  }

  // Return
  json = cupsJSONNew(/*parent*/NULL, /*after*/NULL, CUPS_JTYPE_OBJECT);
  cupsJSONNewString(json, cupsJSONNewKey(json, /*after*/NULL, "sub"), token->user);
  cupsJSONNewString(json, cupsJSONNewKey(json, /*after*/NULL, "name"), pwresult->pw_gecos);

  data = cupsJSONExportString(json);
  cupsJSONDelete(json);

  if (!data)
  {
    moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "Unable to create JSON response.");
    return (moauthdRespondClient(client, HTTP_STATUS_BAD_REQUEST, NULL, NULL, 0, 0));
  }

  datalen = strlen(data);

  if (moauthdRespondClient(client, HTTP_STATUS_OK, "application/json", NULL, 0, datalen))
  {
    if (httpWrite(client->http, data, datalen) == datalen)
      ret = true;
  }

  free(data);

  return (ret);
}


//
// 'validate_uri()' - Validate the URI.
//
// The "uri" argument specifies the URI and must conform to STD 66.
//
// The "urischeme" argument specifies the required URI scheme.  If NULL, any
// URI scheme *except* "http" is allowed.
//

static bool				// O - `true` on success, `false` on failure
validate_uri(const char *uri,		// I - URI
             const char *urischeme)	// I - Required URI scheme or `NULL`
{
  char	scheme[32],			// Scheme name
        userpass[256],			// Username:password
        host[256],			// Hostname
        resource[256];			// Resource path
  int	port;				// Port number


  if (httpSeparateURI(HTTP_URI_CODING_ALL, uri, scheme, sizeof(scheme), userpass, sizeof(userpass), host, sizeof(host), &port, resource, sizeof(resource)) < HTTP_URI_STATUS_OK)
    return (false);
  else if (urischeme)
    return (!strcmp(scheme, urischeme));
  else
    return (strcmp(scheme, "http") != 0);
}
