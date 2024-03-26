//
// Token grant/introspection support for moauth library
//
// Copyright © 2017-2024 by Michael R Sweet
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//

#include <config.h>
#include "moauth-private.h"
#include <cups/form.h>


//
// 'moauthGetToken()' - Get an access token from a grant from the OAuth server.
//

char *					// O - Access token or `NULL` on error
moauthGetToken(
    moauth_t   *server,			// I - Connection to OAuth server
    const char *redirect_uri,		// I - Redirection URI that was used
    const char *client_id,		// I - Client ID that was used
    const char *grant,			// I - Grant code
    const char *code_verifier,		// I - Code verifier string, if any
    char       *token,			// I - Access token buffer
    size_t     tokensize,		// I - Size of access token buffer
    char       *refresh,		// I - Refresh token buffer
    size_t     refreshsize,		// I - Size of refresh token buffer
    time_t     *expires)		// O - Expiration date/time, if known
{
  http_t	*http = NULL;		// HTTP connection
  char		resource[256];		// Token endpoint resource
  http_status_t	status;			// Response status
  size_t	num_form = 0;		// Number of form variables
  cups_option_t	*form = NULL;		// Form variables
  char		*form_data = NULL;	// POST form data
  size_t	form_length;		// Length of data
  char		*json_data = NULL;	// JSON response data
  cups_json_t	*json = NULL;		// JSON variables
  const char	*value;			// JSON value


  // Range check input...
  if (token)
    *token = '\0';

  if (refresh)
    *refresh = '\0';

  if (expires)
    *expires = 0;

  if (!server || !redirect_uri || !client_id || !grant || !token || tokensize < 32)
  {
    if (server)
      snprintf(server->error, sizeof(server->error), "Bad arguments to function.");

    return (NULL);
  }

  if (!server->token_endpoint)
  {
    snprintf(server->error, sizeof(server->error), "Authorization not supported.");
    return (0);
  }

  // Prepare form data to get an access token...
  num_form = cupsAddOption("grant_type", "authorization_code", num_form, &form);
  num_form = cupsAddOption("code", grant, num_form, &form);
  num_form = cupsAddOption("redirect_uri", redirect_uri, num_form, &form);
  num_form = cupsAddOption("client_id", client_id, num_form, &form);

  if (code_verifier)
    num_form = cupsAddOption("code_verifier", code_verifier, num_form, &form);

  if ((form_data = cupsFormEncode(/*url*/NULL, num_form, form)) == NULL)
  {
    snprintf(server->error, sizeof(server->error), "Unable to encode form data.");
    goto done;
  }

  form_length = strlen(form_data);

  // Send a POST request with the form data...
  if ((http = _moauthConnect(server->token_endpoint, resource, sizeof(resource))) == NULL)
  {
    snprintf(server->error, sizeof(server->error), "Connection to token endpoint failed: %s", cupsGetErrorString());
    goto done;
  }

  httpClearFields(http);
  httpSetField(http, HTTP_FIELD_CONTENT_TYPE, "application/x-www-form-urlencoded");
  httpSetLength(http, form_length);

  if (!httpWriteRequest(http, "POST", resource))
  {
    if (!httpReconnect(http, 30000, NULL))
    {
      snprintf(server->error, sizeof(server->error), "Reconnect failed: %s", cupsGetErrorString());
      goto done;
    }

    if (!httpWriteRequest(http, "POST", resource))
    {
      snprintf(server->error, sizeof(server->error), "POST failed: %s", cupsGetErrorString());
      goto done;
    }
  }

  if (httpWrite(http, form_data, form_length) < form_length)
  {
    snprintf(server->error, sizeof(server->error), "Write failed: %s", cupsGetErrorString());
    goto done;
  }

  while ((status = httpUpdate(http)) == HTTP_STATUS_CONTINUE);

  if (status == HTTP_STATUS_OK)
  {
    double	expires_in;		// expires_in value

    json_data = _moauthCopyMessageBody(http);
    json      = cupsJSONImportString(json_data);

    if ((value = cupsJSONGetString(cupsJSONFind(json, "access_token"))) != NULL)
      cupsCopyString(token, value, tokensize);

    if (expires && (expires_in = cupsJSONGetNumber(cupsJSONFind(json, "expires_in"))) > 0.0)
      *expires = time(NULL) + (long)expires_in;

    if (refresh && (value = cupsJSONGetString(cupsJSONFind(json, "refresh_token"))) != NULL)
      cupsCopyString(refresh, value, refreshsize);

    cupsJSONDelete(json);
    free(json_data);
  }
  else
  {
    snprintf(server->error, sizeof(server->error), "Unable to get access token: POST status %d", status);
  }

  // Return whatever we got...
  done:

  httpClose(http);

  cupsFreeOptions(num_form, form);
  free(form_data);

  return (*token ? token : NULL);
}


//
// 'moauthIntrospectToken()' - Get information about an access token.
//

bool					// O - `true` if the token is active, `false` otherwise
moauthIntrospectToken(
    moauth_t   *server,			// I - Connection to OAuth server
    const char *token,			// I - Access token
    char       *username,		// I - Username buffer
    size_t     username_size,		// I - Size of username string
    char       *scope,			// I - Scope buffer
    size_t     scope_size,		// I - Size of scope string
    time_t     *expires)		// O - Expiration date
{
  http_t	*http = NULL;		// HTTP connection
  char		resource[256];		// Token endpoint resource
  http_status_t	status;			// Response status
  size_t	num_form = 0;		// Number of form variables
  cups_option_t	*form = NULL;		// Form variables
  char		*form_data = NULL;	// POST form data
  size_t	form_length;		// Length of data
  char		*json_data = NULL;	// JSON response data
  cups_json_t	*json;			// JSON variables
  const char	*value;			// JSON value
  bool		active = false;		// Is the token active?


  // Range check input...
  if (username)
    *username = '\0';

  if (scope)
    *scope = '\0';

  if (expires)
    *expires = 0;

  if (!server || !token)
  {
    if (server)
      snprintf(server->error, sizeof(server->error), "Bad arguments to function.");

    return (false);
  }

  if (!server->introspection_endpoint)
  {
    snprintf(server->error, sizeof(server->error), "Introspection not supported.");
    return (false);
  }

  // Prepare form data to get an access token...
  num_form = cupsAddOption("token", token, num_form, &form);

  if ((form_data = cupsFormEncode(/*url*/NULL, num_form, form)) == NULL)
  {
    snprintf(server->error, sizeof(server->error), "Unable to encode form data.");
    goto done;
  }

  form_length = strlen(form_data);

  // Send a POST request with the form data...
  if ((http = _moauthConnect(server->introspection_endpoint, resource, sizeof(resource))) == NULL)
  {
    snprintf(server->error, sizeof(server->error), "Connection to introspection endpoint failed: %s", cupsGetErrorString());
    goto done;
  }

  httpClearFields(http);
  httpSetField(http, HTTP_FIELD_CONTENT_TYPE, "application/x-www-form-urlencoded");
  httpSetLength(http, form_length);

  if (!httpWriteRequest(http, "POST", resource))
  {
    if (!httpReconnect(http, 30000, NULL))
    {
      snprintf(server->error, sizeof(server->error), "Reconnect failed: %s", cupsGetErrorString());
      goto done;
    }

    if (!httpWriteRequest(http, "POST", resource))
    {
      snprintf(server->error, sizeof(server->error), "POST failed: %s", cupsGetErrorString());
      goto done;
    }
  }

  if (httpWrite(http, form_data, form_length) < form_length)
  {
    snprintf(server->error, sizeof(server->error), "Write failed: %s", cupsGetErrorString());
    goto done;
  }

  while ((status = httpUpdate(http)) == HTTP_STATUS_CONTINUE);

  if (status == HTTP_STATUS_OK)
  {
    json_data = _moauthCopyMessageBody(http);
    json      = cupsJSONImportString(json_data);

    active = cupsJSONGetType(cupsJSONFind(json, "active")) == CUPS_JTYPE_TRUE;

    if (username && (value = cupsJSONGetString(cupsJSONFind(json, "username"))) != NULL)
      cupsCopyString(username, value, username_size);

    if (scope && (value = cupsJSONGetString(cupsJSONFind(json, "scope"))) != NULL)
      cupsCopyString(scope, value, scope_size);

    if (expires)
      *expires = (long)cupsJSONGetNumber(cupsJSONFind(json, "exp"));

    cupsJSONDelete(json);
    free(json_data);
  }
  else
  {
    snprintf(server->error, sizeof(server->error), "Unable to introspect access token: POST status %d", status);
  }

  // Return whatever we got...
  done:

  httpClose(http);

  cupsFreeOptions(num_form, form);
  free(form_data);

  return (active);
}


//
// 'moauthPasswordToken()' - Get an access token using a username and password
//                           (if supported by the OAuth server)
//

char *					// O - Access token or `NULL` on error
moauthPasswordToken(
    moauth_t   *server,			// I - Connection to OAuth server
    const char *username,		// I - Username string
    const char *password,		// I - Password string
    const char *scope,			// I - Scope to request or `NULL`
    char       *token,			// I - Access token buffer
    size_t     tokensize,		// I - Size of access token buffer
    char       *refresh,		// I - Refresh token buffer
    size_t     refreshsize,		// I - Size of refresh token buffer
    time_t     *expires)		// O - Expiration date/time, if known
{
  http_t	*http = NULL;		// HTTP connection
  char		resource[256];		// Token endpoint resource
  http_status_t	status;			// Response status
  size_t	num_form = 0;		// Number of form variables
  cups_option_t	*form = NULL;		// Form variables
  char		*form_data = NULL;	// POST form data
  size_t	form_length;		// Length of data
  char		*json_data = NULL;	// JSON response data
  cups_json_t	*json;			// JSON variables
  const char	*value;			// JSON value


  // Range check input...
  if (token)
    *token = '\0';

  if (refresh)
    *refresh = '\0';

  if (expires)
    *expires = 0;

  if (!server || !username || !password || !token || tokensize < 32)
  {
    if (server)
      snprintf(server->error, sizeof(server->error), "Bad arguments to function.");

    return (NULL);
  }

  if (!server->token_endpoint)
  {
    snprintf(server->error, sizeof(server->error), "Authorization not supported.");
    return (0);
  }

  // Prepare form data to get an access token...
  num_form = cupsAddOption("grant_type", "password", num_form, &form);
  num_form = cupsAddOption("username", username, num_form, &form);
  num_form = cupsAddOption("password", password, num_form, &form);
  if (scope)
    num_form = cupsAddOption("scope", scope, num_form, &form);

  if ((form_data = cupsFormEncode(/*url*/NULL, num_form, form)) == NULL)
  {
    snprintf(server->error, sizeof(server->error), "Unable to encode form data.");
    goto done;
  }

  form_length = strlen(form_data);

  // Send a POST request with the form data...
  if ((http = _moauthConnect(server->token_endpoint, resource, sizeof(resource))) == NULL)
  {
    snprintf(server->error, sizeof(server->error), "Connection to token endpoint failed: %s", cupsGetErrorString());
    goto done;
  }

  httpClearFields(http);
  httpSetField(http, HTTP_FIELD_CONTENT_TYPE, "application/x-www-form-urlencoded");
  httpSetLength(http, form_length);

  if (!httpWriteRequest(http, "POST", resource))
  {
    if (!httpReconnect(http, 30000, NULL))
    {
      snprintf(server->error, sizeof(server->error), "Reconnect failed: %s", cupsGetErrorString());
      goto done;
    }

    if (!httpWriteRequest(http, "POST", resource))
    {
      snprintf(server->error, sizeof(server->error), "POST failed: %s", cupsGetErrorString());
      goto done;
    }
  }

  if (httpWrite(http, form_data, form_length) < form_length)
  {
    snprintf(server->error, sizeof(server->error), "Write failed: %s", cupsGetErrorString());
    goto done;
  }

  while ((status = httpUpdate(http)) == HTTP_STATUS_CONTINUE);

  if (status == HTTP_STATUS_OK)
  {
    json_data = _moauthCopyMessageBody(http);
    json      = cupsJSONImportString(json_data);

    if ((value = cupsJSONGetString(cupsJSONFind(json, "access_token"))) != NULL)
      cupsCopyString(token, value, tokensize);

    if (expires)
      *expires = time(NULL) + (long)cupsJSONGetNumber(cupsJSONFind(json, "expires_in"));

    if (refresh && (value = cupsJSONGetString(cupsJSONFind(json, "refresh_token"))) != NULL)
      cupsCopyString(refresh, value, refreshsize);

    cupsJSONDelete(json);
    free(json_data);
  }
  else
  {
    snprintf(server->error, sizeof(server->error), "Unable to get access token - POST status %d", status);
  }

  // Return whatever we got...
  done:

  httpClose(http);

  cupsFreeOptions(num_form, form);
  free(form_data);

  return (*token ? token : NULL);
}


//
// 'moauthRefreshToken()' - Refresh an access token from the OAuth server.
//

char *					// O - Access token or `NULL` on error
moauthRefreshToken(
    moauth_t   *server,			// I - Connection to OAuth server
    const char *refresh,		// I - Refresh token
    char       *token,			// I - Access token buffer
    size_t     tokensize,		// I - Size of access token buffer
    char       *new_refresh,		// I - Refresh token buffer
    size_t     new_refreshsize,		// I - Size of refresh token buffer
    time_t     *expires)		// O - Expiration date/time, if known
{
  http_t	*http = NULL;		// HTTP connection
  char		resource[256];		// Token endpoint resource
  http_status_t	status;			// Response status
  size_t	num_form = 0;		// Number of form variables
  cups_option_t	*form = NULL;		// Form variables
  char		*form_data = NULL;	// POST form data
  size_t	form_length;		// Length of data
  char		*json_data = NULL;	// JSON response data
  cups_json_t	*json;			// JSON variables
  const char	*value;			// JSON value


  // Range check input...
  if (token)
    *token = '\0';

  if (new_refresh)
    *new_refresh = '\0';

  if (expires)
    *expires = 0;

  if (!server || !refresh || !token || tokensize < 32)
  {
    if (server)
      snprintf(server->error, sizeof(server->error), "Bad arguments to function.");

    return (NULL);
  }

  if (!server->token_endpoint)
  {
    snprintf(server->error, sizeof(server->error), "Authorization not supported.");
    return (NULL);
  }

  // Prepare form data to get an access token...
  num_form = cupsAddOption("grant_type", "refresh_token", num_form, &form);
  num_form = cupsAddOption("refresh_token", refresh, num_form, &form);

  if ((form_data = cupsFormEncode(/*url*/NULL, num_form, form)) == NULL)
  {
    snprintf(server->error, sizeof(server->error), "Unable to encode form data.");
    goto done;
  }

  form_length = strlen(form_data);

  // Send a POST request with the form data...
  if ((http = _moauthConnect(server->token_endpoint, resource, sizeof(resource))) == NULL)
  {
    snprintf(server->error, sizeof(server->error), "Connection to token endpoint failed: %s", cupsGetErrorString());
    goto done;
  }

  httpClearFields(http);
  httpSetField(http, HTTP_FIELD_CONTENT_TYPE, "application/x-www-form-urlencoded");
  httpSetLength(http, form_length);

  if (!httpWriteRequest(http, "POST", resource))
  {
    if (!httpReconnect(http, 30000, NULL))
    {
      snprintf(server->error, sizeof(server->error), "Reconnect to token endpoint failed: %s", cupsGetErrorString());
      goto done;
    }

    if (!httpWriteRequest(http, "POST", resource))
    {
      snprintf(server->error, sizeof(server->error), "POST failed: %s", cupsGetErrorString());
      goto done;
    }
  }

  if (httpWrite(http, form_data, form_length) < form_length)
  {
    snprintf(server->error, sizeof(server->error), "Write failed: %s", cupsGetErrorString());
    goto done;
  }

  while ((status = httpUpdate(http)) == HTTP_STATUS_CONTINUE);

  if (status == HTTP_STATUS_OK)
  {
    json_data = _moauthCopyMessageBody(http);
    json      = cupsJSONImportString(json_data);

    if ((value = cupsJSONGetString(cupsJSONFind(json, "access_token"))) != NULL)
      cupsCopyString(token, value, tokensize);

    if (expires)
      *expires = time(NULL) + (long)cupsJSONGetNumber(cupsJSONFind(json, "expires_in"));

    if (new_refresh && (value = cupsJSONGetString(cupsJSONFind(json, "refresh_token"))) != NULL)
      cupsCopyString(new_refresh, value, new_refreshsize);

    cupsJSONDelete(json);
    free(json_data);
  }
  else
  {
    snprintf(server->error, sizeof(server->error), "Unable to get access token: POST status %d", status);
  }

  // Close the connection and return whatever we got...
  done:

  httpClose(http);

  cupsFreeOptions(num_form, form);
  free(form_data);

  return (*token ? token : NULL);
}
