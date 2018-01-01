/*
 * Token grant/introspection support for moauth library
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include <config.h>
#include "moauth.h"


/*
 * 'moauthGetToken()' - Get an access token from a grant from the OAuth server.
 */

char *					/* O - Access token or @code NULL@ on error */
moauthGetToken(const char *oauth_uri,	/* I - Authorization URI */
               const char *redirect_uri,/* I - Redirection URI that was used */
               const char *client_id,	/* I - Client ID that was used */
               const char *grant,	/* I - Grant code */
	       char       *token,	/* I - Access token buffer */
	       size_t     tokensize,	/* I - Size of access token buffer */
	       char       *refresh,	/* I - Refresh token buffer */
	       size_t     refreshsize,	/* I - Size of refresh token buffer */
	       time_t     *expires)	/* O - Expiration date/time, if known */
{
  http_t	*http = NULL;		/* Connection to authorization server */
  http_status_t	status;			/* Response status */
  int		num_form = 0;		/* Number of form variables */
  cups_option_t	*form = NULL;		/* Form variables */
  char		*form_data = NULL;	/* POST form data */
  size_t	form_length;		/* Length of data */
  char		*json_data = NULL;	/* JSON response data */
  int		num_json = 0;		/* Number of JSON variables */
  cups_option_t	*json = NULL;		/* JSON variables */
  const char	*value;			/* JSON value */


 /*
  * Range check input...
  */

  if (token)
    *token = '\0';

  if (refresh)
    *refresh = '\0';

  if (expires)
    *expires = 0;

  if (!oauth_uri || !redirect_uri || !client_id || !grant || !token || tokensize < 32)
    return (NULL);

 /*
  * Prepare form data to get an access token...
  */

  num_form = cupsAddOption("grant_type", "authorization_code", num_form, &form);
  num_form = cupsAddOption("code", grant, num_form, &form);
  num_form = cupsAddOption("redirect_uri", redirect_uri, num_form, &form);
  num_form = cupsAddOption("client_id", client_id, num_form, &form);

  if ((form_data = moauthFormEncode(num_form, form)) == NULL)
    goto done;

  form_length = strlen(form_data);

 /*
  * Connect to the authorization server...
  */

  if ((http = moauthConnect(oauth_uri, 30000, NULL)) == NULL)
    goto done;

 /*
  * Send a POST request with the form data...
  */

  httpSetField(http, HTTP_FIELD_CONTENT_TYPE, "application/x-www-form-urlencoded");
  httpSetLength(http, form_length);

  /* TODO: Don't use hardcoded resource path */
  if (httpPost(http, "/token"))
    goto done;

  if (httpWrite2(http, form_data, form_length) < form_length)
    goto done;

  while ((status = httpUpdate(http)) == HTTP_STATUS_CONTINUE);

  if (status == HTTP_STATUS_OK)
  {
    json_data = moauthGetPostData(http);
    num_json  = moauthJSONDecode(json_data, &json);

    if ((value = cupsGetOption("access_token", num_json, json)) != NULL)
    {
      strncpy(token, value, tokensize - 1);
      token[tokensize - 1] = '\0';
    }

    if (expires && (value = cupsGetOption("expires_in", num_json, json)) != NULL)
      *expires = time(NULL) + atoi(value);

    if (refresh && (value = cupsGetOption("refresh_token", num_json, json)) != NULL)
    {
      strncpy(refresh, value, refreshsize - 1);
      refresh[refreshsize - 1] = '\0';
    }
  }

 /*
  * Close the connection and return whatever we got...
  */

  done:

  cupsFreeOptions(num_form, form);
  if (form_data)
    free(form_data);

  cupsFreeOptions(num_json, json);
  if (json_data)
    free(json_data);

  httpClose(http);

  return (*token ? token : NULL);
}


/*
 * 'moauthRefreshToken()' - Refresh an access token from the OAuth server.
 */

char *					/* O - Access token or @code NULL@ on error */
moauthRefreshToken(
    const char *oauth_uri,		/* I - Authorization URI */
    const char *refresh,		/* I - Refresh token */
    char       *token,			/* I - Access token buffer */
    size_t     tokensize,		/* I - Size of access token buffer */
    char       *new_refresh,		/* I - Refresh token buffer */
    size_t     new_refreshsize,		/* I - Size of refresh token buffer */
    time_t     *expires)		/* O - Expiration date/time, if known */
{
  http_t	*http = NULL;		/* Connection to authorization server */
  http_status_t	status;			/* Response status */
  int		num_form = 0;		/* Number of form variables */
  cups_option_t	*form = NULL;		/* Form variables */
  char		*form_data = NULL;	/* POST form data */
  size_t	form_length;		/* Length of data */
  char		*json_data = NULL;	/* JSON response data */
  int		num_json = 0;		/* Number of JSON variables */
  cups_option_t	*json = NULL;		/* JSON variables */
  const char	*value;			/* JSON value */


 /*
  * Range check input...
  */

  if (token)
    *token = '\0';

  if (new_refresh)
    *new_refresh = '\0';

  if (expires)
    *expires = 0;

  if (!oauth_uri || !refresh || !token || tokensize < 32)
    return (NULL);

 /*
  * Prepare form data to get an access token...
  */

  num_form = cupsAddOption("grant_type", "refresh_token", num_form, &form);
  num_form = cupsAddOption("refresh_token", refresh, num_form, &form);

  if ((form_data = moauthFormEncode(num_form, form)) == NULL)
    goto done;

  form_length = strlen(form_data);

 /*
  * Connect to the authorization server...
  */

  if ((http = moauthConnect(oauth_uri, 30000, NULL)) == NULL)
    goto done;

 /*
  * Send a POST request with the form data...
  */

  httpSetField(http, HTTP_FIELD_CONTENT_TYPE, "application/x-www-form-urlencoded");
  httpSetLength(http, form_length);

  /* TODO: Don't use hardcoded resource path */
  if (httpPost(http, "/token"))
    goto done;

  if (httpWrite2(http, form_data, form_length) < form_length)
    goto done;

  while ((status = httpUpdate(http)) == HTTP_STATUS_CONTINUE);

  if (status == HTTP_STATUS_OK)
  {
    json_data = moauthGetPostData(http);
    num_json  = moauthJSONDecode(json_data, &json);

    if ((value = cupsGetOption("access_token", num_json, json)) != NULL)
    {
      strncpy(token, value, tokensize - 1);
      token[tokensize - 1] = '\0';
    }

    if (expires && (value = cupsGetOption("expires_in", num_json, json)) != NULL)
      *expires = time(NULL) + atoi(value);

    if (new_refresh && (value = cupsGetOption("refresh_token", num_json, json)) != NULL)
    {
      strncpy(new_refresh, value, new_refreshsize - 1);
      new_refresh[new_refreshsize - 1] = '\0';
    }
  }

 /*
  * Close the connection and return whatever we got...
  */

  done:

  cupsFreeOptions(num_form, form);
  if (form_data)
    free(form_data);

  cupsFreeOptions(num_json, json);
  if (json_data)
    free(json_data);

  httpClose(http);

  return (*token ? token : NULL);
}
