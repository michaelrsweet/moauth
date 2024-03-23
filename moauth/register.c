//
// Dynamic client registration support for moauth library.
//
// Copyright © 2019-2024 by Michael R Sweet
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//

#include <config.h>
#include "moauth-private.h"
#include <errno.h>


//
// 'moauthRegisterClient()' - Register a client application.
//

char *					// O - client_id string
moauthRegisterClient(
    moauth_t   *server,			// I - OAuth server
    const char *redirect_uri,		// I - Redirection URL
    const char *client_name,		// I - Client name or `NULL`
    const char *client_uri,		// I - Client information URL or `NULL`
    const char *logo_uri,		// I - Logo URL or `NULL`
    const char *tos_uri,		// I - Terms-of-service URL or `NULL`
    char       *client_id,		// I - client_id buffer
    size_t     client_id_size)		// I - Size of client_id buffer
{
  http_t	*http = NULL;		// HTTP connection
  char		resource[256];		// Registration endpoint resource
  http_status_t	status;			// Response status
  char		*json_data = NULL;	// JSON data
  size_t	json_length;		// Length of JSON data
  size_t	num_json = 0;		// Number of JSON variables
  cups_option_t	*json = NULL;		// JSON variables
  char		temp[1024];		// Temporary string
  const char	*value;			// JSON value


  // Range check input...
  if (client_id)
    *client_id = '\0';

  if (!server || !redirect_uri || !client_id || client_id_size < 32)
  {
    if (server)
      snprintf(server->error, sizeof(server->error), "Bad arguments to function.");

    return (NULL);
  }

  if (!server->registration_endpoint)
  {
    snprintf(server->error, sizeof(server->error), "Introspection not supported.");
    return (NULL);
  }

  // Prepare JSON data to register the client application...
  snprintf(temp, sizeof(temp), "[\"%s\"]", redirect_uri);
  num_json = cupsAddOption("redirect_uris", temp, num_json, &json);
  if (client_name)
    num_json = cupsAddOption("client_name", client_name, num_json, &json);
  if (client_uri)
    num_json = cupsAddOption("client_uri", client_uri, num_json, &json);
  if (logo_uri)
    num_json = cupsAddOption("logo_uri", logo_uri, num_json, &json);
  if (tos_uri)
    num_json = cupsAddOption("tos_uri", tos_uri, num_json, &json);

  json_data = _moauthJSONEncode(num_json, json);

  cupsFreeOptions(num_json, json);

  num_json = 0;
  json     = NULL;

  if (!json_data)
  {
    snprintf(server->error, sizeof(server->error), "Unable to encode JSON request: %s", strerror(errno));

    return (NULL);
  }

  json_length = strlen(json_data);

  // Send a POST request with the JSON data...
  if ((http = _moauthConnect(server->registration_endpoint, resource, sizeof(resource))) == NULL)
  {
    snprintf(server->error, sizeof(server->error), "Connection to registration endpoint failed: %s", cupsGetErrorString());
    goto done;
  }

  httpClearFields(http);
  httpSetField(http, HTTP_FIELD_CONTENT_TYPE, "text/json");
  httpSetLength(http, json_length);

  if (!httpWriteRequest(http, "POST", resource))
  {
    if (httpReconnect(http, 30000, NULL))
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

  if (httpWrite(http, json_data, json_length) < json_length)
  {
    snprintf(server->error, sizeof(server->error), "Write failed: %s", cupsGetErrorString());
    goto done;
  }

  free(json_data);
  json_data = NULL;

  while ((status = httpUpdate(http)) == HTTP_STATUS_CONTINUE);

  json_data = _moauthCopyMessageBody(http);
  num_json  = _moauthJSONDecode(json_data, &json);

  if ((value = cupsGetOption("client_id", num_json, json)) != NULL)
  {
    strncpy(client_id, value, client_id_size - 1);
    client_id[client_id_size - 1] = '\0';
  }
  else if ((value = cupsGetOption("error_description", num_json, json)) != NULL)
  {
    snprintf(server->error, sizeof(server->error), "Unable to register client: %s", value);
  }
  else if ((value = cupsGetOption("error", num_json, json)) != NULL)
  {
    snprintf(server->error, sizeof(server->error), "Unable to register client: %s", value);
  }
  else
  {
    snprintf(server->error, sizeof(server->error), "Unable to register client: POST status %d", status);
  }

  // Return whatever we got...
  done:

  httpClose(http);

  cupsFreeOptions(num_json, json);
  if (json_data)
    free(json_data);

  return (*client_id ? client_id : NULL);
}
