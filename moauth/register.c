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
#include <cups/json.h>


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
  cups_json_t	*json,			// JSON variables
		*jarray;		// JSON array
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
  json = cupsJSONNew(/*parent*/NULL, /*after*/NULL, CUPS_JTYPE_OBJECT);
  cupsJSONNewString(json, cupsJSONNewKey(json, /*after*/NULL, "client_name"), client_name);
  cupsJSONNewString(json, cupsJSONNewKey(json, /*after*/NULL, "client_uri"), client_uri);
  cupsJSONNewString(json, cupsJSONNewKey(json, /*after*/NULL, "logo_uri"), logo_uri);
  jarray = cupsJSONNew(json, cupsJSONNewKey(json, /*after*/NULL, "redirect_uris"), CUPS_JTYPE_ARRAY);
  cupsJSONNewString(jarray, /*after*/NULL, redirect_uri);
  cupsJSONNewString(json, cupsJSONNewKey(json, /*after*/NULL, "tos_uri"), tos_uri);

  json_data = cupsJSONExportString(json);
  cupsJSONDelete(json);
  json = NULL;

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
  json      = cupsJSONImportString(json_data);

  if ((value = cupsJSONGetString(cupsJSONFind(json, "client_id"))) != NULL)
  {
    cupsCopyString(client_id, value, client_id_size);
  }
  else if ((value = cupsJSONGetString(cupsJSONFind(json, "error_description"))) != NULL)
  {
    snprintf(server->error, sizeof(server->error), "Unable to register client: %s", value);
  }
  else if ((value = cupsJSONGetString(cupsJSONFind(json, "error"))) != NULL)
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

  cupsJSONDelete(json);
  free(json_data);

  return (*client_id ? client_id : NULL);
}
