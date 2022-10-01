//
// Authentication support for moauth daemon
//
// Copyright © 2017-2022 by Michael R Sweet
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//

#include "moauthd.h"

#ifndef _WIN32
#  include <pwd.h>
#  include <grp.h>
#endif // !_WIN32
#ifdef HAVE_LIBPAM
#  ifdef HAVE_PAM_PAM_APPL_H
#    include <pam/pam_appl.h>
#  else
#    include <security/pam_appl.h>
#  endif // HAVE_PAM_PAM_APPL_H
#endif // HAVE_LIBPAM


//
// Authentication data...
//

typedef struct moauthd_authdata_s	// PAM authentication data
{
  const char	*username,		// Username string
		*password;		// Password string
} moauthd_authdata_t;


//
// Local functions...
//

#ifdef HAVE_LIBPAM
static int	moauthd_pam_func(int num_msg, const struct pam_message **msg, struct pam_response **resp, moauthd_authdata_t *data);
#endif // HAVE_LIBPAM


//
// 'moauthdAuthenticateUser()' - Validate a username + password combination.
//

bool					// O - `true` if correct, `false` otherwise
moauthdAuthenticateUser(
    moauthd_client_t *client,		// I - Client object
    const char       *username,		// I - Username string
    const char       *password)		// I - Password string
{
  int	status = 0;			// Return status


  (void)username;

  if (client->server->test_password)
  {
    status = !strcmp(client->server->test_password, password);

    moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "Test authentication of \"%s\" %s.", username, status ? "succeeded" : "failed");
  }

#ifdef HAVE_LIBPAM
  else
  {
    // Authenticate using PAM...
    moauthd_authdata_t	data;		// Authorization data
    pam_handle_t	*pamh;		// PAM authentication handle
    int			pamerr;		// PAM error code
    struct pam_conv	pamdata;	// PAM conversation data

    data.username = username;
    data.password = password;

    pamdata.conv        = (int (*)(int, const struct pam_message **, struct pam_response **, void *))moauthd_pam_func;
    pamdata.appdata_ptr = &data;
    pamh                = NULL;

    if ((pamerr = pam_start(client->server->auth_service, data.username, &pamdata, &pamh)) != PAM_SUCCESS)
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "pam_start() returned %d (%s)", pamerr, pam_strerror(pamh, pamerr));
    }

#  ifdef PAM_RHOST
    else if ((pamerr = pam_set_item(pamh, PAM_RHOST, client->remote_host)) != PAM_SUCCESS)
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "pam_set_item(PAM_RHOST) returned %d (%s)", pamerr, pam_strerror(pamh, pamerr));
    }
#  endif // PAM_RHOST

#  ifdef PAM_TTY
    else if ((pamerr = pam_set_item(pamh, PAM_TTY, "moauthd")) != PAM_SUCCESS)
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "pam_set_item(PAM_TTY) returned %d (%s)", pamerr, pam_strerror(pamh, pamerr));
    }
#  endif // PAM_TTY

    else if ((pamerr = pam_authenticate(pamh, PAM_SILENT)) != PAM_SUCCESS)
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "pam_authenticate() returned %d (%s)", pamerr, pam_strerror(pamh, pamerr));
    }
    else if ((pamerr = pam_setcred(pamh, PAM_ESTABLISH_CRED | PAM_SILENT)) != PAM_SUCCESS)
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "pam_setcred() returned %d (%s)", pamerr, pam_strerror(pamh, pamerr));
    }
    else if ((pamerr = pam_acct_mgmt(pamh, PAM_SILENT)) != PAM_SUCCESS)
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_ERROR, "pam_acct_mgmt() returned %d (%s)", pamerr, pam_strerror(pamh, pamerr));
    }

    if (pamh)
      pam_end(pamh, PAM_SUCCESS);

    if (pamerr == PAM_SUCCESS)
    {
      moauthdLogc(client, MOAUTHD_LOGLEVEL_INFO, "PAM authentication of \"%s\" succeeded.", username);
      status = 1;
    }
  }
#endif // HAVE_LIBPAM

  return (status);
}


#ifdef HAVE_LIBPAM
//
// 'moauthd_pam_func()' - PAM conversation function.
//

static int				// O - Success or failure
moauthd_pam_func(
    int                      num_msg,	// I - Number of messages
    const struct pam_message **msg,	// I - Messages
    struct pam_response      **resp,	// O - Responses
    moauthd_authdata_t       *data)	// I - Authentication data
{
  int			i;		// Looping var
  struct pam_response	*replies;	// Replies


  // Allocate memory for the responses...
  if ((replies = calloc((size_t)num_msg, sizeof(struct pam_response))) == NULL)
    return (PAM_CONV_ERR);

  // Answer all of the messages...
  for (i = 0; i < num_msg; i ++)
  {
    switch (msg[i]->msg_style)
    {
      case PAM_PROMPT_ECHO_ON :
          replies[i].resp_retcode = PAM_SUCCESS;
          replies[i].resp         = strdup(data->username);
          break;

      case PAM_PROMPT_ECHO_OFF :
          replies[i].resp_retcode = PAM_SUCCESS;
          replies[i].resp         = strdup(data->password);
          break;

      default :
          replies[i].resp_retcode = PAM_SUCCESS;
          replies[i].resp         = NULL;
          break;
    }
  }

  // Return the responses back to PAM...
  *resp = replies;

  return (PAM_SUCCESS);
}
#endif // HAVE_LIBPAM
