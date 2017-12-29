/*
 * Authorization support for moauth library
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include <config.h>
#include "moauth.h"

#ifdef __APPLE__
#  include <CoreFoundation/CoreFoundation.h>
#  include <CoreServices/CoreServices.h>
#else
#  include <spawn.h>
extern char **environ;
#endif /* __APPLE__ */


/*
 * 'moauthAuthorize()' - Open the authorization web page for an OAuth server.
 *
 * This function returns as soon as the web page has been opened.
 */

int					/* O - 1 on success, 0 on error */
moauthAuthorize(
    const char *oauth_uri,		/* I - Authorization URI */
    const char *redirect_uri,		/* I - Redirection URI */
    const char *client_id,		/* I - Client identifier */
    const char *state)			/* I - Client state string or @code NULL@ */
{
  char	scheme[32],			/* Authorization scheme */
	userpass[256],			/* Authorization username:password (not used) */
	host[256],			/* Authorization host */
	resource[256],			/* Authorization resource */
	url[2048];			/* URL for authorization page */
  int	port;				/* Authorization port number */
  int	status = 1;			/* Return status */


 /*
  * Range check input...
  */

  if (!oauth_uri || !redirect_uri || !client_id)
    return (0);

 /*
  * Make the authorization URL using the information supplied...
  */

  if (httpSeparateURI(HTTP_URI_CODING_ALL, oauth_uri, scheme, sizeof(scheme), userpass, sizeof(userpass), host, sizeof(host), &port, resource, sizeof(resource)) < HTTP_URI_STATUS_OK)
    return (0);				/* Bad OAuth server URL */

  /* TODO: recognize common domains and override the resource to point to the right endpoint - OAuth has no standard endpoint for authorization... */

  if (httpAssembleURIf(HTTP_URI_CODING_ALL, url, sizeof(url), scheme, NULL, host, port, "%s%sresponse_type=code&client_id=%s&redirect_uri=%s%s%s", resource, strchr(resource, '?') != NULL ? "&" : "?", client_id, redirect_uri, state ? "&state=" : "", state ? state : "") < HTTP_URI_STATUS_OK)
    return (0);				/* Probably the URL is too long */

#ifdef __APPLE__
  CFURLRef cfurl = CFURLCreateWithBytes(kCFAllocatorDefault, (const UInt8 *)url, (CFIndex)strlen(url), kCFStringEncodingASCII, NULL);

  if (cfurl)
  {
    if (LSOpenCFURLRef(cfurl, NULL) != noErr)
      status = 0;			/* Couldn't open URL */

    CFRelease(cfurl);
  }
  else
    status = 0;				/* Couldn't create CFURL object */

#else
  pid_t		pid = 0;		/* Process ID */
  int		estatus;		/* Exit status */
  static char * const xdg_open_argv[] =	/* xdg-open arguments */
  {
    "xdg-open",
    NULL,
    NULL
  };

  xdg_open_argv[1] = url;

  if (posix_spawnp(&pid, "xdg-open", NULL, NULL, xdg_open_argv, environ))
    status = 0;				/* Couldn't run xdg-open */
  else if (waitpid(pid, &estatus, 0))
    status = 0;				/* Couldn't get exit status */
  else if (estatus)
    status = 0;				/* Non-zero exit status */
#endif /* __APPLE__ */

  return (status);
}
