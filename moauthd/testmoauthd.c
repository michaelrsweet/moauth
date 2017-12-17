/*
 * Unit test program for moauth daemon
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <spawn.h>
#include <pthread.h>
#include <moauth/moauth.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>


/*
 * Constants...
 */

#define REDIRECT_URI	"https://localhost:10000"


/*
 * Local types...
 */

typedef struct _moauth_redirect_s
{
  char	*grant;				/* Grant token */
} _moauth_redirect_t;


/*
 * Local functions...
 */

static int	open_auth_url(void);
static void	*redirect_server(_moauth_redirect_t *data);
static pid_t	start_moauthd(void);


/*
 * 'main()' - Main entry for unit test program.
 */

int					/* O - Exit status */
main(void)
{
  int			status = 0;	/* Exit status */
  pid_t			moauthd_pid;	/* moauthd Process ID */
  _moauth_redirect_t	redirect_data;	/* Redirect server data */
  pthread_t		redirect_tid;	/* Thread ID */
  int			timeout;	/* Timeout counter */


 /*
  * Start daemon...
  */

  moauthd_pid = start_moauthd();
  sleep(1);

 /*
  * Start redirect server thread...
  */

  redirect_data.grant = NULL;

  if (pthread_create(&redirect_tid, NULL, (void *(*)(void *))redirect_server, &redirect_data))
  {
    perror("Unable to create redirect server thread");
    return (1);
  }

 /*
  * Start authentication process...
  */

  open_auth_url();

 /*
  * Wait up to 5 minutes for the response...
  */

  for (timeout = 300; timeout > 0; timeout --)
  {
    if (redirect_data.grant)
      break;
    else
      sleep(1);
  }

  pthread_join(redirect_tid, NULL);

 /*
  * Return the test results...
  */

  return (status);
}


/*
 * 'open_auth_url()' - Open the authentication URL for the OAuth server.
 */

static int				/* O - 1 on success, 0 on failure */
open_auth_url(void)
{
  char	host[256],			/* Hostname */
	authenticate_url[1024];		/* Authentication URL */
  int	status = 1;			/* Status */


  httpGetHostname(NULL, host, sizeof(host));

  snprintf(authenticate_url, sizeof(authenticate_url), "https://%s:%d/authorize?response_type=code&client_id=testmoauthd&redirect_uri=https://localhost:10000/&state=%d", host, 9000 + (getuid() % 1000), getpid());

#ifdef __APPLE__
  CFURLRef cfauthenticate_url = CFURLCreateWithBytes(kCFAllocatorDefault, (const UInt8 *)authenticate_url, (CFIndex)strlen(authenticate_url), kCFStringEncodingASCII, NULL);
  if (cfauthenticate_url)
  {
    if (LSOpenCFURLRef(cfauthenticate_url, NULL) != noErr)
    {
      fprintf(stderr, "testmoauthd: Unable to open authentication URL \"%s\".\n", authenticate_url);
      status = 0;
    }

    CFRelease(cfauthenticate_url);
  }
  else
  {
    fprintf(stderr, "testmoauthd: Unable to create authentication URL \"%s\".\n", authenticate_url);
    status = 0;
  }
#endif /* __APPLE__ */

  return (status);
}


/*
 * 'redirect_server()' - Run a short-lived HTTPS server that accepts the
 *                       redirection from the OAuth authorization request.
 */

static void *				/* O - Exit status */
redirect_server(
    _moauth_redirect_t *data)		/* I - Server data */
{
  data->grant = strdup("test");

  return (NULL);
}


/*
 * 'start_moauthd()' - Start moauthd with the test config file.
 */

static pid_t				/* O - Process ID */
start_moauthd(void)
{
  pid_t		pid = 0;		/* Process ID */
  static char * const moauthd_argv[] =	/* moauthd arguments */
  {
    "moauthd",
    "-c",
    "test.conf",
    NULL
  };


  chdir("..");
  posix_spawn(&pid, "moauthd/moauthd", NULL, NULL, moauthd_argv, NULL);

  return (pid);
}
