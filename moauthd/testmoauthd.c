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
#include <sys/poll.h>
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
 * Local globals...
 */

static int	stop_tests = 0;


/*
 * Local functions...
 */

static int	open_auth_url(void);
static void	*redirect_server(_moauth_redirect_t *data);
static int	respond_client(http_t *http, http_status_t code, const char *message);
static void	sig_handler(int sig);
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
  * Catch signals...
  */

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

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

  for (timeout = 300; timeout > 0 && !stop_tests; timeout --)
  {
    if (redirect_data.grant)
      break;
    else
      sleep(1);
  }

  if (timeout == 0)
  {
   /*
    * No redirect within 5 minutes, treat as a failure.
    */

    pthread_cancel(redirect_tid);
  }

  pthread_join(redirect_tid, NULL);

 /*
  * Stop the test server...
  */

  kill(moauthd_pid, SIGTERM);

  if (redirect_data.grant)
  {
    fprintf(stderr, "Authorization grant code is \"%s\".\n", redirect_data.grant);
  }
  else if  (!stop_tests)
  {
    fputs("No authorization response within 5 minutes, failing.\n", stderr);
    status = 1;
  }

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
  http_addrlist_t *addrlist,		/* List of listener addresses */
		*addr;			/* Current address */
  int		i,			/* Looping var */
		num_listeners = 0;	/* Number of listener sockets */
  struct pollfd	listeners[4],		/* Listener sockets */
		*lis;			/* Pointer to polling data */


 /*
  * Create listener sockets for localhost on port 10000...
  */

  addrlist = httpAddrGetList("localhost", AF_UNSPEC, "10000");
  for (addr = addrlist; addr && num_listeners < (int)(sizeof(listeners) / sizeof(listeners[0])); addr = addr->next)
  {
    int			sock = httpAddrListen(&(addr->addr), 10000);
					/* Listener socket */

    if (sock < 0)
    {
      char temp[256];			/* Address string */

      fprintf(stderr, "testmoauthd: Unable to listen to \"%s:10000\": %s\n", httpAddrString(&(addr->addr), temp, sizeof(temp)), strerror(errno));
      continue;
    }

    lis = listeners + num_listeners;

    num_listeners ++;

    lis->fd     = sock;
    lis->events = POLLIN | POLLHUP | POLLERR;
  }

  httpAddrFreeList(addrlist);

  cupsSetServerCredentials(NULL, "localhost", 1);

 /*
  * Listen for an incoming connection...
  */

  while (!stop_tests && !data->grant)
  {
    if (poll(listeners, num_listeners, 1000) > 0)
    {
      for (i = num_listeners, lis = listeners; i > 0; i --, lis ++)
      {
        if (lis->revents & POLLIN)
        {
          http_t	*http;		/* HTTP connection */
	  http_state_t	state;		/* HTTP state */
	  http_status_t	status;		/* HTTP status */
	  char		path_info[1024],/* Request path */
			*query_string;	/* Query string */
          int		num_vars;	/* Number of form variables */
          cups_option_t	*vars;		/* Form variables */
          const char	*grant;		/* Grant code */
	  static const char * const states[] =
	  {				/* Strings for logging HTTP method */
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

          if ((http = httpAcceptConnection(lis->fd, 1)) == NULL)
          {
            fprintf(stderr, "testmoauthd: Unable to accept client connection - %s\n", cupsLastErrorString());
            continue;
	  }

          if (httpEncryption(http, HTTP_ENCRYPTION_ALWAYS))
          {
            fprintf(stderr, "testmoauthd: Unable to encrypt client connection - %s\n", cupsLastErrorString());
            continue;
	  }

	  while ((state = httpReadRequest(http, path_info, sizeof(path_info))) == HTTP_STATE_WAITING)
	    usleep(1);

	  if (state == HTTP_STATE_ERROR)
	  {
	    if (httpError(http) == EPIPE || httpError(http) == ETIMEDOUT || httpError(http) == 0)
	      fputs("Client closed connection.\n", stderr);
	    else
	      fprintf(stderr, "Bad request line (%s).\n", strerror(httpError(http)));

            httpClose(http);
	    continue;
	  }
	  else if (state == HTTP_STATE_UNKNOWN_METHOD)
	  {
	    fputs("Bad/unknown operation.\n", stderr);
	    respond_client(http, HTTP_STATUS_BAD_REQUEST, "Bad/unknown operation.\n");
            httpClose(http);
	    continue;
	  }
	  else if (state == HTTP_STATE_UNKNOWN_VERSION)
	  {
	    fputs("Bad HTTP version.\n", stderr);
	    respond_client(http, HTTP_STATUS_BAD_REQUEST, "Bad HTTP version.\n");
	    httpClose(http);
	    continue;
	  }

	  fprintf(stderr, "%s %s\n", states[state], path_info);

	  if ((query_string = strchr(path_info, '?')) != NULL)
	  {
	   /*
	    * Chop the query string off the end...
	    */

	    *query_string++ = '\0';
	  }

	  while ((status = httpUpdate(http)) == HTTP_STATUS_CONTINUE);

	  if (status != HTTP_STATUS_OK)
	  {
	   /*
	    * Unable to get the request headers...
	    */

	    fputs("Problem getting request headers.\n", stderr);
	    respond_client(http, HTTP_STATUS_BAD_REQUEST, "Problem getting request headers.");
	    httpClose(http);
	    continue;
	  }

          num_vars = moauthFormDecode(query_string, &vars);
          grant    = cupsGetOption("code", num_vars, vars);

          if (grant)
	  {
	    data->grant = strdup(grant);
	    snprintf(path_info, sizeof(path_info), "Grant code is \"%s\".\n", grant);
	    respond_client(http, HTTP_STATUS_OK, path_info);
	  }
	  else
	    respond_client(http, HTTP_STATUS_OK, "Missing grant code.\n");

          cupsFreeOptions(num_vars, vars);
          httpClose(http);
          break;
        }
      }
    }
  }

  for (i = num_listeners, lis = listeners; i > 0; i --, lis ++)
    close(lis->fd);

  return (NULL);
}


/*
 * 'respond_client()' - Send a HTTP response.
 */

static int				/* O - 1 on success, 0 on failure */
respond_client(http_t        *http,	/* I - HTTP connection */
               http_status_t code,	/* I - HTTP status of response */
               const char    *message)	/* I - Message to show */
{
  size_t	length = strlen(message);
					/* Length of response */


  fprintf(stderr, "HTTP/1.1 %d %s\n", code, httpStatus(code));

 /*
  * Send the HTTP response header...
  */

  httpClearFields(http);

  if (code == HTTP_STATUS_METHOD_NOT_ALLOWED)
    httpSetField(http, HTTP_FIELD_ALLOW, "GET, HEAD, OPTIONS, POST");

  httpSetField(http, HTTP_FIELD_CONTENT_TYPE, "text/plain");
  httpSetLength(http, length);

  if (httpWriteResponse(http, code) < 0)
    return (0);

  if (httpWrite2(http, message, length) < 0)
    return (0);

  httpFlushWrite(http);

  return (1);
}


/*
 * 'sig_handler()' - Signal handler.
 */

static void
sig_handler(int sig)			/* I - Signal number */
{
  (void)sig;

  stop_tests = 1;
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
