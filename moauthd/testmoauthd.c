/*
 * Unit test program for moauth daemon
 *
 * Copyright © 2017-2018 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <spawn.h>
#include <pthread.h>
#include <sys/poll.h>
#include <moauth/moauth-private.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>

extern char **environ;


#ifdef __APPLE__
#  define RANDOM arc4random()
#else
#  define RANDOM random()
#endif /* __APPLE__ */


/*
 * Constants...
 */

#define REDIRECT_URI	"https://localhost:10000"


/*
 * Local types...
 */

typedef struct _moauth_redirect_s
{
  char	state[32];			/* State string */
  char	verifier[45];			/* Verifier string */
  char	*grant;				/* Grant token */
} _moauth_redirect_t;


/*
 * Local globals...
 */

static int	stop_tests = 0;


/*
 * Local functions...
 */

static char	*get_url(const char *url, const char *token, char *filename, size_t filesize);
static moauth_t	*open_auth_url(const char *url, const char *state, const char *verifier);
static void	*redirect_server(_moauth_redirect_t *data);
static int	respond_client(http_t *http, http_status_t code, const char *message);
static void	sig_handler(int sig);
static pid_t	start_moauthd(int verbosity);


/*
 * 'main()' - Main entry for unit test program.
 */

int					/* O - Exit status */
main(int  argc,				/* I - Number of command-line arguments */
     char *argv[])			/* I - Command-line arguments */
{
  int			i,		/* Looping var */
			verbosity = 0;	/* Verbosity for server */
  int			status = 0;	/* Exit status */
  pid_t			moauthd_pid;	/* moauthd Process ID */
  _moauth_redirect_t	redirect_data;	/* Redirect server data */
  pthread_t		redirect_tid;	/* Thread ID */
  int			timeout;	/* Timeout counter */
  char			host[256],	/* Hostname */
			url[1024],	/* Authentication URL */
			token[256],	/* Access token */
			refresh[256],	/* Refresh token */
			filename[256];	/* Temporary filename */
  time_t		expires;	/* Expiration date/time */
  moauth_t		*server;	/* Connection to moauthd*/
  unsigned char		data[32];	/* Data for verifier string */


 /*
  * Parse command-line arguments...
  */

  for (i = 1; i < argc; i ++)
  {
    if (!strcmp(argv[i], "-v"))
    {
      verbosity ++;
    }
    else
    {
      puts("Usage: ./testmoauthd [-v]");
      return (1);
    }
  }

 /*
  * Catch signals...
  */

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

 /*
  * Start daemon...
  */

  moauthd_pid = start_moauthd(verbosity);
  sleep(1);

 /*
  * Start redirect server thread...
  */

  for (i = 0; i < sizeof(data); i ++)
    data[i] = (unsigned char)RANDOM;
  httpEncode64_2(redirect_data.verifier, (int)sizeof(redirect_data.verifier), (char *)data, (int)sizeof(data));

  snprintf(redirect_data.state, sizeof(redirect_data.state), "%d", getpid());
  redirect_data.grant = NULL;

  if (pthread_create(&redirect_tid, NULL, (void *(*)(void *))redirect_server, &redirect_data))
  {
    perror("Unable to create redirect server thread");
    return (1);
  }

 /*
  * Start authentication process...
  */

  httpGetHostname(NULL, host, sizeof(host));

  httpAssembleURI(HTTP_URI_CODING_ALL, url, sizeof(url), "https", NULL, host, 9000 + (getuid() % 1000), "/");

  if ((server = open_auth_url(url, redirect_data.state, redirect_data.verifier)) == NULL)
  {
    status = 1;
    goto finish_up;
  }

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

  if (redirect_data.grant)
  {
    printf("PASS (grant code is \"%s\")\n", redirect_data.grant);
  }
  else if (!stop_tests)
  {
    puts("FAIL (no authorization response within 5 minutes)");
    status = 1;
  }
  else
    puts("FAIL (stopped)");

  if (stop_tests || status)
    goto finish_up;

 /*
  * Try to get an access token...
  */

  fputs("moauthGetToken: ", stdout);
  if (moauthGetToken(server, "https://localhost:10000", "testmoauthd", redirect_data.grant, redirect_data.verifier, token, sizeof(token), refresh, sizeof(refresh), &expires))
  {
    printf("PASS (access token=\"%s\", refresh token=\"%s\", expires %s)\n", token, refresh, httpGetDateString(expires));
  }
  else
  {
    puts("FAIL");
    status = 1;
    goto finish_up;
  }

 /*
  * Access a protected file using the token...
  */

  httpAssembleURI(HTTP_URI_CODING_ALL, url, sizeof(url), "https", NULL, host, 9000 + (getuid() % 1000), "/shared/shared.pdf");
  printf("GET %s: ", url);
  if (get_url(url, token, filename, sizeof(filename)))
  {
    printf("PASS (filename=\"%s\")\n", filename);
    unlink(filename);
  }
  else
  {
    printf("FAIL (%s)\n", filename);
    status = 1;
    goto finish_up;
  }

 /*
  * Stop the test server...
  */

  finish_up:

  moauthClose(server);

  kill(moauthd_pid, SIGTERM);

 /*
  * Return the test results...
  */

  return (status);
}


/*
 * 'get_url()' - Fetch a URL using the specified Bearer token.
 */

static char *				/* O - Temporary filenane or `NULL` on failure */
get_url(const char *url,		/* I - URL to fetch */
        const char *token,		/* I - Bearer token */
	char       *filename,		/* I - Filename buffer */
	size_t     filesize)		/* I - Size of filename buffer */
{
  char			scheme[32],	/* URL scheme */
			userpass[32],	/* URL username:password */
			host[256],	/* URL hostname */
			resource[256];	/* URL resource */
  int			port;		/* URL port number */
  http_encryption_t	encryption;	/* Encrypt the connection? */
  http_t		*http;		/* HTTP connection */
  http_status_t		status;		/* HTTP status */
  int			fd;		/* Temporary file */
  char			buffer[8192];	/* Copy buffer */
  ssize_t		bytes;		/* Bytes read/written */


 /*
  * Validate URL and separate it into its components...
  */

  if (httpSeparateURI(HTTP_URI_CODING_ALL, url, scheme, sizeof(scheme), userpass, sizeof(userpass), host, sizeof(host), &port, resource, sizeof(resource)) < HTTP_URI_STATUS_OK)
  {
    snprintf(filename, filesize, "Bad URL \"%s\".", url);
    return (NULL);
  }

  if (strcmp(scheme, "http") && strcmp(scheme, "https"))
  {
    snprintf(filename, filesize, "Unsupported URL scheme \"%s\".", scheme);
    return (NULL);
  }

 /*
  * Connect to the server...
  */

  if (!strcmp(scheme, "https") || port == 443)
    encryption = HTTP_ENCRYPTION_ALWAYS;
  else
    encryption = HTTP_ENCRYPTION_IF_REQUESTED;

  if ((http = httpConnect2(host, port, NULL, AF_UNSPEC, encryption, 1, 30000, NULL)) == NULL)
  {
    snprintf(filename, filesize, "Unable to connect to \"%s\" on port %d: %s", host, port, cupsLastErrorString());
    return (NULL);
  }

 /*
  * Send a GET request with the Bearer token...
  */

  httpClearFields(http);
  httpSetAuthString(http, "Bearer", token);
  httpSetField(http, HTTP_FIELD_AUTHORIZATION, httpGetAuthString(http));

  if (httpGet(http, resource))
  {
    snprintf(filename, filesize, "\"GET %s\" failed: %s", resource, cupsLastErrorString());
    httpClose(http);
    return (NULL);
  }

  while ((status = httpUpdate(http)) == HTTP_STATUS_CONTINUE);

  if (status != HTTP_STATUS_OK)
  {
    snprintf(filename, filesize, "GET returned status %d.", status);
    httpClose(http);
    return (NULL);
  }

  if ((fd = cupsTempFd(filename, (int)filesize)) < 0)
  {
    snprintf(filename, filesize, "Unable to create temporary file: %s", strerror(errno));
    httpClose(http);
    return (NULL);
  }

  while ((bytes = httpRead2(http, buffer, sizeof(buffer))) > 0)
    write(fd, buffer, (size_t)bytes);

  close(fd);

  httpClose(http);

  return (filename);
}


/*
 * 'open_auth_url()' - Open the authentication URL for the OAuth server.
 */

static moauth_t *			/* O - Server connection or @code NULL@ on failure */
open_auth_url(const char *url,		/* I - OAuth server URL */
              const char *state,	/* I - Client state string */
              const char *verifier)	/* I - Verifier string */
{
  moauth_t	*server;		/* Connection to OAuth server */


  printf("moauthConnect(\"%s\", ...): ", url);

  if ((server = moauthConnect(url)) != NULL)
  {
    puts("PASS");

    fputs("moauthAuthorize: ", stdout);

    if (!moauthAuthorize(server, "https://localhost:10000", "testmoauthd", state, verifier))
    {
      puts("FAIL (unable to open authorization page)");
      moauthClose(server);
      server = NULL;
    }
  }
  else
    puts("FAIL (unable to connect to OAuth server)");

  return (server);
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
          const char	*state_string,	/* State string */
			*grant;		/* Grant code */
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

          num_vars     = _moauthFormDecode(query_string, &vars);
          grant        = cupsGetOption("code", num_vars, vars);
          state_string = cupsGetOption("state", num_vars, vars);

          if (grant && state_string && !strcmp(state_string, data->state))
	  {
	    data->grant = strdup(grant);
	    snprintf(path_info, sizeof(path_info), "Grant code is \"%s\".\n", grant);
	    respond_client(http, HTTP_STATUS_OK, path_info);
	  }
	  else if (grant)
	    respond_client(http, HTTP_STATUS_OK, "Missing or bad state string.\n");
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
start_moauthd(int verbosity)		/* I - Verbosity */
{
  pid_t		pid = 0;		/* Process ID */
  static char * const normal_argv[] =	/* moauthd arguments (normal) */
  {
    "moauthd",
    "-c",
    "test.conf",
    NULL
  };
  static char * const verbose_argv[] =	/* moauthd arguments (verbose) */
  {
    "moauthd",
    "-vvv",
    "-c",
    "test.conf",
    NULL
  };


  chdir("..");
  if (verbosity)
    posix_spawn(&pid, "moauthd/moauthd", NULL, NULL, verbose_argv, environ);
  else
    posix_spawn(&pid, "moauthd/moauthd", NULL, NULL, normal_argv, environ);

  return (pid);
}
