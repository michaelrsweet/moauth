/*
 * Server support for moauth daemon
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include "moauthd.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include "moauth-png.h"
#include "style-css.h"


/*
 * Local functions...
 */

static int	compare_applications(moauthd_application_t *a, moauthd_application_t *b);
static moauthd_application_t *copy_application(moauthd_application_t *a);
static void	free_application(moauthd_application_t *a);
static int	get_seconds(const char *value);


/*
 * 'moauthdCreateServer()' - Create a new server object and load the specified config file.
 */

moauthd_server_t *			/* O - New server object */
moauthdCreateServer(
    const char *configfile,		/* I - Configuration file to load */
    int        verbosity)		/* I - Extra verbosity from command-line */
{
  moauthd_server_t *server;		/* Server object */
  cups_file_t	*fp = NULL;		/* Opened config file */
  char		server_name[256],	/* Server name */
		server_ports[8],	/* Listening port (string) */
		*ptr;			/* Pointer into server name */
  int		server_port = 9000 + (getuid() % 1000);
					/* Listening port (number) */
  http_addrlist_t *addrlist,		/* List of listener addresses */
		*addr;			/* Current address */
  char		temp[1024];		/* Temporary filename */
  struct stat	tempinfo;		/* Temporary information */


 /*
  * Open the configuration file if one is specified...
  */

  if (configfile && (fp = cupsFileOpen(configfile, "r")) == NULL)
  {
    fprintf(stderr, "moauthd: Unable to open configuration file \"%s\": %s\n", configfile, strerror(errno));
    return (NULL);
  }

 /*
  * Allocate a server object and initialize with defaults...
  */

  server = calloc(1, sizeof(moauthd_server_t));

  server->log_file       = 2;		/* stderr */
  server->log_level      = MOAUTHD_LOGLEVEL_ERROR;
  server->max_grant_life = 300;		/* 5 minutes */
  server->max_token_life = 604800;	/* 1 week */

  httpGetHostname(NULL, server_name, sizeof(server_name));
  ptr = server_name + strlen(server_name) - 1;
  if (ptr > server_name && *ptr == '.')
    *ptr = '\0';			/* Strip trailing "." from hostname */

  if (fp)
  {
   /*
    * Load configuration from file...
    */

    char	line[2048],		/* Line from config file */
		*value;			/* Value from config file */
    int		linenum = 0;		/* Current line number */

    while (cupsFileGetConf(fp, line, sizeof(line), &value, &linenum))
    {
      if (!strcasecmp(line, "Application"))
      {
       /*
        * Application client-id redirect-uri
        */

        moauthd_application_t temp;	/* New application object */

        if (!value)
        {
          fprintf(stderr, "moauthd: Missing client ID and redirect URI on line %d of \"%s\".\n", linenum, configfile);
          goto create_failed;
        }

        temp.client_id    = strtok(value, " \t");
        temp.redirect_uri = strtok(NULL, " \t");

        if (!temp.client_id || !*temp.client_id || !temp.redirect_uri || !*temp.redirect_uri)
        {
          fprintf(stderr, "moauthd: Missing client ID and redirect URI on line %d of \"%s\".\n", linenum, configfile);
          goto create_failed;
        }

        if (!server->applications)
          server->applications = cupsArrayNew3((cups_array_func_t)compare_applications, NULL, NULL, 0, (cups_acopy_func_t)copy_application, (cups_afree_func_t)free_application);

        cupsArrayAdd(server->applications, &temp);
      }
      else if (!strcasecmp(line, "LogFile"))
      {
       /*
        * LogFile {filename,none,stderr,syslog}
        */

        if (!value || !strcasecmp(value, "stderr"))
        {
          server->log_file = 2;
	}
	else if (!strcmp(value, "none"))
	{
	  server->log_file = -1;
	}
	else if (!strcasecmp(value, "syslog"))
	{
	  server->log_file = 0;
	  openlog("moauthd", LOG_CONS, LOG_AUTH);
	}
	else if ((server->log_file = open(value, O_WRONLY | O_CREAT | O_APPEND | O_EXCL, 0600)) < 0)
	{
	  fprintf(stderr, "moauthd: Unable to open log file \"%s\" on line %d of \"%s\": %s\n", value, linenum, configfile, strerror(errno));
	  goto create_failed;
	}
      }
      else if (!strcasecmp(line, "LogLevel"))
      {
       /*
        * LogLevel {error,info,debug}
        */

        if (!value)
        {
          fprintf(stderr, "moauthd: Missing log level on line %d of \"%s\".\n", linenum, configfile);
          goto create_failed;
	}
	else if (!strcasecmp(value, "error"))
	  server->log_level = MOAUTHD_LOGLEVEL_ERROR;
	else if (!strcasecmp(value, "info"))
	  server->log_level = MOAUTHD_LOGLEVEL_INFO;
	else if (!strcasecmp(value, "debug"))
	  server->log_level = MOAUTHD_LOGLEVEL_DEBUG;
	else
	{
	  fprintf(stderr, "moauthd: Unknown LogLevel \"%s\" on line %d of \"%s\" ignored.\n", value, linenum, configfile);
	}
      }
      else if (!strcasecmp(line, "MaxGrantLife"))
      {
       /*
        * MaxGrantLife NNN{m,h,d,w}
        *
        * Default units are seconds.  "m" is minutes, "h" is hours, "d" is days,
        * and "w" is weeks.
        */

        int	max_grant_life;		/* Maximum grant life value */

        if (!value)
        {
          fprintf(stderr, "moauthd: Missing time value on line %d of \"%s\".\n", linenum, configfile);
          goto create_failed;
	}

        if ((max_grant_life = get_seconds(value)) < 0)
	{
          fprintf(stderr, "moauthd: Unknown time value \"%s\" on line %d of \"%s\".\n", value, linenum, configfile);
          goto create_failed;
	}

        server->max_grant_life = max_grant_life;
      }
      else if (!strcasecmp(line, "MaxTokenLife"))
      {
       /*
        * MaxTokenLife NNN{m,h,d,w}
        *
        * Default units are seconds.  "m" is minutes, "h" is hours, "d" is days,
        * and "w" is weeks.
        */

        int	max_token_life;		/* Maximum token life value */

        if (!value)
        {
          fprintf(stderr, "moauthd: Missing time value on line %d of \"%s\".\n", linenum, configfile);
          goto create_failed;
	}

        if ((max_token_life = get_seconds(value)) < 0)
	{
          fprintf(stderr, "moauthd: Unknown time value \"%s\" on line %d of \"%s\".\n", value, linenum, configfile);
          goto create_failed;
	}

        server->max_token_life = max_token_life;
      }
      else if (!strcasecmp(line, "Option"))
      {
       /*
        * Option {[-]BasicAuth}
        */

        if (!value)
        {
	  fprintf(stderr, "moauthd: Bad Option on line %d of \"%s\".\n", linenum, configfile);
	  goto create_failed;
        }

        if (!strcasecmp(value, "BasicAuth"))
          server->options |= MOAUTHD_OPTION_BASIC_AUTH;
	else
	  fprintf(stderr, "moauthd: Unknown Option %s on line %d of \"%s\".\n", value, linenum, configfile);
      }
      else if (!strcasecmp(line, "Resource"))
      {
       /*
        * Resource {public,private,shared} /remote/path /local/path
        */

        char		*scope,		/* Access scope */
			*remote_path,	/* Remote path */
			*local_path;	/* Local path */
        struct stat	local_info;	/* Local file info */

        if (!value)
        {
	  fprintf(stderr, "moauthd: Bad Resource on line %d of \"%s\".\n", linenum, configfile);
	  goto create_failed;
        }

        scope       = strtok(value, " \t");
        remote_path = strtok(NULL, " \t");
        local_path  = strtok(NULL, " \t");

        if (!scope || !remote_path || !local_path)
        {
	  fprintf(stderr, "moauthd: Bad Resource on line %d of \"%s\".\n", linenum, configfile);
	  goto create_failed;
	}

        if (stat(local_path, &local_info))
        {
	  fprintf(stderr, "moauthd: Unable to access Resource on line %d of \"%s\": %s\n", linenum, configfile, strerror(errno));
	  goto create_failed;
        }

        moauthdCreateResource(server, S_ISREG(local_info.st_mode) ? MOAUTHD_RESTYPE_FILE : MOAUTHD_RESTYPE_DIR, remote_path, local_path, scope);
      }
      else if (!strcasecmp(line, "ServerName"))
      {
       /*
        * ServerName hostname[:port]
        */

	char	*portptr;		/* Pointer to port in line */

        if (!value)
        {
          fprintf(stderr, "moauthd: Missing server name on line %d of \"%s\".\n", linenum, configfile);
          goto create_failed;
	}

        if ((portptr = strrchr(value, ':')) != NULL && isdigit(portptr[1] & 255))
	{
	 /*
	  * Extract ":port" portion...
	  */

	  *portptr++ = '\0';
	  server_port = atoi(portptr);
	}

        strncpy(server_name, value, sizeof(server_name) - 1);
        server_name[sizeof(server_name) - 1] = '\0';
      }
      else if (!strcasecmp(line, "TestPassword"))
      {
        if (value)
        {
          server->test_password = strdup(value);
	}
	else
	{
          fprintf(stderr, "moauthd: Missing password on line %d of \"%s\".\n", linenum, configfile);
          goto create_failed;
	}
      }
      else
      {
        fprintf(stderr, "moauthd: Unknown configuration directive \"%s\" on line %d of \"%s\" ignored.\n", line, linenum, configfile);
      }
    }

    cupsFileClose(fp);
  }

  server->name = strdup(server_name);
  server->port = server_port;

 /*
  * Setup listeners...
  */

  snprintf(server_ports, sizeof(server_ports), "%d", server_port);
  addrlist = httpAddrGetList(NULL, AF_UNSPEC, server_ports);
  for (addr = addrlist; addr; addr = addr->next)
  {
    int			sock = httpAddrListen(&(addr->addr), server_port);
					/* Listener socket */
    struct pollfd	*lis = server->listeners + server->num_listeners;
					/* Pointer to polling data */

    if (sock < 0)
    {
      char temp[256];			/* Address string */

      fprintf(stderr, "moauthd: Unable to listen to \"%s:%d\": %s\n", httpAddrString(&(addr->addr), temp, sizeof(temp)), server_port, strerror(errno));
      continue;
    }

    if (server->num_listeners >= (int)(sizeof(server->listeners) / sizeof(server->listeners[0])))
    {
     /*
      * Unlikely, but ignore more than N listeners...
      */

      fputs("moauthd: Ignoring extra listener addresses.\n", stderr);
      break;
    }

    server->num_listeners ++;
    lis->fd     = sock;
    lis->events = POLLIN | POLLHUP | POLLERR;
  }

  if (server->num_listeners == 0)
  {
    fputs("moauthd: No working listener sockets.\n", stderr);
    goto create_failed;
  }

 /*
  * Update logging and log our authorization server's URL...
  */

  if (verbosity == 1 && server->log_level < MOAUTHD_LOGLEVEL_DEBUG)
    server->log_level ++;
  else if (verbosity > 1)
    server->log_level = MOAUTHD_LOGLEVEL_DEBUG;

  moauthdLogs(server, MOAUTHD_LOGLEVEL_INFO, "Authorization server is \"https://%s:%d\".", server_name, server_port);

  cupsSetServerCredentials(NULL, server->name, 1);

 /*
  * Final setup...
  */

  time(&server->start_time);

  pthread_mutex_init(&server->applications_lock, NULL);
  pthread_rwlock_init(&server->resources_lock, NULL);
  pthread_rwlock_init(&server->tokens_lock, NULL);

  if (!server->secret)
  {
   /*
    * Generate a random secret string that is used when creating token UUIDs.
    */

    for (ptr = temp; ptr < (temp + sizeof(temp) - 1); ptr ++)
      *ptr = (arc4random() % 95) + ' ';
    *ptr = '\0';
    server->secret = strdup(temp);
  }

  if (!moauthdFindResource(server, "/moauth.png", temp, sizeof(temp), &tempinfo))
  {
   /*
    * Add default moauth.png file...
    */

    moauthd_resource_t *r = moauthdCreateResource(server, MOAUTHD_RESTYPE_STATIC_FILE, "/moauth.png", NULL, "public");
    r->data   = moauth_png;
    r->length = sizeof(moauth_png);
  }

  if (!moauthdFindResource(server, "/style.css", temp, sizeof(temp), &tempinfo))
  {
   /*
    * Add default style.css file...
    */

    moauthd_resource_t *r = moauthdCreateResource(server, MOAUTHD_RESTYPE_STATIC_FILE, "/style.css", NULL, "public");
    r->data   = style_css;
    r->length = strlen(style_css);
  }

 /*
  * Return the server object...
  */

  return (server);


 /*
  * If we get here something went wrong...
  */

  create_failed:

  moauthdDeleteServer(server);

  return (NULL);
}


/*
 * 'moauthdDeleteServer()' - Delete a server object.
 */

void
moauthdDeleteServer(
    moauthd_server_t *server)		/* I - Server object */
{
  int	i;				/* Looping var */


  if (server->name)
    free(server->name);

  for (i = 0; i < server->num_listeners; i ++)
    httpAddrClose(NULL, server->listeners[i].fd);

  cupsArrayDelete(server->applications);
  cupsArrayDelete(server->resources);
  cupsArrayDelete(server->tokens);

  pthread_mutex_destroy(&server->applications_lock);
  pthread_rwlock_destroy(&server->resources_lock);

  if (server->test_password)
    free(server->test_password);

  free(server);
}


/*
 * 'moauthdFindApplication()' - Find an application by its client ID.
 */

moauthd_application_t *			/* O - Matching application, if any */
moauthdFindApplication(
    moauthd_server_t *server,		/* I - Server object */
    const char       *client_id,	/* I - Client ID */
    const char       *redirect_uri)	/* I - Redirect URI or NULL */
{
  moauthd_application_t	*app,		/* Matching application */
			key;		/* Search key */


  pthread_mutex_lock(&server->applications_lock);

  if (redirect_uri)
  {
   /*
    * Exact match...
    */

    key.client_id    = (char *)client_id;
    key.redirect_uri = (char *)redirect_uri;

    app = (moauthd_application_t *)cupsArrayFind(server->applications, &key);
  }
  else
  {
   /*
    * First matching client ID...
    */

    for (app = (moauthd_application_t *)cupsArrayFirst(server->applications); app; app = (moauthd_application_t *)cupsArrayNext(server->applications))
      if (!strcmp(app->client_id, client_id))
        break;
  }

  pthread_mutex_unlock(&server->applications_lock);

  return (app);
}


/*
 * 'moauthdRunServer()' - Listen for client connections and process requests.
 */

int					/* O - Exit status */
moauthdRunServer(
    moauthd_server_t *server)		/* I - Server object */
{
  int	done = 0;			/* Are we done yet? */

  if (!server)
    return (1);

  moauthdLogs(server, MOAUTHD_LOGLEVEL_INFO, "Listening for client connections.");

  while (!done)
  {
    if (poll(server->listeners, server->num_listeners, -1) < 0)
    {
      if (errno != EAGAIN && errno != EINTR)
      {
        moauthdLogs(server, MOAUTHD_LOGLEVEL_ERROR, "poll() failed: %s", strerror(errno));
        done = 1;
      }
    }
    else
    {
      int		i;		/* Looping var */
      struct pollfd	*lis;		/* Current listener */

      for (i = server->num_listeners, lis = server->listeners; i > 0; i --, lis ++)
      {
        if (lis->revents & POLLIN)
	{
	  moauthd_client_t *client = moauthdCreateClient(server, lis->fd);
					/* New client */

          if (client)
          {
            pthread_t tid;		/* New processing thread */

            if (pthread_create(&tid, NULL, (void *(*)(void *))moauthdRunClient, client))
            {
             /*
              * Unable to create client thread...
              */

              moauthdLogs(server, MOAUTHD_LOGLEVEL_ERROR, "Unable to create client processing thread: %s", strerror(errno));
              moauthdDeleteClient(client);
	    }
	    else
	    {
	     /*
	      * Client thread created, detach!
	      */

	      pthread_detach(tid);
	    }
          }
	}
      }
    }
  }

  return (0);
}


/*
 * 'compare_applications()' - Compare two application registrations.
 */

static int				/* O - Result of comparison */
compare_applications(
    moauthd_application_t *a,		/* I - First application */
    moauthd_application_t *b)		/* I - Second application */
{
  return (strcmp(a->client_id, b->client_id));
}


/*
 * 'copy_application()' - Make a copy of an application object.
 */

static moauthd_application_t *		/* O - New application object */
copy_application(
    moauthd_application_t *a)		/* I - Application object */
{
  moauthd_application_t	*na;		/* New application object */


  if ((na = (moauthd_application_t *)calloc(1, sizeof(moauthd_application_t))) != NULL)
  {
    na->client_id    = strdup(a->client_id);
    na->redirect_uri = strdup(a->redirect_uri);
  }

  return (na);
}


/*
 * 'free_application()' - Free an application object.
 */

static void
free_application(
    moauthd_application_t *a)		/* I - Application object */
{
  free(a->client_id);
  free(a->redirect_uri);
  free(a);
}


/*
 * 'get_seconds()' - Get a time value in seconds.
 */

static int				/* O - Number of seconds or -1 on error */
get_seconds(const char *value)		/* I - Value string */
{
  char	*units;				/* Pointer to units */
  int	tval = (int)strtol(value, &units, 10);
					/* Time value */

  if (!strcasecmp(units, "m"))
    tval *= 60;
  else if (!strcasecmp(units, "h"))
    tval *= 3600;
  else if (!strcasecmp(units, "d"))
    tval *= 86400;
  else if (!strcasecmp(units, "w"))
    tval *= 604800;
  else
    tval = -1;

  return (tval);
}
