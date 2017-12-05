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

  server->log_file  = 2;
  server->log_level = MOAUTHD_LOGLEVEL_ERROR;

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
      else if (!strcasecmp(line, "Option"))
      {
       /*
        * Option {BasicAuth}
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
