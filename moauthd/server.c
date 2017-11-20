/*
 * Server support for moauth daemon
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include "moauthd.h"
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>


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
		server_ports[8];	/* Listening port (string) */
  int		server_port = 9000 + (getuid() % 1000);
					/* Listening port (number) */
  http_addrlist_t *addrlist,		/* List of listener addresses */
		*addr;			/* Current address */


 /*
  * Open the configuration file if one is specified...
  */

  if (configfile && (fp = cupsFileOpen(configfile, "r")) == NULL)
   return (NULL);

 /*
  * Allocate a server object and initialize with defaults...
  */

  server = calloc(1, sizeof(moauthd_server_t));

  server->log_file  = -1;
  server->log_level = MOAUTHD_LOGLEVEL_ERROR;

  httpGetHostname(NULL, server_name, sizeof(server_name));

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
      if (!strcasecmp(line, "LogFile"))
      {
       /*
        * LogFile {filename,none,stderr,syslog}
        */

        if (!value || !strcasecmp(value, "stderr"))
          server->log_file = 2;
	else if (!strcmp(value, "none"))
	  server->log_file = open("/dev/null", O_WRONLY, 0600);
	else if (!strcasecmp(value, "syslog"))
	  server->log_file = 0;
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
      else
      {
        fprintf(stderr, "moauthd: Unknown configuration directive \"%s\" on line %d of \"%s\" ignored.\n", line, linenum, configfile);
      }
    }

    cupsFileClose(fp);
  }

  server->server_name = strdup(server_name);
  server->server_port = server_port;

 /*
  * Setup listeners...
  */

  snprintf(server_ports, sizeof(server_ports), "%d", server_port);
  addrlist = httpAddrGetList(server_name, AF_UNSPEC, server_ports);
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
      * Unlikely, but ignore more than N (currently 100) listeners...
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

  if (server->log_file < 0)
    server->log_file = 2;			/* Log to stderr */

  if (verbosity == 1 && server->log_level < MOAUTHD_LOGLEVEL_DEBUG)
    server->log_level ++;
  else if (verbosity > 1)
    server->log_level = MOAUTHD_LOGLEVEL_DEBUG;

  moauthdLog(server, MOAUTHD_LOGLEVEL_INFO, "Authorization server is \"https://%s:%d\".", server_name, server_port);

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


  if (server->server_name)
    free(server->server_name);

  for (i = 0; i < server->num_listeners; i ++)
    httpAddrClose(NULL, server->listeners[i].fd);

  cupsArrayDelete(server->resources);
  cupsArrayDelete(server->scopes);
  cupsArrayDelete(server->tokens);
  cupsArrayDelete(server->users);

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

  moauthdLog(server, MOAUTHD_LOGLEVEL_INFO, "Listening for client connections.");

  do
  {
    if (poll(server->listeners, server->num_listeners, -1) < 0)
    {
      if (errno != EAGAIN && errno != EINTR)
      {
        moauthdLog(server, MOAUTHD_LOGLEVEL_ERROR, "poll() failed: %s", strerror(errno));
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

              moauthdLog(server, MOAUTHD_LOGLEVEL_ERROR, "Unable to create client processing thread: %s", strerror(errno));
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
  while (!done);

  return (0);
}
