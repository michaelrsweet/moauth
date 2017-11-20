/*
 * Main entry for moauth daemon
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include "moauthd.h"


/*
 * Local functions...
 */

static void	usage(void);


/*
 * 'main()' - Main entry for moauth daemon.
 */

int					/* O - Exit status */
main(int  argc,				/* I - Number of command-line arguments */
     char *argv[])			/* I - Command-line arguments */
{
  int		i;			/* Looping var */
  const char	*opt;			/* Current command-line option */
  const char	*configfile = NULL;	/* Server configuration file, if any */
  int		verbosity = 0;		/* Verbosity level */


 /*
  * Parse command-line options...
  */

  for (i = 1; i < argc; i ++)
  {
    if (!strcmp(argv[i], "--help"))
    {
     /*
      * Show help and exit...
      */

      usage();
      return (0);
    }
    else if (argv[i][0] == '-' && argv[i][1] != '-')
    {
      for (opt = argv[i] + 1; *opt; opt ++)
      {
        switch (*opt)
        {
          case 'c' : /* -c configfile */
              i ++;
              if (i < argc && !configfile)
                configfile = argv[i];
	      else
	      {
		if (configfile)
		  fputs("moauthd: Configuration file can only be specified once.\n", stderr);
		else
		  fputs("moauthd: Configuration file expected after \"-c\".\n", stderr);
	        usage();
	        return (1);
	      }
	      break;

          case 'v' : /* -v */
              verbosity ++;
              break;

	  default :
	      fprintf(stderr, "moauthd: Unknown option \"-%c\".\n", *opt);
	      usage();
	      return (1);
        }
      }
    }
    else
    {
     /*
      * Unknown option...
      */

      fprintf(stderr, "moauthd: Unknown option \"%s\".\n", argv[i]);
      usage();
      return (1);
    }
  }

 /*
  * Create the server object and run it...
  */

  return (moauthdRunServer(moauthdCreateServer(configfile, verbosity)));
}


/*
 * 'usage()' - Show program usage.
 */

static void
usage(void)
{
  fputs("Usage: moauthd [options]\n", stderr);
  fputs("Options:\n", stderr);
  fputs("-c configfile     Specify configuration file.\n", stderr);
  fputs("--help            Show usage help.\n", stderr);
}

