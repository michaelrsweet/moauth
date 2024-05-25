//
// Main entry for moauth daemon
//
// Copyright © 2017-2024 by Michael R Sweet
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//

#include "moauthd.h"


//
// Local functions...
//

static void	usage(FILE *out);


//
// 'main()' - Main entry for moauth daemon.
//

int					// O - Exit status
main(int  argc,				// I - Number of command-line arguments
     char *argv[])			// I - Command-line arguments
{
  int		i;			// Looping var
  const char	*opt;			// Current command-line option
  const char	*configfile = NULL,	// Server configuration file, if any
		*statefile = NULL,	// Server state file, if any
		*snap_common = getenv("SNAP_COMMON");
					// Snap directory, if any
  char		configtemp[1024],	// Temporary config filename
		statetemp[1024];	// Temporary state filename
  int		verbosity = 0;		// Verbosity level


  // Parse command-line options...
  for (i = 1; i < argc; i ++)
  {
    if (!strcmp(argv[i], "--help"))
    {
      // Show help and exit...
      usage(stdout);
      return (0);
    }
    else if (!strcmp(argv[i], "--version"))
    {
      // Show version and exit...
      puts(MOAUTH_VERSION);
      return (0);
    }
    else if (argv[i][0] == '-' && argv[i][1] != '-')
    {
      for (opt = argv[i] + 1; *opt; opt ++)
      {
        switch (*opt)
        {
          case 'c' : // -c configfile
	      if (configfile)
	      {
		fputs("moauthd: Configuration file can only be specified once.\n", stderr);
	        usage(stderr);
	        return (1);
	      }

              i ++;

              if (i >= argc)
	      {
		fputs("moauthd: Configuration file expected after '-c'.\n", stderr);
	        usage(stderr);
	        return (1);
	      }

	      configfile = argv[i];
	      break;

          case 's' : // -s statefile
	      if (statefile)
	      {
		fputs("moauthd: State file can only be specified once.\n", stderr);
	        usage(stderr);
	        return (1);
	      }

              i ++;

              if (i >= argc)
	      {
		fputs("moauthd: State file expected after '-s'.\n", stderr);
	        usage(stderr);
	        return (1);
	      }

	      statefile = argv[i];
	      break;

          case 'v' : // -v
              verbosity ++;
              break;

	  default :
	      fprintf(stderr, "moauthd: Unknown option '-%c'.\n", *opt);
	      usage(stderr);
	      return (1);
        }
      }
    }
    else
    {
      // Unknown option...
      fprintf(stderr, "moauthd: Unknown option '%s'.\n", argv[i]);
      usage(stderr);
      return (1);
    }
  }

  // Default config file is "$SNAP_COMMON/moauthd.conf", "/etc/moauthd.conf", or
  // "/usr/local/etc/moauthd.conf"...
  if (!configfile && snap_common)
  {
    snprintf(configtemp, sizeof(configtemp), "%s/moauthd.conf", snap_common);
    if (!access(configtemp, 0))
      configfile = configtemp;
  }

  if (!configfile)
  {
    if (!access("/etc/moauthd.conf", 0))
      configfile = "/etc/moauthd.conf";
    else if (!access("/usr/local/etc/moauthd.conf", 0))
      configfile = "/usr/local/etc/moauthd.conf";
  }

  // Default state file is "$SNAP_COMMON/moauthd.state",
  // "/var/lib/moauthd.state", "/usr/local/var/lib/moauthd.state", or
  // "CONFIGFILE.state"...
  if (!statefile)
  {
    if (snap_common && !strncmp(configfile, snap_common, strlen(snap_common)))
    {
      snprintf(statetemp, sizeof(statetemp), "%s/moauthd.state", snap_common);
      statefile = statetemp;
    }
    else if (!strncmp(configfile, "/etc/", 5))
    {
      statefile = "/var/lib/moauthd.state";
    }
    else if (!strncmp(configfile, "/usr/local/etc/", 15))
    {
      statefile = "/usr/local/var/lib/moauthd.state";
    }
    else
    {
      // Default to configfile.state...
      char	*ptr;			// Pointer into temporary filename

      cupsCopyString(statetemp, configfile, sizeof(statetemp));
      if ((ptr = strstr(statetemp, ".conf")) != NULL)
        *ptr = '\0';
      cupsConcatString(statetemp, ".state", sizeof(statetemp));
      statefile = statetemp;
    }
  }

  // Create the server object and run it...
  return (moauthdRunServer(moauthdCreateServer(configfile, statefile, verbosity)));
}


//
// 'usage()' - Show program usage.
//

static void
usage(FILE *out)			// I - Output file (stdout or stderr)
{
  fputs("Usage: moauthd [options]\n", out);
  fputs("Options:\n", out);
  fputs("-c configfile     Specify configuration file.\n", out);
  fputs("-s configfile     Specify state file.\n", out);
  fputs("-v                Be verbose (more v's increase the verbosity).\n", out);
  fputs("--help            Show usage help.\n", out);
  fputs("--version         Show mOAuth version.\n", out);
}

