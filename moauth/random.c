/*
 * High-quality random number support for moauth library
 *
 * Copyright © 2019 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more
 * information.
 */

#include <config.h>
#include "moauth-private.h"
#include <stdlib.h>

#ifndef HAVE_ARC4RANDOM
#  include <unistd.h>
#  include <fcntl.h>
#  include <sys/time.h>
#endif /* !HAVE_ARC4RANDOM */

#ifdef HAVE_SYS_RANDOM_H
#  include <sys/random.h>
#endif /* HAVE_SYS_RANDOM_H */


/*
 * '_moauthGetRandomBytes()' - Get a series of random bytes suitable for an OAuth 2.0
 *                             exchange.
 */

void
_moauthGetRandomBytes(void   *data,	/* I - Buffer */
                      size_t bytes)	/* I - Number of bytes to generate */
{
#ifdef HAVE_ARC4RANDOM
 /*
  * macOS/iOS provide the arc4random generator which uses hardware entropy as a
  * seed...
  */

  unsigned char *ptr = (unsigned char *)data;
					/* Pointer to byte data */

  while (bytes > 0)
  {
    *ptr++ = (unsigned char)arc4random();
    bytes --;
  }

#else
#  if defined(HAVE_SYS_RANDOM_H)
 /*
  * Linux provides the getrandom function to get high-quality random data from
  * the hardware entropy pool and/or a high-quality pseudo-random number
  * generator...
  */

  if (getrandom(data, bytes, 0) >= (ssize_t)bytes)
    return;
#  endif /* HAVE_SYS_RANDOM_H */

 /*
  * The default random number generator needs a seed.  We use the current time
  * (seconds and microseconds) if /dev/urandom cannot be read...
  */

  int			fd;		/* /dev/urandom */
  unsigned		seed;		/* Seed value */
  struct timeval	curtime;	/* Current time */
  unsigned char		*ptr = (unsigned char *)data;
					/* Pointer to byte data */

  if ((fd = open("/dev/urandom", O_RDONLY)) < 0)
  {
    seed = 0;
  }
  else
  {
    if (read(fd, &seed, sizeof(seed)) < sizeof(seed))
      seed = 0;

    close(fd);
  }

  if (seed == 0)   
  {
    gettimeofday(&curtime, NULL);
    seed = (unsigned)(curtime.tv_sec + curtime.tv_usec);
  }

  srandom(seed);

  while (bytes > 0)
  {
    *ptr++ = (unsigned char)random();
    bytes --;
  }
#endif /* HAVE_ARC4RANDOM */
}

