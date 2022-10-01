//
// High-quality random number support for moauth library
//
// Copyright © 2019-2022 by Michael R Sweet
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//

#include <config.h>
#include "moauth-private.h"
#include <stdlib.h>


//
// '_moauthGetRandomBytes()' - Get a series of random bytes suitable for an OAuth 2.0
//                             exchange.
//

void
_moauthGetRandomBytes(void   *data,	// I - Buffer
                      size_t bytes)	// I - Number of bytes to generate
{
  unsigned char *ptr = (unsigned char *)data;
					// Pointer to byte data

  while (bytes > 0)
  {
    *ptr++ = (unsigned char)cupsGetRand();
    bytes --;
  }
}

