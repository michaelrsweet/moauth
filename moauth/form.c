/*
 * Form variable support for moauth library
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include <config.h>
#include "moauth.h"
#include <ctype.h>


/*
 * Local functions...
 */

static const char *decode_string(const char *data, char term, char *buffer, size_t bufsize);


/*
 * 'moauthFormDecode()' - Decode x-www-form-urlencoded variables.
 */

int					/* O - Number of form variables or 0 on error */
moauthFormDecode(const char    *data,	/* I - Form data */
                 cups_option_t **vars)	/* O - Form variables or @code NULL@ on error */
{
  int   num_vars = 0;                   /* Number of form variables */
  char  ch,                             /* Current character */
        name[1024],                     /* Variable name */
        value[4096],                    /* Variable value */
        *ptr;                           /* Pointer into name/value */


 /*
  * Scan the string for "name=value" pairs, unescaping values as needed.
  */

  *vars = NULL;

  while (*data)
  {
   /*
    * Get the name and value...
    */

    data = decode_string(data, '=', name, sizeof(name));

    if (*data != '=')
      goto decode_error;

    data ++;

    data = decode_string(data, '&', value, sizeof(value));

    if (*data && *data != '&')
      goto decode_error;
    else if (*data)
    {
      data ++;

      if (!*data)
        goto decode_error;
    }

   /*
    * Add the variable...
    */

    num_vars = cupsAddOption(name, value, num_vars, vars);
  }

  return (num_vars);

 /*
  * If we get here there was an error in the form data...
  */

  decode_error:

  cupsFreeOptions(num_vars, *vars);

  *vars = NULL;

  return (0);
}


/*
 * 'moauthFormEncode()' - Encode variables in the x-www-form-urlencoded format.
 *
 * The caller is responsible for calling @code free@ on the returned string.
 */

char *					/* O - Encoded data or @code NULL@ on error */
moauthFormEncode(int           num_vars,/* I - Number of form variables */
                 cups_option_t *vars)	/* I - Form variables */
{
  (void)num_vars;
  (void)vars;

  return (NULL);
}


/*
 * 'decode_string()' - Decode a URL-encoded string.
 */

static const char *                     /* O - New pointer into string */
decode_string(const char *data,         /* I - Pointer into data string */
              char       term,          /* I - Terminating character */
              char       *buffer,       /* I - String buffer */
              size_t     bufsize)       /* I - Size of string buffer */
{
  char  ch,                             /* Current character */
        *ptr,                           /* Pointer info buffer */
        *end;                           /* Pointer to end of buffer */


  for (ptr = buffer, end = buffer + bufsize - 1; *data && *data != term; data ++)
  {
    if ((ch = *data) == '+')
    {
     /*
      * "+" is an escaped space...
      */

      ch = ' ';
    }
    else if (ch == '%')
    {
     /*
      * "%HH" is a hex-escaped character...
      */

      if (isxdigit(data[1] & 255) && isxdigit(data[2] & 255))
      {
        data ++;
        if (isalpha(*data & 255))
          ch = (tolower(*data & 255) - 'a' + 10) << 4;
        else
          ch = (*data - '0') << 4;

        data ++;
        if (isalpha(*data & 255))
          ch += tolower(*data & 255) - 'a' + 10;
        else
          ch += *data - '0';
      }
      else
        break;
    }

    if (ch && ptr < end)
      *ptr++ = ch;
  }

  *ptr = '\0';

  return (data);
}
