//
// Form variable support for moauth library
//
// Copyright © 2017-2022 by Michael R Sweet
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
//

#include <config.h>
#include "moauth-private.h"
#include <ctype.h>


//
// Local functions...
//

static const char *decode_string(const char *data, char term, char *buffer, size_t bufsize);
static char *encode_string(const char *s, char *bufptr, char *bufend);


//
// '_moauthFormDecode()' - Decode x-www-form-urlencoded variables.
//

size_t					// O - Number of form variables or `0` on error
_moauthFormDecode(const char    *data,	// I - Form data
                  cups_option_t **vars)	// O - Form variables or `NULL` on error
{
  size_t	num_vars = 0;		// Number of form variables
  char		name[1024],		// Variable name
		value[4096];		// Variable value


  // Scan the string for "name=value" pairs, unescaping values as needed.
  *vars = NULL;

  if (!data)
    return (0);

  while (*data)
  {
    // Get the name and value...
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

    // Add the variable...
    num_vars = cupsAddOption(name, value, num_vars, vars);
  }

  return (num_vars);

  // If we get here there was an error in the form data...
  decode_error:

  cupsFreeOptions(num_vars, *vars);

  *vars = NULL;

  return (0);
}


//
// '_moauthFormEncode()' - Encode variables in the x-www-form-urlencoded format.
//
// The caller is responsible for calling @code free@ on the returned string.
//

char *					// O - Encoded data or `NULL` on error
_moauthFormEncode(
    size_t        num_vars,		// I - Number of form variables
    cups_option_t *vars)		// I - Form variables
{
  char	buffer[65536],			// Temporary buffer
	*bufptr = buffer,		// Current position in buffer
	*bufend = buffer + sizeof(buffer) - 1;
					// End of buffer


  while (num_vars > 0)
  {
    bufptr = encode_string(vars->name, bufptr, bufend);

    if (bufptr >= bufend)
      return (NULL);

    *bufptr++ = '=';

    bufptr = encode_string(vars->value, bufptr, bufend);

    num_vars --;
    vars ++;

    if (num_vars > 0)
    {
      if (bufptr >= bufend)
        return (NULL);

      *bufptr++ = '&';
    }
  }

  *bufptr = '\0';

  return (strdup(buffer));
}


//
// 'decode_string()' - Decode a URL-encoded string.
//

static const char *                     // O - New pointer into string
decode_string(const char *data,         // I - Pointer into data string
              char       term,          // I - Terminating character
              char       *buffer,       // I - String buffer
              size_t     bufsize)       // I - Size of string buffer
{
  int	ch;				// Current character
  char	*ptr,				// Pointer info buffer
	*end;				// Pointer to end of buffer


  for (ptr = buffer, end = buffer + bufsize - 1; *data && *data != term; data ++)
  {
    if ((ch = *data) == '+')
    {
      // "+" is an escaped space...
      ch = ' ';
    }
    else if (ch == '%')
    {
      // "%HH" is a hex-escaped character...
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
      {
        break;
      }
    }

    if (ch && ptr < end)
      *ptr++ = (char)ch;
  }

  *ptr = '\0';

  return (data);
}


//
// 'encode_string()' - URL-encode a string.
//
// The new buffer pointer can go past bufend, but we don't write past there...
//

static char *                           // O - New buffer pointer
encode_string(const char *s,            // I - String to encode
              char       *bufptr,       // I - Pointer into buffer
              char       *bufend)       // I - End of buffer
{
  static const char *hex = "0123456789ABCDEF";
                                        // Hex digits


  while (*s && bufptr < bufend)
  {
    if (*s == ' ')
    {
      *bufptr++ = '+';
    }
    else if (*s == '\n')
    {
      *bufptr++ = '%';
      if (bufptr < bufend)
        *bufptr++ = '0';
      else
        bufptr ++;
      if (bufptr < bufend)
        *bufptr++ = 'D';
      else
        bufptr ++;
      if (bufptr < bufend)
        *bufptr++ = '%';
      else
        bufptr ++;
      if (bufptr < bufend)
        *bufptr++ = '0';
      else
        bufptr ++;
      if (bufptr < bufend)
        *bufptr++ = 'A';
      else
        bufptr ++;
    }
    else if (*s < ' ' || *s == '&' || *s == '%' || *s == '=' || *s == '+' || *s == '\"')
    {
      *bufptr++ = '%';
      if (bufptr < bufend)
        *bufptr++ = hex[(*s >> 4) & 15];
      else
        bufptr ++;
      if (bufptr < bufend)
        *bufptr++ = hex[*s & 15];
      else
        bufptr ++;
    }
    else
      *bufptr++ = *s;

    s ++;
  }

  if (bufptr <= bufend)
    *bufptr = '\0';
  else
    *bufend = '\0';

  return (bufptr);
}
