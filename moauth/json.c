//
// JSON support for moauth library
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
// '_moauthJSONDecode()' - Decode an application/json object.
//

size_t					// O - Number of JSON member variables or 0 on error
_moauthJSONDecode(const char    *data,	// I - JSON data
                  cups_option_t **vars)	// O - JSON member variables or `NULL` on error
{
  size_t	num_vars = 0;		// Number of form variables
  char		name[1024],		// Variable name
		value[4096],		// Variable value
		*ptr,			// Pointer into value
		*end;			// End of value


  // Scan the string for "name":"value" pairs, unescaping values as needed.
  *vars = NULL;

  if (!data || *data != '{')
    return (0);

  data ++;

  while (*data)
  {
    // Skip leading whitespace/commas...
    while (*data && (isspace(*data & 255) || *data == ','))
      data ++;

    // Get the member variable name, unless we have the end of the object...
    if (*data == '}')
      break;
    else if (*data != '\"')
      goto decode_error;

    data = decode_string(data + 1, '\"', name, sizeof(name));

    if (*data != '\"')
      goto decode_error;

    data ++;

    if (*data != ':')
      goto decode_error;

    data ++;

    if (*data == '\"')
    {
      // Quoted string value...
      data = decode_string(data + 1, '\"', value, sizeof(value));

      if (*data != '\"')
	goto decode_error;

      data ++;
    }
    else if (*data == '[')
    {
      // Array value...
      ptr    = value;
      end    = value + sizeof(value) - 1;
      *ptr++ = '[';

      for (data ++; *data && *data != ']';)
      {
        if (*data == ',')
        {
          if (ptr < end)
            *ptr++ = *data++;
	  else
	    goto decode_error;
        }
        else if (*data == '\"')
        {
          // Quoted string value...
          do
          {
	    if (*data == '\\')
	    {
	      if (ptr < end)
		*ptr++ = *data++;
	      else
		goto decode_error;

              if (!strchr("\\\"/bfnrtu", *data))
                goto decode_error;

	      if (*data == 'u')
	      {
		if (ptr < (end - 5))
		  *ptr++ = *data++;
		else
		  goto decode_error;

	        if (isxdigit(data[0] & 255) && isxdigit(data[1] & 255) && isxdigit(data[2] & 255) && isxdigit(data[3] & 255))
	        {
		  *ptr++ = *data++;
		  *ptr++ = *data++;
		  *ptr++ = *data++;
		  // 4th character is copied below
	        }
	        else
	          goto decode_error;
	      }
	    }

	    if (ptr < end)
	      *ptr++ = *data++;
	    else
	      goto decode_error;
	  }
	  while (*data && *data != '\"');

	  if (*data == '\"')
	  {
	    if (ptr < end)
	      *ptr++ = *data++;
	    else
	      goto decode_error;
	  }
        }
        else if (*data == '{' || *data == '[')
        {
          // Unsupported nested array or object value...
	  goto decode_error;
	}
	else
	{
	  // Number, boolean, etc.
          while (*data && *data != ',' && !isspace(*data & 255))
          {
            if (ptr < end)
              *ptr++ = *data++;
	    else
	      goto decode_error;
	  }
	}
      }

      if (*data != ']' || ptr >= end)
        goto decode_error;

      *ptr++ = *data++;
      *ptr   = '\0';

      data ++;
    }
    else if (*data == '{')
    {
      // Unsupported object value...
      goto decode_error;
    }
    else
    {
      // Number, boolean, etc.
      for (ptr = value; *data && *data != ',' && !isspace(*data & 255); data ++)
        if (ptr < (value + sizeof(value) - 1))
          *ptr++ = *data;

      *ptr = '\0';
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
// '_moauthJSONEncode()' - Encode variables as a JSON object.
//
// The caller is responsible for calling @code free@ on the returned string.
//

char *					// O - Encoded data or `NULL` on error
_moauthJSONEncode(
    size_t        num_vars,		// I - Number of JSON member variables
    cups_option_t *vars)		// I - JSON member variables
{
  char		buffer[65536],		// Temporary buffer
		*bufptr = buffer,	// Current position in buffer
		*bufend = buffer + sizeof(buffer) - 2;
					// End of buffer
  const char	*valptr;		// Pointer into value
  int		is_number;		// Is the value a number?

  *bufptr++ = '{';
  *bufend   = '\0';

  while (num_vars > 0)
  {
    bufptr = encode_string(vars->name, bufptr, bufend);

    if (bufptr >= bufend)
      return (NULL);

    *bufptr++ = ':';

    if (vars->value[0] == '[')
    {
      // Array value, already encoded...
      cupsCopyString(bufptr, vars->value, bufend - bufptr);
      bufptr += strlen(bufptr);
    }
    else
    {
      is_number = 0;

      if (vars->value[0] == '-' || isdigit(vars->value[0] & 255))
      {
	for (valptr = vars->value + 1; *valptr && (isdigit(*valptr & 255) || *valptr == '.'); valptr ++);

	if (*valptr == 'e' || *valptr == 'E' || !*valptr)
	  is_number = 1;
      }

      if (is_number)
      {
        // Copy number literal...
	for (valptr = vars->value; *valptr; valptr ++)
	{
	  if (bufptr < bufend)
	    *bufptr++ = *valptr;
	}
      }
      else
      {
        // Copy string value...
	bufptr = encode_string(vars->value, bufptr, bufend);
      }
    }

    num_vars --;
    vars ++;

    if (num_vars > 0)
    {
      if (bufptr >= bufend)
        return (NULL);

      *bufptr++ = ',';
    }
  }

  *bufptr++ = '}';
  *bufptr   = '\0';

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
    if ((ch = *data) == '\\')
    {
      // "\something" is an escaped character...
      data ++;

      switch (*data)
      {
        case '\\' :
            ch = '\\';
            break;
        case '\"' :
            ch = '\"';
            break;
        case '/' :
            ch = '/';
            break;
        case 'b' :
            ch = 0x08;
            break;
        case 'f' :
            ch = 0x0c;
            break;
        case 'n' :
            ch = 0x0a;
            break;
        case 'r' :
            ch = 0x0d;
            break;
        case 't' :
            ch = 0x09;
            break;
        case 'u' :
            data ++;
            if (isxdigit(data[0] & 255) && isxdigit(data[1] & 255) && isxdigit(data[2] & 255) && isxdigit(data[3] & 255))
            {
              if (isalpha(data[0]))
                ch = (tolower(data[0]) - 'a' + 10) << 12;
	      else
	        ch = (data[0] - '0') << 12;

              if (isalpha(data[1]))
                ch |= (tolower(data[1]) - 'a' + 10) << 8;
	      else
	        ch |= (data[1] - '0') << 8;

              if (isalpha(data[2]))
                ch |= (tolower(data[2]) - 'a' + 10) << 4;
	      else
	        ch |= (data[2] - '0') << 4;

              if (isalpha(data[3]))
                ch |= tolower(data[3]) - 'a' + 10;
	      else
	        ch |= data[3] - '0';
              break;
            }

            // Fall through to default on error
	default :
	    *buffer = '\0';
	    return (NULL);
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
  if (bufptr < bufend)
    *bufptr++ = '\"';

  while (*s && bufptr < bufend)
  {
    if (*s == '\b')
    {
      *bufptr++ = '\\';
      if (bufptr < bufend)
        *bufptr++ = 'b';
    }
    else if (*s == '\f')
    {
      *bufptr++ = '\\';
      if (bufptr < bufend)
        *bufptr++ = 'f';
    }
    else if (*s == '\n')
    {
      *bufptr++ = '\\';
      if (bufptr < bufend)
        *bufptr++ = 'n';
    }
    else if (*s == '\r')
    {
      *bufptr++ = '\\';
      if (bufptr < bufend)
        *bufptr++ = 'r';
    }
    else if (*s == '\t')
    {
      *bufptr++ = '\\';
      if (bufptr < bufend)
        *bufptr++ = 't';
    }
    else if (*s == '\\')
    {
      *bufptr++ = '\\';
      if (bufptr < bufend)
        *bufptr++ = '\\';
    }
    else if (*s == '\"')
    {
      *bufptr++ = '\\';
      if (bufptr < bufend)
        *bufptr++ = '\"';
    }
    else if (*s >= ' ')
      *bufptr++ = *s;

    s ++;
  }

  if (bufptr < bufend)
    *bufptr++ = '\"';

  *bufptr = '\0';

  return (bufptr);
}
