/*
 * Unit test program for moauth library
 *
 * Copyright © 2017 by Michael R Sweet
 *
 * Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include "moauth.h"


/*
 * 'main()' - Main entry for unit test program.
 */

int					/* O - Exit status */
main(void)
{
  int           status = 0;             /* Exit status */
  int           i;                      /* Looping var */
//  char          *data;                  /* Data pointer */
  int           count,                  /* Expected variable count */
                num_vars;               /* Number of variables */
  cups_option_t *vars;                  /* Variables */
  const char    *value;                 /* Value */
  static const char * const decodes[] = /* Decode string tests */
  {
    "0?",
    "0?name",
    "0?%00=",
    "1?empty=",
    "1?name=value",
    "0?name=value&",
    "2?name1=value1&name2=value2",
    "1?name+with+spaces=value+with+spaces",
    "1?quotes=%22value%22"
  };


 /*
  * Test different URL strings...
  */

  for (i = 0; i < (int)(sizeof(decodes) / sizeof(decodes[0])); i ++)
  {
    printf("moauthFormDecode(\"%s\", ...): ", decodes[i]);

    count    = (int)strtol(decodes[i], NULL, 10);
    num_vars = moauthFormDecode(decodes[i] + 2, &vars);

    if (count != num_vars)
    {
      printf("FAIL (got %d variables, expected %d)\n", num_vars, count);
      status = 1;
    }
    else if ((value = cupsGetOption("empty", num_vars, vars)) != NULL && strcmp(value, ""))
    {
      printf("FAIL (got \"empty=%s\", expected \"empty=\")\n", value);
      status = 1;
    }
    else if ((value = cupsGetOption("name", num_vars, vars)) != NULL && strcmp(value, "value"))
    {
      printf("FAIL (got \"name=%s\", expected \"name=value\")\n", value);
      status = 1;
    }
    else if ((value = cupsGetOption("name1", num_vars, vars)) != NULL && strcmp(value, "value1"))
    {
      printf("FAIL (got \"name1=%s\", expected \"name1=value1\")\n", value);
      status = 1;
    }
    else if ((value = cupsGetOption("name2", num_vars, vars)) != NULL && strcmp(value, "value2"))
    {
      printf("FAIL (got \"name2=%s\", expected \"name2=value2\")\n", value);
      status = 1;
    }
    else if ((value = cupsGetOption("name with spaces", num_vars, vars)) != NULL && strcmp(value, "value with spaces"))
    {
      printf("FAIL (got \"name with spaces=%s\", expected \"name with spaces=value with spaces\")\n", value);
      status = 1;
    }
    else if ((value = cupsGetOption("quotes", num_vars, vars)) != NULL && strcmp(value, "\"value\""))
    {
      printf("FAIL (got \"quotes=%s\", expected \"quotes=\\\"value\\\"\")\n", value);
      status = 1;
    }
    else
      puts("PASS");

    cupsFreeOptions(num_vars, vars);
  }

 /*
  * Return the test results...
  */

  return (status);
}
