//
// Unit test program for moauth library
//
// Copyright © 2017-2022 by Michael R Sweet
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more information.
//

#include <config.h>
#include <stdio.h>
#include <string.h>
#include "moauth-private.h"
#include <cups/form.h>


//
// 'main()' - Main entry for unit test program.
//

int					// O - Exit status
main(void)
{
  int           status = 0;             // Exit status
  int           i;                      // Looping var
  char          *data;                  // Data pointer
  size_t	count,                  // Expected variable count
		num_vars;               // Number of variables
  cups_option_t *vars;                  // Variables
  cups_json_t	*json;			// JSON values
  const char    *value;                 // Value
  double	expires_in;		// "expires_in" value
  static const char * const decodes[] = // Decode string tests
  {
    "0?",
    "0?name",
    "0?%00=",
    "1?empty=",
    "1?name=value",
    "0?name=value&",
    "2?name1=value1&name2=value2",
    "1?name+with+spaces=value+with+spaces",
    "1?quotes=%22value%22",
    "1?challenge=zUbp6O0S%2Byxx1VwQkOU9clcNDoBTddyY2e2SDwV1ha0%3D"
  };
  static const char * const encodes[][3] =
  {                                     // Encode string tests
    { "empty", "", "empty=" },
    { "name", "value", "empty=&name=value" },
    { "name", "value with spaces", "empty=&name=value+with+spaces" },
    { "quotes", "\"value\"", "empty=&name=value+with+spaces&quotes=%22value%22" },
    { "equation", "1+2=3 & 2+1=3", "empty=&equation=1%2B2%3D3+%26+2%2B1%3D3&name=value+with+spaces&quotes=%22value%22" }
  };
  static const char *json_in =
    "{\n"
    "\"access_token\":\"2YotnFZFEjr1zCsicMWpAA\",\n"
    "\"example_array\":[\"value1\",\"value2\",\"value3\"],\n"
    "\"example_parameter\":\"example_value\",\n"
    "\"expires_in\":3600,\n"
    "\"refresh_token\":\"tGzv3JOkF0XG5Qx2TlKWIA\",\n"
    "\"token_type\":\"example\"\n"
    "}\n";
  static const char *json_out =
    "{"
    "\"access_token\":\"2YotnFZFEjr1zCsicMWpAA\","
    "\"example_array\":[\"value1\",\"value2\",\"value3\"],"
    "\"example_parameter\":\"example_value\","
    "\"expires_in\":3600,"
    "\"refresh_token\":\"tGzv3JOkF0XG5Qx2TlKWIA\","
    "\"token_type\":\"example\""
    "}";


  // Test decoding different URL strings...
  for (i = 0; i < (int)(sizeof(decodes) / sizeof(decodes[0])); i ++)
  {
    printf("_moauthFormDecode(\"%s\", ...): ", decodes[i]);

    count    = (int)strtol(decodes[i], NULL, 10);
    num_vars = cupsFormDecode(decodes[i] + 2, &vars);

    if (count != num_vars)
    {
      printf("FAIL (got %d variables, expected %d)\n", (int)num_vars, (int)count);
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
      printf("FAIL (got \"quotes=%s\", expected \"quotes=\"value\"\")\n", value);
      status = 1;
    }
    else if ((value = cupsGetOption("challenge", num_vars, vars)) != NULL && strcmp(value, "zUbp6O0S+yxx1VwQkOU9clcNDoBTddyY2e2SDwV1ha0="))
    {
      printf("FAIL (got \"challenge=%s\", expected \"challenge=zUbp6O0S+yxx1VwQkOU9clcNDoBTddyY2e2SDwV1ha0=\")\n", value);
      status = 1;
    }
    else
    {
      puts("PASS");
    }

    cupsFreeOptions(num_vars, vars);
  }

  // Test encoding different form variables...
  for (i = 0, num_vars = 0, vars = NULL; i < (int)(sizeof(encodes) / sizeof(encodes[0])); i ++)
  {
    printf("_moauthFormEncode(\"%s=%s\", ...): ", encodes[i][0], encodes[i][1]);

    num_vars = cupsAddOption(encodes[i][0], encodes[i][1], num_vars, &vars);
    data     = cupsFormEncode(/*url*/NULL, num_vars, vars);

    if (!data)
    {
      puts("FAIL (unable to encode)");
      status = 1;
    }
    else if (strcmp(data, encodes[i][2]))
    {
      printf("FAIL (got \"%s\", expected \"%s\")\n", data, encodes[i][2]);
      status = 1;
    }
    else
      puts("PASS");

    if (data)
      free(data);
  }

  cupsFreeOptions(num_vars, vars);

  // Test JSON encoding/decoding...
  fputs("_moauthJSONDecode(...): ", stdout);

  json = cupsJSONImportString(json_in);

  if (cupsJSONGetCount(json) != 12)
  {
    printf("FAIL (got %d values, expected 12)\n", (int)cupsJSONGetCount(json));
    status = 1;
  }
  else if ((value = cupsJSONGetString(cupsJSONFind(json, "access_token"))) == NULL || strcmp(value, "2YotnFZFEjr1zCsicMWpAA"))
  {
    if (value)
      printf("FAIL (got \"%s\" for \"access_token\", expected \"2YotnFZFEjr1zCsicMWpAA\")\n", value);
    else
      puts("FAIL (missing \"access_token\")");

    status = 1;
  }
#if 0 // TODO: Finish up tests
  else if ((value = cupsGetOption("example_array", num_vars, vars)) == NULL || strcmp(value, "[\"value1\",\"value2\",\"value3\"]"))
  {
    if (value)
      printf("FAIL (got \"%s\" for \"example_array\", expected '[\"value1\",\"value2\",\"value3\"]')\n", value);
    else
      puts("FAIL (missing \"example_array\")");

    status = 1;
  }
  else if ((value = cupsGetOption("example_parameter", num_vars, vars)) == NULL || strcmp(value, "example_value"))
  {
    if (value)
      printf("FAIL (got \"%s\" for \"example_parameter\", expected \"example_value\")\n", value);
    else
      puts("FAIL (missing \"example_parameter\")");

    status = 1;
  }
#endif // 0
  else if ((expires_in = cupsJSONGetNumber(cupsJSONFind(json, "expires_in"))) != 3600.0)
  {
    if (value)
      printf("FAIL (got %g for \"expires_in\", expected 3600)\n", expires_in);
    else
      puts("FAIL (missing \"expires_in\")");

    status = 1;
  }
  else if ((value = cupsJSONGetString(cupsJSONFind(json, "refresh_token"))) == NULL || strcmp(value, "tGzv3JOkF0XG5Qx2TlKWIA"))
  {
    if (value)
      printf("FAIL (got \"%s\" for \"refresh_token\", expected \"tGzv3JOkF0XG5Qx2TlKWIA\")\n", value);
    else
      puts("FAIL (missing \"refresh_token\")");

    status = 1;
  }
  else if ((value = cupsJSONGetString(cupsJSONFind(json, "token_type"))) == NULL || strcmp(value, "example"))
  {
    if (value)
      printf("FAIL (got \"%s\" for \"token_type\", expected \"example\")\n", value);
    else
      puts("FAIL (missing \"token_type\")");

    status = 1;
  }
  else
    puts("PASS");

  fputs("_moauthJSONEncode(...): ", stdout);

  if ((data = cupsJSONExportString(json)) == NULL)
  {
    puts("FAIL (unable to encode)");
    status = 1;
  }
  else if (strcmp(data, json_out))
  {
    printf("FAIL (got \"%s\", expected \"%s\")\n", data, json_out);
    status = 1;
  }
  else
    puts("PASS");

  if (data)
    free(data);

  cupsJSONDelete(json);

  // Return the test results...
  return (status);
}
