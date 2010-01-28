#include <stdlib.h>

#include "vink.h"

static void
error (int code, const char *message)
{
  printf ("HTTP/1.1 %1$d %2$s\r\n"
          "Content-Type: text/javascript\r\n"
          "\r\n"
          "{'error-code': %1$d, 'error-message': ' %2$s' }",
          code, message);

  exit (EXIT_SUCCESS);
}

int
main (int argc, char **argv)
{
  const char *query_string;
  const char *begin, *end;

  query_string = getenv ("QUERY_STRING");

  if (!query_string)
    error (500, "Internal server error");

  printf ("HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\n
  begin = query_string;

  while (*begin)
    {
      end = begin;

      while (*end && *end != '&')
        ++end;

      printf
    }

  return EXIT_SUCCESS;
}
