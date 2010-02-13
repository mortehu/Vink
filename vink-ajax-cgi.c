#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backend.h"
#include "vink-internal.h"
#include "vink.h"

static struct vink_backend_callbacks callbacks;

static const char *jid;

static void
error (int code, const char *message)
{
  printf ("Status: %1$d %2$s\r\n"
          "Content-Type: text/javascript\r\n"
          "\r\n"
          "{'error-code': %1$d, 'error-message': ' %2$s' }\n",
          code, message);

  exit (EXIT_SUCCESS);
}

static void
login (const char *username, const char *secret)
{
  if (-1 == callbacks.xmpp.authenticate(0, username, secret))
    error (-1, "Permission denied");

}

static int
list_message (struct vink_message *msg)
{
  printf ("%.*s\n", (int) msg->body_size, msg->body);

  return 0;
}

static void
list_messages ()
{
  if (!jid)
    error (-1, "Permission denied");

  callbacks.list_messages (jid, list_message, 0, 20);
}

static const struct
{
  void *function;
  const char *name;
  const char *args;
}
functions[] =
{
    { login,         "login",         "ss" },
    { list_messages, "list-messages", "" }
};

typedef void (*fun_v) (void);
typedef void (*fun_s) (const char *);
typedef void (*fun_ss) (const char *, const char*);

int
main (int argc, char **argv)
{
  const char *query_string;
  const char *begin, *end, *c;
  size_t i = 0, script_argc = 0;
  char **script_argv;

  if (-1 == vink_init ("/etc/vink.d/vink.conf", VINK_CLIENT, VINK_API_VERSION))
    error (500, "Internal server error");

  backend_init (&callbacks);

  query_string = getenv ("QUERY_STRING");

  if (0 == (query_string = getenv ("QUERY_STRING")))
    error (500, "Internal server error");

  begin = strchr (query_string, '?');

  if (!begin)
    error (500, "Internal server error");

  ++begin;

  for (c = begin; *c; )
    {
      ++script_argc;

      while (*c && *c != '&')
        ++c;

      if (!*c++)
        break;
    }

  if (!script_argc)
    error (500, "Internal server error");

  script_argv = malloc (sizeof (*script_argv) * script_argc);

  while (*begin)
    {
      size_t arglen;

      end = begin;

      while (*end && *end != '&')
        ++end;

      arglen = end - begin;

      script_argv[i] = malloc (arglen + 1);
      strncpy (script_argv[i], begin, arglen);
      script_argv[i][arglen] = 0;
      ++i;

      if (!*end)
        break;

      begin = end + 1;
    }

  for (i = 0; i < ARRAY_SIZE (functions); ++i)
    {
      if (strcmp (functions[i].name, script_argv[0]))
        continue;

      if (strlen (functions[i].args) != script_argc - 1)
        continue;

      if (!functions[i].args[0])
        ((fun_v) (functions[i].function)) ();
      else if (!strcmp (functions[i].args, "s"))
        ((fun_s) (functions[i].function)) (script_argv[1]);
      else if (!strcmp (functions[i].args, "ss"))
        ((fun_ss) (functions[i].function)) (script_argv[1],
                                            script_argv[2]);

      break;
    }

  if (i == ARRAY_SIZE (functions))
    error (404, "Function not found");

  printf ("HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\n\r\n");

  return EXIT_SUCCESS;
}
