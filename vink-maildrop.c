#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <getopt.h>
#include <fcntl.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include "backend.h"
#include "vink.h"
#include "vink-internal.h"

static int print_version;
static int print_help;

static struct option long_options[] =
{
    { "recipient",      required_argument, 0, 'r' },
    { "version",        no_argument, &print_version, 1 },
    { "help",           no_argument, &print_help,    1 },
    { 0, 0, 0, 0 }
};

static void
read_to_buffer (int fd, struct VINK_buffer* buf)
{
  char buffer[1024];
  int result;

  ARRAY_INIT (buf);

  while (0 != (result = read (fd, buffer, sizeof (buffer))))
    {
      if (result < 0)
        err (EX_OSERR, "Read error");

      ARRAY_ADD_SEVERAL (buf, buffer, result);
    }
}

int
main (int argc, char** argv)
{
  struct vink_backend_callbacks callbacks;
  struct VINK_buffer buf;
  struct vink_message *message;
  int i;

  while ((i = getopt_long (argc, argv, "", long_options, 0)) != -1)
    {
      switch (i)
        {
        case 0:

          break;

        case '?':

          fprintf (stderr, "Try `%s --help' for more information.\n", argv[0]);

          return EXIT_FAILURE;
        }
    }

  if (print_help)
    {
      printf ("Usage: %s <SENDER> <RECIPIENT> [OPTION]...\n"
              "\n"
              "      --help     display this help and exit\n"
              "      --version  display version information\n"
              "\n"
              "Report bugs to <morten@rashbox.org>\n", argv[0]);

      return EXIT_SUCCESS;
    }

  if (print_version)
    {
      fprintf (stdout, "%s\n", PACKAGE_STRING);

      return EXIT_SUCCESS;
    }

  if (optind + 2 != argc)
    {
      fprintf (stderr,
               "Usage: %1$s <SENDER> <RECIPIENT> [OPTION]...\n"
               "Try `%1$s --help' for more information.\n", argv[0]);

      return EX_DATAERR;
    }

  openlog ("vink-maildrop", LOG_PID | LOG_PERROR, LOG_USER);

  if (-1 == vink_init ("/etc/vink.d/vink.conf", VINK_CLIENT, VINK_API_VERSION))
    errx (EXIT_FAILURE, "vink_init failed: %s", vink_last_error ());

  backend_init (&callbacks);

  read_to_buffer (0, &buf);

  message = vink_email_parse (&ARRAY_GET (&buf, 0), ARRAY_COUNT (&buf));

  callbacks.email.message (message);

  vink_message_free (message);

  return EXIT_SUCCESS;
}
