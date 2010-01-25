#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <sysexits.h>
#include <unistd.h>

#include "array.h"
#include "vink.h"

static int print_version;
static int print_help;

static struct option long_options[] =
{
  { "version",        no_argument, &print_version, 1 },
  { "help",           no_argument, &print_help,    1 },
  { 0, 0, 0, 0 }
};

const char *
object_types[] =
{
  "urn:ietf:params:xml:ns:domain-1.0",
  "urn:ietf:params:xml:ns:contact-1.0",
  "urn:ietf:params:xml:ns:host-1.0"
};

static void
response (struct vink_epp_state *state,
          const char *transaction_id,
          const struct vink_tree *data)
{
  fprintf (stderr, "Got response\n");
}

int
main (int argc, char **argv)
{
  char *config_path;
  struct vink_client* cl;
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
      printf ("Usage: %s [OPTION]...\n"
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

  if (!(config_path = getenv ("HOME")))
    errx (EXIT_FAILURE, "HOME environment variable is not set");

  if (-1 == asprintf (&config_path, "%s/.config/vink/vink.conf", config_path))
    err (EXIT_FAILURE, "asprintf failed");

  if (-1 == vink_init (config_path, VINK_CLIENT, VINK_API_VERSION))
    errx (EXIT_FAILURE, "vink_init failed: %s", vink_last_error ());

  free (config_path);

  if (0 == (cl = vink_client_alloc ()))
    errx (EXIT_FAILURE, "vink_client_alloc failed: %s", vink_last_error ());

  for (i = 0; i < sizeof (object_types) / sizeof (object_types[0]); ++i)
    {
      if(-1 == vink_epp_register_object_type (cl, object_types[i]))
        {
          errx (EXIT_FAILURE, "vink_epp_register_object_type failed: %s",
                vink_last_error ());
        }
    }

  if (-1 == vink_client_connect (cl, "epptest.norid.no", VINK_EPP))
    errx (EXIT_FAILURE, "vink_client_connect failed: %s", vink_last_error ());

  if (-1 == vink_client_run (cl))
    errx (EXIT_FAILURE, "vink_client_run failed: %s", vink_last_error ());

  return EXIT_SUCCESS;
}
