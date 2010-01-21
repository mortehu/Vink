#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <err.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <syslog.h>

#include "tree.h"
#include "server.h"
#include "vink.h"

static int print_version;
static int print_help;

static struct option long_options[] =
{
  { "version",        no_argument, &print_version, 1 },
  { "help",           no_argument, &print_help,    1 },
  { 0, 0, 0, 0 }
};

int
vink_daemon_main (int argc, char** argv)
{
  int i;

  signal (SIGPIPE, SIG_IGN);

  while ((i = getopt_long (argc, argv, "", long_options, 0)) != -1)
  {
    switch (i)
    {
    case 0: break;
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

  openlog ("vinkd", LOG_PID | LOG_PERROR, LOG_DAEMON);

  if (-1 == vink_init ("/etc/vink.d/vink.conf", 0, VINK_API_VERSION))
    errx (EXIT_FAILURE, "vink_init failed: %s", vink_last_error ());

  server_run ();

  return EXIT_SUCCESS;
}
