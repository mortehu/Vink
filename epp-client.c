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
#include "common.h"
#include "vink.h"

struct tree *config;

static int print_version;
static int print_help;

struct
{
  ARRAY_MEMBERS(const char *);
} recipients;

static struct option long_options[] =
{
  { "recipient",      required_argument, 0, 'r' },
  { "version",        no_argument, &print_version, 1 },
  { "help",           no_argument, &print_help,    1 },
  { 0, 0, 0, 0 }
};

static void
read_to_buffer(int fd, struct buffer* buf)
{
  char buffer[1024];
  int result;

  ARRAY_INIT(buf);

  while(0 != (result = read(fd, buffer, sizeof(buffer))))
    {
      if(result < 0)
        err(EX_OSERR, "Read error");

      ARRAY_ADD_SEVERAL(buf, buffer, result);
    }
}

int
main(int argc, char **argv)
{
  char *config_path;
  struct vink_client* cl;
  struct buffer message;
  int i;

  while((i = getopt_long(argc, argv, "", long_options, 0)) != -1)
  {
    switch(i)
    {
    case 0:

      break;

    case 'r':

      ARRAY_ADD(&recipients, optarg);

      break;

    case '?':

      fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);

      return EXIT_FAILURE;
    }
  }

  if(print_help)
    {
      printf("Usage: %s [OPTION]...\n"
             "\n"
             "      --recipient=JID        send a message to the given recipient.  This\n"
             "                             option can be given multiple times to send\n"
             "                             copies to multiple addresses\n"
             "      --help     display this help and exit\n"
             "      --version  display version information\n"
             "\n"
             "Report bugs to <morten@rashbox.org>\n", argv[0]);

      return EXIT_SUCCESS;
    }

  if(print_version)
    {
      fprintf(stdout, "%s\n", PACKAGE_STRING);

      return EXIT_SUCCESS;
    }

  memset(&message, 0, sizeof(message));

  if(ARRAY_COUNT(&recipients))
    read_to_buffer(0, &message);

  if(!(config_path = getenv("HOME")))
    errx(EXIT_FAILURE, "HOME environment variable is not set");

  if(-1 == asprintf(&config_path, "%s/.config/vink/vink.conf", config_path))
    err(EXIT_FAILURE, "asprintf failed");

  vink_init(config_path, VINK_API_VERSION);
  free(config_path);

  cl = vink_client_alloc();
  vink_client_connect(cl, "epptest.norid.no", VINK_EPP);

  vink_client_run(cl);

  return EXIT_SUCCESS;
}
