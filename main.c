#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include <gcrypt.h>

#include "common.h"
#include "tree.h"
#include "server.h"

struct tree* config;

static int print_version;
static int print_help;

static struct option long_options[] =
{
  { "version",        no_argument, &print_version, 1 },
  { "help",           no_argument, &print_help,    1 },
  { 0, 0, 0, 0 }
};

GCRY_THREAD_OPTION_PTHREAD_IMPL;

gnutls_dh_params_t dh_params;
gnutls_certificate_credentials_t xcred;
gnutls_priority_t priority_cache;

int
main(int argc, char** argv)
{
  int i, res;
  const char* c;

  gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
  gnutls_global_init();

  while((i = getopt_long(argc, argv, "", long_options, 0)) != -1)
  {
    switch(i)
    {
    case 0: break;
    case '?':

      fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);

      return EXIT_FAILURE;
    }
  }

  if(print_help)
    {
      printf("Usage: %s [OPTION]...\n"
             "\n"
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

  config = tree_load_cfg("/etc/vink.d/vink.conf");

  if(0 > (res = gnutls_dh_params_init(&dh_params)))
    errx(EXIT_FAILURE, "error initializing Diffie-Hellman parameters: %s",
         gnutls_strerror(res));

  if(0 > gnutls_dh_params_generate2(dh_params, 1024))
    errx(EXIT_FAILURE, "error generating Diffie-Hellman parameters: %s",
         gnutls_strerror(res));

  if(0 > (res = gnutls_certificate_allocate_credentials(&xcred)))
    errx(EXIT_FAILURE, "error allocating certificate credentials: %s",
         gnutls_strerror(res));

  if(0 > (res = gnutls_certificate_set_x509_key_file(xcred,
                                                     tree_get_string(config, "ssl.certificates"),
                                                     tree_get_string(config, "ssl.private-key"),
                                                      GNUTLS_X509_FMT_PEM)))
    errx(EXIT_FAILURE, "error loading certificates: %s", gnutls_strerror(res));

  gnutls_certificate_set_dh_params(xcred, dh_params);

  gnutls_priority_init(&priority_cache, "NONE:+VERS-TLS1.0:+AES-128-CBC:+RSA:+SHA1:+COMP-NULL", &c);

  server_run();

  return EXIT_SUCCESS;
}
