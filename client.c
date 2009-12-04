#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <syslog.h>
#include <sysexits.h>

#include <gcrypt.h>

#include <ruli.h>

#include "array.h"
#include "common.h"
#include "tree.h"
#include "xmpp.h"

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

GCRY_THREAD_OPTION_PTHREAD_IMPL;

gnutls_dh_params_t dh_params;
gnutls_certificate_credentials_t xcred;
gnutls_priority_t priority_cache;

struct client
{
  int fd;

  struct sockaddr addr;
  socklen_t addrlen;

  struct buffer writebuf;

  struct xmpp_state *state;
};

int
client_connect(struct client *cl, const char *domain)
{
  struct addrinfo *addrs = 0;
  struct addrinfo *addr;
  struct addrinfo hints;
  int fd = -1, one = 1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_protocol = getprotobyname("tcp")->p_proto;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;
  hints.ai_family = PF_UNSPEC;

  ruli_getaddrinfo(domain, "xmpp-client", &hints, &addrs);

  if(!addrs)
    err(EXIT_FAILURE, "No servers found for domain '%s'", domain);

  for(addr = addrs; addr; addr = addr->ai_next)
    {
      fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

      if(fd == -1)
        continue;

      if(-1 != connect(fd, addr->ai_addr, addr->ai_addrlen))
        break;

      close(fd);
      fd = -1;
    }

  ruli_freeaddrinfo(addrs);

  if(fd == -1)
    err(EXIT_FAILURE, "Connection to domain '%s' failed", domain);

  if(-1 == fcntl(fd, F_SETFL, O_NONBLOCK, one))
    err(EXIT_FAILURE, "failed to set socket to non-blocking");

  cl->fd = fd;
  ARRAY_INIT(&cl->writebuf);

  if(!(cl->state = xmpp_state_init(&cl->writebuf, domain, XMPP_CLIENT)))
    errx(EXIT_FAILURE, "failed to create XMPP state structure (out of memory?)\n");

  return 0;
}

static int
client_write(struct client *cl)
{
  int result;
  struct buffer *b;

  b = &cl->writebuf;

  while(ARRAY_COUNT(b))
    {
      result = write(cl->fd, &ARRAY_GET(b, 0), ARRAY_COUNT(b));

      if(result <= 0)
        {
          if(result == 0)
            return 0;

          if(result == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;

          close(cl->fd);

          cl->fd = -1;

          return -1;
        }

      ARRAY_CONSUME(b, result);
    }

  return 0;
}

static int
client_read(struct client *cl)
{
  char buf[4096];
  int result;

  for(;;)
    {
      result = read(cl->fd, buf, sizeof(buf));

      if(result <= 0
         || -1 == xmpp_state_data(cl->state, buf, result))
        {
          if(result == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;

          close(cl->fd);

          cl->fd = -1;

          return -1;
        }
    }

  return 0;
}

static void
client_message(struct xmpp_state *state, const char *from, const char *to,
               const char *body)
{
  fprintf(stderr, "From: %s\nTo: %s\nContent-Length: %zu\n\n%s\n",
          from, to, strlen(body), body);
}

static void
client_idle(struct xmpp_state *state)
{
  /* We were only supposed to send one message, so we can safely terminate the stream now */
  if(ARRAY_COUNT(&recipients))
    xmpp_end_stream(state);
}

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
  struct xmpp_callbacks callbacks;
  struct client cl;
  struct buffer message;
  struct buffer escaped_message;
  int i, res;
  const char *c;

  gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
  gnutls_global_init();

  signal(SIGPIPE, SIG_IGN);

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

  openlog("vink", LOG_PID, LOG_USER);

  if(getuid() == 0)
    config = tree_load_cfg("/etc/vink.d/vink.conf");
  else
    {
      char *path;

      if(!(path = getenv("HOME")))
        errx(EXIT_FAILURE, "HOME environment variable is not set");

      if(-1 == asprintf(&path, "%s/.config/vink/vink.conf", path))
        err(EXIT_FAILURE, "asprintf failed");

      config = tree_load_cfg(path);

      free(path);
    }

  if(0 > (res = gnutls_dh_params_init(&dh_params)))
    errx(EXIT_FAILURE, "Error initializing Diffie-Hellman parameters: %s",
         gnutls_strerror(res));

  if(0 > gnutls_dh_params_generate2(dh_params, 1024))
    errx(EXIT_FAILURE, "Error generating Diffie-Hellman parameters: %s",
         gnutls_strerror(res));

  if(0 > (res = gnutls_certificate_allocate_credentials(&xcred)))
    errx(EXIT_FAILURE, "Error allocating certificate credentials: %s",
         gnutls_strerror(res));

  if(0 > (res = gnutls_certificate_set_x509_trust_file(xcred, CA_CERT_FILE,
                                                       GNUTLS_X509_FMT_PEM)))
    errx(EXIT_FAILURE, "Error setting X.509 trust file: %s", gnutls_strerror(res));

  gnutls_certificate_set_dh_params(xcred, dh_params);

  gnutls_priority_init(&priority_cache, "NONE:+VERS-TLS1.0:+AES-128-CBC:+RSA:+SHA1:+COMP-NULL", &c);

  client_connect(&cl, "idium.net");

  callbacks.message = client_message;
  callbacks.queue_empty = client_idle;

  xmpp_state_set_callbacks(cl.state, &callbacks);

  if(!ARRAY_COUNT(&recipients))
    {
      xmpp_queue_stanza2(cl.state, "<presence from='%s@%s'/>",
                         tree_get_string(config, "user"),
                         tree_get_string(config, "domain"));
    }
  else
    {
      size_t i;

      ARRAY_INIT(&escaped_message);

      for(i = 0; i < ARRAY_COUNT(&message); ++i)
        {
          int ch;

          ch = ARRAY_GET(&message, i);

          switch(ch)
            {
            case '0':

              ARRAY_ADD_SEVERAL(&escaped_message, "&#00;", 5);

              break;

            case '<':

              ARRAY_ADD_SEVERAL(&escaped_message, "&lt;", 4);

              break;

            case '&':

              ARRAY_ADD_SEVERAL(&escaped_message, "&amp;", 5);

              break;


            default:

              ARRAY_ADD(&escaped_message, ch);
            }
        }

      ARRAY_ADD(&escaped_message, 0);

      for(i = 0; i < ARRAY_COUNT(&recipients); ++i)
        {
          xmpp_send_message(cl.state, ARRAY_GET(&recipients, i),
                            &ARRAY_GET(&escaped_message, 0));
        }
    }

  while(!xmpp_state_finished(cl.state))
    {
      fd_set readset, writeset;
      int maxfd;

      FD_ZERO(&readset);
      FD_ZERO(&writeset);

      if(ARRAY_COUNT(&cl.writebuf))
        FD_SET(cl.fd, &writeset);
      FD_SET(cl.fd, &readset);
      maxfd = cl.fd;

      if(-1 == select(maxfd + 1, &readset, &writeset, 0, 0))
        {
          if(errno == EAGAIN || errno == EINTR)
            continue;

          err(EXIT_FAILURE, "select failed");
        }

      if(FD_ISSET(cl.fd, &writeset) && -1 == client_write(&cl))
        err(EX_OSERR, "Write to server failed");

      if(FD_ISSET(cl.fd, &readset)
         && -1 == client_read(&cl)
         && !xmpp_state_finished(cl.state))
        err(EX_OSERR, "Read from server failed");
    }

  return EXIT_SUCCESS;
}
