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
#include "vink.h"

GCRY_THREAD_OPTION_PTHREAD_IMPL;

struct vink_client
{
  int fd;

  struct sockaddr addr;
  socklen_t addrlen;

  struct buffer writebuf;

  struct vink_xmpp_state *state;
};

gnutls_dh_params_t dh_params;
gnutls_certificate_credentials_t xcred;
gnutls_priority_t priority_cache;

void
vink_init(const char *config_path)
{
  const char *c;
  const char *ssl_certificates;
  const char *ssl_private_key;
  int res;

  gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
  gnutls_global_init();

  signal(SIGPIPE, SIG_IGN);

  openlog("vink", LOG_PID, LOG_USER);

  config = tree_load_cfg(config_path);

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

  ssl_certificates = tree_get_string_default(config, "ssl.certificates", 0);
  ssl_private_key = tree_get_string_default(config, "ssl.private-key", 0);

  if(!ssl_certificates ^ !ssl_private_key)
    errx(EXIT_FAILURE,
         "%s: Only one of 'ssl.certificates' and 'ssl.private-key' found",
         config_path);

  if(ssl_certificates && ssl_private_key)
    {
      if(0 > (res = gnutls_certificate_set_x509_key_file(xcred,
                                                         ssl_certificates,
                                                         ssl_private_key,
                                                         GNUTLS_X509_FMT_PEM)))
        errx(EXIT_FAILURE, "error loading certificates: %s",
             gnutls_strerror(res));
    }

  gnutls_certificate_set_dh_params(xcred, dh_params);

  gnutls_priority_init(&priority_cache, "NONE:+VERS-TLS1.0:+AES-128-CBC:+RSA:+SHA1:+COMP-NULL", &c);
}

struct vink_client *
vink_client_alloc()
{
  return calloc(sizeof(struct vink_client), 1);
}

struct vink_xmpp_state *
vink_client_state(struct vink_client *cl)
{
  return cl->state;
}

static int
buffer_write(const void* data, size_t size, void* arg)
{
  struct buffer *buf = arg;

  ARRAY_ADD_SEVERAL(buf, data, size);

  return ARRAY_RESULT(buf);
}

int
vink_client_connect(struct vink_client *cl, const char *domain)
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

  if(!(cl->state = vink_xmpp_state_init(buffer_write, domain, VINK_CLIENT, &cl->writebuf)))
    errx(EXIT_FAILURE, "failed to create XMPP state structure (out of memory?)\n");

  return 0;
}

static int
VINK_client_write(struct vink_client *cl)
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
VINK_client_read(struct vink_client *cl)
{
  char buf[4096];
  int result;

  for(;;)
    {
      result = read(cl->fd, buf, sizeof(buf));

      if(result <= 0
         || -1 == vink_xmpp_state_data(cl->state, buf, result))
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

void
vink_client_run(struct vink_client *cl)
{
  while(!vink_xmpp_state_finished(cl->state))
    {
      fd_set readset, writeset;
      int maxfd;

      FD_ZERO(&readset);
      FD_ZERO(&writeset);

      if(ARRAY_COUNT(&cl->writebuf))
        FD_SET(cl->fd, &writeset);
      FD_SET(cl->fd, &readset);
      maxfd = cl->fd;

      if(-1 == select(maxfd + 1, &readset, &writeset, 0, 0))
        {
          if(errno == EAGAIN || errno == EINTR)
            continue;

          err(EXIT_FAILURE, "select failed");
        }

      if(FD_ISSET(cl->fd, &writeset) && -1 == VINK_client_write(cl))
        err(EX_OSERR, "Write to server failed");

      if(FD_ISSET(cl->fd, &readset)
         && -1 == VINK_client_read(cl)
         && !vink_xmpp_state_finished(cl->state))
        err(EX_OSERR, "Read from server failed");
    }
}

char*
vink_xml_escape(const char* data, size_t size)
{
  size_t i;
  struct buffer result;

  ARRAY_INIT(&result);

  for(i = 0; i < size; ++i)
    {
      int ch;

      ch = data[i];

      switch(ch)
        {
        case 0:

          ARRAY_ADD_SEVERAL(&result, "&#00;", 5);

          break;

        case '<':

          ARRAY_ADD_SEVERAL(&result, "&lt;", 4);

          break;

        case '&':

          ARRAY_ADD_SEVERAL(&result, "&amp;", 5);

          break;


        default:

          ARRAY_ADD(&result, ch);
        }
    }

  ARRAY_ADD(&result, 0);

  return &ARRAY_GET(&result, 0);
}
