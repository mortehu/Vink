#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <syslog.h>
#include <sysexits.h>

#include <gcrypt.h>
#include <ruli.h>

#include "arena.h"
#include "array.h"
#include "common.h"
#include "io.h"
#include "tree.h"
#include "vink.h"

GCRY_THREAD_OPTION_PTHREAD_IMPL;

struct tree* VINK_config;

struct vink_client
{
  int fd;

  struct sockaddr addr;
  socklen_t addrlen;

  pthread_mutex_t writebuf_mutex;
  struct buffer writebuf;

  enum vink_protocol protocol;

  void *state;
};

gnutls_dh_params_t dh_params;
gnutls_certificate_credentials_t xcred;
#if LIBGNUTLS_VERSION_NUMBER >= 0x020600
gnutls_priority_t priority_cache;
#endif

static __thread char* VINK_last_error;

const char *
vink_last_error()
{
  return VINK_last_error ? VINK_last_error : strerror(errno);
}

void
VINK_clear_error()
{
  free(VINK_last_error);
  VINK_last_error = 0;
}

void
VINK_set_error(const char *format, ...)
{
  va_list args;
  char* prev_error;

  prev_error = VINK_last_error;

  va_start(args, format);

  vasprintf(&VINK_last_error, format, args);

  free(prev_error);
}

int
vink_init(const char *config_path, unsigned int flags, unsigned int version)
{
  const char *c;
  const char *ssl_certificates;
  const char *ssl_private_key;
  const char *dh_cache_path;
  int fd, res;

  gnutls_datum prime, generator;
  uint32_t size;

  VINK_clear_error();

  gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
  gnutls_global_init();

  signal(SIGPIPE, SIG_IGN);

  VINK_config = tree_load_cfg(config_path);

  if(0 > (res = gnutls_certificate_allocate_credentials(&xcred)))
    {
      VINK_set_error("Error allocating certificate credentials: %s",
                     gnutls_strerror(res));

      return -1;
    }

  if(!(flags & VINK_CLIENT))
    {
      dh_cache_path = tree_get_string(VINK_config, "ssl.dh-cache");

      if(0 > (res = gnutls_dh_params_init(&dh_params)))
        {
          VINK_set_error("Error initializing Diffie-Hellman parameters: %s",
                         gnutls_strerror(res));

          return -1;
        }

      fd = open(dh_cache_path, O_RDONLY);

      if(fd == -1)
        {
          if(errno != ENOENT)
            {
              VINK_set_error("Failed to access Diffie-Hellman cache '%s': %s",
                             dh_cache_path, strerror(errno));

              return -1;
            }

          if(0 > gnutls_dh_params_generate2(dh_params, 1024))
            {
              VINK_set_error("Error generating Diffie-Hellman parameters: %s",
                             gnutls_strerror(res));

              return -1;
            }


          fd = open(dh_cache_path, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0600);

          if(fd != -1)
            {
              gnutls_dh_params_export_raw(dh_params, &prime, &generator, 0);

              size = htonl(prime.size);
              if(-1 == write_all(fd, &size, sizeof(size), dh_cache_path)
                 || -1 == write_all(fd, &prime.data, prime.size, dh_cache_path))
                return -1;

              size = htonl(generator.size);

              if(-1 == write_all(fd, &size, sizeof(size), dh_cache_path)
                 || -1 == write_all(fd, &generator.data, generator.size, dh_cache_path))
                return -1;

              close(fd);
            }
        }
      else
        {
          read_all(fd, &size, sizeof(size), dh_cache_path);
          prime.size = ntohl(size);
          prime.data = malloc(prime.size);
          read_all(fd, prime.data, prime.size, dh_cache_path);

          read_all(fd, &size, sizeof(size), dh_cache_path);
          generator.size = ntohl(size);
          generator.data = malloc(generator.size);
          read_all(fd, generator.data, generator.size, dh_cache_path);

          gnutls_dh_params_import_raw(dh_params, &prime, &generator);

          close(fd);
        }

      gnutls_certificate_set_dh_params(xcred, dh_params);
    }

  if(0 > (res = gnutls_certificate_set_x509_trust_file(xcred, CA_CERT_FILE,
                                                       GNUTLS_X509_FMT_PEM)))
    {
      VINK_set_error("Error setting X.509 trust file: %s", gnutls_strerror(res));

      return -1;
    }

  ssl_certificates = tree_get_string_default(VINK_config, "ssl.certificates", 0);
  ssl_private_key = tree_get_string_default(VINK_config, "ssl.private-key", 0);

  if(!ssl_certificates ^ !ssl_private_key)
    {
      VINK_set_error("%s: Only one of 'ssl.certificates' and 'ssl.private-key' found",
                     config_path);

      return -1;
    }

  if(ssl_certificates && ssl_private_key)
    {
      if(0 > (res = gnutls_certificate_set_x509_key_file(xcred,
                                                         ssl_certificates,
                                                         ssl_private_key,
                                                         GNUTLS_X509_FMT_PEM)))
        {
          VINK_set_error("Error loading certificates/private key (\"%s\" and \"%s\"): %s",
                         ssl_certificates, ssl_private_key, gnutls_strerror(res));

          return -1;
        }
    }

#if LIBGNUTLS_VERSION_NUMBER >= 0x020600
  gnutls_priority_init(&priority_cache, "NONE:+VERS-TLS1.0:+AES-128-CBC:+RSA:+SHA1:+COMP-NULL", &c);
#endif

  return 0;
}

const char *
vink_config(const char *key)
{
  return tree_get_string(VINK_config, key);
}

void
vink_message_free(struct vink_message *message)
{
  arena_free(message->_private);
}

struct vink_client *
vink_client_alloc()
{
  VINK_clear_error();

  return calloc(sizeof(struct vink_client), 1);
}

void *
vink_client_state(struct vink_client *cl)
{
  VINK_clear_error();

  return cl->state;
}

static int
buffer_write(const void* data, size_t size, void* arg)
{
  struct vink_client *cl = arg;
  struct buffer *buf = &cl->writebuf;
  int result;

  pthread_mutex_lock(&cl->writebuf_mutex);

  if(!ARRAY_COUNT(buf))
    {
      result = write(cl->fd, data, size);

      if(result == -1)
        {
          pthread_mutex_unlock(&cl->writebuf_mutex);

          return -1;
        }

      data = (const char*) data + result;
      size -= result;
    }

  if(size)
    {
      ARRAY_ADD_SEVERAL(buf, data, size);

      /* XXX: Awaken select */
    }

  pthread_mutex_unlock(&cl->writebuf_mutex);

  return ARRAY_RESULT(buf);
}

int
vink_client_connect(struct vink_client *cl, const char *domain,
                    enum vink_protocol protocol)
{
  struct addrinfo *addrs = 0;
  struct addrinfo *addr;
  struct addrinfo hints;
  int fd = -1, one = 1;

  VINK_clear_error();

  memset(&hints, 0, sizeof(hints));
  hints.ai_protocol = getprotobyname("tcp")->p_proto;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;
  hints.ai_family = PF_UNSPEC;

  switch(protocol)
    {
    case VINK_XMPP:

      ruli_getaddrinfo(domain, "xmpp-client", &hints, &addrs);

      break;

    case VINK_EPP:

      getaddrinfo(domain, "7000", &hints, &addrs);

      break;

    default:

      VINK_set_error("Unknown protocol id '%d' passed to vink_client_connect",
                     protocol);

      return -1;
    }


  if(!addrs)
    {
      VINK_set_error("No servers found for domain '%s'", domain);

      return -1;
    }

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

  switch(protocol)
    {
    case VINK_XMPP:

      ruli_freeaddrinfo(addrs);

      break;

    default:

      freeaddrinfo(addrs);
    }

  if(fd == -1)
    {
      VINK_set_error("Connection to domain '%s' failed: %s", domain, strerror(errno));

      return -1;
    }

  if(-1 == fcntl(fd, F_SETFL, O_NONBLOCK, one))
    {
      VINK_set_error("Failed to set socket to non-blocking: %s", strerror(errno));

      return -1;
    }

  cl->fd = fd;
  ARRAY_INIT(&cl->writebuf);
  pthread_mutex_init(&cl->writebuf_mutex, 0);
  cl->protocol = protocol;

  switch(protocol)
    {
    case VINK_XMPP:

      if(!(cl->state = vink_xmpp_state_init(buffer_write, domain, VINK_CLIENT, cl)))
        return -1;

      break;

    case VINK_EPP:

      if(!(cl->state = vink_epp_state_init(buffer_write, domain, VINK_CLIENT, cl)))
        return -1;

      break;

    default:

      assert(!"unsupported protocol");
    }

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
            {
              VINK_set_error("Failed to write to peer: write returned 0");

              return -1;
            }

          if(result == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;

          VINK_set_error("Failed to write to peer: %s", strerror(errno));

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

      if(result <= 0)
        {
          if(result == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;

          VINK_set_error("Failed to read from peer: %s", strerror(errno));

          close(cl->fd);

          cl->fd = -1;

          return -1;
        }

      switch(cl->protocol)
        {
        case VINK_XMPP:

          result = vink_xmpp_state_data(cl->state, buf, result);

          break;

        case VINK_EPP:

          result = vink_epp_state_data(cl->state, buf, result);

          break;

        default:

          assert(!"unsupported protocol");
        }

      if(result == -1)
        {
          close(cl->fd);

          cl->fd = -1;

          return -1;
        }
    }

  return 0;
}

int
vink_client_run(struct vink_client *cl)
{
  int (*finished)(void *state);

  VINK_clear_error();

  switch(cl->protocol)
    {
    case VINK_XMPP:

      finished = (void*) vink_xmpp_state_finished;

      break;

    case VINK_EPP:

      finished = (void*) vink_epp_state_finished;

      break;

    default:

      VINK_set_error("vink_client_run: Unknown protocol %u", cl->protocol);

      return -1;
    }

  while(!finished(cl->state))
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

          VINK_set_error("The select system call failed: %s", strerror(errno));

          return -1;
        }

      if(FD_ISSET(cl->fd, &writeset) && -1 == VINK_client_write(cl))
        return -1;

      if(FD_ISSET(cl->fd, &readset) && -1 == VINK_client_read(cl))
        return -1;
    }

  return 0;
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
