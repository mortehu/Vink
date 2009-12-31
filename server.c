/**
 * Connection and buffer handling.
 */

#ifndef CONFIG_H
#include "config.h"
#endif

#define USE_SELECT 1

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <syslog.h>
#include <unistd.h>

#include <ruli.h>

#include "array.h"
#include "backend.h"
#include "common.h"
#include "tree.h"
#include "vink.h"
#include "vink-internal.h"

struct peer
{
  int fd;
  int closing;

  struct sockaddr addr;
  socklen_t addrlen;

  pthread_mutex_t writebuf_mutex;
  struct buffer writebuf;

  struct vink_xmpp_state *state;
};

struct peer_array
{
  ARRAY_MEMBERS(struct peer *);
};

static struct peer_array peers;
static struct vink_backend_callbacks callbacks;

static void
net_addr_to_string(const void *addr, int addrlen, char *buf, int bufsize)
{
  getnameinfo(addr, addrlen, buf, bufsize, 0, 0, 0);
  buf[bufsize - 1] = 0;
}

static int
buffer_write(const void* data, size_t size, void* arg)
{
  struct peer *peer = arg;
  struct buffer *buf = &peer->writebuf;
  int result;

  pthread_mutex_lock(&peer->writebuf_mutex);

  if(!ARRAY_COUNT(buf))
    {
      result = write(peer->fd, data, size);

      if(result == -1)
        {
          pthread_mutex_unlock(&peer->writebuf_mutex);

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

  pthread_mutex_unlock(&peer->writebuf_mutex);

  return ARRAY_RESULT(buf);
}

static void
server_accept(int listen_fd)
{
  struct peer *peer;
  int fd;
  long one = 1;

  peer = calloc(1, sizeof(*peer));

  peer->addrlen = sizeof(peer->addr);

  if(-1 == (fd = accept(listen_fd, &peer->addr, &peer->addrlen)))
    {
      if(errno == EAGAIN || errno == ENETDOWN || errno == EPROTO
         || errno == ENOPROTOOPT || errno == EHOSTDOWN || errno == ENONET
         || errno == EHOSTUNREACH || errno == EOPNOTSUPP
         || errno == ENETUNREACH)
        return;

      err(EXIT_FAILURE, "accept failed");
    }

  fprintf(stderr, "Accepted connection\n");

  if(-1 == fcntl(fd, F_SETFL, O_NONBLOCK, one))
    err(EXIT_FAILURE, "failed to set socket to non-blocking");

  peer->fd = fd;
  ARRAY_INIT(&peer->writebuf);
  pthread_mutex_init(&peer->writebuf_mutex, 0);

  if(!(peer->state = vink_xmpp_state_init(buffer_write, 0, 0, peer)))
    {
      close(fd);

      syslog(LOG_WARNING, "failed to create XMPP state structure (out of memory?)");
    }

  vink_xmpp_set_callbacks(peer->state, &callbacks.xmpp);

  ARRAY_ADD(&peers, peer);

  if(ARRAY_RESULT(&peers) == -1)
    {
      close(fd);
      vink_xmpp_state_free(peer->state);

      syslog(LOG_WARNING, "failed to add peer to peer list: %s",
             strerror(errno));

      ARRAY_RESULT(&peers) = 0;
    }
}

struct vink_xmpp_state *
VINK_xmpp_server_connect(const char *domain)
{
  struct peer *peer;
  struct addrinfo *addrs = 0;
  struct addrinfo *addr;
  struct addrinfo hints;
  int fd = -1, one = 1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_protocol = getprotobyname("tcp")->p_proto;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;
  hints.ai_family = PF_UNSPEC;

  ruli_getaddrinfo(domain, "xmpp-server", &hints, &addrs);

  if(!addrs)
    ruli_getaddrinfo(domain, "jabber-server", &hints, &addrs);

  if(!addrs)
    {
      VINK_set_error("Failed to resolve '%s'", domain);

      return 0;
    }

  for(addr = addrs; addr; addr = addr->ai_next)
    {
      fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

      if(fd == -1)
        continue;

      if(-1 != connect(fd, addr->ai_addr, addr->ai_addrlen))
        break;

      VINK_set_error("Connect failed:", strerror(errno));

      close(fd);
      fd = -1;
    }

  ruli_freeaddrinfo(addrs);

  if(fd == -1)
    return 0;

  if(-1 == fcntl(fd, F_SETFL, O_NONBLOCK, one))
    VINK_set_error("Failed to set socket to non-blocking: %s", strerror(errno));

  peer = calloc(1, sizeof(*peer));

  peer->fd = fd;
  ARRAY_INIT(&peer->writebuf);

  if(!(peer->state = vink_xmpp_state_init(buffer_write, domain, 0, peer)))
    {
      VINK_set_error("Failed to create XMPP state structure: %s", vink_last_error());

      close(fd);

      return 0;
    }

  ARRAY_ADD(&peers, peer);

  if(ARRAY_RESULT(&peers) == -1)
    {
      VINK_set_error("Failed to add peer to peer list: %s", strerror(errno));

      close(fd);
      vink_xmpp_state_free(peer->state);

      ARRAY_RESULT(&peers) = 0;

      return 0;
    }

  return peer->state;
}

int
server_peer_count()
{
  return ARRAY_COUNT(&peers);
}

struct vink_xmpp_state *
server_peer_get_state(unsigned int peer_index)
{
  assert(peer_index < ARRAY_COUNT(&peers));

  return ARRAY_GET(&peers, peer_index)->state;
}

static int
server_peer_write(size_t peer_index)
{
  int result;
  struct peer *peer;
  struct buffer *b;

  peer = ARRAY_GET(&peers, peer_index);
  b = &peer->writebuf;

  pthread_mutex_lock(&peer->writebuf_mutex);

  while(ARRAY_COUNT(b))
    {
      result = write(peer->fd, &ARRAY_GET(b, 0), ARRAY_COUNT(b));

      if(result <= 0)
        {
          if(result == 0)
            break;

          if(result == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;

          close(peer->fd);

          peer->fd = -1;

          pthread_mutex_unlock(&peer->writebuf_mutex);

          return -1;
        }

      ARRAY_CONSUME(b, result);
    }

  pthread_mutex_unlock(&peer->writebuf_mutex);

  return 0;
}

static int
server_peer_read(size_t peer_index)
{
  char buf[4096];
  int result;
  struct peer *peer;

  peer = ARRAY_GET(&peers, peer_index);

  for(;;)
    {
      result = read(peer->fd, buf, sizeof(buf));

      if(result <= 0)
        {
          if(result == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;

          close(peer->fd);

          peer->fd = -1;

          return -1;
        }

       if(-1 == vink_xmpp_state_data(peer->state, buf, result))
         return -1;
    }

  return 0;
}

static void
server_peer_remove(size_t peer_index)
{
  struct peer *peer;

  peer = ARRAY_GET(&peers, peer_index);

  if(peer->fd >= 0)
    close(peer->fd);

  vink_xmpp_state_free(peer->state);

  --ARRAY_COUNT(&peers);

  memmove(peer, peer + 1, sizeof(*peer) * (ARRAY_COUNT(&peers) - peer_index));
}

void
server_run()
{
  char listen_addr[256];
  struct addrinfo *addrs = 0;
  struct addrinfo *addr;
  struct addrinfo hints;
  int ret;
  int listen_fd;
  int on = 1;

  const char *service;

  ARRAY_INIT(&peers);

  service = tree_get_string(VINK_config, "tcp.listen.port");

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_UNSPEC;

  ret = getaddrinfo(0, service, &hints, &addrs);

  if(ret)
    errx(EXIT_FAILURE, "getaddrinfo failed on service '%s': %s",
         service, gai_strerror(ret));

  for(addr = addrs; addr; addr = addr->ai_next)
    {
      listen_fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

      if(listen_fd == -1)
        continue;

      if(tree_get_bool(VINK_config, "tcp.listen.reuse-address")
         && -1 == setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
        err(EXIT_FAILURE, "failed to set SO_REUSEADDR on listening socket");

      if(-1 != bind(listen_fd, addr->ai_addr, addr->ai_addrlen))
        break;

      close(listen_fd);
    }

  if(!addr)
    errx(EXIT_FAILURE, "could not bind to service '%s'", service);

  net_addr_to_string(addr->ai_addr, addr->ai_addrlen, listen_addr,
                     sizeof(listen_addr));


  if(-1 == listen(listen_fd, tree_get_integer(VINK_config, "tcp.listen.backlog")))
    err(EXIT_FAILURE, "failed to start listening on '%s'", listen_addr);

  freeaddrinfo(addrs);

  syslog(LOG_INFO, "Listening on port '%s'", service);

  backend_init(&callbacks);

  for(;;)
    {
#if USE_SELECT
      struct peer *p;
      fd_set readset, writeset;
      int i, maxfd;

      maxfd = listen_fd;

      FD_ZERO(&readset);
      FD_ZERO(&writeset);

      FD_SET(listen_fd, &readset);

      for(i = 0; i < ARRAY_COUNT(&peers); )
        {
          p = ARRAY_GET(&peers, i);

          if(p->fd == -1)
            {
              server_peer_remove(i);

              continue;
            }

          FD_SET(p->fd, &readset);

          if(ARRAY_COUNT(&p->writebuf))
            FD_SET(p->fd, &writeset);
          else if(p->closing)
            {
              server_peer_remove(i);

              continue;
            }

          if(p->fd > maxfd)
            maxfd = p->fd;

          ++i;
        }

      if(-1 == select(maxfd + 1, &readset, &writeset, 0, 0))
        {
          if(errno == EAGAIN || errno == EINTR)
            continue;

          err(EXIT_FAILURE, "select failed");
        }

      for(i = 0; i < ARRAY_COUNT(&peers); )
        {
          p = ARRAY_GET(&peers, i);

          if(p->fd < 0)
            continue;

          if(FD_ISSET(p->fd, &writeset) && -1 == server_peer_write(i))
            {
              server_peer_remove(i);

              continue;
            }

          if(FD_ISSET(p->fd, &readset) && -1 == server_peer_read(i))
            p->closing = 1;

          ++i;
        }

      if(FD_ISSET(listen_fd, &readset))
        server_accept(listen_fd);
#else
#  error "No I/O multiplexing method selected."
#endif
    }
}
