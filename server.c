/**
 * Connection and buffer handling.
 */

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
#include <syslog.h>
#include <unistd.h>

#include "array.h"
#include "common.h"
#include "peer.h"
#include "protocol.h"
#include "tree.h"

struct peer
{
  int fd;

  struct sockaddr addr;
  socklen_t addrlen;

  struct buffer writebuf;

  struct xmpp_state state;
};

struct peer_array
{
  ARRAY_MEMBERS(struct peer*);
};

struct peer_array peers;

static void
net_addr_to_string(const void* addr, int addrlen, char* buf, int bufsize)
{
  getnameinfo(addr, addrlen, buf, bufsize, 0, 0, 0);
  buf[bufsize - 1] = 0;
}

static void
server_accept(int listen_fd)
{
  struct peer* peer;
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

  if(-1 == fcntl(fd, F_SETFL, O_NONBLOCK, one))
    err(EXIT_FAILURE, "failed to set socket to non-blocking");

  peer->fd = fd;
  ARRAY_INIT(&peer->writebuf);

  if(-1 == xmpp_state_init(&peer->state, &peer->writebuf))
    {
      close(fd);

      syslog(LOG_WARNING, "failed to create XMPP state structure (out of memory?)");
    }

  ARRAY_ADD(&peers, peer);

  if(ARRAY_RESULT(&peers) == -1)
    {
      close(fd);
      xmpp_state_free(&peer->state);

      syslog(LOG_WARNING, "failed to add peer to peer list: %s",
             strerror(errno));
    }
}

static int
server_peer_write(size_t peer_index)
{
  int result;
  struct peer* p;
  struct buffer* b;

  p = ARRAY_GET(&peers, peer_index);
  b = &p->writebuf;

  while(ARRAY_COUNT(b))
    {
      result = write(p->fd, &ARRAY_GET(b, 0), ARRAY_COUNT(b));

      if(result <= 0)
        {
          /*
          XXX: Need this?
          if(result == 0)
            return 0;
            */

          if(result == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;

          close(p->fd);

          p->fd = -1;

          return -1;
        }

      ARRAY_CONSUME(b, result);
    }

  return 0;
}

static int
server_peer_read(size_t peer_index)
{
  char buf[4096];
  int result;
  struct peer* p;

  p = ARRAY_GET(&peers, peer_index);

  for(;;)
    {
      result = read(p->fd, buf, sizeof(buf));

      if(result <= 0
         || -1 == xmpp_state_data(&p->state, buf, result))
        {
          if(result == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;

          close(p->fd);

          p->fd = -1;

          return -1;
        }
    }

  return 0;
}

static void
server_peer_remove(size_t peer_index)
{
  struct peer* p;

  p = ARRAY_GET(&peers, peer_index);

  xmpp_state_free(&p->state);

  --ARRAY_COUNT(&peers);

  memmove(p, p + 1, sizeof(*p) * (ARRAY_COUNT(&peers) - peer_index));
}

void
server_run()
{
  char listen_addr[256];
  struct addrinfo* addrs = 0;
  struct addrinfo* addr;
  struct addrinfo hints;
  int ret;
  int listen_fd;
  int on = 1;

  const char* service;

  ARRAY_INIT(&peers);

  service = tree_get_string(config, "tcp.listen.port");

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

      if(tree_get_bool(config, "tcp.listen.reuse-address")
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


  if(-1 == listen(listen_fd, tree_get_integer(config, "tcp.listen.backlog")))
    err(EXIT_FAILURE, "failed to start listening on '%s'", listen_addr);

  freeaddrinfo(addrs);

  syslog(LOG_INFO, "Listening on port '%s'", service);

  for(;;)
    {
#if USE_SELECT
      struct peer* p;
      fd_set readset, writeset;
      int i, maxfd;

      maxfd = listen_fd;

      FD_ZERO(&readset);
      FD_ZERO(&writeset);

      FD_SET(listen_fd, &readset);

      for(i = 0; i < ARRAY_COUNT(&peers); ++i)
        {
          p = ARRAY_GET(&peers, i);

          FD_SET(p->fd, &readset);

          if(ARRAY_COUNT(&p->writebuf))
            FD_SET(p->fd, &writeset);

          if(p->fd > maxfd)
            maxfd = p->fd;
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

          if(FD_ISSET(p->fd, &writeset) && -1 == server_peer_write(i))
            {
              server_peer_remove(i);

              continue;
            }

          if(FD_ISSET(p->fd, &readset) && -1 == server_peer_read(i))
            {
              server_peer_remove(i);

              continue;
            }

          ++i;
        }

      if(FD_ISSET(listen_fd, &readset))
        server_accept(listen_fd);
#else
#  error "No I/O multiplexing method selected."
#endif
    }
}
