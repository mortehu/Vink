#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ruli_getaddrinfo.h>

#include "common.h"
#include "peer.h"
#include "tree.h"

static pthread_t poll_thread;

static void
net_addr_to_string(const void* addr, int addrlen, char* buf, int bufsize)
{
  getnameinfo(addr, addrlen, buf, bufsize, 0, 0, 0);
  buf[bufsize - 1] = 0;
}

int
create_channel(const char* domain)
{
  struct addrinfo* addrs = 0;
  struct addrinfo* addr;
  struct addrinfo hints;
  int result = -1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_protocol = getprotobyname("tcp")->p_proto;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;
  hints.ai_family = PF_UNSPEC;

  ruli_getaddrinfo(domain, "xmpp-server", &hints, &addrs);

  if(!addrs)
    ruli_getaddrinfo(domain, "jabber-server", &hints, &addrs);

  for(addr = addrs; addr; addr = addr->ai_next)
    {
      result = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

      if(result == -1)
        continue;

      if(-1 != connect(result, addr->ai_addr, addr->ai_addrlen))
        break;

      close(result);
      result = -1;
    }

  ruli_freeaddrinfo(addrs);

  return result;
}

void*
poll_thread_entry()
{
  int fd = create_channel("acmewave.com");

  if(fd != -1)
    {
      struct peer_arg* pca;
      pthread_t peer_thread;

      pca = malloc(sizeof(*pca));
      memset(pca, 0, sizeof(*pca));
      pca->addrlen = sizeof(pca->addr);
      pca->fd = fd;
      pca->is_initiator = 1;
      pca->remote_name = strdup("acmewave.com");

      fprintf(stderr, "Connected to %s\n", pca->remote_name);

      pthread_create(&peer_thread, 0, peer_thread_entry, pca);
    }

  return 0;
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

  const char* service = tree_get_string(config, "tcp.listen.port");

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

  pthread_create(&poll_thread, 0, poll_thread_entry, 0);

  for(;;)
    {
      struct peer_arg* pca;
      struct peer_arg ca;
      pthread_t peer_thread;

      memset(&ca, 0, sizeof(ca));
      ca.addrlen = sizeof(ca.addr);
      ca.fd = accept(listen_fd, &ca.addr, &ca.addrlen);

      if(ca.fd == -1)
        {
          if(errno == EAGAIN || errno == ENETDOWN || errno == EPROTO
             || errno == ENOPROTOOPT || errno == EHOSTDOWN || errno == ENONET
             || errno == EHOSTUNREACH || errno == EOPNOTSUPP
             || errno == ENETUNREACH)
            continue;

          err(EXIT_FAILURE, "accept failed");
        }

      fprintf(stderr, "Got connection\n");

      pca = malloc(sizeof(*pca));
      memcpy(pca, &ca, sizeof(*pca));

      pthread_create(&peer_thread, 0, peer_thread_entry, pca);
    }
}
