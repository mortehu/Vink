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
#include <syslog.h>
#include <unistd.h>

#include "common.h"
#include "peer.h"
#include "protocol.h"
#include "tree.h"

static pthread_t poll_thread;

static void
net_addr_to_string(const void* addr, int addrlen, char* buf, int bufsize)
{
  getnameinfo(addr, addrlen, buf, bufsize, 0, 0, 0);
  buf[bufsize - 1] = 0;
}

void*
poll_thread_entry()
{
  /*
  struct proto_stanza request;
  struct proto_stanza reply;

  request.type = proto_iq_ping;

  proto_request("acmewave.com", &request, &reply);

  proto_request("acmewave.com", &request, &reply);
*/
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
  int on = 1;

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

  pthread_create(&poll_thread, 0, poll_thread_entry, 0);

  for(;;)
    {
      int fd;
      struct sockaddr addr;
      socklen_t addrlen;

      addrlen = sizeof(addr);
      fd = accept(listen_fd, &addr, &addrlen);

      if(fd == -1)
        {
          if(errno == EAGAIN || errno == ENETDOWN || errno == EPROTO
             || errno == ENOPROTOOPT || errno == EHOSTDOWN || errno == ENONET
             || errno == EHOSTUNREACH || errno == EOPNOTSUPP
             || errno == ENETUNREACH)
            continue;

          err(EXIT_FAILURE, "accept failed");
        }

      peer_add(fd);
    }
}
