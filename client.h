#ifndef CLIENT_H_
#define CLIENT_H_ 1

#include <sys/socket.h>

struct client_arg
{
  int fd;
  struct sockaddr addr;
  socklen_t addrlen;

  gnutls_session_t session;
};

void*
client_thread_entry(void* arg);

#endif /* !CLIENT_H_ */
