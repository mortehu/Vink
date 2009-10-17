#ifndef CLIENT_H_
#define CLIENT_H_ 1

#include <sys/socket.h>

struct client_arg
{
  int fd;
  struct sockaddr addr;
  socklen_t addrlen;

  unsigned int major_version;
  unsigned int minor_version;

  unsigned int tag_depth;

  int do_ssl;
  gnutls_session_t session;

  int fatal;
};

void*
client_thread_entry(void* arg);

#endif /* !CLIENT_H_ */
