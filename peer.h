#ifndef CLIENT_H_
#define CLIENT_H_ 1

#include <sys/socket.h>

#include "protocol.h"

struct peer_arg
{
  int fd;
  struct sockaddr addr;
  socklen_t addrlen;

  char* remote_name;

  unsigned int major_version;
  unsigned int minor_version;

  unsigned int tag_depth;

  int do_ssl;
  gnutls_session_t session;

  unsigned int is_initiator : 1;
  unsigned int is_authenticated : 1;

  int fatal;

  struct proto_stanza stanza;
};

void*
peer_thread_entry(void* arg);

#endif /* !CLIENT_H_ */
