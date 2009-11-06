#ifndef CLIENT_H_
#define CLIENT_H_ 1

#include <sys/socket.h>

enum peer_state
{
  ps_none = 0,
  ps_unknown,
  ps_auth,
  ps_features,
  ps_proceed
};

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

  int is_initiator;

  int fatal;

  enum peer_state state;
};

void*
peer_thread_entry(void* arg);

#endif /* !CLIENT_H_ */
