#ifndef CLIENT_H_
#define CLIENT_H_ 1

#include <sys/socket.h>

#include "protocol.h"

void
peer_add(int fd);

struct peer*
peer_get(const char* remote_domain);

void
peer_release(struct peer* pa);

int
peer_send(struct peer *ca, const char *format, ...);

int
peer_get_reply(struct peer* p, const char* id, struct xmpp_stanza* reply);

#endif /* !CLIENT_H_ */
