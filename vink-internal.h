#ifndef VINK_INTERNAL_H_
#define VINK_INTERNAL_H_ 1

extern struct tree* VINK_config;

void
VINK_set_error(const char *format, ...);

struct vink_xmpp_state *
VINK_xmpp_server_connect(const char *domain);

size_t
VINK_peer_count();

struct vink_xmpp_state *
VINK_peer_state(unsigned int peer_index);

#endif /* !VINK_INTERNAL_H_ */
