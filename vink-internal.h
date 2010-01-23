#ifndef VINK_INTERNAL_H_
#define VINK_INTERNAL_H_ 1

#include "array.h"
#include "tree.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

extern struct tree* VINK_config;

struct VINK_buffer
{
  ARRAY_MEMBERS(char);
};

void
VINK_set_error(const char *format, ...);

struct vink_xmpp_state *
VINK_xmpp_server_connect(const char *domain);

size_t
VINK_peer_count();

struct vink_xmpp_state *
VINK_peer_state(unsigned int peer_index);

int
VINK_buffer_addf (struct VINK_buffer *buf, const char *format, ...);

#endif /* !VINK_INTERNAL_H_ */
