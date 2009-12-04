#ifndef PROTOCOL_H_
#define PROTOCOL_H_ 1

#include <expat.h>
#include <gnutls/gnutls.h>

#include "arena.h"
#include "array.h"
#include "common.h"
#include "vink.h"

#define XMPP_CLIENT 0x00001

struct vink_xmpp_state *
xmpp_state_init(struct buffer *writebuf,
                const char *remote_domain, unsigned int flags);

int
xmpp_state_data(struct vink_xmpp_state *state,
                const void *data, size_t count);

int
xmpp_state_finished(struct vink_xmpp_state *state);

void
xmpp_state_free(struct vink_xmpp_state *state);

#endif /* !PROTOCOL_H_ */
