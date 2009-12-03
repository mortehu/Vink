#ifndef PROTOCOL_H_
#define PROTOCOL_H_ 1

#include <expat.h>
#include <gnutls/gnutls.h>

#include "arena.h"
#include "array.h"
#include "common.h"

struct xmpp_jid
{
  const char *node;
  const char *domain;
  const char *resource;
};

struct xmpp_callbacks
{
  void (*message)(const char *from, const char *to, const char *body);
};

#define XMPP_CLIENT 0x00001

struct xmpp_state *
xmpp_state_init(struct buffer *writebuf,
                const char *remote_domain, unsigned int flags);

void
xmpp_state_callbacks(struct xmpp_state *state,
                     struct xmpp_callbacks *callbacks);

int
xmpp_state_data(struct xmpp_state *state,
                const void *data, size_t count);

void
xmpp_state_free(struct xmpp_state *state);

/**
 * Generates an ID of 32 chars or less (including terminating NUL).
 */
void
xmpp_gen_id(char *target);

void
xmpp_queue_stanza(const char *to, const char *format, ...);

void
xmpp_queue_stanza2(struct xmpp_state* state, const char *format, ...);

int
xmpp_parse_jid(struct xmpp_jid *target, char *input);

void
xmpp_send_message(struct xmpp_state* state, const char *to, const char *body);

#endif /* !PROTOCOL_H_ */
