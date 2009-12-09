#ifndef VINK_H_
#define VINK_H_ 1

#include <stdlib.h>

#define XMPP_CLIENT 0x00001

struct vink_client;

struct vink_xmpp_state;

enum vink_xmpp_presence
{
  VINK_XMPP_PRESENT
};

struct vink_xmpp_jid
{
  const char *node;
  const char *domain;
  const char *resource;
};

struct vink_xmpp_callbacks
{
  void (*message)(struct vink_xmpp_state *state, const char *from, const char *to, const char *body);
  void (*queue_empty)(struct vink_xmpp_state *state);
};

void
vink_init();

/* Client functions */

struct vink_client *
vink_client_alloc();

struct vink_xmpp_state *
vink_client_state(struct vink_client *cl);

int
vink_client_connect(struct vink_client *cl, const char *domain);

void
vink_client_run(struct vink_client *cl);

/* XMPP stream functions */

struct vink_xmpp_state *
vink_xmpp_state_init(int (*write_func)(const void*, size_t, void*),
                     const char *remote_domain, unsigned int flags,
                     void* arg);

int
vink_xmpp_state_data(struct vink_xmpp_state *state,
                     const void *data, size_t count);

int
vink_xmpp_state_finished(struct vink_xmpp_state *state);

void
vink_xmpp_state_free(struct vink_xmpp_state *state);

void
vink_xmpp_set_callbacks(struct vink_xmpp_state *state,
                        struct vink_xmpp_callbacks *callbacks);

int
vink_xmpp_parse_jid(struct vink_xmpp_jid *target, char *input);

/**
 * Send raw XML stanza.
 */
void
vink_xmpp_queue_stanza(struct vink_xmpp_state* state, const char *format, ...);

/**
 * Signify presence.
 */
void
vink_xmpp_set_presence(struct vink_xmpp_state *state, enum vink_xmpp_presence type);

/**
 * Send a message stanza.  Values must be escaped for XML.
 */
void
vink_xmpp_send_message(struct vink_xmpp_state* state, const char *to, const char *body);

/**
 * Signify that the stream should be terminated.
 *
 * The stream will wait for the remote end to acknowledge the end-of-stream
 * condition, to ensure that all previous commands have either succeeded or
 * reported an error.
 */
void
vink_xmpp_end_stream(struct vink_xmpp_state* state);

/* Utility functions */
char*
vink_xml_escape(const char* data, size_t size);

#endif /* !VINK_H_ */
