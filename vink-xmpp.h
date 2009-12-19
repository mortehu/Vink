#ifndef VINK_XMPP_H_
#define VINK_XMPP_H_ 1

struct vink_xmpp_state;

enum vink_xmpp_presence
{
  VINK_XMPP_PRESENT = 0,
  VINK_XMPP_AWAY,
  VINK_XMPP_CHAT,
  VINK_XMPP_DND,
  VINK_XMPP_XA,
  VINK_XMPP_UNAVAILABLE
};

struct vink_xmpp_jid
{
  const char *node;
  const char *domain;
  const char *resource;
};

struct vink_xmpp_callbacks
{
  /**
   * Called during SASL authentication.
   *
   * Returns 0 on success, -1 on failure.
   */
  int (*authenticate)(struct vink_xmpp_state *state, const char *authzid,
                      const char *user, const char *secret);

  /**
   * Called when a messages is received.
   */
  void (*message)(struct vink_xmpp_state *state, const char *from,
                  const char *to, const char *body);

  /**
   * Called when presence is received.
   */
  void (*presence)(struct vink_xmpp_state *state, const char *jid, enum vink_xmpp_presence presence);

  void (*backend_free)(void *data);

  /**
   * Called when all requests have been queued in the transport buffer.
   *
   * This is useful for batch mode operation; you may safely end the stream
   * when this function is called.
   */
  void (*queue_empty)(struct vink_xmpp_state *state);
};

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
vink_xmpp_queue_stanza(struct vink_xmpp_state *state, const char *format, ...);

/**
 * Signify presence.
 */
void
vink_xmpp_set_presence(struct vink_xmpp_state *state, enum vink_xmpp_presence type);

/**
 * Send a message stanza.  Values must be escaped for XML.
 */
void
vink_xmpp_send_message(struct vink_xmpp_state *state, const char *to, const char *body);

/**
 * Signify that the stream should be terminated.
 *
 * The stream will wait for the remote end to acknowledge the end-of-stream
 * condition, to ensure that all previous commands have either succeeded or
 * reported an error.
 */
void
vink_xmpp_end_stream(struct vink_xmpp_state *state);

void
vink_xmpp_set_backend_data(struct vink_xmpp_state *state, void *data);

void *
vink_xmpp_backend_data(struct vink_xmpp_state *state);

#endif /* !VINK_XMPP_H_ */
