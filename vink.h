#ifndef VINK_H_
#define VINK_H_ 1

#include <stdlib.h>

#define VINK_API_VERSION 0x000000

enum vink_protocol
{
  VINK_XMPP = 1,
  VINK_EPP = 2
};

#define VINK_CLIENT 0x00001

#ifdef __GNUC__
#define USE_RESULT __attribute__((warn_unused_result))
#else
#define USE_RESULT
#endif

struct vink_client;

struct vink_epp_state;
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
  /**
   * Called when a messages is received.
   */
  void (*message)(struct vink_xmpp_state *state, const char *from, const char *to, const char *body);

  /**
   * Called when all requests have been queued in the transport buffer.
   *
   * This is useful for batch mode operation; you may safely end the stream
   * when this function is called.
   */
  void (*queue_empty)(struct vink_xmpp_state *state);
};

/**
 * Initializes the vink library.
 *
 * Pass the value of VINK_API_VERSION in the `version' parameter.
 */
int
vink_init(const char *config_path, unsigned int flags, unsigned int version) USE_RESULT;

const char *
vink_last_error();

/* Client functions */

struct vink_client *
vink_client_alloc();

void *
vink_client_state(struct vink_client *cl);

int
vink_client_connect(struct vink_client *cl, const char *domain,
                    enum vink_protocol protocol) USE_RESULT;

int
vink_client_run(struct vink_client *cl) USE_RESULT;

/* EPP stream functions */

struct vink_epp_state *
vink_epp_state_init(int (*write_func)(const void*, size_t, void*),
                    const char *remote_domain, unsigned int flags,
                    void* arg);

int
vink_epp_state_data(struct vink_epp_state *state,
                    const void *data, size_t count);

int
vink_epp_state_finished(struct vink_epp_state *state);

void
vink_epp_state_free(struct vink_epp_state *state);

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
