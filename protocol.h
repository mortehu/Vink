#ifndef PROTOCOL_H_
#define PROTOCOL_H_ 1

#include <expat.h>
#include <gnutls/gnutls.h>

#include "arena.h"
#include "array.h"

/* jabber:server|features */
struct xmpp_features
{
  unsigned int starttls : 1;
  unsigned int dialback : 1;
};

/* jabber:server:dialback|verify */
struct xmpp_dialback_verify
{
  char *hash;
};

/* jabber:server:dialback|result */
struct xmpp_dialback_result
{
  char *type;
  char *hash;
};

/* urn:ietf:params:xml:ns:xmpp-sasl|auth */
struct xmpp_auth
{
  char *mechanism;
  char *content;
};

enum xmpp_stanza_type
{
  xmpp_unknown,
  xmpp_features,
  xmpp_tls_proceed,
  xmpp_tls_starttls,
  xmpp_dialback_verify,
  xmpp_dialback_result,
  xmpp_auth,
  xmpp_iq,
  xmpp_iq_ping,
  xmpp_message,
  xmpp_presence
};

struct xmpp_stanza
{
  enum xmpp_stanza_type type;

  char *id;
  char *from;
  char *to;

  union
    {
      struct xmpp_features features;
      struct xmpp_dialback_verify dialback_verify;
      struct xmpp_dialback_result dialback_result;
      struct xmpp_auth auth;
    } u;

  struct arena_info arena;
};

struct xmpp_jid
{
  const char *node;
  const char *domain;
  const char *resource;
};

typedef unsigned int bit;

struct xmpp_state
{
  bit is_initiator : 1;        /* We initiated this connection */
  bit remote_is_client : 1;    /* Peer is a client */
  bit local_identified : 1;    /* We have identified ourselves */
  bit remote_identified : 1;   /* Peer has identified itself */
  bit using_tls : 1;           /* We are using TLS */
  bit tls_handshake : 1;       /* We are in TLS handshake */
  bit using_zlib : 1;          /* We are using zlib compression */
  bit stream_finished : 1;     /* Stream finished */
  bit fatal_error : 1;         /* Unrecoverable error occured */

  char* remote_jid;

  unsigned int remote_major_version;
  unsigned int remote_minor_version;

  XML_Parser xml_parser;
  unsigned int xml_tag_level;
  struct xmpp_node* current_node;
  struct xmpp_stanza stanza;

  gnutls_session_t tls_session;
  const char* tls_read_start;
  const char* tls_read_end;

  struct buffer *writebuf;
};

int
xmpp_state_init(struct xmpp_state *state, struct buffer *writebuf,
                const char *remote_domain);

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

int
xmpp_request(const char *remote_domain,
              struct xmpp_stanza *request,
              struct xmpp_stanza *reply);

int
xmpp_parse_jid(struct xmpp_jid *target, char *input);

#endif /* !PROTOCOL_H_ */
