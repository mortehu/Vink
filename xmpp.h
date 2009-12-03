#ifndef PROTOCOL_H_
#define PROTOCOL_H_ 1

#include <expat.h>
#include <gnutls/gnutls.h>

#include "arena.h"
#include "array.h"

typedef unsigned int bit;

/* jabber:server|features */
struct xmpp_features
{
  bit starttls : 1;
  bit dialback : 1;
  bit auth_external : 1;
  bit auth_plain : 1;
  bit bind : 1;
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
  xmpp_unknown = 0,
  xmpp_features,
  xmpp_error,
  xmpp_tls_proceed,
  xmpp_tls_starttls,
  xmpp_dialback_verify,
  xmpp_dialback_result,
  xmpp_auth,
  xmpp_challenge,
  xmpp_success,
  xmpp_iq,
  xmpp_message,
  xmpp_presence
};

enum xmpp_stanza_sub_type
{
  xmpp_sub_unknown = 0,
  xmpp_sub_iq_discovery_info,
  xmpp_sub_iq_discovery_items,
  xmpp_sub_iq_bind,
  xmpp_sub_features_mechanisms,
  xmpp_sub_features_compression
};

enum xmpp_stanza_subsub_type
{
  xmpp_subsub_unknown = 0,
  xmpp_subsub_iq_bind_jid,
  xmpp_subsub_features_mechanisms_mechanism
};

struct xmpp_stanza
{
  enum xmpp_stanza_type type;
  enum xmpp_stanza_sub_type sub_type;
  enum xmpp_stanza_subsub_type subsub_type;

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

struct xmpp_queued_stanza
{
  char *target;
  char *data;

  struct xmpp_queued_stanza* next;
};

struct xmpp_state
{
  bit is_initiator : 1;        /* We initiated this connection */
  bit is_client : 1;           /* We are a client */
  bit remote_is_client : 1;    /* Peer is a client */
  bit local_identified : 1;    /* We have identified ourselves */
  bit remote_identified : 1;   /* Peer has identified itself */
  bit using_tls : 1;           /* We are using TLS */
  bit tls_handshake : 1;       /* We are in TLS handshake */
  bit using_zlib : 1;          /* We are using zlib compression */
  bit stream_finished : 1;     /* Stream finished */
  bit fatal_error : 1;         /* Unrecoverable error occured */
  bit ready : 1;

  struct xmpp_features features;

  /* Discovered features */
  bit feature_google_jingleinfo : 1;
  bit feature_jabber_address : 1;
  bit feature_jabber_commands : 1;
  bit feature_jabber_disco_info : 1;
  bit feature_jabber_disco_items : 1;
  bit feature_jabber_offline : 1;
  bit feature_jabber_pubsub : 1;
  bit feature_jabber_pubsub_collections : 1;
  bit feature_jabber_pubsub_config_node : 1;
  bit feature_jabber_pubsub_create_and_configure : 1;
  bit feature_jabber_pubsub_create_nodes : 1;
  bit feature_jabber_pubsub_default_access_model_open : 1;
  bit feature_jabber_pubsub_delete_nodes : 1;
  bit feature_jabber_pubsub_get_pending : 1;
  bit feature_jabber_pubsub_instant_nodes : 1;
  bit feature_jabber_pubsub_item_ids : 1;
  bit feature_jabber_pubsub_manage_subscriptions : 1;
  bit feature_jabber_pubsub_meta_data : 1;
  bit feature_jabber_pubsub_modify_affiliations : 1;
  bit feature_jabber_pubsub_multi_subscribe : 1;
  bit feature_jabber_pubsub_outcast_affiliation : 1;
  bit feature_jabber_pubsub_persistent_items : 1;
  bit feature_jabber_pubsub_presence_notifications : 1;
  bit feature_jabber_pubsub_publish : 1;
  bit feature_jabber_pubsub_publisher_affiliation : 1;
  bit feature_jabber_pubsub_purge_nodes : 1;
  bit feature_jabber_pubsub_retract_items : 1;
  bit feature_jabber_pubsub_retrieve_affiliations : 1;
  bit feature_jabber_pubsub_retrieve_default : 1;
  bit feature_jabber_pubsub_retrieve_items : 1;
  bit feature_jabber_pubsub_retrieve_subscriptions : 1;
  bit feature_jabber_pubsub_subscribe : 1;
  bit feature_jabber_pubsub_subscription_options : 1;
  bit feature_jabber_rsm : 1;
  bit feature_jabber_iq_last : 1;
  bit feature_jabber_iq_privacy : 1;
  bit feature_jabber_iq_private : 1;
  bit feature_jabber_iq_register : 1;
  bit feature_jabber_iq_roster : 1;
  bit feature_jabber_iq_time : 1;
  bit feature_jabber_iq_version : 1;
  bit feature_urn_xmpp_ping : 1;
  bit feature_vcard_temp : 1;

  bit please_restart : 1;

  char* remote_stream_id;
  char* remote_jid;

  char* resource;

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

  struct xmpp_queued_stanza *first_queued_stanza;
  struct xmpp_queued_stanza *last_queued_stanza;
};

#define XMPP_CLIENT 0x00001

int
xmpp_state_init(struct xmpp_state *state, struct buffer *writebuf,
                const char *remote_domain, unsigned int flags);

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

#endif /* !PROTOCOL_H_ */
