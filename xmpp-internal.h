#ifndef XMPP_INTERNAL_H_
#define XMPP_INTERNAL_H_ 1

#include <expat.h>

#include "arena.h"
#include "vink.h"

typedef unsigned int bit;

enum xmpp_auth_mechanism
{
  XMPP_AUTH_UNKNOWN = 0,
  XMPP_PLAIN,
  XMPP_DIGEST_MD5,
  XMPP_EXTERNAL
};

/* jabber:server|features */
struct xmpp_features
{
  bit starttls : 1;
  bit dialback : 1;
  bit auth_external : 1;
  bit auth_plain : 1;
  bit bind : 1;
  bit session : 1;
  bit ack : 1;
};

/* jabber:server:dialback|verify */
struct xmpp_dialback_verify
{
  char *type;
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

struct xmpp_response
{
  char *content;
};

struct xmpp_iq
{
  char *type;
  bit bind : 1;
  bit disco_items : 1;
  bit disco_info : 1;
};

struct xmpp_wavelet_applied_delta
{
  char *data;
  size_t size;

  struct xmpp_wavelet_applied_delta *next;
};

struct xmpp_wavelet_update
{
  const char *wavelet_name;

  struct xmpp_wavelet_applied_delta *first_applied_delta;
  struct xmpp_wavelet_applied_delta *last_applied_delta;
};

struct xmpp_pubsub_item
{
  struct xmpp_wavelet_update *wavelet_update;

  struct xmpp_pubsub_item *next;
};

/* jabber:client|message and jabber:server|message */
struct xmpp_message
{
  bit request_receipt : 1;

  char *body;

  struct xmpp_pubsub_item* first_item;
  struct xmpp_pubsub_item* last_item;
};

struct xmpp_presence
{
  enum vink_presence show;
  char *status;
};

enum xmpp_stanza_type
{
  xmpp_unknown = 0,

  xmpp_root,

  /* level 0 */
  xmpp_ack_request,
  xmpp_ack_response,
  xmpp_dialback_result,
  xmpp_dialback_verify,
  xmpp_error,
  xmpp_features,
  xmpp_iq,
  xmpp_message,
  xmpp_presence,
  xmpp_sasl_auth,
  xmpp_sasl_challenge,
  xmpp_sasl_failure,
  xmpp_sasl_response,
  xmpp_sasl_success,
  xmpp_tls_proceed,
  xmpp_tls_starttls,

  /* level 1 */
  xmpp_features_ack,
  xmpp_features_bind,
  xmpp_features_compression,
  xmpp_features_dialback,
  xmpp_features_mechanisms,
  xmpp_features_session,
  xmpp_features_starttls,
  xmpp_iq_bind,
  xmpp_iq_discovery_info,
  xmpp_iq_discovery_info_feature,
  xmpp_iq_discovery_items,
  xmpp_message_body,
  xmpp_message_event,
  xmpp_message_requect_receipt,
  xmpp_presence_show,

  /* level 2 */
  xmpp_features_mechanisms_mechanism,
  xmpp_iq_bind_jid,
  xmpp_message_event_items,

  /* level 3 */
  xmpp_message_event_items_item,

  /* level 4 */
  xmpp_message_event_items_item_wavelet_update,

  xmpp_message_event_items_item_wavelet_update_applied_delta
};

struct xmpp_stanza
{
  enum xmpp_stanza_type types[5];

  char *id;
  char *from;
  char *to;

  union
    {
      struct xmpp_features features;
      struct xmpp_dialback_verify dialback_verify;
      struct xmpp_dialback_result dialback_result;
      struct xmpp_auth auth;
      struct xmpp_response response;
      struct xmpp_message message;
      struct xmpp_presence presence;
      struct xmpp_iq iq;
    } u;

  struct arena_info arena;
};

struct xmpp_queued_stanza
{
  char *target;
  char *data;

  struct xmpp_queued_stanza* next;
};

struct vink_xmpp_state;

struct vink_xmpp_state
{
  /* XMPP requires one connection in each direction for server-server communication */
  struct vink_xmpp_state *outbound_stream;
  struct vink_xmpp_state *inbound_stream;

  char stream_id[32];

  bit is_initiator : 1;        /* We initiated this connection */
  bit is_client : 1;           /* We are a client */
  bit remote_is_client : 1;    /* Peer is a client */
  bit local_identified : 1;    /* We have identified ourselves */
  bit remote_identified : 1;   /* Peer has identified itself */
  bit using_tls : 1;           /* We are using TLS */
  bit tls_handshake : 1;       /* We are in TLS handshake */
  bit using_zlib : 1;          /* We are using zlib compression */
  bit stream_finished : 1;     /* Stream finished */
  bit active_resource : 1;
  bit ready : 1;

  const char *fatal_error;

  struct xmpp_features features;
  bit has_dialback_ns : 1;

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

  char *remote_stream_id;
  char *remote_jid;
  char remote_resource[32];

  char *jid;
  char *resource;

  char session_id[32];

  unsigned int acks_sent;

  unsigned int remote_major_version;
  unsigned int remote_minor_version;

  XML_Parser xml_parser;
  unsigned int xml_tag_level;
  struct xmpp_node* current_node;
  struct xmpp_stanza stanza;

  gnutls_session_t tls_session;
  const char* tls_read_start;
  const char* tls_read_end;

  int (*write_func)(const void*, size_t, void*);
  void* write_func_arg;

  struct vink_xmpp_callbacks callbacks;

  enum xmpp_auth_mechanism auth_mechanism;

  struct xmpp_queued_stanza *first_queued_stanza;
  struct xmpp_queued_stanza *last_queued_stanza;

  void *backend_data;
};

static void
xmpp_printf(struct vink_xmpp_state *state, const char *format, ...);

static void
xmpp_stream_error(struct vink_xmpp_state *state, const char *type,
                  const char *format, ...);

static void
xmpp_start_tls(struct vink_xmpp_state *state);

static void XMLCALL
xmpp_start_element(void *user_data, const XML_Char *name,
                   const XML_Char **atts);

static void XMLCALL
xmpp_end_element(void *user_data, const XML_Char *name);

static void XMLCALL
xmpp_character_data(void *user_data, const XML_Char *str, int len);

static void XMLCALL
xmpp_start_namespace(void *user_data, const XML_Char *prefix, const XML_Char *uri);

static void
xmpp_process_stanza(struct vink_xmpp_state *state);

static void
xmpp_handshake(struct vink_xmpp_state *state);

/**
 * Generates an ID of 32 chars or less (including terminating NUL).
 */
static void
xmpp_gen_id(char *target);

#endif /* !XMPP_INTERNAL_H_ */
