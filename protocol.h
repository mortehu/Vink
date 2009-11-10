#ifndef PROTOCOL_H_
#define PROTOCOL_H_ 1

/* jabber:server|features */
struct proto_features
{
  unsigned int starttls : 1;
  unsigned int dialback : 1;
};

/* jabber:server:dialback|verify */
struct proto_dialback_verify
{
  char *hash;
};

/* jabber:server:dialback|result */
struct proto_dialback_result
{
  char *type;
  char *hash;
};

/* urn:ietf:params:xml:ns:xmpp-sasl|auth */
struct proto_auth
{
  char *mechanism;
  char *content;
};

enum proto_stanza_type
{
  proto_invalid = 0,
  proto_unknown,
  proto_features,
  proto_tls_proceed,
  proto_tls_starttls,
  proto_dialback_verify,
  proto_dialback_result,
  proto_auth,
  proto_iq,
  proto_iq_ping,
  proto_message,
  proto_presence
};

struct proto_stanza
{
  enum proto_stanza_type type;

  char *id;
  char *from;
  char *to;

  union
    {
      struct proto_features features;
      struct proto_dialback_verify dialback_verify;
      struct proto_dialback_result dialback_result;
      struct proto_auth auth;
    } u;
};

struct proto_jid
{
  const char *node;
  const char *domain;
  const char *resource;
};

void
proto_gen_id(char *target);

int
proto_request(const char *remote_domain,
              struct proto_stanza *request,
              struct proto_stanza *reply);

int
proto_parse_jid(struct proto_jid *target, char *input);

#endif /* !PROTOCOL_H_ */
