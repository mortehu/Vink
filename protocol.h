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
  char* hash;
};

/* jabber:server:dialback|result */
struct proto_dialback_result
{
  char* type;
  char* hash;
};

enum proto_stanza_type
{
  proto_invalid = 0,
  proto_unknown,
  proto_features,
  proto_iq,
  proto_iq_ping,
  proto_tls_proceed,
  proto_tls_starttls,
  proto_dialback_verify,
  proto_dialback_result
};

struct proto_stanza
{
  enum proto_stanza_type type;

  char* id;
  char* from;
  char* to;

  union
    {
      struct proto_features features;
      struct proto_dialback_verify dialback_verify;
      struct proto_dialback_result dialback_result;
    } u;
};

int
proto_request(const char* remote_domain,
              struct proto_stanza* request,
              struct proto_stanza* reply);

#endif /* !PROTOCOL_H_ */
