#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <syslog.h>
#include <sys/time.h>

#include "base64.h"
#include "common.h"
#include "hash.h"
#include "protocol.h"
#include "server.h"
#include "tree.h"

static void
xmpp_printf(struct xmpp_state *state, const char *format, ...);

static void
xmpp_stream_error(struct xmpp_state *state, const char *type,
                  const char *format, ...);

static void
xmpp_start_tls(struct xmpp_state *state);

static void XMLCALL
xmpp_start_element(void *user_data, const XML_Char *name,
                   const XML_Char **atts);

static void XMLCALL
xmpp_end_element(void *userData, const XML_Char *name);

static void XMLCALL
xmpp_character_data(void *userData, const XML_Char *str, int len);

static void
xmpp_process_stanza(struct xmpp_state *state);

static void
xmpp_reset_stream(struct xmpp_state *state)
{
  XML_ParserReset(state->xml_parser, "utf-8");
  XML_SetUserData(state->xml_parser, state);
  XML_SetElementHandler(state->xml_parser, xmpp_start_element, xmpp_end_element);
  XML_SetCharacterDataHandler(state->xml_parser, xmpp_character_data);

  if(state->is_initiator)
    {
      xmpp_printf(state,
                  "<?xml version='1.0'?>"
                  "<stream:stream xmlns='jabber:server' "
                  "xmlns:stream='http://etherx.jabber.org/streams' "
                  "from='%s' "
                  "to='%s' "
                  "xmlns:db='jabber:server:dialback' "
                  "version='1.0'>",
                  tree_get_string(config, "domain"), state->remote_jid);
    }

  state->xml_tag_level = 0;
}

int
xmpp_state_init(struct xmpp_state *state, struct buffer *writebuf,
                const char *remote_domain)
{
  memset(state, 0, sizeof(*state));

  state->writebuf = writebuf;

  state->xml_parser = XML_ParserCreateNS("utf-8", '|');

  if(!state->xml_parser)
    return -1;

  if(!remote_domain)
    {
      /* XXX: Determine if remote is client */
      /* state->remote_is_client = 1; */
    }
  else
    {
      state->is_initiator = 1;
      state->remote_jid = strdup(remote_domain);
    }

  xmpp_reset_stream(state);

  return 0;
}

void
xmpp_state_free(struct xmpp_state *state)
{
  free(state->remote_jid);

  if(state->tls_session)
    gnutls_bye(state->tls_session, GNUTLS_SHUT_WR);

  if(state->xml_parser)
    XML_ParserFree(state->xml_parser);
}

static void
xmpp_write(struct xmpp_state *state, const char *data)
{
  size_t size;

  if(state->fatal_error)
    return;

  size = strlen(data);

  if(state->using_tls && !state->tls_handshake)
    {
      const char *buf;
      size_t offset = 0, to_write;
      int result;

      buf = data;

      fprintf(stderr, "LOCAL-TLS(%p): \033[1;35m%.*s\033[0m\n", state, (int) size, buf);

      while(offset < size)
        {
          to_write = size - offset;

          if(to_write > 4096)
            to_write = 4096;

          result = gnutls_record_send(state->tls_session, buf + offset, to_write);

          if(result <= 0)
            {
              if(result < 0)
                syslog(LOG_INFO, "write error to peer: %s", gnutls_strerror(result));

              state->fatal_error = 1;

              return;
            }

          offset += result;
        }
    }
  else
    {
      fprintf(stderr, "LOCAL(%p): \033[1;35m%.*s\033[0m\n", state, (int) size, data);

      ARRAY_ADD_SEVERAL(state->writebuf, data, size);

      if(ARRAY_RESULT(state->writebuf))
        {
          syslog(LOG_WARNING, "buffer append error: %s", strerror(errno));

          state->fatal_error = 1;
        }
    }
}

static void
xmpp_printf(struct xmpp_state *state, const char *format, ...)
{
  va_list args;
  char *buf;
  int result;

  va_start(args, format);

  result = vasprintf(&buf, format, args);

  if(result == -1)
    {
      syslog(LOG_WARNING, "asprintf failed: %s", strerror(errno));

      xmpp_stream_error(state, "internal-server-error", 0);

      return;
    }

  xmpp_write(state, buf);

  free(buf);
}

void
xmpp_queue_stanza(const char *to, const char *format, ...)
{
  struct xmpp_state *state;
  struct xmpp_queued_stanza *qs;
  int i, peer_count, result;
  va_list args;
  char *buf;

  va_start(args, format);

  result = vasprintf(&buf, format, args);

  if(result == -1)
    {
      syslog(LOG_WARNING, "asprintf failed: %s", strerror(errno));

      xmpp_stream_error(state, "internal-server-error", 0);

      return;
    }

  xmpp_write(state, buf);

  peer_count = server_peer_count();

  /* XXX: Handle specific JIDs, not only domains */

  for(i = 0; i < peer_count; ++i)
    {
      state = server_peer_get_state(i);

      if(!state->is_initiator)
        continue;

      if(!strcmp(state->remote_jid, to))
        break;
    }

  if(i == peer_count)
    {
      if(-1 == (i = server_connect(to)))
        {
          syslog(LOG_WARNING, "connecting to %s failed", to);

          free(buf);

          return;
        }

      state = server_peer_get_state(i);
    }

  if(state->ready)
    {
      xmpp_write(state, buf);
      free(buf);
    }
  else
    {
      qs = malloc(sizeof(*qs));
      qs->target = strdup(to);
      qs->data = buf;
      qs->next = 0;

      if(!state->first_queued_stanza)
        {
          state->first_queued_stanza = qs;
          state->last_queued_stanza = qs;
        }
      else
        {
          state->last_queued_stanza->next = qs;
          state->last_queued_stanza = qs;
        }
    }
}

static void
xmpp_stream_error(struct xmpp_state *state, const char *type,
                  const char *format, ...)
{
  va_list args;
  char *buf;
  int result;

  xmpp_printf(state,
              "<stream:error>"
              "<%s xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>",
              type);

  if(format)
    {
      xmpp_write(state,
                 "<text xmlns='urn:ietf:params:xml:ns:xmpp-streams'"
                 " xml:lang='en'>");

      va_start(args, format);

      result = vasprintf(&buf, format, args);

      if(result == -1)
        {
          syslog(LOG_WARNING, "asprintf failed: %s", strerror(errno));

          state->fatal_error = 1;

          return;
        }

      xmpp_write(state, buf);

      free(buf);

      xmpp_write(state, "</text>");
    }

  xmpp_write(state, "</stream:error></stream:stream>");

  state->fatal_error = 1;
}

static void XMLCALL
xmpp_start_element(void *user_data, const XML_Char *name,
                   const XML_Char **atts)
{
  struct xmpp_state *state = user_data;
  const XML_Char **attr;
  struct xmpp_stanza *stanza;
  struct arena_info *arena;

  stanza = &state->stanza;
  arena = &stanza->arena;

  if(state->xml_tag_level == 0)
    {
      if(strcmp(name, "http://etherx.jabber.org/streams|stream"))
        {
          xmpp_stream_error(state, "invalid-namespace",
                            "Expected stream tag in "
                            "http://etherx.jabber.org/streams namespace");

          return;
        }

      state->remote_major_version = 0;
      state->remote_minor_version = 0;

      for(attr = atts; *attr; attr += 2)
        {
          if(!strcmp(attr[0], "version"))
            {
              if(2 != sscanf(attr[1], "%u.%u", &state->remote_major_version,
                             &state->remote_minor_version))
                {
                  xmpp_stream_error(state, "unspported-version",
                                    "Unable to parse stream version");

                  return;
                }
            }
          else if(!strcmp(attr[0], "to"))
            {
              if(strcmp(attr[1], tree_get_string(config, "domain")))
                {
                  xmpp_stream_error(state, "host-unknown", 0);

                  return;
                }
            }
          else if(!strcmp(attr[0], "id"))
            state->remote_stream_id = strdup(attr[1]);
        }

      /* Clamp remote version to maximum version supported by us */
      if(state->remote_major_version > 1)
        {
          xmpp_stream_error(state, "unsupported-version",
                            "Major version %d not supported.  Max is 1.",
                            state->remote_major_version);

          return;
        }

      if(state->remote_major_version == 1 && state->remote_minor_version > 0)
        {
          state->remote_major_version = 1;
          state->remote_minor_version = 1;
        }

      if(state->remote_is_client)
        {
          char id[32];

          xmpp_gen_id(id);

          xmpp_printf(state,
                      "<?xml version='1.0'?>"
                      "<stream:stream xmlns='jabber:client' "
                      "xmlns:stream='http://etherx.jabber.org/streams' "
                      "from='%s' id='%s'",
                      tree_get_string(config, "domain"), id);

          if(state->remote_major_version || state->remote_minor_version)
            xmpp_printf(state, " version='%d.%d'>",
                        state->remote_major_version,
                        state->remote_minor_version);
          else
            xmpp_write(state, ">");

          if(state->remote_major_version >= 1)
            {
              xmpp_write(state, "<stream:features>");

              if(!state->using_tls && state->remote_major_version >= 1)
                xmpp_write(state,
                           "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");

              if(!state->remote_identified)
                xmpp_write(state,
                           "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                           /*"<mechanism>DIGEST-MD5</mechanism>"*/
                           "<mechanism>PLAIN</mechanism>"
                           "</mechanisms>");

              xmpp_write(state, "</stream:features>");
            }
        }
      else if(!state->is_initiator)
        {
          char id[32];

          xmpp_gen_id(id);

          xmpp_printf(state,
                      "<?xml version='1.0'?>"
                      "<stream:stream xmlns='jabber:server' "
                      "xmlns:stream='http://etherx.jabber.org/streams' "
                      "xmlns:db='jabber:server:dialback' "
                      "from='%s' id='%s' ",
                      tree_get_string(config, "domain"), id);

          if(state->remote_major_version || state->remote_minor_version)
            xmpp_printf(state, " version='%d.%d'>",
                        state->remote_major_version,
                        state->remote_minor_version);
          else
            xmpp_write(state, ">");

          if(state->remote_major_version >= 1)
            {
              xmpp_write(state, "<stream:features>");

              if(!state->using_tls)
                {
                  xmpp_write(state,
                             "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>"
                             "<required/>"
                             "</starttls>");

                  if(!state->remote_identified)
                    xmpp_write(state, "<db:dialback/>");
                }
              else if(!state->remote_identified)
                {
                  xmpp_write(state,
                             "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                             "<mechanism>EXTERNAL</mechanism>"
                             "</mechanisms>"
                             "</stream:features>");
                }

              xmpp_write(state, "</stream:features>");
            }
        }
      else
        {
          assert(state->is_initiator);

          if(!state->remote_stream_id)
            {
              xmpp_stream_error(state, "invalid-id", 0);

              return;
            }
        }
    }
  else if(state->xml_tag_level == 1)
    {
      memset(&state->stanza, 0, sizeof(state->stanza));

      for(attr = atts; *attr; attr += 2)
        {
          if(!strcmp(attr[0], "id"))
            stanza->id = arena_strdup(arena, attr[1]);
          else if(!strcmp(attr[0], "from"))
            stanza->from = arena_strdup(arena, attr[1]);
          else if(!strcmp(attr[0], "to"))
            {
              if(strcmp(attr[1], tree_get_string(config, "domain")))
                {
                  xmpp_stream_error(state, "host-unknown", 0);

                  return;
                }

              stanza->to = arena_strdup(arena, attr[1]);
            }
        }

      if(!strcmp(name, "http://etherx.jabber.org/streams|features"))
        {
          stanza->type = xmpp_features;
        }
      else if(!strcmp(name, "http://etherx.jabber.org/streams|error"))
        {
          stanza->type = xmpp_error;
        }
      else if(!strcmp(name, "urn:ietf:params:xml:ns:xmpp-tls|proceed"))
        {
          stanza->type = xmpp_tls_proceed;
        }
      else if(!strcmp(name, "urn:ietf:params:xml:ns:xmpp-tls|starttls"))
        {
          stanza->type = xmpp_tls_starttls;
        }
      else if(!strcmp(name, "jabber:server:dialback|verify"))
        {
          stanza->type = xmpp_dialback_verify;
        }
      else if(!strcmp(name, "jabber:server:dialback|result"))
        {
          struct xmpp_dialback_result *pdr = &stanza->u.dialback_result;

          stanza->type = xmpp_dialback_result;

          for(attr = atts; *attr; attr += 2)
            {
              if(!strcmp(attr[0], "type"))
                pdr->type = arena_strdup(arena, attr[1]);
            }
        }
      else if(!strcmp(name, "urn:ietf:params:xml:ns:xmpp-sasl|auth"))
        {
          if(state->is_initiator)
            {
              xmpp_stream_error(state, "bad-format", "Receiving server attempted to initiate SASL");

              return;
            }

          stanza->type = xmpp_auth;

          for(attr = atts; *attr; attr += 2)
            {
              if(!strcmp(attr[0], "mechanism"))
                stanza->u.auth.mechanism = arena_strdup(arena, attr[1]);
            }
        }
      else if(!strcmp(name, "jabber:server|iq")
              || !strcmp(name, "jabber:client|iq"))
        {
          stanza->type = xmpp_iq;
        }
      else if(!strcmp(name, "jabber:server|message")
              ||!strcmp(name, "jabber:client|message"))
        {
          stanza->type = xmpp_message;
        }
      else if(!strcmp(name, "jabber:server|presence")
              || strcmp(name, "jabber:clent|presence"))
        {
          stanza->type = xmpp_presence;
        }
      else
        {
          stanza->type = xmpp_unknown;

          xmpp_stream_error(state, "unsupported-stanza-type",
                            "Unknown element '%s'", name);
        }
    }
  else if(state->xml_tag_level == 2)
    {
      stanza->sub_type = xmpp_sub_unknown;

      if(state->stanza.type == xmpp_features)
        {
          struct xmpp_features *pf = &stanza->u.features;

          if(!strcmp(name, "urn:ietf:params:xml:ns:xmpp-tls|starttls"))
            pf->starttls = 1;
          else if(!strcmp(name, "urn:xmpp:features:dialback|dialback"))
            pf->dialback = 1;
          else if(!strcmp(name, "urn:ietf:params:xml:ns:xmpp-sasl|mechanisms"))
            stanza->sub_type = xmpp_sub_features_mechanisms;
          else if(!strcmp(name, "http://jabber.org/features/compress|compression"))
            stanza->sub_type = xmpp_sub_features_compression;
          else
            fprintf(stderr, "Unhandled feature tag '%s'\n", name);
        }
      else if(state->stanza.type == xmpp_iq)
        {
          if(!strcmp(name, "http://jabber.org/protocol/disco#info|query"))
            stanza->sub_type = xmpp_sub_iq_discovery_info;
          if(!strcmp(name, "http://jabber.org/protocol/disco#items|query"))
            stanza->sub_type = xmpp_sub_iq_discovery_items;
        }
      else
        fprintf(stderr, "Unhandled level 2 tag '%s'\n", name);
    }
  else if(state->xml_tag_level == 3)
    {
      stanza->subsub_type = xmpp_subsub_unknown;

      if(stanza->sub_type == xmpp_sub_iq_discovery_info)
        {
          if(!strcmp(name, "http://jabber.org/protocol/disco#info|feature"))
            {
              const char *var = 0;

              for(attr = atts; *attr; attr += 2)
                {
                  if(!strcmp(attr[0], "var"))
                    {
                      var = attr[1];

                      break;
                    }
                }

              if(!var)
                {
                  fprintf(stderr, "Missing 'var' in feature element\n");

                  state->fatal_error = 1;

                  return;
                }

#define CHECK_FEATURE(str, symbol) \
  if(!strcmp(var, str)) state->feature_##symbol = 1;

              CHECK_FEATURE("google:jingleinfo", google_jingleinfo);
              CHECK_FEATURE("http://jabber.org/protocol/address", jabber_address);
              CHECK_FEATURE("http://jabber.org/protocol/commands", jabber_commands);
              CHECK_FEATURE("http://jabber.org/protocol/disco#info", jabber_disco_info);
              CHECK_FEATURE("http://jabber.org/protocol/disco#items", jabber_disco_items);
              CHECK_FEATURE("http://jabber.org/protocol/offline", jabber_offline);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub", jabber_pubsub);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#collections", jabber_pubsub_collections);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#config-node", jabber_pubsub_config_node);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#create-and-configure", jabber_pubsub_create_and_configure);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#create-nodes", jabber_pubsub_create_nodes);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#default_access_model_open", jabber_pubsub_default_access_model_open);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#delete-nodes", jabber_pubsub_delete_nodes);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#get-pending", jabber_pubsub_get_pending);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#instant-nodes", jabber_pubsub_instant_nodes);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#item-ids", jabber_pubsub_item_ids);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#manage-subscriptions", jabber_pubsub_manage_subscriptions);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#meta-data", jabber_pubsub_meta_data);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#modify-affiliations", jabber_pubsub_modify_affiliations);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#multi-subscribe", jabber_pubsub_multi_subscribe);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#outcast-affiliation", jabber_pubsub_outcast_affiliation);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#persistent-items", jabber_pubsub_persistent_items);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#presence-notifications", jabber_pubsub_presence_notifications);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#publish", jabber_pubsub_publish);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#publisher-affiliation", jabber_pubsub_publisher_affiliation);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#purge-nodes", jabber_pubsub_purge_nodes);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#retract-items", jabber_pubsub_retract_items);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#retrieve-affiliations", jabber_pubsub_retrieve_affiliations);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#retrieve-default", jabber_pubsub_retrieve_default);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#retrieve-items", jabber_pubsub_retrieve_items);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#retrieve-subscriptions", jabber_pubsub_retrieve_subscriptions);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#subscribe", jabber_pubsub_subscribe);
              CHECK_FEATURE("http://jabber.org/protocol/pubsub#subscription-options", jabber_pubsub_subscription_options);
              CHECK_FEATURE("http://jabber.org/protocol/rsm", jabber_rsm);
              CHECK_FEATURE("jabber:iq:last", jabber_iq_last);
              CHECK_FEATURE("jabber:iq:privacy", jabber_iq_privacy);
              CHECK_FEATURE("jabber:iq:private", jabber_iq_private);
              CHECK_FEATURE("jabber:iq:register", jabber_iq_register);
              CHECK_FEATURE("jabber:iq:roster", jabber_iq_roster);
              CHECK_FEATURE("jabber:iq:time", jabber_iq_time);
              CHECK_FEATURE("jabber:iq:version", jabber_iq_version);
              CHECK_FEATURE("urn:xmpp:ping", urn_xmpp_ping);
              CHECK_FEATURE("vcard-temp", vcard_temp);

#undef CHECK_FEATURE
            }
        }
      else if(stanza->sub_type == xmpp_sub_features_mechanisms)
        {
          if(!strcmp(name, "urn:ietf:params:xml:ns:xmpp-sasl|mechanism"))
            stanza->subsub_type = xmpp_subsub_features_mechanisms_mechanism;
        }
      else
        fprintf(stderr, "Unhandled level 3 tag '%s'\n", name);
    }


  ++state->xml_tag_level;
}

static void XMLCALL
xmpp_end_element(void *user_data, const XML_Char *name)
{
  struct xmpp_state *state = user_data;

  if(!state->xml_tag_level)
    {
      xmpp_stream_error(state, "invalid-xml", "Too many end tags");

      return;
    }

  --state->xml_tag_level;

  if(state->xml_tag_level == 1)
    {
      if(state->stanza.type != xmpp_unknown)
        xmpp_process_stanza(state);
    }
  else if(state->xml_tag_level == 0)
    state->stream_finished = 1;
  else if(state->xml_tag_level == 2)
    state->stanza.sub_type = xmpp_sub_unknown;
  else if(state->xml_tag_level == 3)
    state->stanza.subsub_type = xmpp_sub_unknown;
}

static void XMLCALL
xmpp_character_data(void *user_data, const XML_Char *str, int len)
{
  char* data;
  struct xmpp_state *state = user_data;
  struct xmpp_stanza *stanza = &state->stanza;
  struct arena_info *arena = &stanza->arena;

  data = strndupa(str, len);

  if(stanza->subsub_type != xmpp_subsub_unknown)
    {
      switch(stanza->subsub_type)
        {
        case xmpp_subsub_features_mechanisms_mechanism:

            {
              struct xmpp_features *pf = &state->stanza.u.features;

              if(!strcmp(data, "EXTERNAL"))
                pf->auth_external = 1;
            }

          break;

        default:

          fprintf(stderr, "\033[31;1mUnhandled sub-subtag data: '%.*s'\033[0m\n", len, str);
        }
    }
  else if(stanza->sub_type != xmpp_sub_unknown)
    {
      switch(stanza->sub_type)
        {
        default:

          fprintf(stderr, "\033[31;1mUnhandled subtag data: '%.*s'\033[0m\n", len, str);
        }
    }
  else
    {
      switch(stanza->type)
        {
        case xmpp_dialback_verify:

          stanza->u.dialback_verify.hash = arena_strndup(arena, str, len);

          break;

        case xmpp_dialback_result:

          stanza->u.dialback_result.hash = arena_strndup(arena, str, len);

          break;

        case xmpp_auth:

          stanza->u.auth.content = arena_strndup(arena, str, len);

          break;

        default:

          fprintf(stderr, "\033[31;1mUnhandled data: '%.*s'\033[0m\n", len, str);
        }
    }
}

void
xmpp_gen_dialback_key(char *key, struct xmpp_state *state,
                      const char *remote_jid, const char *id)
{
  const char* secret;
  char secret_hash[65];
  char* data;

  if(-1 == asprintf(&data, "%s %s %s",
                    tree_get_string(config, "domain"),
                    remote_jid, id))
    {
      syslog(LOG_WARNING, "asprintf failed: %s", strerror(errno));

      state->fatal_error = 1;

      return;
    }

  secret = tree_get_string(config, "secret");

  hash_sha256(secret, strlen(secret), secret_hash);

  hash_hmac_sha256(secret_hash, strlen(secret_hash),
                   data, strlen(data), key);

  free(data);
}

static void
xmpp_xml_error(struct xmpp_state *state, enum XML_Error error)
{
  const char* message;

  message = XML_ErrorString(error);

  switch(error)
    {
    case XML_ERROR_INVALID_TOKEN:
    case XML_ERROR_UNDECLARING_PREFIX:
    case XML_ERROR_INCOMPLETE_PE:
    case XML_ERROR_TAG_MISMATCH:

      xmpp_stream_error(state, "xml-not-well-formed", "XML parser reported: %s", message);

      break;

    default:

      xmpp_stream_error(state, "invalid-xml", "XML parser reported: %s", message);
    }
}

int
xmpp_state_data(struct xmpp_state *state,
                const void *data, size_t count)
{
  int result;

  assert(!state->fatal_error);

  if(state->using_tls)
    {
      state->tls_read_start = data;
      state->tls_read_end = state->tls_read_start + count;

      while(state->tls_read_start != state->tls_read_end)
        {
          if(state->tls_handshake == 1)
            {
              result = gnutls_handshake(state->tls_session);

              if(result == GNUTLS_E_AGAIN || result == GNUTLS_E_INTERRUPTED)
                continue;

              if(result < 0)
                {
                  syslog(LOG_INFO, "TLS handshake failed: %s", gnutls_strerror(result));

                  return -1;
                }

              state->tls_handshake = 0;

              xmpp_reset_stream(state);
            }
          else
            {
              char buf[4096];
              int result;

              result = gnutls_record_recv(state->tls_session, buf, sizeof(buf));

              if(result < 0)
                {
                  if(result == GNUTLS_E_AGAIN || result == GNUTLS_E_INTERRUPTED)
                    continue;

                  return -1;
                }

              if(!result)
                return -1;

              fprintf(stderr, "REMOTE-TLS(%p): \033[1;36m%.*s\033[0m\n", state, (int) result, buf);

              if(!XML_Parse(state->xml_parser, buf, result, 0))
                {
                  xmpp_xml_error(state, XML_GetErrorCode(state->xml_parser));

                  return -1;
                }
            }
        }
    }
  else
    {
      fprintf(stderr, "REMOTE(%p): \033[1;36m%.*s\033[0m\n", state, (int) count, (char*) data);

      if(!XML_Parse(state->xml_parser, data, count, 0))
        {
          xmpp_xml_error(state, XML_GetErrorCode(state->xml_parser));

          return -1;
        }
    }

  if(state->stream_finished)
    {
      xmpp_write(state, "</stream:stream>");

      /* XXX: Find some way to transmit this data before disconnecting */

      return -1;
    }

  return state->fatal_error ? -1 : 0;
}

static void
xmpp_handle_queued_stanzas(struct xmpp_state *state)
{
  struct xmpp_queued_stanza *qs, *prev;

  if(!state->ready || state->first_queued_stanza)
    return;

  qs = state->first_queued_stanza;

  while(qs)
    {
      xmpp_write(state, qs->data);

      free(qs->data);
      free(qs->target);
      prev = qs;
      qs = qs->next;

      free(prev);
    }

  state->first_queued_stanza = 0;
  state->last_queued_stanza = 0;
}

static void
xmpp_handshake(struct xmpp_state *state)
{
  struct xmpp_features *pf = &state->features;

  if(pf->starttls && !state->using_tls)
    {
      xmpp_write(state, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
    }
  else if(!state->local_identified)
    {
      if(pf->auth_external)
        {
          const char* domain;
          char* base64_domain;

          domain = tree_get_string(config, "domain");

          base64_domain = base64_encode(domain, strlen(domain));

          xmpp_printf(state,
                      "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>"
                      "%s"
                      "</auth>",
                      base64_domain);

          free(base64_domain);
        }
      else if(pf->dialback || state->using_tls)
        {
          char key[65];

          /* Use dialback even if it isn't advertised.  Openfire does
           * not advertise dialback after TLS, even though it's
           * supported.
           */

          xmpp_gen_dialback_key(key, state, state->remote_jid,
                                state->remote_stream_id);

          xmpp_printf(state,
                      "<db:result from='%s' to='%s'>%s</db:result>",
                      tree_get_string(config, "domain"),
                      state->remote_jid, key);
        }
    }
  else
    {
      char id[32];

      xmpp_gen_id(id);

      xmpp_printf(state,
                  "<iq type='get' id='%s' from='%s' to='%s'>"
                  "<query xmlns='http://jabber.org/protocol/disco#info'/>"
                  "</iq>",
                  id, tree_get_string(config, "domain"), state->remote_jid);

      state->ready = 1;

      xmpp_handle_queued_stanzas(state);
    }
}

static void
xmpp_process_stanza(struct xmpp_state *state)
{
  struct xmpp_stanza *stanza = &state->stanza;

  switch(stanza->type)
    {
    case xmpp_unknown:

      break;

    case xmpp_features:

        {
          if(state->is_initiator)
            {
              state->features = state->stanza.u.features;

              xmpp_handshake(state);
            }
        }

      break;

    case xmpp_error:

      /* "It is assumed that all stream-level errors are unrecoverable"
       *   -- RFC 3920, section 4.7.1. Rules:
       */

      state->fatal_error = 1;

      break;

    case xmpp_tls_proceed:

      if(state->using_tls)
        break;

      state->using_tls = 1;

      xmpp_start_tls(state);

      break;

    case xmpp_tls_starttls:

        {
          if(state->using_tls)
            {
              /* XXX: Is this the correct way to handle redundant starttls tags? */
              xmpp_write(state, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>");

              state->fatal_error = 1;
            }
          else
            {
              xmpp_write(state, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");

              state->using_tls = 1;

              xmpp_start_tls(state);
            }
        }

      break;

    case xmpp_dialback_verify:

        {
          struct xmpp_dialback_verify *pdv = &stanza->u.dialback_verify;
          char key[65];

          if(!stanza->id || !stanza->from || !stanza->to)
            {
              xmpp_stream_error(state, "invalid-xml",
                                "Missing attribute(s) in dialback verify tag");

              return;
            }

          xmpp_gen_dialback_key(key, state, stanza->from, stanza->id);

          /* Reverse from/to values, since we got these from a remote host */
          xmpp_printf(state, "<db:verify id='%s' from='%s' to='%s' type='%s'/>",
                      stanza->id, stanza->to, stanza->from,
                      strcmp(pdv->hash, key) ? "invalid" : "valid");
        }

      break;

    case xmpp_dialback_result:

        {
          struct xmpp_dialback_result *pdr = &stanza->u.dialback_result;

          if(!stanza->from || !stanza->to)
            {
              xmpp_stream_error(state, "invalid-xml",
                                "Missing attribute(s) in dialback result tag");

              return;
            }

          if(!pdr->type)
            {
              /* XXX: Validate */

              free(state->remote_jid);
              state->remote_jid = strdup(stanza->from);

              xmpp_printf(state,
                        "<db:result from='%s' to='%s' type='valid'/>",
                        stanza->to, stanza->from);
            }
          else
            {
              if(strcmp(pdr->type, "valid"))
                {
                  fprintf(stderr, "Dialback result invalid\n");
                  state->fatal_error = 1;

                  return;
                }

              state->local_identified = 1;

              xmpp_handshake(state);
            }
        }

      break;

    case xmpp_auth:

        {
          struct xmpp_auth *pa = &stanza->u.auth;

          if(!pa->mechanism)
            {
              xmpp_stream_error(state, "invalid-mechanism",
                                "No SASL mechanism given");

              return;
            }

          if(!strcmp(pa->mechanism, "DIGEST-MD5"))
            {
              char nonce[16];
              char *challenge;
              char *challenge_base64;

              xmpp_gen_id(nonce);

              if(-1 == asprintf(&challenge,
                                "realm=\"%s\",nonce=\"%s\",qop=\"auth\",charset=utf-8,algorithm=md5-ses",
                                tree_get_string(config, "domain"), nonce))
                {
                  fprintf(stderr, "asprintf failed\n");
                  state->fatal_error = 1;

                  return;
                }

              challenge_base64 = base64_encode(challenge, strlen(challenge));

              free(challenge);

              xmpp_printf(state,
                        "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                        "%s"
                        "</challenge>",
                        challenge_base64);

              free(challenge_base64);
            }
          else if(!strcmp(pa->mechanism, "PLAIN"))
            {
              char *content;
              const char *user;
              const char *secret;
              ssize_t content_length;

              if(!pa->content)
                {
                  xmpp_write(state,
                            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                            "<incorrect-encoding/>"
                            "</failure>");

                  state->fatal_error = 1;

                  return;
                }

              content = malloc(strlen(pa->content) + 1);
              content_length = base64_decode(content, pa->content, 0);
              content[content_length] = 0;

              if(!(user = memchr(content, 0, content_length))
                 || !(secret = memchr(user + 1, 0, content + content_length - user - 1)))
                {
                  xmpp_write(state,
                            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                            "<incorrect-encoding/>"
                            "</failure>");

                  state->fatal_error = 1;

                  return;
                }

              ++user;
              ++secret;

              /*
              if(-1 == peer_authenticate(state, content, user, secret))
                {
                  free(content);

                  return;
                }
                */

              free(state->remote_jid);
              state->remote_jid = strdup(content);

              free(content);

              xmpp_write(state, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
              xmpp_reset_stream(state);
            }
          else if(!strcmp(pa->mechanism, "EXTERNAL"))
            {
            }
          else
            {
              xmpp_stream_error(state, "invalid-mechanism",
                                "Unknown SASL mechanism");
            }
        }

      break;

    case xmpp_iq:

      switch(stanza->sub_type)
        {
        case xmpp_sub_iq_discovery_info:

          fprintf(stderr, "Got discovery.  We are full\n");

          break;

        case xmpp_sub_iq_discovery_items:

          if(!stanza->from || !stanza->to)
            {
              xmpp_stream_error(state, "invalid-xml",
                                "Missing attribute(s) in discovery tag");

              return;
            }

          xmpp_queue_stanza(stanza->from,
                            "<iq type='result' id='%s' from='%s' to='%s'>"
                            "<query xmlns='http://jabber.org/protocol/disco#info'>"
                            "<identity category='server' name='Vink server' type='im'/>"
                            "<identity category='pubsub' type='pep'/>"
                            "<feature var='google:jingleinfo'/>"
                            "<feature var='http://jabber.org/protocol/address'/>"
                            "<feature var='http://jabber.org/protocol/commands'/>"
                            "<feature var='http://jabber.org/protocol/disco#info'/>"
                            "<feature var='http://jabber.org/protocol/disco#items'/>"
                            "<feature var='http://jabber.org/protocol/offline'/>"
                            "<feature var='http://jabber.org/protocol/pubsub'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#collections'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#config-node'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#create-and-configure'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#create-nodes'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#default_access_model_open'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#delete-nodes'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#get-pending'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#instant-nodes'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#item-ids'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#manage-subscriptions'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#meta-data'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#modify-affiliations'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#multi-subscribe'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#outcast-affiliation'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#persistent-items'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#presence-notifications'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#publish'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#publisher-affiliation'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#purge-nodes'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#retract-items'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#retrieve-affiliations'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#retrieve-default'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#retrieve-items'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#retrieve-subscriptions'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#subscribe'/>"
                            "<feature var='http://jabber.org/protocol/pubsub#subscription-options'/>"
                            "<feature var='http://jabber.org/protocol/rsm'/>"
                            "<feature var='jabber:iq:last'/>"
                            "<feature var='jabber:iq:privacy'/>"
                            "<feature var='jabber:iq:private'/>"
                            "<feature var='jabber:iq:register'/>"
                            "<feature var='jabber:iq:roster'/>"
                            "<feature var='jabber:iq:time'/>"
                            "<feature var='jabber:iq:version'/>"
                            "<feature var='urn:xmpp:ping'/>"
                            "<feature var='vcard-temp'/>"
                            "</query>"
                            "</iq>",
                            stanza->id, stanza->to, stanza->from);

          break;
        }

      break;
    }
}

ssize_t
xmpp_tls_pull(gnutls_transport_ptr_t arg, void *data, size_t size)
{
  struct xmpp_state *state = arg;

  if(state->tls_read_start == state->tls_read_end)
    {
      errno = EAGAIN;

      return -1;
    }

  if(size > state->tls_read_end - state->tls_read_start)
    size = state->tls_read_end - state->tls_read_start;

  memcpy(data, state->tls_read_start, size);

  state->tls_read_start += size;

  return size;
}

ssize_t
xmpp_tls_push(gnutls_transport_ptr_t arg, const void *data, size_t size)
{
  struct xmpp_state *state = arg;

  if(state->fatal_error)
    return -1;

  ARRAY_ADD_SEVERAL(state->writebuf, data, size);

  if(ARRAY_RESULT(state->writebuf))
    {
      syslog(LOG_WARNING, "buffer append error: %s", strerror(errno));

      state->fatal_error = 1;

      return -1;
    }

  return size;
}

static void
xmpp_start_tls(struct xmpp_state *state)
{
  int result;

  if(0 > (result = gnutls_init(&state->tls_session, state->is_initiator ? GNUTLS_CLIENT : GNUTLS_SERVER)))
    {
      syslog(LOG_WARNING, "gnutls_init failed: %s", gnutls_strerror(result));

      state->fatal_error = 1;

      return;
    }

  gnutls_priority_set(state->tls_session, priority_cache);

  if(0 > (result = gnutls_credentials_set(state->tls_session, GNUTLS_CRD_CERTIFICATE, xcred)))
    {
      syslog(LOG_WARNING, "failed to set credentials for TLS session: %s",
             gnutls_strerror(result));

      gnutls_bye(state->tls_session, GNUTLS_SHUT_WR);
      state->tls_session = 0;
      state->fatal_error = 1;

      return;
    }

  gnutls_certificate_server_set_request(state->tls_session, GNUTLS_CERT_REQUEST);
  gnutls_dh_set_prime_bits(state->tls_session, 1024);

  gnutls_transport_set_ptr(state->tls_session, (gnutls_transport_ptr_t) state);
  gnutls_transport_set_push_function(state->tls_session, xmpp_tls_push);
  gnutls_transport_set_pull_function(state->tls_session, xmpp_tls_pull);

  state->tls_handshake = 1;

  result = gnutls_handshake(state->tls_session);

  if (result == GNUTLS_E_AGAIN || result == GNUTLS_E_INTERRUPTED)
    return;

  if(result < 0)
    {
      syslog(LOG_INFO, "TLS handshake failed: %s", gnutls_strerror(result));

      gnutls_bye(state->tls_session, GNUTLS_SHUT_WR);
      state->tls_session = 0;
      state->tls_handshake = 0;
      state->fatal_error = 1;
    }
}


int
xmpp_parse_jid(struct xmpp_jid *target, char *input)
{
  char *c;

  target->node = 0;
  target->resource = 0;

  c = strchr(input, '@');

  if(c)
    {
      target->node = input;
      *c++ = 0;
      input = c;
    }

  target->domain = input;

  c = strchr(input, '/');

  if(c)
    {
      *c++ = 0;
      target->resource = c;
    }

  return 0;
}

void
xmpp_gen_id(char *target)
{
  struct timeval now;

  gettimeofday(&now, 0);

  sprintf(target, "%llx-%x",
          (unsigned long long) now.tv_sec * 1000000
          + (unsigned long long) now.tv_usec,
          (unsigned int) rand());

}
