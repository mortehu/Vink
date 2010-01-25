#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <syslog.h>
#include <sys/time.h>

#include <expat.h>

#include "base64.h"
#include "hash.h"
#include "tls-common.h"
#include "vink-tree.h"
#include "vink.h"

#include "vink-internal.h"
#include "xmpp-internal.h"

#define TRACE 1

#if TRACE
static FILE *trace;
#endif

static void
xmpp_reset_stream (struct vink_xmpp_state *state)
{
  XML_ParserReset (state->xml_parser, "utf-8");
  XML_SetUserData (state->xml_parser, state);
  XML_SetElementHandler (state->xml_parser, xmpp_start_element, xmpp_end_element);
  XML_SetCharacterDataHandler (state->xml_parser, xmpp_character_data);
  XML_SetStartNamespaceDeclHandler (state->xml_parser, xmpp_start_namespace);

  if (state->is_client)
    {
      xmpp_printf (state,
                   "<?xml version='1.0'?>"
                   "<stream:stream xmlns='jabber:client'"
                   " xmlns:stream='http://etherx.jabber.org/streams'"
                   " to='%s'"
                   " version='1.0'>",
                   state->remote_jid);
    }
  else if (state->is_initiator)
    {
      xmpp_printf (state,
                   "<?xml version='1.0'?>"
                   "<stream:stream xmlns='jabber:server'"
                   " xmlns:stream='http://etherx.jabber.org/streams'"
                   " from='%s'"
                   " to='%s'"
                   " xmlns:db='jabber:server:dialback'"
                   " version='1.0'>",
                   vink_tree_get_string (VINK_config, "domain"), state->remote_jid);
    }

  state->xml_tag_level = 0;
}

struct vink_xmpp_state *
vink_xmpp_state_init (int (*write_func)(const void*, size_t, void*),
                      const char *remote_domain, unsigned int flags,
                      void *arg)
{
  struct vink_xmpp_state *state;

  state = malloc (sizeof (*state));

  if (!state)
    return 0;

#if TRACE
  if (!trace)
    {
      if (flags & VINK_CLIENT)
        trace = fopen ("xmpp-client.txt", "w");
      else
        trace = stderr;
    }
#endif

  memset (state, 0, sizeof (*state));

  if (flags & VINK_CLIENT)
    {
      state->is_client = 1;

      if (-1 == asprintf (&state->jid, "%s@%s",
                          vink_config ("user"), vink_config ("domain")))
        {
          free (state);

          return 0;
        }
    }

  state->write_func = write_func;
  state->write_func_arg = arg;

  state->xml_parser = XML_ParserCreateNS ("utf-8", '|');

  if (!state->xml_parser)
    {
      free (state);

      return 0;
    }

  if (remote_domain)
    {
      state->is_initiator = 1;
      state->remote_jid = strdup (remote_domain);
    }

  xmpp_reset_stream (state);

  return state;
}

void
vink_xmpp_set_callbacks (struct vink_xmpp_state *state,
                         struct vink_xmpp_callbacks *callbacks)
{
  state->callbacks = *callbacks;
}

void
vink_xmpp_state_free (struct vink_xmpp_state *state)
{
  vink_arena_free (&state->stanza.arena);
  free (state->remote_jid);

  if (state->backend_data && state->callbacks.backend_free)
    state->callbacks.backend_free (state->backend_data);

  if (state->tls_session)
    gnutls_bye (state->tls_session, GNUTLS_SHUT_WR);

  if (state->xml_parser)
    XML_ParserFree (state->xml_parser);
}

static void
xmpp_writen (struct vink_xmpp_state *state, const char *data, size_t size)
{
  int result;

  if (state->fatal_error)
    return;

  if (state->using_tls && !state->tls_handshake)
    {
      const char *buf;
      size_t offset = 0, to_write;

      buf = data;

#if TRACE
      fprintf (trace, "LOCAL-TLS (%p): \033[1;35m%.*s\033[0m\n", state, (int) size, buf);
      fflush (trace);
#endif

      while (offset < size)
        {
          to_write = size - offset;

          if (to_write > 4096)
            to_write = 4096;

          result = gnutls_record_send (state->tls_session, buf + offset, to_write);

          if (result <= 0)
            {
              if (result < 0)
                syslog (LOG_INFO, "Failed to create TLS records: %s", gnutls_strerror (result));

              state->fatal_error = gnutls_strerror (result);

              return;
            }

          offset += result;
        }
    }
  else
    {
#if TRACE
      fprintf (trace, "LOCAL (%p): \033[1;35m%.*s\033[0m\n", state, (int) size, data);
      fflush (trace);
#endif

      if (-1 == state->write_func (data, size, state->write_func_arg))
        {
          syslog (LOG_WARNING, "Failed to buffer data for remote host: %s", strerror (errno));

          state->fatal_error = strerror (errno);
        }
    }
}

static void
xmpp_write (struct vink_xmpp_state *state, const char *data)
{
  xmpp_writen (state, data, strlen (data));
}

static void
xmpp_printf (struct vink_xmpp_state *state, const char *format, ...)
{
  va_list args;
  char *buf;
  int result;

  va_start (args, format);

  result = vasprintf (&buf, format, args);

  if (result == -1)
    {
      syslog (LOG_WARNING, "asprintf failed: %s", strerror (errno));

      xmpp_stream_error (state, "internal-server-error", 0);

      return;
    }

  xmpp_write (state, buf);

  free (buf);
}

int
vink_xmpp_queue_stanza (struct vink_xmpp_state *state, const char *format, ...)
{
  struct xmpp_queued_stanza *qs;
  int result;
  va_list args;
  char *buf;

  va_start (args, format);

  result = vasprintf (&buf, format, args);

  if (result == -1)
    {
      syslog (LOG_WARNING, "asprintf failed: %s", strerror (errno));

      return -1;
    }

  if (state->ready)
    {
      xmpp_write (state, buf);
      free (buf);
    }
  else
    {
      qs = malloc (sizeof (*qs));

      if (!qs)
        {
          syslog (LOG_WARNING, "malloc failed: %s", strerror (errno));

          free (buf);

          return -1;
        }

      qs->target = 0;
      qs->data = buf;
      qs->next = 0;

      if (!state->first_queued_stanza)
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

  return 0;
}

static void
xmpp_stream_error (struct vink_xmpp_state *state, const char *type,
                   const char *format, ...)
{
  va_list args;
  char *buf;
  int result;

  xmpp_printf (state,
               "<stream:error>"
               "<%s xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>",
               type);

  if (format)
    {
      xmpp_write (state,
                  "<text xmlns='urn:ietf:params:xml:ns:xmpp-streams'"
                  " xml:lang='en'>");

      va_start (args, format);

      result = vasprintf (&buf, format, args);

      if (result == -1)
        {
          syslog (LOG_WARNING, "asprintf failed: %s", strerror (errno));

          state->fatal_error = strerror (errno);

          return;
        }

      xmpp_write (state, buf);

      free (buf);

      xmpp_write (state, "</text>");
    }

  xmpp_write (state, "</stream:error></stream:stream>");

  state->fatal_error = type;
}

static void
xmpp_stanza_error (struct vink_xmpp_state *state,
                   const char *type, const char *id,
                   const char *error_type,
                   const char *error_condition,
                   const char *format, ...)
{
  va_list args;
  char *buf;
  int result;

  va_start (args, format);

  result = vasprintf (&buf, format, args);

  if (result == -1)
    {
      syslog (LOG_WARNING, "asprintf failed: %s", strerror (errno));

      state->fatal_error = strerror (errno);

      return;
    }

  xmpp_printf (state,
               "<%1$s type='error' id='%2$s'>"
               "<error type='%3$s'>"
               "<%4$s/>"
               "<text xmlns='urn:ietf:params:xml:ns:xmpp-streams'"
               " xml:lang='en'>"
               "%5$s"
               "</text>"
               "</error>"
               "</%1$s>",
               type, id, error_type, error_condition, buf);

  free (buf);
}

static void
xmpp_stanza_unauthorized (struct vink_xmpp_state *state,
                          const char *type, const char *id)
{
  xmpp_stanza_error (state, type, id, "auth", "forbidden", "Authorization required");
}

static char *
plain_auth_data (struct vink_xmpp_state *state)
{
  const char *authzid, *authcid, *password;
  char *response, *base64_response, *c;
  size_t length;

  authzid = vink_tree_get_string_default (VINK_config, "authzid", "");
  authcid = vink_tree_get_string (VINK_config, "user");
  password = vink_tree_get_string (VINK_config, "password");

  length = strlen (authzid) + strlen (authcid) + strlen (password) + 2;
  response = malloc (length + 1);

  if (!response)
    {
      syslog (LOG_WARNING, "malloc failed: %s", strerror (errno));

      xmpp_stream_error (state, "internal-server-error", 0);

      return 0;
    }

  strcpy (response, authzid);
  c = strchr (response, 0) + 1;

  strcpy (c, authcid);
  c = strchr (c, 0) + 1;

  strcpy (c, password);

  base64_response = base64_encode (response, length);

  free (response);

  return base64_response;
}

static const struct
{
  enum xmpp_stanza_type parent;
  enum xmpp_stanza_type next;
  const char *tag;
} state_transitions[] =
{
  { xmpp_root, xmpp_ack_request, "urn:xmpp:sm:2|r" },
  { xmpp_root, xmpp_ack_response, "urn:xmpp:sm:2|a" },
  { xmpp_root, xmpp_dialback_result, "jabber:server:dialback|result" },
  { xmpp_root, xmpp_dialback_verify, "jabber:server:dialback|verify" },
  { xmpp_root, xmpp_error, "http://etherx.jabber.org/streams|error" },
  { xmpp_root, xmpp_features, "http://etherx.jabber.org/streams|features" },
  { xmpp_root, xmpp_iq, "jabber:client|iq" },
  { xmpp_root, xmpp_iq, "jabber:server|iq" },
  { xmpp_root, xmpp_message, "jabber:client|message" },
  { xmpp_root, xmpp_message, "jabber:server|message" },
  { xmpp_root, xmpp_presence, "jabber:client|presence" },
  { xmpp_root, xmpp_presence, "jabber:server|presence" },
  { xmpp_root, xmpp_sasl_auth, "urn:ietf:params:xml:ns:xmpp-sasl|auth" },
  { xmpp_root, xmpp_sasl_challenge, "urn:ietf:params:xml:ns:xmpp-sasl|challenge" },
  { xmpp_root, xmpp_sasl_failure, "urn:ietf:params:xml:ns:xmpp-sasl|failure" },
  { xmpp_root, xmpp_sasl_response, "urn:ietf:params:xml:ns:xmpp-sasl|response" },
  { xmpp_root, xmpp_sasl_success, "urn:ietf:params:xml:ns:xmpp-sasl|success" },
  { xmpp_root, xmpp_tls_proceed, "urn:ietf:params:xml:ns:xmpp-tls|proceed" },
  { xmpp_root, xmpp_tls_starttls, "urn:ietf:params:xml:ns:xmpp-tls|starttls" },

  { xmpp_features, xmpp_features_ack,
    "http://www.xmpp.org/extensions/xep-0198.html#ns|ack" },
  { xmpp_features, xmpp_features_bind, "urn:ietf:params:xml:ns:xmpp-bind|bind" },
  { xmpp_features, xmpp_features_compression,
    "http://jabber.org/features/compress|compression" },
  { xmpp_features, xmpp_features_dialback, "urn:xmpp:features:dialback|dialback" },
  { xmpp_features, xmpp_features_mechanisms,
    "urn:ietf:params:xml:ns:xmpp-sasl|mechanisms" },
  { xmpp_features, xmpp_features_session, "urn:ietf:params:xml:ns:xmpp-session|session" },
  { xmpp_features, xmpp_features_starttls, "urn:ietf:params:xml:ns:xmpp-tls|starttls" },
  { xmpp_iq, xmpp_iq_bind, "urn:ietf:params:xml:ns:xmpp-bind|bind" },
  { xmpp_iq, xmpp_iq_discovery_info, "http://jabber.org/protocol/disco#info|query" },
  { xmpp_iq, xmpp_iq_discovery_items, "http://jabber.org/protocol/disco#items|query" },
  { xmpp_message, xmpp_message_body, "jabber:client|body" },
  { xmpp_message, xmpp_message_body, "jabber:server|body" },
  { xmpp_message, xmpp_message_event, "http://jabber.org/protocol/pubsub#event|event" },
  { xmpp_message, xmpp_message_requect_receipt, "urn:xmpp:receipts|request" },
  { xmpp_presence, xmpp_presence_show, "jabber:server|show" },
  { xmpp_presence, xmpp_presence_show, "jabber:server|show" },

  { xmpp_features_mechanisms, xmpp_features_mechanisms_mechanism,
    "urn:ietf:params:xml:ns:xmpp-sasl|mechanism" },
  { xmpp_iq_bind, xmpp_iq_bind_jid, "urn:ietf:params:xml:ns:xmpp-bind|jid" },
  { xmpp_iq_discovery_info, xmpp_iq_discovery_info_feature,
    "http://jabber.org/protocol/disco#info|feature" },
  { xmpp_message_event, xmpp_message_event_items,
    "http://jabber.org/protocol/pubsub#event|items" },

  { xmpp_message_event_items, xmpp_message_event_items_item,
    "http://jabber.org/protocol/pubsub#event|item" },

  { xmpp_message_event_items_item,
    xmpp_message_event_items_item_wavelet_update,
    "http://waveprotocol.org/protocol/0.2/waveserver|wavelet-update" },

  { xmpp_message_event_items_item_wavelet_update,
    xmpp_message_event_items_item_wavelet_update_applied_delta,
    "http://waveprotocol.org/protocol/0.2/waveserver|applied-delta" }
};

static void XMLCALL
xmpp_start_element (void *user_data, const XML_Char *name,
                    const XML_Char **atts)
{
  struct vink_xmpp_state *state = user_data;
  const XML_Char **attr;
  struct xmpp_stanza *stanza;
  struct vink_arena *arena;

  stanza = &state->stanza;
  arena = &stanza->arena;

  if (state->xml_tag_level == 0)
    {
      if (strcmp (name, "http://etherx.jabber.org/streams|stream"))
        {
          xmpp_stream_error (state, "invalid-namespace",
                             "Expected stream tag in "
                             "http://etherx.jabber.org/streams namespace");

          return;
        }

      state->remote_major_version = 0;
      state->remote_minor_version = 0;

      for (attr = atts; *attr; attr += 2)
        {
          if (!strcmp (attr[0], "version"))
            {
              if (2 != sscanf (attr[1], "%u.%u", &state->remote_major_version,
                               &state->remote_minor_version))
                {
                  xmpp_stream_error (state, "unspported-version",
                                     "Unable to parse stream version");

                  return;
                }
            }
          else if (!strcmp (attr[0], "to"))
            {
              if (strcmp (attr[1], vink_tree_get_string (VINK_config, "domain")))
                {
                  xmpp_stream_error (state, "host-unknown", 0);

                  return;
                }
            }
          else if (!strcmp (attr[0], "id"))
            state->remote_stream_id = strdup (attr[1]);
        }

      /* Clamp remote version to maximum version supported by us */
      if (state->remote_major_version > 1)
        {
          xmpp_stream_error (state, "unsupported-version",
                             "Major version %d not supported.  Max is 1.",
                             state->remote_major_version);

          return;
        }

      if (state->remote_major_version == 1 && state->remote_minor_version > 0)
        {
          state->remote_major_version = 1;
          state->remote_minor_version = 1;
        }

      if (state->remote_is_client)
        {
          xmpp_gen_id (state->stream_id);

          xmpp_printf (state,
                       "<?xml version='1.0'?>"
                       "<stream:stream xmlns='jabber:client' "
                       "xmlns:stream='http://etherx.jabber.org/streams' "
                       "from='%s' id='%s'",
                       vink_tree_get_string (VINK_config, "domain"), state->stream_id);

          if (state->remote_major_version || state->remote_minor_version)
            xmpp_printf (state, " version='%d.%d'>",
                         state->remote_major_version,
                         state->remote_minor_version);
          else
            xmpp_write (state, ">");

          if (state->remote_major_version >= 1)
            {
              xmpp_write (state, "<stream:features>");

              if (!state->using_tls && state->remote_major_version >= 1)
                xmpp_write (state,
                            "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");

              if (!state->remote_identified)
                xmpp_write (state,
                            "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                            /*"<mechanism>DIGEST-MD5</mechanism>"*/
                            "<mechanism>PLAIN</mechanism>"
                            "</mechanisms>");

              if (state->remote_is_client)
                xmpp_write (state, "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>");

              xmpp_write (state, "</stream:features>");
            }
        }
      else if (!state->is_initiator)
        {
          xmpp_gen_id (state->stream_id);

          xmpp_printf (state,
                       "<?xml version='1.0'?>"
                       "<stream:stream xmlns='jabber:server' "
                       "xmlns:stream='http://etherx.jabber.org/streams' "
                       "xmlns:db='jabber:server:dialback' "
                       "from='%s' id='%s' ",
                       vink_tree_get_string (VINK_config, "domain"), state->stream_id);

          if (state->remote_major_version || state->remote_minor_version)
            xmpp_printf (state, " version='%d.%d'>",
                         state->remote_major_version,
                         state->remote_minor_version);
          else
            xmpp_write (state, ">");

          if (state->remote_major_version >= 1)
            {
              xmpp_write (state, "<stream:features>");

              if (!state->using_tls)
                {
                  xmpp_write (state,
                              "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>"
                              "<required/>"
                              "</starttls>");

                  if (!state->remote_identified)
                    xmpp_write (state, "<dialback xmlns='urn:xmpp:features:dialback'/>");
                }
              else if (!state->remote_identified)
                {
                  xmpp_write (state,
                              "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                              "<mechanism>EXTERNAL</mechanism>"
                              "</mechanisms>");
                }

              xmpp_write (state, "</stream:features>");
            }
        }
      else
        {
          assert (state->is_initiator);

          if (!state->remote_stream_id)
            {
              xmpp_stream_error (state, "invalid-id", 0);

              return;
            }
        }
    }
  else
    {
      enum xmpp_stanza_type parent;
      enum xmpp_stanza_type next = xmpp_unknown;
      size_t i;

      if (state->xml_tag_level == 1)
        {
          memset (&state->stanza, 0, sizeof (state->stanza));
          parent = xmpp_root;

          for (attr = atts; *attr; attr += 2)
            {
              if (!strcmp (attr[0], "id"))
                stanza->id = vink_arena_strdup (arena, attr[1]);
              else if (!strcmp (attr[0], "from"))
                stanza->from = vink_arena_strdup (arena, attr[1]);
              else if (!strcmp (attr[0], "to"))
                {
                  if (!state->remote_is_client)
                    {
                      char *jid_buf;
                      struct vink_xmpp_jid jid;

                      jid_buf = strdupa (attr[1]);
                      vink_xmpp_parse_jid (&jid, jid_buf);

                      if (strcmp (jid.domain, vink_tree_get_string (VINK_config, "domain")))
                        {
                          xmpp_stream_error (state, "host-unknown",
                                             "Unknown domain '%s'", jid.domain);

                          return;
                        }
                    }

                  stanza->to = vink_arena_strdup (arena, attr[1]);
                }
            }
        }
      else
        parent = stanza->types[state->xml_tag_level - 2];

      for (i = 0; i < ARRAY_SIZE (state_transitions); ++i)
        {
          if (state_transitions[i].parent == parent
              && !strcmp (state_transitions[i].tag, name))
            {
              next = state_transitions[i].next;

              break;
            }
        }

      if (next == xmpp_unknown)
        {
          if (parent == xmpp_root)
            {
              xmpp_stream_error (state, "unsupported-stanza-type",
                                 "Unknown element '%s'", name);

              return;
            }
#if TRACE
          fprintf (trace,
                   "\033[31;1mUnhandled element: '%s', parent = %d\033[0m\n",
                   name, parent);
#endif
        }


      stanza->types[state->xml_tag_level - 1] = next;

      switch (next)
        {
        case xmpp_dialback_verify:

            {
              struct xmpp_dialback_verify *pdv = &stanza->u.dialback_verify;

              for (attr = atts; *attr; attr += 2)
                {
                  if (!strcmp (attr[0], "type"))
                    pdv->type = vink_arena_strdup (arena, attr[1]);
                }
            }

          break;

        case xmpp_dialback_result:

            {
              struct xmpp_dialback_result *pdr = &stanza->u.dialback_result;

              for (attr = atts; *attr; attr += 2)
                {
                  if (!strcmp (attr[0], "type"))
                    pdr->type = vink_arena_strdup (arena, attr[1]);
                }
            }

          break;

        case xmpp_sasl_auth:

          if (state->is_initiator)
            {
              xmpp_stream_error (state, "bad-format",
                                 "Receiving entity attempted to initiate SASL");

              return;
            }

          for (attr = atts; *attr; attr += 2)
            {
              if (!strcmp (attr[0], "mechanism"))
                stanza->u.auth.mechanism = vink_arena_strdup (arena, attr[1]);
            }

          break;

        case xmpp_sasl_challenge:

          if (!state->is_initiator)
            {
              xmpp_stream_error (state, "bad-format", "Initiating entity sent SASL challenge");

              return;
            }

          break;

        case xmpp_sasl_response:

          if (state->is_initiator)
            {
              xmpp_stream_error (state, "bad-format", "Receiving entity attempted to initiate SASL");

              return;
            }

          for (attr = atts; *attr; attr += 2)
            {
              if (!strcmp (attr[0], "mechanism"))
                stanza->u.auth.mechanism = vink_arena_strdup (arena, attr[1]);
            }

          break;

        case xmpp_sasl_success:

          if (!state->is_initiator)
            {
              xmpp_stream_error (state, "bad-format", "Initiating entity sent SASL success");

              return;
            }

          break;

        case xmpp_sasl_failure:

          if (!state->is_initiator)
            {
              xmpp_stream_error (state, "bad-format", "Initiating entity sent SASL failure");

              return;
            }

          break;

        case xmpp_iq:

          for (attr = atts; *attr; attr += 2)
            {
              if (!strcmp (attr[0], "type"))
                stanza->u.iq.type = vink_arena_strdup (arena, attr[1]);
            }

          break;

        case xmpp_features_ack: stanza->u.features.ack = 1; break;
        case xmpp_features_bind: stanza->u.features.bind = 1; break;
        case xmpp_features_dialback: stanza->u.features.dialback = 1; break;
        case xmpp_features_session: stanza->u.features.session = 1; break;
        case xmpp_features_starttls: stanza->u.features.starttls = 1; break;

        case xmpp_iq_discovery_info:

          stanza->u.iq.disco_info = 1;

          break;

        case xmpp_iq_discovery_items:

          stanza->u.iq.disco_items = 1;

          break;

        case xmpp_iq_bind:

          stanza->u.iq.bind = 1;

          break;

        case xmpp_message_requect_receipt:

          stanza->u.message.request_receipt = 1;

          break;

        case xmpp_iq_discovery_info_feature:

            {
              const char *var = 0;

              for (attr = atts; *attr; attr += 2)
                {
                  if (!strcmp (attr[0], "var"))
                    {
                      var = attr[1];

                      break;
                    }
                }

              if (!var)
                {
                  xmpp_stream_error (state, "bad-format", "Missing 'var' in feature element");

                  return;
                }

#define CHECK_FEATURE(str, symbol) \
              if (!strcmp (var, str)) state->feature_##symbol = 1;

              CHECK_FEATURE ("google:jingleinfo", google_jingleinfo);
              CHECK_FEATURE ("http://jabber.org/protocol/address", jabber_address);
              CHECK_FEATURE ("http://jabber.org/protocol/commands", jabber_commands);
              CHECK_FEATURE ("http://jabber.org/protocol/disco#info", jabber_disco_info);
              CHECK_FEATURE ("http://jabber.org/protocol/disco#items", jabber_disco_items);
              CHECK_FEATURE ("http://jabber.org/protocol/offline", jabber_offline);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub", jabber_pubsub);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#collections", jabber_pubsub_collections);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#config-node", jabber_pubsub_config_node);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#create-and-configure", jabber_pubsub_create_and_configure);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#create-nodes", jabber_pubsub_create_nodes);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#default_access_model_open", jabber_pubsub_default_access_model_open);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#delete-nodes", jabber_pubsub_delete_nodes);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#get-pending", jabber_pubsub_get_pending);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#instant-nodes", jabber_pubsub_instant_nodes);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#item-ids", jabber_pubsub_item_ids);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#manage-subscriptions", jabber_pubsub_manage_subscriptions);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#meta-data", jabber_pubsub_meta_data);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#modify-affiliations", jabber_pubsub_modify_affiliations);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#multi-subscribe", jabber_pubsub_multi_subscribe);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#outcast-affiliation", jabber_pubsub_outcast_affiliation);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#persistent-items", jabber_pubsub_persistent_items);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#presence-notifications", jabber_pubsub_presence_notifications);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#publish", jabber_pubsub_publish);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#publisher-affiliation", jabber_pubsub_publisher_affiliation);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#purge-nodes", jabber_pubsub_purge_nodes);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#retract-items", jabber_pubsub_retract_items);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#retrieve-affiliations", jabber_pubsub_retrieve_affiliations);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#retrieve-default", jabber_pubsub_retrieve_default);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#retrieve-items", jabber_pubsub_retrieve_items);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#retrieve-subscriptions", jabber_pubsub_retrieve_subscriptions);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#subscribe", jabber_pubsub_subscribe);
              CHECK_FEATURE ("http://jabber.org/protocol/pubsub#subscription-options", jabber_pubsub_subscription_options);
              CHECK_FEATURE ("http://jabber.org/protocol/rsm", jabber_rsm);
              CHECK_FEATURE ("jabber:iq:last", jabber_iq_last);
              CHECK_FEATURE ("jabber:iq:privacy", jabber_iq_privacy);
              CHECK_FEATURE ("jabber:iq:private", jabber_iq_private);
              CHECK_FEATURE ("jabber:iq:register", jabber_iq_register);
              CHECK_FEATURE ("jabber:iq:roster", jabber_iq_roster);
              CHECK_FEATURE ("jabber:iq:time", jabber_iq_time);
              CHECK_FEATURE ("jabber:iq:version", jabber_iq_version);
              CHECK_FEATURE ("urn:xmpp:ping", urn_xmpp_ping);
              CHECK_FEATURE ("vcard-temp", vcard_temp);

#undef CHECK_FEATURE
            }

        case xmpp_message_event_items_item:

            {
              struct xmpp_message *msg;
              struct xmpp_pubsub_item* item;

              msg = &stanza->u.message;
              item = vink_arena_calloc (arena, sizeof (*item));

              if (msg->first_item)
                msg->last_item->next = item;
              else
                msg->first_item = item;

              msg->last_item = item;
            }

          break;

        case xmpp_message_event_items_item_wavelet_update:

            {
              struct xmpp_message *msg;
              struct xmpp_wavelet_update *wu;

              msg = &stanza->u.message;
              wu = vink_arena_calloc (arena, sizeof (*wu));

              for (attr = atts; *attr; attr += 2)
                {
                  if (!strcmp (attr[0], "wavelet-name"))
                    {
                      wu->wavelet_name = attr[1];

                      break;
                    }
                }

              if (!wu->wavelet_name)
                {
                  xmpp_stream_error (state, "bad-format", "Missing 'wavelet-name' in wavelet update");

                  return;
                }

              msg->last_item->wavelet_update = wu;
            }

          break;

        case xmpp_message_event_items_item_wavelet_update_applied_delta:

            {
              struct xmpp_message *msg;
              struct xmpp_wavelet_update *wu;
              struct xmpp_wavelet_applied_delta *ad;

              msg = &stanza->u.message;
              wu = msg->last_item->wavelet_update;

              ad = vink_arena_calloc (arena, sizeof (*ad));

              if (wu->first_applied_delta)
                wu->last_applied_delta->next = ad;
              else
                wu->first_applied_delta = ad;

              wu->last_applied_delta = ad;
            }

          break;

        default:;
        }
    }

  ++state->xml_tag_level;
}

static void XMLCALL
xmpp_end_element (void *user_data, const XML_Char *name)
{
  struct vink_xmpp_state *state = user_data;

  if (!state->xml_tag_level)
    {
      xmpp_stream_error (state, "invalid-xml", "Too many end tags");

      return;
    }

  --state->xml_tag_level;

  if (state->xml_tag_level == 0)
    state->stream_finished = 1;
  else if (state->xml_tag_level == 1
           && state->stanza.types[0] != xmpp_unknown)
    xmpp_process_stanza (state);
}

static void XMLCALL
xmpp_character_data (void *user_data, const XML_Char *str, int len)
{
  struct vink_xmpp_state *state;
  struct xmpp_stanza *stanza;
  struct vink_arena *arena;
  enum xmpp_stanza_type type;

  state = user_data;
  stanza = &state->stanza;
  arena = &stanza->arena;

  if (state->xml_tag_level < 2
      || state->xml_tag_level >= 10)
    return;

  type = stanza->types[state->xml_tag_level - 2];

  switch (type)
    {
    case xmpp_features_mechanisms_mechanism:

        {
          struct xmpp_features *pf = &state->stanza.u.features;

          if (len == 8 && !memcmp (str, "EXTERNAL", 8))
            pf->auth_external = 1;
          else if (len == 5 && !memcmp (str, "PLAIN", 5))
            pf->auth_plain = 1;
        }

      break;

    case xmpp_iq_bind_jid:

      if (state->is_initiator)
        {
          free (state->resource);
          state->resource = strndup (str, len);

          free (state->jid);

          if (0 == (state->jid = strdup (state->resource)))
            {
              syslog (LOG_WARNING, "strdup failed: %s", strerror (errno));

              state->fatal_error = strerror (errno);

              return;
            }

          if (!state->ready)
            xmpp_handshake (state);
        }

      break;

    case xmpp_message_body:

        {
          struct xmpp_message *msg = &state->stanza.u.message;

          msg->body = vink_arena_strndup (arena, str, len);
        }

      break;

    case xmpp_presence_show:

        {
          struct xmpp_presence *pp = &state->stanza.u.presence;
          char *show;

          show = strndupa (str, len);

          if (!strcmp (show, "away"))
            pp->show = VINK_AWAY;
          else if (!strcmp (show, "chat"))
            pp->show = VINK_CHAT;
          else if (!strcmp (show, "dnd"))
            pp->show = VINK_DND;
          else if (!strcmp (show, "xa"))
            pp->show = VINK_XA;
#if TRACE
          else
            fprintf (trace, "\033[31;1mUnhandled presence show value: '%.*s'\033[0m\n", len, str);
#endif
        }

      break;


    case xmpp_dialback_verify:

      stanza->u.dialback_verify.hash = vink_arena_strndup (arena, str, len);

      break;

    case xmpp_dialback_result:

      stanza->u.dialback_result.hash = vink_arena_strndup (arena, str, len);

      break;

    case xmpp_sasl_response:

      stanza->u.response.content = vink_arena_strndup (arena, str, len);

      break;

    case xmpp_sasl_auth:

      stanza->u.auth.content = vink_arena_strndup (arena, str, len);

      break;

    case xmpp_message_event_items_item_wavelet_update_applied_delta:

        {
          struct xmpp_message *msg = &state->stanza.u.message;
          struct xmpp_wavelet_applied_delta *ad;
          ssize_t result;

          ad = msg->last_item->wavelet_update->last_applied_delta;

          ad->data = vink_arena_alloc (arena, len + 1);

          result = base64_decode (ad->data, str, len);

          if (result == -1)
            {
              state->fatal_error = "base64 decode failed";

              return;
            }

          ad->size = result;
        }

      break;

    default:

#if TRACE
      fprintf (trace, "\033[31;1mUnhandled character data: '%.*s'\033[0m\n", len, str);
#else
      ;
#endif
    }
}

static void XMLCALL
xmpp_start_namespace (void *user_data, const XML_Char *prefix, const XML_Char *uri)
{
  struct vink_xmpp_state *state = user_data;

  if (!uri)
    return;

  if (!strcmp (uri, "jabber:client") && !state->is_initiator)
    {
      state->remote_is_client = 1;
      state->outbound_stream = state;
      state->inbound_stream = state;
    }
  else if (!strcmp (uri, "jabber:server:dialback") && state->is_initiator)
    state->has_dialback_ns = 1;
}

void
xmpp_gen_dialback_key (char *key, struct vink_xmpp_state *state,
                       const char *remote_jid, const char *id)
{
  const char *secret;
  char secret_hash[65];
  char *data;

  if (-1 == asprintf (&data, "%s %s %s",
                      vink_tree_get_string (VINK_config, "domain"),
                      remote_jid, id))
    {
      syslog (LOG_WARNING, "asprintf failed: %s", strerror (errno));

      state->fatal_error = strerror (errno);

      return;
    }

  secret = vink_tree_get_string (VINK_config, "secret");

  hash_sha256 (secret, strlen (secret), secret_hash);

  hash_hmac_sha256 (secret_hash, strlen (secret_hash),
                    data, strlen (data), key);

  free (data);
}

static void
xmpp_xml_error (struct vink_xmpp_state *state, enum XML_Error error)
{
  const char *message;

  message = XML_ErrorString (error);

  switch (error)
    {
    case XML_ERROR_INVALID_TOKEN:
    case XML_ERROR_UNDECLARING_PREFIX:
    case XML_ERROR_INCOMPLETE_PE:
    case XML_ERROR_TAG_MISMATCH:

      xmpp_stream_error (state, "xml-not-well-formed", "XML parser reported: %s", message);

      break;

    default:

      xmpp_stream_error (state, "invalid-xml", "XML parser reported: %s", message);
    }
}

int
vink_xmpp_state_data (struct vink_xmpp_state *state,
                      const void *data, size_t count)
{
  int result;

  assert (!state->fatal_error);

  if (state->using_tls)
    {
      state->tls_read_start = data;
      state->tls_read_end = state->tls_read_start + count;

      while (state->tls_read_start != state->tls_read_end)
        {
          if (state->tls_handshake == 1)
            {
              result = gnutls_handshake (state->tls_session);

              if (result == GNUTLS_E_AGAIN || result == GNUTLS_E_INTERRUPTED)
                continue;

              if (result < 0)
                {
                  syslog (LOG_INFO, "TLS handshake failed: %s", gnutls_strerror (result));

                  VINK_set_error ("TLS handshake failed: %s", gnutls_strerror (result));

                  return -1;
                }

              state->tls_handshake = 0;

              if (state->is_initiator)
                state->remote_identified = 1;

              xmpp_reset_stream (state);
            }
          else
            {
              char buf[4096];
              int result;

              result = gnutls_record_recv (state->tls_session, buf, sizeof (buf));

              if (result < 0)
                {
                  if (result == GNUTLS_E_AGAIN || result == GNUTLS_E_INTERRUPTED)
                    continue;

                  return -1;
                }

              if (!result)
                {
                  VINK_set_error ("Received empty TLS packet");

                  return -1;
                }

#if TRACE
              fprintf (trace, "REMOTE-TLS (%p): \033[1;36m%.*s\033[0m\n", state, (int) result, buf);
              fflush (trace);
#endif

              if (!XML_Parse (state->xml_parser, buf, result, 0))
                {
                  int code = XML_GetErrorCode (state->xml_parser);

                  xmpp_xml_error (state, code);

                  VINK_set_error ("Parse error in XML stream from peer: %d", code);

                  return -1;
                }
            }
        }
    }
  else
    {
#if TRACE
      fprintf (trace, "REMOTE (%p): \033[1;36m%.*s\033[0m\n", state, (int) count, (char*) data);
      fflush (trace);
#endif

      if (!XML_Parse (state->xml_parser, data, count, 0))
        {
          xmpp_xml_error (state, XML_GetErrorCode (state->xml_parser));

          return -1;
        }
    }

  if (state->please_restart)
    {
      state->please_restart = 0;
      xmpp_reset_stream (state);
    }

  if (state->fatal_error)
    {
      VINK_set_error ("Error communicating with remote host: %s", state->fatal_error);

      return -1;
    }

  return 0;
}

int
vink_xmpp_state_finished (struct vink_xmpp_state *state)
{
  return state->stream_finished;
}

static void
xmpp_handle_queued_stanzas (struct vink_xmpp_state *state)
{
  struct xmpp_queued_stanza *qs, *prev;

  if (!state->ready)
    return;

  if (!state->first_queued_stanza)
    {
      if (state->callbacks.queue_empty)
        state->callbacks.queue_empty (state);

      return;
    }

  qs = state->first_queued_stanza;

  while (qs)
    {
      xmpp_write (state, qs->data);

      free (qs->data);
      free (qs->target);
      prev = qs;
      qs = qs->next;

      free (prev);
    }

  state->first_queued_stanza = 0;
  state->last_queued_stanza = 0;

  if (state->callbacks.queue_empty)
    state->callbacks.queue_empty (state);
}

static void
xmpp_handshake (struct vink_xmpp_state *state)
{
  struct xmpp_features *pf = &state->features;

  if (state->please_restart)
    return;

  if (pf->starttls && !state->using_tls)
    {
      xmpp_write (state, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
    }
  else if (!state->local_identified)
    {
      if (pf->auth_external)
        {
          const char *domain;
          char *base64_domain;

          domain = vink_tree_get_string (VINK_config, "domain");

          base64_domain = base64_encode (domain, strlen (domain));

          xmpp_printf (state,
                       "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>"
                       "%s"
                       "</auth>",
                       base64_domain);

          free (base64_domain);
        }
      else if (pf->auth_plain)
        {
          char *auth_data;

          auth_data = plain_auth_data (state);

          if (!auth_data)
            return;

          xmpp_printf (state,
                       "<auth"
                       " xmlns='urn:ietf:params:xml:ns:xmpp-sasl'"
                       " mechanism='PLAIN'>%s</auth>",
                       auth_data);

          free (auth_data);
        }
      else if (pf->dialback || state->has_dialback_ns)
        {
          char key[65];

          xmpp_gen_dialback_key (key, state, state->remote_jid,
                                 state->remote_stream_id);

          xmpp_printf (state,
                       "<db:result from='%s' to='%s'>%s</db:result>",
                       vink_config ("domain"), state->remote_jid, key);
        }
    }
  else if (!state->resource && pf->bind)
    {
      char id[32];

      xmpp_gen_id (id);

      xmpp_printf (state, "<iq type='set' id='%s'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq>", id);
    }
  else if (!state->active_resource && pf->session)
    {
      xmpp_gen_id (state->session_id);

      xmpp_printf (state, "<iq type='set' id='%s'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>", state->session_id);
    }
  else
    {
      if (pf->ack)
        xmpp_write (state, "<enable xmlns='urn:xmpp:sm:2'/>");

      if (!state->is_client && state->is_initiator)
        {
          char id[32];

          xmpp_gen_id (id);

          xmpp_printf (state,
                       "<iq type='get' id='%s' from='%s' to='%s'>"
                       "<query xmlns='http://jabber.org/protocol/disco#info'/>"
                       "</iq>",
                       id, vink_tree_get_string (VINK_config, "domain"), state->remote_jid);
        }

      state->ready = 1;

      xmpp_handle_queued_stanzas (state);
    }
}

static void
remote_identified (struct vink_xmpp_state *state)
{
  size_t i;

  if (state->remote_identified)
    return;

  state->remote_identified = 1;

  /* May already be established due to dialback */
  if (!state->is_initiator && !state->outbound_stream)
    {
      for (i = 0; i < VINK_peer_count (); ++i)
        {
          struct vink_xmpp_state *outbound_stream;

          outbound_stream = VINK_peer_state (i);

          if (outbound_stream->is_initiator)
            {
              state->outbound_stream = outbound_stream;

              break;
            }
        }

      if (!state->outbound_stream)
        state->outbound_stream = VINK_xmpp_server_connect (state->remote_jid);

      if (!state->outbound_stream)
        {
          state->fatal_error = "Failed to establish response stream";

          return;
        }

      state->outbound_stream->inbound_stream = state;
    }
  else
    assert (state->outbound_stream->inbound_stream == state);

  xmpp_handshake (state);
}

static void
sasl_plain_verify (struct vink_xmpp_state *state, const char *data)
{
  char *content;
  const char *user;
  const char *secret;
  ssize_t content_length;

  content = malloc (strlen (data) + 1);
  content_length = base64_decode (content, data, 0);
  content[content_length] = 0;

  if (!(user = memchr (content, 0, content_length))
      || !(secret = memchr (user + 1, 0, content + content_length - user - 1)))
    {
      xmpp_write (state,
                  "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                  "<incorrect-encoding/>"
                  "</failure>");

      state->fatal_error = "Incorrect encoding in PLAIN authentication request";

      return;
    }

  ++user;
  ++secret;

  assert (state->callbacks.authenticate);

  if (-1 == state->callbacks.authenticate (state, content, user, secret))
    {
      free (content);

      xmpp_write (state,
                  "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                  "<not-authorized/>"
                  "</failure>");

      return;
    }

  free (state->remote_jid);

  if (*content)
    state->remote_jid = strdup (content);
  else
    asprintf (&state->remote_jid, "%s@%s", user, vink_config ("domain"));

  free (content);

  xmpp_write (state, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");

  state->remote_identified = 1;
  state->please_restart = 1;
}

static void
sasl_external_verify (struct vink_xmpp_state *state, const char *data)
{
  char *domain;
  ssize_t domain_length;

  domain = malloc (strlen (data) + 1);
  domain_length = base64_decode (domain, data, 0);

  domain[domain_length] = 0;

  /* XXX: Verify against certificate */

  xmpp_write (state, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");

  state->remote_jid = domain;
  state->please_restart = 1;

  remote_identified (state);
}

static void
xmpp_process_stanza (struct vink_xmpp_state *state)
{
  struct xmpp_stanza *stanza = &state->stanza;

  switch (stanza->types[0])
    {
    case xmpp_ack_request:

      xmpp_printf (state, "<a xmlns='urn:xmpp:sm:2' h='%u'/>",
                   state->acks_sent);

      ++state->acks_sent;
      state->acks_sent &= 0xffffffff;

      break;

    case xmpp_features:

      if (state->is_initiator)
        {
          state->features = state->stanza.u.features;

          xmpp_handshake (state);
        }

      break;

    case xmpp_error:

      /* "It is assumed that all stream-level errors are unrecoverable"
       *   -- RFC 3920, section 4.7.1. Rules:
       */

      state->fatal_error = "Received a stream-level error";

      break;

    case xmpp_tls_proceed:

      if (state->using_tls)
        break;

      state->using_tls = 1;

      xmpp_start_tls (state);

      break;

    case xmpp_tls_starttls:

        {
          if (state->using_tls)
            {
              /* XXX: Is this the correct way to handle redundant starttls tags? */
              xmpp_write (state, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>");

              state->fatal_error = "Got redundant STARTTLS";
            }
          else
            {
              xmpp_write (state, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");

              state->using_tls = 1;

              xmpp_start_tls (state);
            }
        }

      break;

    case xmpp_dialback_verify:

        {
          struct xmpp_dialback_verify *pdv = &stanza->u.dialback_verify;
          char key[65];

          if (!stanza->id || !stanza->from || !stanza->to)
            {
              xmpp_stream_error (state, "invalid-xml",
                                 "Missing attribute (s) in dialback verify tag");

              return;
            }

          if (!pdv->type)
            {
              xmpp_gen_dialback_key (key, state, stanza->from, stanza->id);

              xmpp_printf (state, "<db:verify id='%s' from='%s' to='%s' type='%s'/>",
                           stanza->id, stanza->to, stanza->from,
                           strcmp (pdv->hash, key) ? "invalid" : "valid");
            }
          else
            {
              if (!state->is_initiator)
                {
                  xmpp_stream_error (state, "invalid-xml",
                                     "Got dialback verification on inbound stream");

                  return;
                }

              if (!state->inbound_stream)
                {
                  xmpp_stream_error (state, "invalid-xml",
                                     "Got dialback verification even though we didn't ask");

                  return;
                }

              xmpp_printf (state->inbound_stream,
                           "<db:result from='%s' to='%s' type='%s'/>",
                           stanza->to, stanza->from, pdv->type);

              if (!strcmp (pdv->type, "valid"))
                remote_identified (state->inbound_stream);
            }
        }

      break;

    case xmpp_dialback_result:

        {
          struct xmpp_dialback_result *pdr = &stanza->u.dialback_result;

          if (!stanza->from || !stanza->to)
            {
              xmpp_stream_error (state, "invalid-xml",
                                 "Missing attribute (s) in dialback result tag");

              return;
            }

          if (!pdr->type)
            {
              size_t i;

              free (state->remote_jid);
              state->remote_identified = 0;
              state->remote_jid = strdup (stanza->from);

              if (!state->outbound_stream)
                {
                  for (i = 0; i < VINK_peer_count (); ++i)
                    {
                      struct vink_xmpp_state *outbound_stream;

                      outbound_stream = VINK_peer_state (i);

                      if (outbound_stream->is_initiator)
                        {
                          state->outbound_stream = outbound_stream;

                          break;
                        }
                    }

                  if (!state->outbound_stream)
                    state->outbound_stream = VINK_xmpp_server_connect (state->remote_jid);

                  if (!state->outbound_stream)
                    {
                      xmpp_stream_error (state, "invalid-xml", "Failed to establish response stream");

                      return;
                    }

                  state->outbound_stream->inbound_stream = state;
                }
              else
                assert (state->outbound_stream->inbound_stream == state);

              xmpp_printf (state->outbound_stream,
                           "<db:verify to='%s' from='%s' id='%s'>"
                           "%s"
                           "</db:verify>",
                           state->remote_jid, vink_config ("domain"),
                           state->stream_id, pdr->hash);
            }
          else
            {
              if (strcmp (pdr->type, "valid"))
                {
                  state->fatal_error = "Dialback authentication failed";

                  return;
                }

              state->local_identified = 1;

              xmpp_handshake (state);
            }
        }

      break;

    case xmpp_sasl_auth:

        {
          struct xmpp_auth *pa = &stanza->u.auth;

          if (!pa->mechanism)
            {
              xmpp_stream_error (state, "invalid-mechanism",
                                 "No SASL mechanism given");

              return;
            }

          if (!strcmp (pa->mechanism, "DIGEST-MD5"))
            {
              char nonce[16];
              char *challenge;
              char *challenge_base64;

              state->auth_mechanism = XMPP_DIGEST_MD5;

              xmpp_gen_id (nonce);

              if (-1 == asprintf (&challenge,
                                  "realm=\"%s\",nonce=\"%s\",qop=\"auth\",charset=utf-8,algorithm=md5-ses",
                                  vink_tree_get_string (VINK_config, "domain"), nonce))
                {
                  state->fatal_error = "Failed to parse DIGEST-MD5 challenge";

                  return;
                }

              challenge_base64 = base64_encode (challenge, strlen (challenge));

              free (challenge);

              xmpp_printf (state,
                           "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                           "%s"
                           "</challenge>",
                           challenge_base64);

              free (challenge_base64);
            }
          else if (!strcmp (pa->mechanism, "PLAIN"))
            {
              state->auth_mechanism = XMPP_PLAIN;

              if (pa->content)
                sasl_plain_verify (state, pa->content);
              else
                xmpp_printf (state, "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
            }
          else if (!strcmp (pa->mechanism, "EXTERNAL"))
            {
              state->auth_mechanism = XMPP_EXTERNAL;

              if (pa->content)
                sasl_external_verify (state, pa->content);
              else
                xmpp_printf (state, "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
            }
          else
            {
              xmpp_stream_error (state, "invalid-mechanism", "Unknown SASL mechanism");
            }
        }

      break;

    case xmpp_sasl_response:

        {
          struct xmpp_response *pr = &stanza->u.response;

          if (state->is_initiator)
            {
              xmpp_stream_error (state, "bad-format", "Receiving entity attempted to send SASL response");

              return;
            }

          if (state->auth_mechanism == XMPP_DIGEST_MD5)
            {
            }
          else if (state->auth_mechanism == XMPP_PLAIN)
            {
              if (!pr->content)
                {
                  xmpp_write (state,
                              "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                              "<incorrect-encoding/>"
                              "</failure>");

                  state->fatal_error = "Missing content in PLAIN authentication request";
                }
              else
                sasl_plain_verify (state, pr->content);
            }
          else if (state->auth_mechanism == XMPP_EXTERNAL)
            {
            }
          else
            xmpp_stream_error (state, "invalid-mechanism", "No SASL mechanism given");

          state->auth_mechanism = XMPP_AUTH_UNKNOWN;
        }

      break;

    case xmpp_sasl_challenge:

        {
          char *response;

          if (state->features.auth_external)
            {
              response = strdup ("LOL");
            }
          else if (state->features.auth_plain)
            {
              response = plain_auth_data (state);
            }

          if (!response)
            return;

          xmpp_printf (state,
                       "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                       "%s"
                       "</response>",
                       response);

          free (response);
        }

      break;

    case xmpp_sasl_success:

      state->local_identified = 1;

      state->please_restart = 1;

      break;

    case xmpp_sasl_failure:

      state->fatal_error = "SASL authentication failed";

      break;

    case xmpp_message:

        {
          struct xmpp_message *msg = &stanza->u.message;
          struct xmpp_pubsub_item *item;

          if (!stanza->id)
            {
              xmpp_stream_error (state, "invalid-id", 0);

              break;
            }

          if (!state->remote_jid)
            {
              xmpp_stanza_unauthorized (state, "message", stanza->id);

              break;
            }

          if (msg->body && state->callbacks.message)
            {
              struct vink_arena arena, *vink_arena_copy;
              struct vink_message *message;

              vink_arena_init (&arena);
              message = vink_arena_calloc (&arena, sizeof (*message));
              message->protocol = VINK_XMPP;
              message->part_type = VINK_PART_MESSAGE;
              message->sent = time (0); /* XXX: Support delayed delivery */
              message->received = time (0);
              message->content_type = "text/plain";
              message->id = vink_arena_strdup (&arena, stanza->id);
              message->from = vink_arena_strdup (&arena, stanza->from);
              message->to = vink_arena_strdup (&arena, stanza->to);
              message->body = vink_arena_strdup (&arena, msg->body);
              message->body_size = strlen (message->body);

              vink_arena_copy = vink_arena_alloc (&arena, sizeof (arena));
              memcpy (vink_arena_copy, &arena, sizeof (arena));
              message->_private = vink_arena_copy;

              state->callbacks.message (state, message);
            }

          for (item = msg->first_item; item; item = item->next)
            {
              struct xmpp_wavelet_update *wu;

              wu = item->wavelet_update;

              if (wu && state->callbacks.wave_applied_delta)
                {
                  struct xmpp_wavelet_applied_delta *ad;

                  for (ad = wu->first_applied_delta; ad; ad = ad->next)
                    {
                      state->callbacks.wave_applied_delta (state,
                                                           wu->wavelet_name,
                                                           ad->data, ad->size);
                    }
                }
            }

          if (msg->request_receipt)
            {
              if (-1 == vink_xmpp_queue_stanza (state->outbound_stream,
                                                "<message id='%s' from='%s' to='%s'>"
                                                "<received xmlns='urn:xmpp:receipts'/>"
                                                "</message>",
                                                stanza->id, stanza->to, stanza->from))
                {
                  state->fatal_error = "Failed to queue stanza on return stream";
                }
            }
        }

      break;

    case xmpp_presence:

      if (!state->remote_jid)
        {
          xmpp_stanza_unauthorized (state, "presence", stanza->id);

          break;
        }

      if (state->callbacks.presence)
        {
          struct xmpp_presence *pp = &stanza->u.presence;

          state->callbacks.presence (state, stanza->from, pp->show);
        }

      break;

    case xmpp_iq:

      if (!stanza->id)
        {
          xmpp_stream_error (state, "invalid-id", 0);

          break;
        }

      if (!state->is_initiator)
        {
          if (!state->remote_jid)
            {
              xmpp_stanza_unauthorized (state, "iq", stanza->id);

              break;
            }

          if (!stanza->u.iq.type)
            {
              xmpp_stream_error (state, "bad-format", "Missing type attribute in iq element");

              break;
            }

          if (!strcmp (stanza->u.iq.type, "get"))
            {
              if (stanza->u.iq.disco_info)
                {
                  static const char *disco_info_format =
                    "<iq type='result' id='%s' from='%s' to='%s'>"
                    "<query xmlns='http://jabber.org/protocol/disco#info'>"
                    "<identity category='collaboration' type='google-wave'/>"
                    "<identity category='server' type='im'/>"
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
                    "<feature var='http://waveprotocol.org/protocol/0.2/waveserver'/>"
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
                    "</iq>";

                  if (-1 == vink_xmpp_queue_stanza (state->outbound_stream, disco_info_format,
                                                    stanza->id, stanza->to, stanza->from))
                    {
                      state->fatal_error = "Failed to queue stanza on return stream";
                    }
                }
              else if (stanza->u.iq.disco_items)
                {
                  static const char *disco_items_format =
                    "<iq type='result' id='%s' from='%s' to='%s'>"
                    "<query xmlns='http://jabber.org/protocol/disco#items'>"
                    "<item jid='%s' name='Primary'/>"
                    "</query>"
                    "</iq>";

                  if (-1 == vink_xmpp_queue_stanza (state->outbound_stream, disco_items_format,
                                                    stanza->id, stanza->to, stanza->from,
                                                    vink_config ("domain")))
                    {
                      state->fatal_error = "Failed to queue stanza on return stream";
                    }
                }
            }
          else if (!strcmp (stanza->u.iq.type, "set"))
            {
              if (stanza->u.iq.bind)
                {
                  xmpp_gen_id (state->remote_resource);

                  /* XXX: rebuild state->remote_jid */

                  xmpp_printf (state->outbound_stream,
                               "<iq type='result' id='%s'>"
                               "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
                               "<jid>%s/%s</jid>"
                               "</bind>"
                               "</iq>",
                               stanza->id, state->remote_jid,
                               state->remote_resource);
                }
            }
          else if (!strcmp (stanza->u.iq.type, "result"))
            {
              if (stanza->u.iq.disco_info)
                {
                  char id[32];

                  xmpp_gen_id (id);

                  xmpp_printf (state->outbound_stream,
                               "<iq type='get' id='%s' from='%s' to='%s'>"
                               "<query xmlns='http://jabber.org/protocol/disco#items'/>"
                               "</iq>",
                               id, vink_tree_get_string (VINK_config, "domain"), state->remote_jid);
                }
            }
        }
      else
        {
          /* XXX: Check for request, response, whatnot */
          if (!strcmp (state->session_id, stanza->id))
            {
              state->active_resource = 1;

              xmpp_handshake (state);
            }
        }

      break;

    default:;
    }
}

ssize_t
xmpp_tls_pull (gnutls_transport_ptr_t arg, void *data, size_t size)
{
  struct vink_xmpp_state *state = arg;

  if (state->tls_read_start == state->tls_read_end)
    {
      errno = EAGAIN;

      return -1;
    }

  if (size > state->tls_read_end - state->tls_read_start)
    size = state->tls_read_end - state->tls_read_start;

  memcpy (data, state->tls_read_start, size);

  state->tls_read_start += size;

  return size;
}

ssize_t
xmpp_tls_push (gnutls_transport_ptr_t arg, const void *data, size_t size)
{
  struct vink_xmpp_state *state = arg;

  if (state->fatal_error)
    return -1;

  if (-1 == state->write_func (data, size, state->write_func_arg))
    {
      syslog (LOG_WARNING, "Buffer append error: %s", strerror (errno));

      state->fatal_error = strerror (errno);

      return -1;
    }

  return size;
}

static void
xmpp_start_tls (struct vink_xmpp_state *state)
{
  int result;

  if (0 > (result = gnutls_init (&state->tls_session, state->is_initiator ? GNUTLS_CLIENT : GNUTLS_SERVER)))
    {
      syslog (LOG_WARNING, "gnutls_init failed: %s", gnutls_strerror (result));

      state->fatal_error = gnutls_strerror (result);

      return;
    }

#if LIBGNUTLS_VERSION_NUMBER >= 0x020600
  gnutls_priority_set (state->tls_session, priority_cache);
#else
  gnutls_protocol_set_priority (state->tls_session, protocol_priority);
  gnutls_cipher_set_priority (state->tls_session, cipher_priority);
  gnutls_compression_set_priority (state->tls_session, comp_priority);
  gnutls_kx_set_priority (state->tls_session, kx_priority);
  gnutls_mac_set_priority (state->tls_session, mac_priority);
#endif

  gnutls_handshake_set_max_packet_length (state->tls_session, 64 * 1024);

  if (0 > (result = gnutls_credentials_set (state->tls_session, GNUTLS_CRD_CERTIFICATE, xcred)))
    {
      syslog (LOG_WARNING, "Failed to set credentials for TLS session: %s",
              gnutls_strerror (result));

      gnutls_bye (state->tls_session, GNUTLS_SHUT_WR);
      state->tls_session = 0;
      state->fatal_error = gnutls_strerror (result);

      return;
    }

  if (!state->remote_is_client)
    {
      syslog (LOG_INFO, "Remote is a server");
      gnutls_certificate_server_set_request (state->tls_session, GNUTLS_CERT_REQUIRE);
    }

  gnutls_dh_set_prime_bits (state->tls_session, 1024);

  gnutls_transport_set_ptr (state->tls_session, (gnutls_transport_ptr_t) state);
  gnutls_transport_set_push_function (state->tls_session, xmpp_tls_push);
  gnutls_transport_set_pull_function (state->tls_session, xmpp_tls_pull);

  state->tls_handshake = 1;

  result = gnutls_handshake (state->tls_session);

  if (result == GNUTLS_E_AGAIN || result == GNUTLS_E_INTERRUPTED)
    return;

  if (result < 0)
    {
      syslog (LOG_INFO, "TLS handshake failed: %s", gnutls_strerror (result));

      gnutls_bye (state->tls_session, GNUTLS_SHUT_WR);
      state->tls_session = 0;
      state->tls_handshake = 0;
      state->fatal_error = gnutls_strerror (result);
    }
}


int
vink_xmpp_parse_jid (struct vink_xmpp_jid *target, char *input)
{
  char *c;

  target->node = 0;
  target->resource = 0;

  c = strchr (input, '@');

  if (c)
    {
      target->node = input;
      *c++ = 0;
      input = c;
    }

  target->domain = input;

  c = strchr (input, '/');

  if (c)
    {
      *c++ = 0;
      target->resource = c;
    }

  return 0;
}

static void
xmpp_gen_id (char *target)
{
  static unsigned int seq;
  struct timeval now;

  gettimeofday (&now, 0);

  sprintf (target, "%llx-%x",
           (unsigned long long) now.tv_sec * 1000000
           + (unsigned long long) now.tv_usec,
           seq++);
}

int
vink_xmpp_set_presence (struct vink_xmpp_state *state, enum vink_presence type)
{
  const char *show;

  switch (type)
    {
    case VINK_AWAY: show = "away"; break;
    case VINK_CHAT: show = "chat"; break;
    case VINK_DND: show = "dnd"; break;
    case VINK_XA: show = "xa"; break;
    default: show = 0;
    }

  if (show)
    return vink_xmpp_queue_stanza (state, "<presence from='%s'><show>%s</show></presence>", state->jid, show);

  switch (type)
    {
    case VINK_PRESENT:

      return vink_xmpp_queue_stanza (state, "<presence from='%s'/>", state->jid);

    case VINK_UNAVAILABLE:

      return vink_xmpp_queue_stanza (state, "<presence from='%s' type='unavailable'/>", state->jid);

    default:;
    }

  return 0;
}

int
vink_xmpp_send_message (struct vink_xmpp_state *state, const char *to,
                        const char *body)
{
  char id[32];

  xmpp_gen_id (id);

  return vink_xmpp_queue_stanza (state,
                                 "<message from='%s' to='%s' id='%s' type='chat'>"
                                 "<body>%s</body>"
                                 "</message>",
                                 state->jid, to, id, body);
}

const char *
vink_xmpp_jid (struct vink_xmpp_state *state)
{
  return state->jid;
}

void
vink_xmpp_end_stream (struct vink_xmpp_state *state)
{
  xmpp_write (state, "</stream:stream>");
}

void
vink_xmpp_set_backend_data (struct vink_xmpp_state *state, void *data)
{
  state->backend_data = data;
}

void *
vink_xmpp_backend_data (struct vink_xmpp_state *state)
{
  return state->backend_data;
}
