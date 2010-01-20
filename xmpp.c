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
#include <gnutls/gnutls.h>

#include "base64.h"
#include "common.h"
#include "hash.h"
#include "tree.h"
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
                   "<stream:stream xmlns='jabber:client' "
                   "xmlns:stream='http://etherx.jabber.org/streams' "
                   "to='%s' "
                   "version='1.0'>",
                   state->remote_jid);
    }
  else if (state->is_initiator)
    {
      xmpp_printf (state,
                   "<?xml version='1.0'?>"
                   "<stream:stream xmlns='jabber:server' "
                   "xmlns:stream='http://etherx.jabber.org/streams' "
                   "from='%s' "
                   "to='%s' "
                   "xmlns:db='jabber:server:dialback' "
                   "version='1.0'>",
                   tree_get_string (VINK_config, "domain"), state->remote_jid);
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
  arena_free (&state->stanza.arena);
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

  authzid = tree_get_string_default (VINK_config, "authzid", "");
  authcid = tree_get_string (VINK_config, "user");
  password = tree_get_string (VINK_config, "password");

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

static void XMLCALL
xmpp_start_element (void *user_data, const XML_Char *name,
                    const XML_Char **atts)
{
  struct vink_xmpp_state *state = user_data;
  const XML_Char **attr;
  struct xmpp_stanza *stanza;
  struct arena_info *arena;

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
              if (strcmp (attr[1], tree_get_string (VINK_config, "domain")))
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
                       tree_get_string (VINK_config, "domain"), state->stream_id);

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
                       tree_get_string (VINK_config, "domain"), state->stream_id);

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
  else if (state->xml_tag_level == 1)
    {
      memset (&state->stanza, 0, sizeof (state->stanza));

      for (attr = atts; *attr; attr += 2)
        {
          if (!strcmp (attr[0], "id"))
            stanza->id = arena_strdup (arena, attr[1]);
          else if (!strcmp (attr[0], "from"))
            stanza->from = arena_strdup (arena, attr[1]);
          else if (!strcmp (attr[0], "to"))
            {
              if (!state->remote_is_client)
                {
                  char *jid_buf;
                  struct vink_xmpp_jid jid;

                  jid_buf = strdupa (attr[1]);
                  vink_xmpp_parse_jid (&jid, jid_buf);

                  if (strcmp (jid.domain, tree_get_string (VINK_config, "domain")))
                    {
                      xmpp_stream_error (state, "host-unknown", "Unknown domain '%s'", jid.domain);

                      return;
                    }
                }

              stanza->to = arena_strdup (arena, attr[1]);
            }
        }

      if (!strcmp (name, "http://etherx.jabber.org/streams|features"))
        {
          stanza->type = xmpp_features;
        }
      else if (!strcmp (name, "http://etherx.jabber.org/streams|error"))
        {
          stanza->type = xmpp_error;
        }
      else if (!strcmp (name, "urn:ietf:params:xml:ns:xmpp-tls|proceed"))
        {
          stanza->type = xmpp_tls_proceed;
        }
      else if (!strcmp (name, "urn:ietf:params:xml:ns:xmpp-tls|starttls"))
        {
          stanza->type = xmpp_tls_starttls;
        }
      else if (!strcmp (name, "jabber:server:dialback|verify"))
        {
          struct xmpp_dialback_verify *pdv = &stanza->u.dialback_verify;

          stanza->type = xmpp_dialback_verify;

          for (attr = atts; *attr; attr += 2)
            {
              if (!strcmp (attr[0], "type"))
                pdv->type = arena_strdup (arena, attr[1]);
            }
        }
      else if (!strcmp (name, "jabber:server:dialback|result"))
        {
          struct xmpp_dialback_result *pdr = &stanza->u.dialback_result;

          stanza->type = xmpp_dialback_result;

          for (attr = atts; *attr; attr += 2)
            {
              if (!strcmp (attr[0], "type"))
                pdr->type = arena_strdup (arena, attr[1]);
            }
        }
      else if (!strcmp (name, "urn:ietf:params:xml:ns:xmpp-sasl|auth"))
        {
          if (state->is_initiator)
            {
              xmpp_stream_error (state, "bad-format", "Receiving entity attempted to initiate SASL");

              return;
            }

          stanza->type = xmpp_auth;

          for (attr = atts; *attr; attr += 2)
            {
              if (!strcmp (attr[0], "mechanism"))
                stanza->u.auth.mechanism = arena_strdup (arena, attr[1]);
            }
        }
      else if (!strcmp (name, "urn:ietf:params:xml:ns:xmpp-sasl|challenge"))
        {
          if (!state->is_initiator)
            {
              xmpp_stream_error (state, "bad-format", "Initiating entity sent SASL challenge");

              return;
            }

          stanza->type = xmpp_challenge;
        }
      else if (!strcmp (name, "urn:ietf:params:xml:ns:xmpp-sasl|response"))
        {
          if (state->is_initiator)
            {
              xmpp_stream_error (state, "bad-format", "Receiving entity attempted to initiate SASL");

              return;
            }

          stanza->type = xmpp_response;

          for (attr = atts; *attr; attr += 2)
            {
              if (!strcmp (attr[0], "mechanism"))
                stanza->u.auth.mechanism = arena_strdup (arena, attr[1]);
            }
        }
      else if (!strcmp (name, "urn:ietf:params:xml:ns:xmpp-sasl|success"))
        {
          if (!state->is_initiator)
            {
              xmpp_stream_error (state, "bad-format", "Initiating entity sent SASL success");

              return;
            }

          stanza->type = xmpp_success;
        }
      else if (!strcmp (name, "urn:ietf:params:xml:ns:xmpp-sasl|failure"))
        {
          if (!state->is_initiator)
            {
              xmpp_stream_error (state, "bad-format", "Initiating entity sent SASL failure");

              return;
            }

          stanza->type = xmpp_failure;
        }
      else if (!strcmp (name, "jabber:server|iq")
               || !strcmp (name, "jabber:client|iq"))
        {
          stanza->type = xmpp_iq;

          for (attr = atts; *attr; attr += 2)
            {
              if (!strcmp (attr[0], "type"))
                stanza->u.iq.type = arena_strdup (arena, attr[1]);
            }
        }
      else if (!strcmp (name, "jabber:server|message")
               || !strcmp (name, "jabber:client|message"))
        {
          stanza->type = xmpp_message;
        }
      else if (!strcmp (name, "jabber:server|presence")
               || !strcmp (name, "jabber:client|presence"))
        {
          stanza->type = xmpp_presence;
        }
      else if (!strcmp (name, "urn:xmpp:sm:2|r"))
        {
          stanza->type = xmpp_ack_request;
        }
      else
        {
          stanza->type = xmpp_unknown;

          xmpp_stream_error (state, "unsupported-stanza-type",
                             "Unknown element '%s'", name);
        }
    }
  else if (state->xml_tag_level == 2)
    {
      stanza->sub_type = xmpp_sub_unknown;

      if (state->stanza.type == xmpp_features)
        {
          struct xmpp_features *pf = &stanza->u.features;

          if (!strcmp (name, "urn:ietf:params:xml:ns:xmpp-tls|starttls"))
            pf->starttls = 1;
          else if (!strcmp (name, "urn:xmpp:features:dialback|dialback"))
            pf->dialback = 1;
          else if (!strcmp (name, "urn:ietf:params:xml:ns:xmpp-sasl|mechanisms"))
            stanza->sub_type = xmpp_sub_features_mechanisms;
          else if (!strcmp (name, "http://jabber.org/features/compress|compression"))
            stanza->sub_type = xmpp_sub_features_compression;
          else if (!strcmp (name, "urn:ietf:params:xml:ns:xmpp-bind|bind"))
            pf->bind = 1;
          else if (!strcmp (name, "urn:ietf:params:xml:ns:xmpp-session|session"))
            pf->session = 1;
          else if (!strcmp (name, "http://www.xmpp.org/extensions/xep-0198.html#ns|ack"))
            pf->ack = 1;
#if TRACE
          else
            fprintf (trace, "Unhandled feature tag '%s'\n", name);
#endif
        }
      else if (state->stanza.type == xmpp_iq)
        {
          if (!strcmp (name, "http://jabber.org/protocol/disco#info|query"))
            {
              stanza->u.iq.disco_info = 1;
              stanza->sub_type = xmpp_sub_iq_discovery_info;
            }
          else if (!strcmp (name, "http://jabber.org/protocol/disco#items|query"))
            stanza->u.iq.disco_items = 1;
          else if (!strcmp (name, "urn:ietf:params:xml:ns:xmpp-bind|bind"))
            {
              stanza->sub_type = xmpp_sub_iq_bind;

              stanza->u.iq.bind = 1;
            }
#if TRACE
          else
            fprintf (trace, "Unhandled iq tag '%s'\n", name);
#endif
        }
      else if (state->stanza.type == xmpp_message)
        {
          if (!strcmp (name, "jabber:server|body")
              || !strcmp (name, "jabber:client|body"))
            stanza->sub_type = xmpp_sub_message_body;
          else if (!strcmp (name, "http://jabber.org/protocol/pubsub#event|event"))
            stanza->sub_type = xmpp_sub_message_pubsub_event;
          else if (!strcmp (name, "urn:xmpp:receipts|request"))
            stanza->u.message.request_receipt = 1;
#if TRACE
          else
            fprintf (trace, "Unhandled message tag '%s'\n", name);
#endif
        }
      else if (state->stanza.type == xmpp_presence)
        {
          if (!strcmp (name, "jabber:server|show")
              || !strcmp (name, "jabber:client|show"))
            stanza->sub_type = xmpp_sub_presence_show;
#if TRACE
          else
            fprintf (trace, "Unhandled presence tag '%s'\n", name);
#endif
        }
#if TRACE
      else
        fprintf (trace, "Unhandled level 2 tag '%s'\n", name);
#endif
    }
  else if (state->xml_tag_level == 3)
    {
      stanza->subsub_type = xmpp_subsub_unknown;

      if (stanza->sub_type == xmpp_sub_iq_bind)
        {
          if (!strcmp (name, "urn:ietf:params:xml:ns:xmpp-bind|jid"))
            stanza->subsub_type = xmpp_subsub_iq_bind_jid;
        }
      else if (stanza->sub_type == xmpp_sub_iq_discovery_info)
        {
          if (!strcmp (name, "http://jabber.org/protocol/disco#info|feature"))
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
        }
      else if (stanza->sub_type == xmpp_sub_features_mechanisms)
        {
          if (!strcmp (name, "urn:ietf:params:xml:ns:xmpp-sasl|mechanism"))
            stanza->subsub_type = xmpp_subsub_features_mechanisms_mechanism;
        }
#if TRACE
      else
        fprintf (trace, "Unhandled level 3 tag '%s'\n", name);
#endif
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
  else if (state->xml_tag_level == 1)
    {
      if (state->stanza.type != xmpp_unknown)
        xmpp_process_stanza (state);
    }
  else if (state->xml_tag_level == 2)
    {
      if (state->stanza.sub_type != xmpp_sub_unknown)
        state->stanza.sub_type = xmpp_sub_unknown;
    }
  else if (state->xml_tag_level == 3)
    {
      if (state->stanza.subsub_type != xmpp_subsub_unknown)
        state->stanza.subsub_type = xmpp_subsub_unknown;
    }
}

static void XMLCALL
xmpp_character_data (void *user_data, const XML_Char *str, int len)
{
  char *data;
  struct vink_xmpp_state *state = user_data;
  struct xmpp_stanza *stanza = &state->stanza;
  struct arena_info *arena = &stanza->arena;

  data = strndupa (str, len);

  while (isspace (*data))
    ++data;

  if (!*data)
    return;

  if (stanza->subsub_type != xmpp_subsub_unknown)
    {
      switch (stanza->subsub_type)
        {
        case xmpp_subsub_features_mechanisms_mechanism:

            {
              struct xmpp_features *pf = &state->stanza.u.features;

              if (!strcmp (data, "EXTERNAL"))
                pf->auth_external = 1;
              else if (!strcmp (data, "PLAIN"))
                pf->auth_plain = 1;
            }

          break;

        case xmpp_subsub_iq_bind_jid:

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

        default:

#if TRACE
          fprintf (trace, "\033[31;1mUnhandled sub-subtag data: '%.*s'\033[0m\n", len, str);
#else
          ;
#endif
        }
    }
  else if (stanza->sub_type != xmpp_sub_unknown)
    {
      switch (stanza->sub_type)
        {
        case xmpp_sub_message_body:

            {
              struct xmpp_message *pm = &state->stanza.u.message;

              pm->body = arena_strndup (arena, str, len);
            }

          break;

        case xmpp_sub_presence_show:

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

        default:

#if TRACE
          fprintf (trace, "\033[31;1mUnhandled subtag data: '%.*s'\033[0m\n", len, str);
#else
          ;
#endif
        }
    }
  else
    {
      switch (stanza->type)
        {
        case xmpp_dialback_verify:

          stanza->u.dialback_verify.hash = arena_strndup (arena, str, len);

          break;

        case xmpp_dialback_result:

          stanza->u.dialback_result.hash = arena_strndup (arena, str, len);

          break;

        case xmpp_response:

          stanza->u.response.content = arena_strndup (arena, str, len);

          break;

        case xmpp_auth:

          stanza->u.auth.content = arena_strndup (arena, str, len);

          break;

        default:

#if TRACE
          fprintf (trace, "\033[31;1mUnhandled data: '%.*s'\033[0m\n", len, str);
#else
          ;
#endif
        }
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
                      tree_get_string (VINK_config, "domain"),
                      remote_jid, id))
    {
      syslog (LOG_WARNING, "asprintf failed: %s", strerror (errno));

      state->fatal_error = strerror (errno);

      return;
    }

  secret = tree_get_string (VINK_config, "secret");

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

          domain = tree_get_string (VINK_config, "domain");

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
                       id, tree_get_string (VINK_config, "domain"), state->remote_jid);
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

  switch (stanza->type)
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

    case xmpp_auth:

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
                                  tree_get_string (VINK_config, "domain"), nonce))
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

    case xmpp_response:

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

    case xmpp_challenge:

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

    case xmpp_success:

      state->local_identified = 1;

      state->please_restart = 1;

      break;

    case xmpp_failure:

      state->fatal_error = "SASL authentication failed";

      break;

    case xmpp_message:

        {
          struct xmpp_message *pm = &stanza->u.message;
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

          if (pm->body && state->callbacks.message)
            {
              struct arena_info arena, *arena_copy;
              struct vink_message *message;

              arena_init (&arena);
              message = arena_calloc (&arena, sizeof (*message));
              message->protocol = VINK_XMPP;
              message->part_type = VINK_PART_MESSAGE;
              message->sent = time (0); /* XXX: Support delayed delivery */
              message->received = time (0);
              message->content_type = "text/plain";
              message->id = arena_strdup (&arena, stanza->id);
              message->from = arena_strdup (&arena, stanza->from);
              message->to = arena_strdup (&arena, stanza->to);
              message->body = arena_strdup (&arena, pm->body);
              message->body_size = strlen (message->body);

              arena_copy = arena_alloc (&arena, sizeof (arena));
              memcpy (arena_copy, &arena, sizeof (arena));
              message->_private = arena_copy;

              state->callbacks.message (state, message);
            }

          for (item = pm->items; item; item = item->next)
            {
              if (item->wavelet_update && state->callbacks.wave_applied_delta)
                {
                  struct xmpp_wavelet_update *wu = item->wavelet_update;

                  if (wu->applied_delta)
                    state->callbacks.wave_applied_delta (state,
                                                         wu->wavelet_name,
                                                         wu->applied_delta,
                                                         wu->applied_delta_size);
                }
            }

          if (pm->request_receipt)
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
                               id, tree_get_string (VINK_config, "domain"), state->remote_jid);
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
