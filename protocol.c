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
#include "tree.h"

static void
xmpp_printf(struct xmpp_state *state, const char *format, ...);

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
                  "from='%s' id='stream' "
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
          fprintf(stderr, "Buffer append error: %s\n", strerror(errno));

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
      fprintf(stderr, "asprintf failed\n");
      state->fatal_error = 1;

      return;
    }

  xmpp_write(state, buf);

  free(buf);
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
      fprintf(stderr, "Got stream header, ought to reply\n");

      if(strcmp(name, "http://etherx.jabber.org/streams|stream"))
        {
          fprintf(stderr, "stream tag in wrong namespace\n");
          state->fatal_error = 1;

          return;
        }

      state->remote_major_version = 0;
      state->remote_minor_version = 9;

      for(attr = atts; *attr; attr += 2)
        {
          if(!strcmp(attr[0], "version"))
            {
              if(2 != sscanf(attr[1], "%u.%u", &state->remote_major_version,
                             &state->remote_minor_version))
                {
                  fprintf(stderr, "stream tag in wrong namespace\n");
                  state->fatal_error = 1;

                  return;
                }
            }
          else if(!strcmp(attr[0], "to"))
            {
              if(strcmp(attr[1], tree_get_string(config, "domain")))
                {
                  fprintf(stderr, "wrong target domain in stream header\n");
                  state->fatal_error = 1;

                  return;
                }
            }
          else if(!strcmp(attr[0], "id"))
            state->remote_stream_id = strdup(attr[1]);
        }

      if(state->remote_is_client)
        {
          char id[32];

          xmpp_gen_id(id);

          xmpp_printf(state,
                      "<?xml version='1.0'?>"
                      "<stream:stream xmlns='jabber:client' "
                      "xmlns:stream='http://etherx.jabber.org/streams' "
                      "from='%s' id='%s' "
                      "version='1.0'>",
                      tree_get_string(config, "domain"), id);

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
                      "from='%s' id='%s' "
                      "version='1.0'>",
                      tree_get_string(config, "domain"), id);

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
              fprintf(stderr, "Remote missing stream id\n");

              state->fatal_error = 1;

              return;
            }
        }
    }
  else if(state->xml_tag_level == 1)
    {
      for(attr = atts; *attr; attr += 2)
        {
          if(!strcmp(attr[0], "id"))
            stanza->id = arena_strdup(arena, attr[1]);
          else if(!strcmp(attr[0], "from"))
            stanza->from = arena_strdup(arena, attr[1]);
          else if(!strcmp(attr[0], "to"))
            stanza->to = arena_strdup(arena, attr[1]);
        }

      if(!strcmp(name, "http://etherx.jabber.org/streams|features"))
        {
          stanza->type = xmpp_features;
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
              fprintf(stderr, "sasl authentication requested by non-origin server\n");
              state->fatal_error = 1;

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

          xmpp_write(state,
                     "<stream:error>"
                     "<unsupported-stanza-type xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
                     "</stream:error>");
        }
    }
  else if(state->xml_tag_level == 2)
    {
      if(state->stanza.type == xmpp_features)
        {
          struct xmpp_features *pf = &stanza->u.features;

          if(!strcmp(name, "urn:ietf:params:xml:ns:xmpp-tls|starttls"))
            pf->starttls = 1;
          else if(!strcmp(name, "urn:xmpp:features:dialback|dialback"))
            pf->dialback = 1;
          else
            fprintf(stderr, "Unhandled feature tag '%s'\n", name);
        }
      else
        fprintf(stderr, "Unhandled level 2 tag '%s'\n", name);
    }

  ++state->xml_tag_level;
}

static void XMLCALL
xmpp_end_element(void *user_data, const XML_Char *name)
{
  struct xmpp_state *state = user_data;

  if(!state->xml_tag_level)
    {
      fprintf(stderr, "unexpected end tag\n");
      state->fatal_error = 1;

      return;
    }

  --state->xml_tag_level;

  if(state->xml_tag_level == 0)
    {
      state->stream_finished = 1;
    }
  else if(state->xml_tag_level == 1)
    {
      if(state->stanza.type != xmpp_unknown)
        xmpp_process_stanza(state);
    }
}

static void XMLCALL
xmpp_character_data(void *user_data, const XML_Char *str, int len)
{
  struct xmpp_state *state = user_data;
  struct xmpp_stanza *stanza = &state->stanza;
  struct arena_info *arena = &stanza->arena;

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
                  fprintf(stderr, "XML parse failed: %s\n",
                          XML_ErrorString(XML_GetErrorCode(state->xml_parser)));

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
          fprintf(stderr, "XML parse failed: %s\n",
                  XML_ErrorString(XML_GetErrorCode(state->xml_parser)));

          return -1;
        }
    }

  return state->fatal_error ? -1 : 0;
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
          struct xmpp_features *pf = &state->stanza.u.features;

          if(state->is_initiator)
            {
              if(!pf->starttls && !state->using_tls)
                {
                  fprintf(stderr, "TLS unsupported\n");
                  state->fatal_error = 1;

                  return;
                }

              if(!state->local_identified && pf->dialback)
                {
                  char key[65];

                  xmpp_gen_dialback_key(key, state, state->remote_jid,
                                        state->remote_stream_id);

                  xmpp_printf(state,
                            "<db:result from='%s' to='%s'>%s</db:result>",
                            tree_get_string(config, "domain"),
                            state->remote_jid, key);
                }
              else if(!state->using_tls)
                {
                  xmpp_write(state, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
                }
              /*
              else if(!state->local_identified && using_tls && pf->auth_external)
                {
                }
                */
              else
                {
                  fprintf(stderr, "AOK\n");


                  /*
                  xmpp_write(state,
                            "<iq type='get' id='157-3' from='%s' to='%s'>"
                            "<query xmlns='http://jabber.org/protocol/disco#info'/>"
                            "</iq>",
                            tree_get_string(config, "domain"), state->remote_jid);
                            */
                }
            }
        }

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
              fprintf(stderr, "Redundant starttls\n");
              state->fatal_error = 1;

              return;
            }

          xmpp_write(state, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");

          state->using_tls = 1;

          xmpp_start_tls(state);
        }

      break;

    case xmpp_dialback_verify:

        {
          struct xmpp_dialback_verify *pdv = &stanza->u.dialback_verify;
          char key[65];

          if(!stanza->id || !stanza->from || !stanza->to)
            {
              fprintf(stderr, "Insufficient parameters to dialback verify\n");
              state->fatal_error = 1;

              return;
            }

          if(strcmp(stanza->to, tree_get_string(config, "domain")))
            {
              fprintf(stderr, "Got verify for incorrect domain\n");
              state->fatal_error = 1;

              return;
            }

          xmpp_gen_dialback_key(key, state, stanza->from, stanza->id);

          /* Reverse from/to values, since we got these from a remote host */
          xmpp_printf(state, "<db:verify id='%s' from='%s' to='%s' type='valid'/>",
                      stanza->id, stanza->to, stanza->from,
                      strcmp(pdv->hash, key) ? "invalid" : "valid");
        }

      break;

    case xmpp_dialback_result:

        {
          struct xmpp_dialback_result *pdr = &stanza->u.dialback_result;

          if(!stanza->from || !stanza->to)
            {
              fprintf(stderr, "Insufficient parameters to dialback result\n");
              state->fatal_error = 1;

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

              if(!state->using_tls)
                xmpp_write(state, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
              /*
              xmpp_printf(state,
                        "<iq type='get' id='157-3' from='%s' to='%s'>"
                        "<query xmlns='http://jabber.org/protocol/disco#info'/>"
                        "</iq>",
                        tree_get_string(config, "domain"), state->remote_jid);
                        */
            }
        }

      break;

    case xmpp_auth:

        {
          struct xmpp_auth *pa = &stanza->u.auth;

          if(!pa->mechanism)
            {
              fprintf(stderr, "No mechanism given to auth\n");
              state->fatal_error = 1;

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

                  fprintf(stderr, "No content in plain auth\n");
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

                  fprintf(stderr, "Incorrect encoding of plain auth\n");
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
              xmpp_write(state,
                        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                        "<invalid-mechanism/>"
                        "</failure>");

              fprintf(stderr, "Unsupported auth mechnanism\n");
              state->fatal_error = 1;

              return;
            }
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
      fprintf(stderr, "Buffer append error: %s\n", strerror(errno));

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
