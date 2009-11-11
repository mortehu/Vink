#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/time.h>
#include <pthread.h>

#include "common.h"
#include "peer.h"
#include "protocol.h"
#include "tree.h"

static void XMLCALL
xmpp_start_element(void *user_data, const XML_Char *name,
                   const XML_Char **atts);

static void XMLCALL
xmpp_end_element(void *userData, const XML_Char *name);

static void XMLCALL
xmpp_character_data(void *userData, const XML_Char *str, int len);

static void
xmpp_process_stanza(struct xmpp_state *state);

int
xmpp_state_init(struct xmpp_state *state,
                struct buffer *writebuf)
{
  memset(state, 0, sizeof(*state));

  state->writebuf = writebuf;

  state->xml_parser = XML_ParserCreateNS("utf-8", '|');

  if(!state->xml_parser)
    return -1;

  XML_SetUserData(state->xml_parser, state);
  XML_SetElementHandler(state->xml_parser, xmpp_start_element, xmpp_end_element);
  XML_SetCharacterDataHandler(state->xml_parser, xmpp_character_data);

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
  size_t size = strlen(data);

  ARRAY_ADD_SEVERAL(state->writebuf, data, size);
}

static void
xmpp_printf(struct xmpp_state *state, const char* format, ...)
{
  va_list args;
  char* buf;
  int res;

  va_start(args, format);

  res = vasprintf(&buf, format, args);

  if(res == -1)
    {
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

  if(state->xml_tag_level == 0)
    {
      if(strcmp(name, "http://etherx.jabber.org/streams|stream"))
        {
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
                  state->fatal_error = 1;

                  return;
                }
            }
          else if(!strcmp(attr[0], "to"))
            {
              if(strcmp(attr[1], tree_get_string(config, "domain")))
                {
                  state->fatal_error = 1;

                  return;
                }
            }
        }

      state->remote_is_client = 1; /* XXX */

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
      else if(!state->is_initiator)
        {
          xmpp_printf(state,
                      "<?xml version='1.0'?>"
                      "<stream:stream xmlns='jabber:server' "
                      "xmlns:stream='http://etherx.jabber.org/streams' "
                      "xmlns:db='jabber:server:dialback' "
                      "from='%s' id='stream' "
                      "version='1.0'>",
                      tree_get_string(config, "domain"));

          xmpp_write(state, "<stream:features>");

          if(!state->using_tls)
            {
              if(state->remote_major_version >= 1)
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
      struct xmpp_node* node;
      struct arena_info* arena;

      arena = &state->stanza.arena;

      node = arena_calloc(arena, sizeof(*node));
      node->key = arena_strdup(arena, name);

      if(atts)
        {
          size_t i = 0, attr_count = 0;

          for(attr = atts; *attr; attr += 2)
            ++attr_count;

          node->atts = arena_alloc(arena, sizeof(*node->atts) * (1 + 2 * attr_count));

          for(attr = atts; *attr; attr += 2)
            {
              node->atts[i++] = arena_strdup(arena, attr[0]);
              node->atts[i++] = arena_strdup(arena, attr[0]);
            }

          node->atts[i] = 0;
        }

      if(!state->current_node)
        {
          assert(state->xml_tag_level == 1);
          assert(!state->stanza.root);

          state->stanza.root = node;
        }
      else
        {
          node->next_sibling = state->current_node->first_child;
          state->current_node->first_child = node;
        }

       state->current_node = node;
    }
#if 0
  else if(ca->tag_depth == 1)
    {
      struct xmpp_stanza* s = &ca->stanza;

      memset(s, 0, sizeof(*s));

      for(attr = atts; *attr; attr += 2)
        {
          if(!strcmp(attr[0], "id"))
            s->id = arena_strdup(&s->arena, attr[1]);
          else if(!strcmp(attr[0], "from"))
            s->from = arena_strdup(&s->arena, attr[1]);
          else if(!strcmp(attr[0], "to"))
            s->to = arena_strdup(&s->arena, attr[1]);
        }

      if(!strcmp(name, "http://etherx.jabber.org/streams|features"))
        {
          s->type = xmpp_features;
        }
      else if(!strcmp(name, "urn:ietf:params:xml:ns:xmpp-tls|proceed"))
        {
          s->type = xmpp_tls_proceed;
        }
      else if(!strcmp(name, "urn:ietf:params:xml:ns:xmpp-tls|starttls"))
        {
          s->type = xmpp_tls_starttls;
        }
      else if(!strcmp(name, "jabber:server:dialback|verify"))
        {
          s->type = xmpp_dialback_verify;
        }
      else if(!strcmp(name, "jabber:server:dialback|result"))
        {
          struct xmpp_dialback_result* pdr = &s->u.dialback_result;

          s->type = xmpp_dialback_result;

          for(attr = atts; *attr; attr += 2)
            {
              if(!strcmp(attr[0], "type"))
                pdr->type = arena_strdup(&s->arena, attr[1]);
            }
        }
      else if(!strcmp(name, "urn:ietf:params:xml:ns:xmpp-sasl|auth"))
        {
          if(ca->is_initiator)
            {
              syslog(LOG_INFO, "Got auth packet while in initiator mode");

              ca->fatal = 1;

              return;
            }

          s->type = xmpp_auth;

          for(attr = atts; *attr; attr += 2)
            {
              if(!strcmp(attr[0], "mechanism"))
                s->u.auth.mechanism = arena_strdup(&s->arena, attr[1]);
            }
        }
      else if(!strcmp(name, "jabber:server|iq")
              || !strcmp(name, "jabber:client|iq"))
        {
          s->type = xmpp_iq;
        }
      else if(!strcmp(name, "jabber:server|message")
              ||!strcmp(name, "jabber:client|message"))
        {
          s->type = xmpp_message;
        }
      else if(!strcmp(name, "jabber:server|presence")
              || strcmp(name, "jabber:clent|presence"))
        {
          s->type = xmpp_presence;
        }
      else
        {
          s->type = xmpp_unknown;

          peer_send(ca,
                    "<stream:error>"
                    "<unsupported-stanza-type xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
                    "</stream:error>",
                    tree_get_string(config, "domain"), ca->remote_domain);
        }
    }
  else if(ca->tag_depth == 2)
    {
      if(ca->stanza.type == xmpp_features)
        {
          struct xmpp_features* pf = &ca->stanza.u.features;

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
#endif

  ++state->xml_tag_level;
}

static void XMLCALL
xmpp_end_element(void *user_data, const XML_Char *name)
{
  struct xmpp_state *state = user_data;

  if(!state->xml_tag_level)
    {
      state->fatal_error = 1;

      return;
    }

  --state->xml_tag_level;

  if(state->xml_tag_level == 0)
    {
      state->stream_finished = 1;
    }
  else
    {
      assert(state->current_node);

      state->current_node = state->current_node->parent;

      if(!state->current_node)
        xmpp_process_stanza(state);
    }
}

static void XMLCALL
xmpp_character_data(void *user_data, const XML_Char *str, int len)
{
  struct xmpp_state *state = user_data;

  if(state->current_node)
    {
      state->current_node->value
        = arena_strndup(&state->stanza.arena, str, len);
    }
}

int
xmpp_state_data(struct xmpp_state *state,
                const void* data, size_t count)
{
  if(!XML_Parse(state->xml_parser, data, count, 0))
    return -1;

  return state->fatal_error ? -1 : 0;
}

static void
xmpp_process_stanza(struct xmpp_state *state)
{
  const char *type;

  type = state->stanza.root->key;

  if(!strcmp(type, "http://etherx.jabber.org/streams|error"))
    {
    }
  else if(!strcmp(type, "http://etherx.jabber.org/streams|features"))
    {
    }
  else if(!strcmp(type, "urn:ietf:params:xml:ns:xmpp-tls|proceed"))
    {
    }
  else if(!strcmp(type, "urn:ietf:params:xml:ns:xmpp-tls|starttls"))
    {
    }
  else if(!strcmp(type, "jabber:server:dialback|verify"))
    {
    }
  else if(!strcmp(type, "jabber:server:dialback|result"))
    {
    }
  else if(!strcmp(type, "urn:ietf:params:xml:ns:xmpp-sasl|auth"))
    {
    }
  else if(!strcmp(type, "jabber:server|iq")
          || !strcmp(type, "jabber:client|iq"))
    {
    }
  else if(!strcmp(type, "jabber:server|message")
          ||!strcmp(type, "jabber:client|message"))
    {
    }
  else if(!strcmp(type, "jabber:server|presence")
          || strcmp(type, "jabber:clent|presence"))
    {
    }
  else
    {
      xmpp_write(state,
                 "<stream:error>"
                 "<unsupported-stanza-type xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
                 "</stream:error>");
    }
}

int
xmpp_parse_jid(struct xmpp_jid *target, char *input)
{
  char* c;

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
xmpp_gen_id(char* target)
{
  struct timeval now;

  gettimeofday(&now, 0);

  sprintf(target, "%llx-%x",
          (unsigned long long) now.tv_sec * 1000000
          + (unsigned long long) now.tv_usec,
          (unsigned int) rand());

}

