#include <err.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <expat.h>
#include <gnutls/gnutls.h>

#include "common.h"
#include "peer.h"
#include "data.h"
#include "tree.h"
#include "protocol.h"

static int
peer_send(struct peer_arg *ca, const char *format, ...)
{
  va_list args;
  char *buf;
  size_t size, offset = 0, to_write;
  int res;

  va_start(args, format);
  vasprintf(&buf, format, args);

  size = strlen(buf);

  fprintf(stderr, "LOCAL(%d): \033[1;35m%.*s\033[0m\n", ca->fd, (int) size, buf);

  while(offset < size)
    {
      to_write = size - offset;

      if(ca->do_ssl)
        {
          if(to_write > 4096)
            to_write = 4096;

          res = gnutls_record_send(ca->session, buf + offset, to_write);
        }
      else
        res = write(ca->fd, buf + offset, to_write);

      if(res <= 0)
        {
          if(ca->do_ssl)
            {
              if(res == 0)
                syslog(LOG_INFO, "peer closed connection");
              else
                syslog(LOG_INFO, "write error to peer: %s", strerror(errno));
            }
          else
            {
              if(res == 0)
                syslog(LOG_INFO, "TLS peer closed connection");
              else
                syslog(LOG_INFO, "write error to TLS peer: %s", gnutls_strerror(res));
            }

          free(buf);

          ca->fatal = 1;

          return -1;
        }

      offset += res;
    }

  free(buf);

  return 0;
}

static void
peer_handle_stanza(struct peer_arg *ca)
{
  struct proto_stanza* s = &ca->stanza;

  switch(s->type)
    {
    case proto_invalid:

      break;

    case proto_starttls:

        {
          if(ca->do_ssl)
            {
              ca->fatal = 1;

              syslog(LOG_INFO, "Got starttls while already in TLS");

              return;
            }

          peer_send(ca, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");

          ca->do_ssl = 1;
        }

      break;

    case proto_dialback_verify:

        {
          struct proto_dialback_verify* pdv = &s->u.dialback_verify;

          if(!pdv->id || !pdv->from || !pdv->to)
            {
              ca->fatal = 1;

              syslog(LOG_INFO, "peer sent dialback verify with insufficient parameters");

              return;
            }

          /* XXX: Verify */

          /* Reverse from/to values, since we got these from a remote host */
          peer_send(ca, "<db:verify id='%s' from='%s' to='%s' type='valid'></db:verify>",
                    pdv->id, pdv->to, pdv->from);
        }

      break;

    case proto_dialback_result:

        {
          struct proto_dialback_result* pdr = &s->u.dialback_result;

          syslog(LOG_INFO, "got dialback result: %s %s %s", pdr->type, pdr->from, pdr->to);

          if(!pdr->from || !pdr->to)
            {
              ca->fatal = 1;

              syslog(LOG_INFO, "peer sent dialback result with insufficient parameters");

              return;
            }

          if(!pdr->type)
            {
              /* XXX: Validate */

              peer_send(ca,
                        "<db:result from='%s' to='%s' type='valid'/>",
                        pdr->to, pdr->from);
            }
          else
            {
              peer_send(ca,
                        /*
                           "<iq type='get' id='157-3' from='%s' to='%s'>"
                           "<query xmlns='http://jabber.org/protocol/disco#info'/>"
                           "</iq>",
                           */
                        "<iq from='%s' to='%s' id='hest123' type='get'>"
                        "<ping xmlns='urn:xmpp:ping'/>"
                        "</iq>",
                        tree_get_string(config, "domain"), ca->remote_name);
            }
        }

      break;

    }
}

static void XMLCALL
xml_start_element(void *userData, const XML_Char *name, const XML_Char **atts)
{
  struct peer_arg *ca = userData;
  const XML_Char **attr;

  if(ca->tag_depth == 0 && !strcmp(name, "http://etherx.jabber.org/streams|stream"))
    {
      ca->major_version = 0;
      ca->minor_version = 9;

      for(attr = atts; *attr; attr += 2)
        {
          if(!strcmp(attr[0], "version"))
            {
              sscanf(attr[1], "%u.%u", &ca->major_version, &ca->minor_version);
            }
          else if(!strcmp(attr[0], "to"))
            {
              if(strcmp(attr[1], tree_get_string(config, "domain")))
                {
                  syslog(LOG_INFO, "peer expected '%s', but our domain is '%s'",
                         attr[1], tree_get_string(config, "domain"));

                  ca->fatal = 1;

                  return;
                }
            }
        }

      if(!ca->is_initiator)
        {
          if(-1 == peer_send(ca, "<?xml version='1.0'?>"
                             "<stream:stream xmlns='jabber:server' "
                             "xmlns:stream='http://etherx.jabber.org/streams' "
                             "xmlns:db='jabber:server:dialback' "
                             "from='%s' id='stream' "
                             "version='1.0'>",
                             tree_get_string(config, "domain")))
            {
              return;
            }

          if(ca->major_version >= 1)
            {
              if(ca->do_ssl)
                {
                  peer_send(ca, "<stream:features></stream:features>");
                }
              else
                {
                  peer_send(ca,
                            "<stream:features>"
                            "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>"
                            "<required/>"
                            "</starttls>"
                            "</stream:features>");
                }
            }
        }
    }
  else if(ca->tag_depth == 1 && !strcmp(name, "auth"))
    {
      ca->state = ps_auth;
    }
  else if(ca->tag_depth == 1 && !strcmp(name, "http://etherx.jabber.org/streams|features"))
    {
      ca->state = ps_features;
    }
  else if(ca->tag_depth == 1 && !strcmp(name, "urn:ietf:params:xml:ns:xmpp-tls|proceed"))
    {
      ca->state = ps_proceed;
    }
  else if(ca->tag_depth == 1 && !strcmp(name, "urn:ietf:params:xml:ns:xmpp-tls|starttls"))
    {
      memset(&ca->stanza, 0, sizeof(ca->stanza));
      ca->stanza.type = proto_starttls;
    }
  else if(ca->tag_depth == 1 && !strcmp(name, "jabber:server:dialback|verify"))
    {
      struct proto_dialback_verify* pdv = &ca->stanza.u.dialback_verify;

      memset(&ca->stanza, 0, sizeof(ca->stanza));
      ca->stanza.type = proto_dialback_verify;

      for(attr = atts; *attr; attr += 2)
        {
          if(!strcmp(attr[0], "id"))
            pdv->id = strdup(attr[1]);
          else if(!strcmp(attr[0], "from"))
            pdv->from = strdup(attr[1]);
          else if(!strcmp(attr[0], "to"))
            pdv->to = strdup(attr[1]);
        }
    }
  else if(ca->tag_depth == 1 && !strcmp(name, "jabber:server:dialback|result"))
    {
      struct proto_dialback_result* pdr = &ca->stanza.u.dialback_result;

      memset(&ca->stanza, 0, sizeof(ca->stanza));
      ca->stanza.type = proto_dialback_result;

      for(attr = atts; *attr; attr += 2)
        {
          if(!strcmp(attr[0], "type"))
            pdr->type = strdup(attr[1]);
          else if(!strcmp(attr[0], "from"))
            pdr->from = strdup(attr[1]);
          else if(!strcmp(attr[0], "to"))
            pdr->to = strdup(attr[1]);
        }
    }
  else if(ca->tag_depth == 1)
    {
      ca->state = ps_unknown;
    }

    {
      fprintf(stderr, "Begin: %s (%u)\n", name, ca->tag_depth);

      for(attr = atts; *attr; attr += 2)
        fprintf(stderr, "  %s = %s\n", attr[0], attr[1]);
    }

  ++ca->tag_depth;
}

static void XMLCALL
xml_end_element(void *userData, const XML_Char *name)
{
  struct peer_arg *ca = userData;

  --ca->tag_depth;

  if(ca->tag_depth == 0)
    {
      ca->fatal = 1;
    }
  else if(ca->tag_depth == 1)
    {
      fprintf(stderr, "Leaving state %u\n", ca->state);

      switch(ca->state)
        {
        case ps_features:

          if(!ca->do_ssl)
            {
              if(-1 == peer_send(ca, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"))
                {
                  return;
                }
            }
          else
            {
              if(-1 == peer_send(ca, "<db:result from='%s' "
                                 "to='%s'>"
                                 "1e701f120f66824b57303384e83b51feba858024fd2221d39f7acc52dcf767a9"
                                 "</db:result>",
                                 tree_get_string(config, "domain"),
                                 ca->remote_name))
                {
                  return;
                }
#if 0
              if(-1 == peer_send(ca, "<iq type='get' id='157-3' from='%s' to='%s'>"
                                 "<query xmlns='http://jabber.org/protocol/disco#info'/>"
                                 "</iq>", tree_get_string(config, "domain"),
                                 ca->remote_name))
                {
                  return;
                }
#endif
#if 0

/* d2F2ZS5yYXNoYm94Lm9yZw== */
/* cmFzaGJveC5vcmc= */

              if(-1 == peer_send(ca, "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>d2F2ZS5yYXNoYm94Lm9yZw==</auth>"))
                {
                  return;
                }
#endif
#if 0
              if(-1 == peer_send(ca, "<iq from='%s' to='%s.com' id='hest123' type='get'>"
                                 "<ping xmlns='urn:xmpp:ping'/>"
                                 "</iq>", tree_get_string(config, "domain"),
                                 ca->remote_name))
                {
                  return;
                }
#endif
            }

          break;

        case ps_proceed:

          ca->do_ssl = 1;

          break;


        default:;

        }

      ca->state = ps_none;

      peer_handle_stanza(ca);

      ca->stanza.type = proto_invalid;
    }

  fprintf(stderr, "End element '%s' (tag depth is now %u)\n", name, ca->tag_depth);
}

static void XMLCALL
xml_character_data(void *userData, const XML_Char *s, int len)
{
  struct peer_arg *ca = userData;

  switch(ca->stanza.type)
    {
    case proto_dialback_verify:

      ca->stanza.u.dialback_verify.hash = strndup(s, len);

      break;

    case proto_dialback_result:

      ca->stanza.u.dialback_result.hash = strndup(s, len);

      break;

    default:;
    }

  fprintf(stderr, "Data: '%.*s'\n", len, s);
}

void*
peer_thread_entry(void *arg)
{
  struct peer_arg *ca = arg;
  char buf[4095];
  int res;

  XML_Parser parser;

  ca->session = 0;

  parser = XML_ParserCreateNS("utf-8", '|');

  if(!parser)
    {
      syslog(LOG_WARNING, "XML_ParserCreate failed");

      goto done;
    }

  XML_SetUserData(parser, arg);
  XML_SetElementHandler(parser, xml_start_element, xml_end_element);
  XML_SetCharacterDataHandler(parser, xml_character_data);

  if(ca->is_initiator)
    {
      if(-1 == peer_send(ca, "<?xml version='1.0'?>"
                         "<stream:stream xmlns='jabber:server' "
                         "xmlns:stream='http://etherx.jabber.org/streams' "
                         "from='%s' id='stream' "
                         "to='%s' "
                         "xmlns:db='jabber:server:dialback' "
                         "version='1.0'>",
                         tree_get_string(config, "domain"),
                         ca->remote_name))
        {
          goto done;
        }
    }

  while(!ca->do_ssl)
    {
      if(ca->fatal)
        goto done;

      res = read(ca->fd, buf, sizeof(buf));

      if(!res)
        {
          syslog(LOG_INFO, "peer closed connection");

          goto done;
        }
      else if(res < 0)
        {
          syslog(LOG_INFO, "read error from peer: %s", strerror(errno));

          goto done;
        }

      fprintf(stderr, "REMOTE(%d): \033[1;36m%.*s\033[0m\n", ca->fd, res, buf);

      if(!XML_Parse(parser, buf, res, 0))
        {
          syslog(LOG_INFO, "parse error in XML stream");

          goto done;
        }
    }

  fprintf(stderr, "Time for TLS! \\o/\n");

  ca->tag_depth = 0;

  if(0 > (res = gnutls_init(&ca->session, ca->is_initiator ? GNUTLS_CLIENT : GNUTLS_SERVER)))
    {
      syslog(LOG_WARNING, "gnutls_init failed: %s", gnutls_strerror(res));

      ca->session = 0;

      goto done;
    }

  gnutls_priority_set(ca->session, priority_cache);

  if(0 > (res = gnutls_credentials_set(ca->session, GNUTLS_CRD_CERTIFICATE, xcred)))
    {
      syslog(LOG_WARNING, "failed to set credentials for TLS session: %s",
             gnutls_strerror(res));

      goto done;
    }

  gnutls_transport_set_ptr(ca->session, (gnutls_transport_ptr_t) (ptrdiff_t) ca->fd);

  if(0 > (res = gnutls_handshake(ca->session)))
    {
      syslog(LOG_INFO, "TLS handshake failed: %s", gnutls_strerror(res));

      goto done;
    }

  XML_ParserReset(parser, "utf-8");
  XML_SetUserData(parser, arg);
  XML_SetElementHandler(parser, xml_start_element, xml_end_element);
  XML_SetCharacterDataHandler(parser, xml_character_data);

  fprintf(stderr, "Sending header once again\n");

  if(ca->is_initiator)
    {
      if(-1 == peer_send(ca, "<?xml version='1.0'?>"
                         "<stream:stream xmlns='jabber:server' "
                         "xmlns:stream='http://etherx.jabber.org/streams' "
                         "from='%s' id='stream' "
                         "to='%s' "
                         "xmlns:db='jabber:server:dialback' "
                         "version='1.0'>",
                         tree_get_string(config, "domain"),
                         ca->remote_name))
        {
          goto done;
        }
    }

  fprintf(stderr, "Entering loop\n");

  for(;;)
    {
      res = gnutls_record_recv(ca->session, buf, sizeof(buf));

      if(!res)
        {
          XML_Parse(parser, 0, 0, 1);

          syslog(LOG_INFO, "TLS peer closed connection");

          break;
        }
      else if(res < 0)
        {
          syslog(LOG_INFO, "read error from TLS peer: %s", gnutls_strerror(res));

          break;
        }

      fprintf(stderr, "REMOTE(%d): \033[1;36m%.*s\033[0m\n", ca->fd, res, buf);

      if(!XML_Parse(parser, buf, res, 0))
        {
          syslog(LOG_INFO, "parse error in XML stream");

          break;
        }
    }

done:

  if(ca->session)
    peer_send(ca, "</stream:stream>");

  if(parser)
    XML_ParserFree(parser);

  if(ca->session)
    gnutls_bye(ca->session, GNUTLS_SHUT_RDWR);

  close(ca->fd);
  free(ca);

  return 0;
}
