#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <err.h>
#include <crypt.h>
#include <pthread.h>
#include <pwd.h>
#include <unistd.h>

#include <ruli_getaddrinfo.h>
#include <expat.h>
#include <gnutls/gnutls.h>

#include "base64.h"
#include "common.h"
#include "peer.h"
#include "data.h"
#include "tree.h"
#include "protocol.h"

struct peer
{
  int fd;

  char* remote_domain;

  unsigned int major_version;
  unsigned int minor_version;

  unsigned int tag_depth;

  gnutls_session_t session;

  unsigned int do_ssl : 1;
  unsigned int remote_is_client : 1;
  unsigned int is_initiator : 1;
  unsigned int is_authenticated : 1;
  unsigned int ready : 1;
  unsigned int fatal : 1;
  unsigned int need_restart : 1;

  struct xmpp_stanza stanza;

  pthread_mutex_t lock;
  pthread_cond_t cond;
  pthread_cond_t cond_awaiting_reply;
  pthread_cond_t cond_processing_reply;

  unsigned int ref_count;

  struct peer* next_peer;
  struct peer* previous_peer;

  unsigned int waiters, waiters_completed;
};

struct waiter
{
  const char* remote_domain;
  const char* id;
  struct xmpp_stanza* reply;

  pthread_barrier_t barrier;

  struct waiter* next_waiter;
  struct waiter* previous_waiter;
};

static pthread_mutex_t peer_list_lock = PTHREAD_MUTEX_INITIALIZER;
static struct peer* first_peer;

static pthread_mutex_t waiter_list_lock = PTHREAD_MUTEX_INITIALIZER;
static struct waiter* first_waiter;

static void
peer_handle_stanza(struct peer *ca);

static int
peer_write(struct peer *ca, const void* data, size_t size)
{
  const char *buf;
  size_t offset = 0, to_write;
  int res;

  buf = data;

  fprintf(stderr, "LOCAL(%d): \033[1;35m%.*s\033[0m\n", ca->fd, (int) size, buf);

  while(offset < size)
    {
      to_write = size - offset;

      if(ca->session)
        {
          if(to_write > 4096)
            to_write = 4096;

          res = gnutls_record_send(ca->session, buf + offset, to_write);
        }
      else
        res = write(ca->fd, buf + offset, to_write);

      if(res <= 0)
        {
          if(res == 0)
            syslog(LOG_INFO, "peer closed connection");
          else
            syslog(LOG_INFO, "write error to peer: %s", ca->session ? gnutls_strerror(res) : strerror(errno));

          ca->fatal = 1;

          return -1;
        }

      offset += res;
    }

  return 0;
}

int
peer_send(struct peer *ca, const char *format, ...)
{
  va_list args;
  char* buf;
  int res;

  va_start(args, format);

  res = vasprintf(&buf, format, args);

  if(res == -1)
    return -1;

  res = peer_write(ca, buf, res);

  free(buf);

  return res;
}

static void
peer_error(struct peer* p, const char* message)
{
  peer_write(p, message, strlen(message));
  p->fatal = -1;
}

static int
peer_authenticate(struct peer *p, const char *jid_string, const char *user, const char *password)
{
  struct xmpp_jid jid;
  const char* realhash;
  const char* hash;
  struct crypt_data cdata;

  struct passwd pwdbuf;
  struct passwd* pwd;
  char* buffer;
  int buffer_size;

  buffer = strdupa(jid_string);

  xmpp_parse_jid(&jid, buffer);

  if(!jid.node || strcmp(jid.node, user))
    {
      fprintf(stderr, "No jid node (%s)\n", buffer);
      peer_send(p,
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                "<not-authorized/>"
                "</failure>");
    }

  buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
  buffer = malloc(buffer_size);

  if(!buffer)
    {
      peer_send(p,
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                "<temporary-auth-failure/>"
                "</failure>");

      return -1;
    }

  getpwnam_r(jid.node, &pwdbuf, buffer, buffer_size, &pwd);

  if(!pwd)
    {
      free(buffer);

      peer_send(p,
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                "<not-authorized/>"
                "</failure>");

      return -1;
    }

  realhash = pwd->pw_passwd;

  if(!(hash = crypt_r(password, realhash, &cdata))
     || strcmp(hash, realhash))
    {
      fprintf(stderr, "%s %s %s [%s]\n", hash, realhash, jid.node, password);
      free(buffer);

      peer_send(p,
                "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                "<not-authorized/>"
                "</failure>");

      return -1;
    }

  free(buffer);

  return 0;
}

static void XMLCALL
xml_start_element(void *user_data, const XML_Char *name, const XML_Char **atts)
{
  struct peer *ca = user_data;
  const XML_Char **attr;

  if(ca->tag_depth == 0)
    {
      if(strcmp(name, "http://etherx.jabber.org/streams|stream"))
        {
          syslog(LOG_INFO, "got unexpected root element '%s'", name);

          ca->fatal = 1;

          return;
        }

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

      ca->remote_is_client = 1; /* XXX */

      if(ca->remote_is_client)
        {
          char id[32];

          xmpp_gen_id(id);

          peer_send(ca,
                    "<?xml version='1.0'?>"
                    "<stream:stream xmlns='jabber:client' "
                    "xmlns:stream='http://etherx.jabber.org/streams' "
                    "from='%s' id='%s' "
                    "version='1.0'>",
                    tree_get_string(config, "domain"),
                    id);

          peer_send(ca, "<stream:features>");

          if(!ca->remote_domain)
            {
              peer_send(ca,
                        "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                        /*"<mechanism>DIGEST-MD5</mechanism>"*/
                        "<mechanism>PLAIN</mechanism>"
                        "</mechanisms>");
            }

          if(!ca->do_ssl && ca->major_version >= 1)
            {
              peer_send(ca,
                        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>"
                        "</starttls>");
            }

          peer_send(ca, "</stream:features>");
        }
      else if(!ca->is_initiator)
        {
          if(-1 == peer_send(ca,
                             "<?xml version='1.0'?>"
                             "<stream:stream xmlns='jabber:server' "
                             "xmlns:stream='http://etherx.jabber.org/streams' "
                             "xmlns:db='jabber:server:dialback' "
                             "from='%s' id='stream' "
                             "version='1.0'>",
                             tree_get_string(config, "domain")))
            {
              return;
            }

          if(ca->do_ssl || ca->major_version < 1)
            {
              peer_send(ca,
                        "<stream:features>"
                        "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                        "<mechanism>EXTERNAL</mechanism>"
                        "</mechanisms>"
                        "<db:dialback/>"
                        "</stream:features>");
            }
          else
            {
              peer_send(ca,
                        "<stream:features>"
                        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>"
                        "</starttls>"
                        "<db:dialback/>"
                        "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                        "<mechanism>EXTERNAL</mechanism>"
                        "</mechanisms>"
                        "</stream:features>");
            }
        }
    }
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

  ++ca->tag_depth;
}

static void
peer_handle_stanza(struct peer *ca)
{
  struct xmpp_stanza* s = &ca->stanza;

  switch(s->type)
    {
    case xmpp_invalid:
    case xmpp_unknown:

      break;

    case xmpp_features:

        {
          struct xmpp_features* pf = &ca->stanza.u.features;

          fprintf(stderr, "Got features\n");

          if(ca->is_initiator)
            {
              if(!pf->starttls && !ca->do_ssl)
                {
                  syslog(LOG_INFO, "Peer does not support TLS");

                  ca->fatal = 1;

                  return;
                }

              if(!ca->is_authenticated && pf->dialback)
                {
                  peer_send(ca,
                            "<db:result from='%s' to='%s'>"
                            "1e701f120f66824b57303384e83b51feba858024fd2221d39f7acc52dcf767a9"
                            "</db:result>",
                            tree_get_string(config, "domain"),
                            ca->remote_domain);
                }
              /*
              else if(!ca->is_authenticated && do_ssl && pf->auth_external)
                {
                }
                */
              else if(!ca->do_ssl)
                {
                  peer_send(ca, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
                }
              else
                {
                  fprintf(stderr, "AOK\n");

                  ca->ready = 1;
                  pthread_cond_signal(&ca->cond);

                  /*
                  peer_send(ca,
                            "<iq type='get' id='157-3' from='%s' to='%s'>"
                            "<query xmlns='http://jabber.org/protocol/disco#info'/>"
                            "</iq>",
                            tree_get_string(config, "domain"), ca->remote_domain);
                            */
                }
            }
        }

      break;

    case xmpp_tls_proceed:

      if(ca->do_ssl)
        syslog(LOG_INFO, "peer sent TLS proceed even though we're already using TLS");

      ca->do_ssl = 1;

      break;

    case xmpp_tls_starttls:

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

    case xmpp_dialback_verify:

        {
          struct xmpp_dialback_verify* pdv = &s->u.dialback_verify;

          if(!s->id || !s->from || !s->to)
            {
              ca->fatal = 1;

              syslog(LOG_INFO, "peer sent dialback verify with insufficient parameters");

              return;
            }

          /* XXX: Verify */

          /* Reverse from/to values, since we got these from a remote host */
          peer_send(ca, "<db:verify id='%s' from='%s' to='%s' type='valid'/>",
                    s->id, s->to, s->from);
        }

      break;

    case xmpp_dialback_result:

        {
          struct xmpp_dialback_result* pdr = &s->u.dialback_result;

          syslog(LOG_INFO, "got dialback result: %s %s %s", pdr->type, s->from, s->to);

          if(!s->from || !s->to)
            {
              syslog(LOG_INFO, "peer sent dialback result with insufficient parameters");

              ca->fatal = 1;

              return;
            }

          if(!pdr->type)
            {
              /* XXX: Validate */

              free(ca->remote_domain);
              ca->remote_domain = strdup(s->from);
              ca->ready = 1;
              pthread_cond_signal(&ca->cond);

              peer_send(ca,
                        "<db:result from='%s' to='%s' type='valid'/>",
                        s->to, s->from);
            }
          else
            {
              if(strcmp(pdr->type, "valid"))
                {
                  syslog(LOG_INFO, "dialback validation failed");

                  ca->fatal = 1;

                  return;
                }

              ca->is_authenticated = 1;

              if(!ca->do_ssl)
                peer_send(ca, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
              /*
              peer_send(ca,
                        "<iq type='get' id='157-3' from='%s' to='%s'>"
                        "<query xmlns='http://jabber.org/protocol/disco#info'/>"
                        "</iq>",
                        tree_get_string(config, "domain"), ca->remote_domain);
                        */
            }
        }

      break;

    case xmpp_auth:

        {
          struct xmpp_auth *pa = &s->u.auth;

          syslog(LOG_INFO, "got auth");

          if(!pa->mechanism)
            {
              syslog(LOG_INFO, "auth missing mechanism");

              ca->fatal = 1;

              return;
            }

          if(!strcmp(pa->mechanism, "DIGEST-MD5"))
            {
              char nonce[16];
              char* challenge;
              char* challenge_base64;

              xmpp_gen_id(nonce);

              if(-1 == asprintf(&challenge,
                                "realm=\"%s\",nonce=\"%s\",qop=\"auth\",charset=utf-8,algorithm=md5-ses",
                                tree_get_string(config, "domain"), nonce))
                {
                  syslog(LOG_INFO, "malloc failed");

                  ca->fatal = 1;

                  return;
                }

              challenge_base64 = base64_encode(challenge, strlen(challenge));

              free(challenge);

              peer_send(ca,
                        "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                        "%s"
                        "</challenge>",
                        challenge_base64);

              free(challenge_base64);
            }
          else if(!strcmp(pa->mechanism, "PLAIN"))
            {
              char* content;
              const char* user;
              const char* secret;
              ssize_t content_length;

              if(!pa->content)
                {
                  peer_send(ca,
                            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                            "<incorrect-encoding/>"
                            "</failure>");

                  ca->fatal = 1;

                  return;
                }

              content = malloc(strlen(pa->content) + 1);
              content_length = base64_decode(content, pa->content, 0);
              content[content_length] = 0;

              fprintf(stderr, "[");
              write(2, content, content_length);
              fprintf(stderr, "]\n");

              if(!(user = memchr(content, 0, content_length))
                 || !(secret = memchr(user + 1, 0, content + content_length - user - 1)))
                {
                  peer_send(ca,
                            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                            "<incorrect-encoding/>"
                            "</failure>");

                  ca->fatal = 1;

                  return;
                }

              ++user;
              ++secret;

              if(-1 == peer_authenticate(ca, content, user, secret))
                {
                  free(content);

                  return;
                }

              free(ca->remote_domain);
              ca->remote_domain = strdup(content);
              ca->need_restart = 1;

              free(content);

              peer_send(ca, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
            }
          else if(!strcmp(pa->mechanism, "EXTERNAL"))
            {
            }
          else
            {
              peer_send(ca,
                        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                        "<invalid-mechanism/>"
                        "</failure>");

              ca->fatal = 1;

              return;
            }
        }

      break;

    default:

      if(ca->stanza.id);
        {
          struct waiter* i;

          pthread_mutex_lock(&waiter_list_lock);

          for(i = first_waiter; i; i = i->next_waiter)
            {
              if(!strcmp(ca->remote_domain, i->remote_domain)
                 && !strcmp(ca->stanza.id, i->id))
                {
                  if(i->next_waiter)
                    i->next_waiter->previous_waiter = i->previous_waiter;

                  if(i->previous_waiter)
                    i->previous_waiter->next_waiter = i->next_waiter;
                  else
                    first_waiter = i->next_waiter;

                  *i->reply = *s;
                  memset(s, 0, sizeof(*s));

                  pthread_barrier_wait(&i->barrier);

                  break;
                }
            }

          pthread_mutex_unlock(&waiter_list_lock);
        }
    }

  ca->stanza.type = xmpp_invalid;
  arena_free(&s->arena);
}

int
peer_get_reply(struct peer* p, const char* id, struct xmpp_stanza* reply)
{
  struct waiter w;

  pthread_mutex_unlock(&p->lock);

  w.remote_domain = p->remote_domain;
  w.id = id;
  w.reply = reply;

  pthread_barrier_init(&w.barrier, 0, 2);

  pthread_mutex_lock(&waiter_list_lock);
  w.next_waiter = first_waiter;
  w.previous_waiter = 0;
  if(first_waiter)
    first_waiter->previous_waiter = &w;
  first_waiter = &w;
  pthread_mutex_unlock(&waiter_list_lock);

  pthread_barrier_wait(&w.barrier);
  pthread_barrier_destroy(&w.barrier);

  pthread_mutex_lock(&p->lock);

  return 0;
}


static void XMLCALL
xml_end_element(void *userData, const XML_Char *name)
{
  struct peer *ca = userData;

  --ca->tag_depth;

  if(ca->tag_depth == 0)
    {
      /* End of stream */
      ca->fatal = 1;
    }
  else if(ca->tag_depth == 1)
    {
      /* End of stanza */
      peer_handle_stanza(ca);
    }
}

static void XMLCALL
xml_character_data(void *userData, const XML_Char *str, int len)
{
  struct peer *ca = userData;
  struct xmpp_stanza *s = &ca->stanza;

  switch(ca->stanza.type)
    {
    case xmpp_dialback_verify:

      ca->stanza.u.dialback_verify.hash = arena_strndup(&s->arena, str, len);

      break;

    case xmpp_dialback_result:

      ca->stanza.u.dialback_result.hash = arena_strndup(&s->arena, str, len);

      break;

    case xmpp_auth:

      ca->stanza.u.auth.content = arena_strndup(&s->arena, str, len);

      break;

    default:

      fprintf(stderr, "\033[31;1mUnhandled data: '%.*s'\033[0m\n", len, str);
    }
}

static int
peer_starttls(struct peer* ca)
{
  int res;

  if(0 > (res = gnutls_init(&ca->session, ca->is_initiator ? GNUTLS_CLIENT : GNUTLS_SERVER)))
    {
      syslog(LOG_WARNING, "gnutls_init failed: %s", gnutls_strerror(res));

      ca->session = 0;

      return -1;
    }

  gnutls_priority_set(ca->session, priority_cache);

  if(0 > (res = gnutls_credentials_set(ca->session, GNUTLS_CRD_CERTIFICATE, xcred)))
    {
      syslog(LOG_WARNING, "failed to set credentials for TLS session: %s",
             gnutls_strerror(res));

      gnutls_bye(ca->session, GNUTLS_SHUT_WR);
      ca->session = 0;

      return -1;
    }

  gnutls_certificate_server_set_request(ca->session, GNUTLS_CERT_REQUEST);
  gnutls_dh_set_prime_bits(ca->session, 1024);

  gnutls_transport_set_ptr(ca->session, (gnutls_transport_ptr_t) (ptrdiff_t) ca->fd);

  if(0 > (res = gnutls_handshake(ca->session)))
    {
      syslog(LOG_INFO, "TLS handshake failed: %s", gnutls_strerror(res));

      gnutls_bye(ca->session, GNUTLS_SHUT_WR);
      ca->session = 0;

      return -1;
    }

  return 0;
}

void*
peer_thread_entry(void *arg)
{
  struct peer *ca = arg;
  char buf[4095];
  int res;

  /* ca->mutex is locked upon entry */

  pthread_mutex_lock(&peer_list_lock);
  ca->next_peer = first_peer;
  if(first_peer)
    first_peer->previous_peer = ca;
  first_peer = ca;
  pthread_mutex_unlock(&peer_list_lock);

  XML_Parser parser;

  ca->session = 0;

  parser = XML_ParserCreateNS("utf-8", '|');

  if(!parser)
    {
      syslog(LOG_WARNING, "XML_ParserCreate failed");

      close(ca->fd);

      ca->fatal = 1;

      pthread_cond_broadcast(&ca->cond);
      pthread_cond_broadcast(&ca->cond_awaiting_reply);

      peer_release(ca);

      return 0;
    }

  /* The session might have to be reset if TLS or compression is enabled */
  while(!ca->fatal)
    {
      ca->need_restart = 0;
      ca->tag_depth = 0;

      if(ca->do_ssl && !ca->session)
        {
          if(-1 == peer_starttls(ca))
            break;
        }

      XML_ParserReset(parser, "utf-8");
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
                             ca->remote_domain))
            {
              break;
            }
        }

      while(!ca->fatal)
        {
          pthread_mutex_unlock(&ca->lock);

          res = ca->do_ssl ? gnutls_record_recv(ca->session, buf, sizeof(buf))
                           : read(ca->fd, buf, sizeof(buf));

          pthread_mutex_lock(&ca->lock);

          if(!res)
            {
              XML_Parse(parser, 0, 0, 1);

              syslog(LOG_INFO, "peer closed connection");

              ca->fatal = 1;

              break;
            }
          else if(res < 0)
            {
              syslog(LOG_INFO, "read error from peer: %s",
                     ca->do_ssl ? gnutls_strerror(res) : strerror(errno));

              ca->fatal = 1;

              break;
            }

          fprintf(stderr, "REMOTE(%d): \033[1;36m%.*s\033[0m\n", ca->fd, res, buf);

          if(!XML_Parse(parser, buf, res, 0))
            {
              syslog(LOG_INFO, "parse error in XML stream");

              ca->fatal = 1;

              break;
            }

          /* Start TLS? */
          if(ca->do_ssl && !ca->session)
            break;

          if(ca->need_restart)
            break;
        }
    }

  ca->fatal = 1;

  XML_ParserFree(parser);

  peer_send(ca, "</stream:stream>");

  if(ca->session)
    gnutls_bye(ca->session, GNUTLS_SHUT_WR);

  close(ca->fd);

  pthread_cond_broadcast(&ca->cond);
  pthread_cond_broadcast(&ca->cond_awaiting_reply);

  peer_release(ca);

  return 0;
}

static int
create_channel(const char* domain)
{
  struct addrinfo* addrs = 0;
  struct addrinfo* addr;
  struct addrinfo hints;
  int result = -1;

  memset(&hints, 0, sizeof(hints));
  hints.ai_protocol = getprotobyname("tcp")->p_proto;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_CANONNAME;
  hints.ai_family = PF_UNSPEC;

  ruli_getaddrinfo(domain, "xmpp-server", &hints, &addrs);

  if(!addrs)
    ruli_getaddrinfo(domain, "jabber-server", &hints, &addrs);

  for(addr = addrs; addr; addr = addr->ai_next)
    {
      result = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

      if(result == -1)
        continue;

      if(-1 != connect(result, addr->ai_addr, addr->ai_addrlen))
        break;

      close(result);
      result = -1;
    }

  ruli_freeaddrinfo(addrs);

  return result;
}

void
peer_add(int fd)
{
  pthread_t new_peer_thread;
  struct peer* new_peer;

  new_peer = malloc(sizeof(*new_peer));
  memset(new_peer, 0, sizeof(*new_peer));

  new_peer->fd = fd;
  new_peer->is_initiator = 0;
  new_peer->ref_count = 1;
  pthread_mutex_init(&new_peer->lock, 0);
  pthread_cond_init(&new_peer->cond, 0);
  pthread_cond_init(&new_peer->cond_processing_reply, 0);

  fprintf(stderr, "Got connection\n");

  pthread_mutex_lock(&new_peer->lock);

  assert(!new_peer->remote_domain);
  pthread_create(&new_peer_thread, 0, peer_thread_entry, new_peer);
  pthread_detach(new_peer_thread);
}

struct peer*
peer_get(const char* remote_domain)
{
  pthread_t new_peer_thread;
  struct peer* result;
  int fd;

  pthread_mutex_lock(&peer_list_lock);

  for(result = first_peer; result; result = result->next_peer)
    {
      if(result->is_initiator && result->remote_domain
         && !strcmp(result->remote_domain, remote_domain))
        {
          pthread_mutex_lock(&result->lock);

          while(!result->fatal && !result->ready)
            pthread_cond_wait(&result->cond, &result->lock);

          if(result->fatal)
            {
              peer_release(result);

              continue;
            }

          ++result->ref_count;

          return result;
        }
    }

  pthread_mutex_unlock(&peer_list_lock);

  fd = create_channel(remote_domain);

  if(fd == -1)
    return 0;

  result = malloc(sizeof(*result));
  memset(result, 0, sizeof(*result));

  result->fd = fd;
  result->is_initiator = 1;
  result->remote_domain = strdup(remote_domain);
  result->ref_count = 2;
  pthread_mutex_init(&result->lock, 0);
  pthread_cond_init(&result->cond, 0);
  pthread_cond_init(&result->cond_awaiting_reply, 0);
  pthread_cond_init(&result->cond_processing_reply, 0);

  fprintf(stderr, "Connected to %s\n", result->remote_domain);

  pthread_mutex_lock(&result->lock);

  pthread_create(&new_peer_thread, 0, peer_thread_entry, result);
  pthread_detach(new_peer_thread);

  pthread_mutex_lock(&result->lock);

  while(!result->fatal && !result->ready)
    pthread_cond_wait(&result->cond, &result->lock);

  if(result->fatal)
    {
      peer_release(result);

      return 0;
    }

  return result;
}

void
peer_release(struct peer* p)
{
  if(!--p->ref_count)
    {
      /* Remove peer from linked list */
      pthread_mutex_lock(&peer_list_lock);

      if(p->next_peer)
        p->next_peer->previous_peer = p->previous_peer;

      if(p->previous_peer)
        p->previous_peer->next_peer = p->next_peer;
      else
        first_peer = p->next_peer;

      pthread_mutex_unlock(&peer_list_lock);

      /* Free memory used by peer */
      arena_free(&p->stanza.arena);
      free(p->remote_domain);
      free(p);

      return;
    }

  pthread_mutex_unlock(&p->lock);
}
