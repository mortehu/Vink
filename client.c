#include <err.h>
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
#include "client.h"
#include "tree.h"

static void XMLCALL
xml_start_element(void *userData, const XML_Char *name, const XML_Char **atts)
{
  /* struct client_arg *ca = userData; */

  fprintf(stderr, "Begin element '%s'\n", name);
}

static void XMLCALL
xml_end_element(void *userData, const XML_Char *name)
{
  /* struct client_arg *ca = userData; */

  fprintf(stderr, "End element '%s'\n", name);
}

static void XMLCALL
xml_character_data(void *userData, const XML_Char *s, int len)
{
  /* struct client_arg *ca = userData; */

  fprintf(stderr, "Data: '%.*s'\n", len, s);
}

static int
client_send(struct client_arg *ca, const char *format, ...)
{
  va_list args;
  char *buf;
  size_t size, offset, to_write;
  int res;

  va_start(args, format);
  vasprintf(&buf, format, args);

  size = strlen(buf);

  while(offset < size)
    {
      to_write = size - offset;

      if(to_write > 4096)
        to_write = 4096;

      res = gnutls_record_send(ca->session, buf + offset, to_write);

      if(res <= 0)
        {
          if(res == 0)
            syslog(LOG_INFO, "TLS peer closed connection");
          else
            syslog(LOG_INFO, "write error to TLS peer: %s", gnutls_strerror(res));

          free(buf);

          return -1;
        }

      offset += res;
    }

  free(buf);

  return 0;
}

void*
client_thread_entry(void *arg)
{
  struct client_arg *ca = arg;
  char buf[4095];
  int res;

  XML_Parser parser;

  ca->session = 0;

  parser = XML_ParserCreate("utf-8");

  if(!parser)
    {
      syslog(LOG_WARNING, "XML_ParserCreate failed");

      goto done;
    }

  XML_SetUserData(parser, arg);
  XML_SetElementHandler(parser, xml_start_element, xml_end_element);
  XML_SetCharacterDataHandler(parser, xml_character_data);

  if(0 > (res = gnutls_init(&ca->session, GNUTLS_SERVER)))
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

  gnutls_transport_set_ptr(ca->session, (gnutls_transport_ptr_t) ca->fd);

  if(0 > (res = gnutls_handshake(ca->session)))
    {
      syslog(LOG_INFO, "TLS handshake failed: %s", gnutls_strerror(res));

      goto done;
    }

  if(-1 == client_send(ca, "<?xml version='1.0'?>"))
    goto done;

  if(-1 == client_send(ca, "<stream:stream from='%s' id='stream' "
                       "xmlns='jabber:client' "
                       "xmlns:stream='http://etherx.jabber.org/streams' "
                       "version='1.0'>", tree_get_string(config, "domain")))
    goto done;

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

      if(!XML_Parse(parser, buf, res, 0))
        {
          syslog(LOG_INFO, "parse error in XML stream");

          break;
        }
    }

  client_send(ca, "</stream:stream>");

done:

  if(parser)
    XML_ParserFree(parser);

  if(ca->session)
    gnutls_bye(ca->session, GNUTLS_SHUT_RDWR);

  close(ca->fd);
  free(ca);

  return 0;
}
