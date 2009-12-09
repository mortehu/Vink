#include <alloca.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "vink.h"

static int ok = 1;

#define EXPECT(a) \
  if(!(a)) \
    { \
      fprintf(stderr, "%s:%d: %s failed\n", __PRETTY_FUNCTION__, __LINE__, #a); \
      ok = 0; \
    }

static void
t0x0000_xmpp_parse_jid()
{
  char* input;

  struct vink_xmpp_jid result;
  int ret;

  input = strdupa("example.org");

  ret = vink_xmpp_parse_jid(&result, input);

  EXPECT(ret == 0);
  EXPECT(result.node == 0);
  EXPECT(!strcmp(result.domain, "example.org"));
  EXPECT(result.resource == 0);
}

static void
t0x0001_xmpp_parse_jid()
{
  char* input;

  struct vink_xmpp_jid result;
  int ret;

  input = strdupa("test@example.org");

  ret = vink_xmpp_parse_jid(&result, input);

  EXPECT(ret == 0);
  EXPECT(!strcmp(result.node, "test"));
  EXPECT(!strcmp(result.domain, "example.org"));
  EXPECT(result.resource == 0);
}

static void
t0x0002_xmpp_parse_jid()
{
  char* input;

  struct vink_xmpp_jid result;
  int ret;

  input = strdupa("test@example.org/resource");

  ret = vink_xmpp_parse_jid(&result, input);

  EXPECT(ret == 0);
  EXPECT(!strcmp(result.node, "test"));
  EXPECT(!strcmp(result.domain, "example.org"));
  EXPECT(!strcmp(result.resource, "resource"));
}

int
main(int argc, char** argv)
{
  t0x0000_xmpp_parse_jid();
  t0x0001_xmpp_parse_jid();
  t0x0002_xmpp_parse_jid();

  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
