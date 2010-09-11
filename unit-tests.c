#ifndef CONFIG_H
#include "config.h"
#endif

#include <alloca.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <malloc.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "base64.h"
#include "vink-internal.h"
#include "vink.h"

static int ok = 1;

#define EXPECT(a) \
  do \
    { \
      if(!(a)) \
        { \
          fprintf(stderr, "%s:%d: %s failed\n", __PRETTY_FUNCTION__, __LINE__, #a); \
          ok = 0; \
        } \
    } \
  while(0)

static int
buffer_write(const void* data, size_t size, void* arg)
{
  struct VINK_buffer *buf = arg;

  ARRAY_ADD_SEVERAL(buf, data, size);

  return ARRAY_RESULT(buf);
}

int
myrand ()
{
  static unsigned long next = 1;

  next = next * 1103515245 + 12345;

  return ((unsigned) (next / 65536) % 32768);
}

static void
t0x0000_base64_decode()
{
  char input_buf[257];
  char decoded_buf[257];
  char *coded_buf;
  size_t i, len, decoded_len, iteration;

  for (iteration = 0; iteration <= 256; ++iteration)
    {
      len = iteration;

      for (i = 0; i < len; ++i)
        input_buf[i] = myrand ();

      coded_buf = base64_encode (input_buf, len);

      if (!coded_buf)
        continue;

      decoded_len = base64_decode (decoded_buf, coded_buf, strlen (coded_buf));

      EXPECT (decoded_len == len);
      EXPECT (!memcmp (input_buf, decoded_buf, len));

      decoded_len = base64_decode (decoded_buf, coded_buf, 0);

      EXPECT (decoded_len == len);
      EXPECT (!memcmp (input_buf, decoded_buf, len));

      free (coded_buf);
    }
}

static void
t0x0001_base64_decode()
{
  EXPECT (-1 == base64_decode (0, "%", 0));
}

static void
t0x0002_base64_decode()
{
  char buf[4];

  EXPECT (4 == base64_decode (buf, " a G V z d A = = ", 0));
  EXPECT (!memcmp (buf, "hest", 4));
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

static void
t0x0000_xmpp_init()
{
  struct vink_xmpp_state *state;
  struct VINK_buffer buffer;

  ARRAY_INIT(&buffer);

  state = vink_xmpp_state_init(buffer_write, "example.org",
                               VINK_CLIENT, &buffer);
}

void
signhandler(int signal)
{
  fprintf(stderr, "Signal handler called (%d)\n", signal);

  exit(EXIT_FAILURE);
}

int
main(int argc, char** argv)
{
  signal(SIGSEGV, signhandler);

  if (-1 == vink_init (SRCDIR "/unit-tests.conf", VINK_CLIENT, VINK_API_VERSION))
    {
      fprintf (stderr, "vink_init failed: %s\n", vink_last_error());

      return ok ? EXIT_SUCCESS : EXIT_FAILURE;
    }

  t0x0000_base64_decode();
  t0x0001_base64_decode();
  t0x0002_base64_decode();

  t0x0000_xmpp_parse_jid();
  t0x0001_xmpp_parse_jid();
  t0x0002_xmpp_parse_jid();

  t0x0000_xmpp_init();

  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
