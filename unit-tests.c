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
#include "vink-wave.h"

static int ok = 1;

#define EXPECT(a) \
  do \
    { \
      if (!(a)) \
        { \
          fprintf (stderr, "%s:%d: %s failed\n", __PRETTY_FUNCTION__, __LINE__, #a); \
          ok = 0; \
        } \
    } \
  while (0)

#if 0
static int malloc_fork_active = 0;

/* Prototypes for our hooks.  */
static void my_init_hook (void);

/* Variables to save original hooks. */
static void *(*old_malloc_hook)(size_t, const void *);

/* Override initializing hook from the C library. */
void (*__malloc_initialize_hook) (void) = my_init_hook;

static void *
my_malloc_hook (size_t size, const void *caller)
{
  void *result;
  pid_t child;

  /* Restore all old hooks */
  __malloc_hook = old_malloc_hook;

  if (malloc_fork_active)
    {
      child = fork ();

      if (!child)
        {
          errno = ENOMEM;

          old_malloc_hook = __malloc_hook;
          __malloc_hook = my_malloc_hook;

          return 0;
        }

      wait (0);
    }

  /* Call recursively */
  result = malloc (size);

  /* Save underlying hooks */
  old_malloc_hook = __malloc_hook;

  /* Restore our own hooks */
  __malloc_hook = my_malloc_hook;

  return result;
}

static void
my_init_hook (void)
{
  old_malloc_hook = __malloc_hook;

  __malloc_hook = my_malloc_hook;
}
#endif

static int
buffer_write (const void* data, size_t size, void* arg)
{
  struct VINK_buffer *buf = arg;

  ARRAY_ADD_SEVERAL (buf, data, size);

  return ARRAY_RESULT (buf);
}

int
myrand ()
{
  static unsigned long next = 1;

  next = next * 1103515245 + 12345;

  return ((unsigned) (next / 65536) % 32768);
}

static void
t0x0000_base64_decode ()
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
t0x0001_base64_decode ()
{
  EXPECT (-1 == base64_decode (0, "%", 0));
}

static void
t0x0002_base64_decode ()
{
  char buf[4];

  EXPECT (4 == base64_decode (buf, " a G V z d A = = ", 0));
  EXPECT (!memcmp (buf, "hest", 4));
}

static void
t0x0000_xmpp_parse_jid ()
{
  char* input;

  struct vink_xmpp_jid result;
  int ret;

  input = strdupa ("example.org");

  ret = vink_xmpp_parse_jid (&result, input);

  EXPECT (ret == 0);
  EXPECT (result.node == 0);
  EXPECT (!strcmp (result.domain, "example.org"));
  EXPECT (result.resource == 0);
}

static void
t0x0001_xmpp_parse_jid ()
{
  char* input;

  struct vink_xmpp_jid result;
  int ret;

  input = strdupa ("test@example.org");

  ret = vink_xmpp_parse_jid (&result, input);

  EXPECT (ret == 0);
  EXPECT (!strcmp (result.node, "test"));
  EXPECT (!strcmp (result.domain, "example.org"));
  EXPECT (result.resource == 0);
}

static void
t0x0002_xmpp_parse_jid ()
{
  char* input;

  struct vink_xmpp_jid result;
  int ret;

  input = strdupa ("test@example.org/resource");

  ret = vink_xmpp_parse_jid (&result, input);

  EXPECT (ret == 0);
  EXPECT (!strcmp (result.node, "test"));
  EXPECT (!strcmp (result.domain, "example.org"));
  EXPECT (!strcmp (result.resource, "resource"));
}

static void
t0x0000_xmpp_init ()
{
  struct vink_xmpp_state *state;
  struct VINK_buffer buffer;

  ARRAY_INIT (&buffer);

  state = vink_xmpp_state_init (buffer_write, "example.org",
                               VINK_CLIENT, &buffer);

  vink_xmpp_state_free (state);

  ARRAY_FREE (&buffer);
}

static void
t0x0000_wave_apply_delta ()
{
  const char *wavelet_name = "wave://wavesandbox.com/w+Z57_pKu-D/conv+root";
  static const char *inputs[] =
    {
      "CsEHCpQGCjAIABIsd2F2ZTovL3dhdmVzYW5kYm94LmNvbS93K1o1N19wS3UtRC9jb252K3Jvb3QSF21vcnRlaHVAd2F2ZXNhbmRib3guY29tGhkKF21vcnRlaHVAd2F2ZXNhbmRib3guY29tGigaJgoMY29udmVyc2F0aW9uEhYKEBoOCgxjb252ZXJzYXRpb24KAiABGlEaTwoLYitaNTdfcEt1LUUSQAoIGgYKBGJvZHkKEgoQGg4KCmNvbnYvdGl0bGUaAAoIGgYKBGxpbmUKAiABCgIgAQoOCgwSCmNvbnYvdGl0bGUaOxo5Cgxjb252ZXJzYXRpb24SKQoCKAEKGxoZCgRibGlwEhEKAmlkEgtiK1o1N19wS3UtRQoCIAEKAigBGmkaZwoLYitaNTdfcEt1LUUSWAoQCg4aDAoKY29udi90aXRsZQoCKAEKFAoSGhAKCmNvbnYvdGl0bGUSABoACgIoAgoSChAaDgoKY29udi90aXRsZRIACgIoAQoOCgwSCmNvbnYvdGl0bGUaGwoZYWxpY2VAdG91cmluZ21hY2hpbmVzLm9yZxq2ARqzAQoecGluZy9hbGljZUB0b3VyaW5nbWFjaGluZXMub3JnEpABChkaFwoEcGluZxIPCgJpZBIJWjU3X3BLdS1GCgYaBAoCdG8KGxIZYWxpY2VAdG91cmluZ21hY2hpbmVzLm9yZwoCIAEKCBoGCgRmcm9tChkSF21vcnRlaHVAd2F2ZXNhbmRib3guY29tCgIgAQoIGgYKBHRpbWUKDxINMTI2MjQ0ODc2MjI4OQoCIAEKAiABGrABGq0BCgtiK1o1N19wS3UtRRKdAQo9CjsaOQoPdXNlci9kL1o1N19wS3UtGiZtb3J0ZWh1QHdhdmVzYW5kYm94LmNvbSwxMjYyNDQ4NzYyMzMzLAoCKAMKLgosGioKD3VzZXIvZS9aNTdfcEt1LRoXbW9ydGVodUB3YXZlc2FuZGJveC5jb20KAigBCiQKIhIPdXNlci9kL1o1N19wS3UtEg91c2VyL2UvWjU3X3BLdS0SpwEKgAFpobenW9awqPUAB+fQO/qnwJGrQ1XBrVjjKff32ayaizGnXT7p43li0FGu0NqoefIN/ibVnifUW8TCg2xXo/PeZ9gBeouUwO22rAu+tnPbPDPMDbRcf7El7is9SUD/sPzEQNHI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"
    };

  static const size_t sizes[] =
    {
      973, 267, 291, 423, 295, 386, 332, 347
    };

  struct vink_wave_wavelet *wavelet = 0;
  char *buf;
  ssize_t i, buf_size;

  wavelet = vink_wave_wavelet_create ();

  for (i = 0; i < sizeof (inputs) / sizeof (inputs[0]); ++i)
    {
      int result;

      buf = malloc (strlen (inputs[i]) + 1);

      buf_size = base64_decode (buf, inputs[i], 0);

      EXPECT (buf_size == sizes[i]);

      result = vink_wave_apply_delta (wavelet, buf, buf_size, wavelet_name);

      EXPECT (0 == result);

      if (0 != result)
        {
          fprintf (stderr, "vink_wave_apply_delta failed: %s\n", vink_last_error ());

          break;
        }

      free (buf);
    }

  vink_wave_wavelet_free (wavelet);
}

void
signhandler (int signal)
{
  fprintf (stderr, "Signal handler called (%d)\n", signal);

  exit (EXIT_FAILURE);
}

int
main (int argc, char** argv)
{
  signal (SIGSEGV, signhandler);

  if (-1 == vink_init ("unit-tests.conf", VINK_CLIENT, VINK_API_VERSION))
    {
      fprintf (stderr, "vink_init failed: %s\n", vink_last_error ());

      return ok ? EXIT_SUCCESS : EXIT_FAILURE;
    }

  t0x0000_base64_decode ();
  t0x0001_base64_decode ();
  t0x0002_base64_decode ();

  t0x0000_xmpp_parse_jid ();
  t0x0001_xmpp_parse_jid ();
  t0x0002_xmpp_parse_jid ();

  t0x0000_wave_apply_delta ();

  t0x0000_xmpp_init ();

  vink_finish ();

  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
