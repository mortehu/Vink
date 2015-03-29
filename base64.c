#include <ctype.h>

#include "base64.h"

/*
 * Base 64 decoder copyright (c) 2006 Ryan Martell. (rdm4@martellventures.com)
 *
 * Fetched from ffmpeg/libavformat/base64.c in the FFmpeg package, originally
 * licensed under the GNU Lesser General Public License version 2.1 or later.
 */
static unsigned char map2[] =
{
  0x3e, 0xff, 0xff, 0xff, 0x3f, 0x34, 0x35, 0x36,
  0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01,
  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
  0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1a, 0x1b,
  0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
  0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
  0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33
};

ssize_t
base64_decode (void *out, const char *in, size_t inlen)
{
  size_t i, o = 0;
  int v = 0;
  char * dst = out;

  for (i = 0; (!inlen || i < inlen) && in[i] && in[i] != '='; ++i)
    {
      if (isspace (in[i]))
        continue;

      unsigned int index = in[i] - '+';

      if (index >= sizeof (map2) / sizeof (map2[0]) || map2[index] == 0xff)
        return -1;

      v = (v << 6) + map2[index];

      if (o & 3)
        *dst++ = v >> (6 - 2 * (o & 3));
      ++o;
    }

  return (dst - (char *) out);
}

/*
 * Base 64 encoder fetched from ffmpeg/libavformat/base64.c in the FFmpeg
 * package, who in turn stole it from "VLC's http.c"
 */
char*
base64_encode (const void *src, int len)
{
  static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  char *ret, *dst;
  unsigned i_bits = 0;
  int i_shift = 0;
  int bytes_remaining = len;
  unsigned char *in = (unsigned char *) src;

  ret = dst = malloc (len * 4 / 3 + 12);

  if (!ret)
    return 0;

  if (len)
    {
      while (bytes_remaining)
        {
          i_bits = (i_bits << 8) + *in++;
          bytes_remaining--;
          i_shift += 8;

          do
            {
              *dst++ = b64[(i_bits << 6 >> i_shift) & 0x3f];
              i_shift -= 6;
            }
          while (i_shift > 6 || (bytes_remaining == 0 && i_shift > 0));
        }
      while ((dst - ret) & 3)
        *dst++ = '=';
    }

  *dst = '\0';

  return ret;
}
