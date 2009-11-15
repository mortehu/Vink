#include <gcrypt.h>

static void
hash_tohex(char *out, const unsigned char *in, size_t count)
{
  static const char* hex = "0123456789abcdef";

  while(count--)
    {
      *out++ = hex[*in & 0x0F];
      *out++ = hex[*in >> 4];
      ++in;
    }

  *out = 0;
}

void
hash_sha256(const void *data, size_t datalen,
            char *dest)
{
  gcry_md_hd_t h;
  unsigned char tmp[20];

  gcry_md_open(&h, GCRY_MD_SHA1, 0);

  gcry_md_write(h, data, datalen);
  memcpy(tmp, gcry_md_read(h, GCRY_MD_SHA1), 20);
  hash_tohex(dest, tmp, 20);

  gcry_md_close(h);
}

void
hash_hmac_sha256(const void *key, size_t keylen,
                 const void *data, size_t datalen, char *dest)
{
  gcry_md_hd_t h;
  unsigned char tmp[32];

  gcry_md_open(&h, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);

  gcry_md_ctl(h, GCRYCTL_SET_KEY, (char*) key, keylen);
  gcry_md_write(h, data, datalen);
  memcpy(tmp, gcry_md_read(h, GCRY_MD_SHA256), 32);
  hash_tohex(dest, tmp, 32);

  gcry_md_close(h);
}
