#ifndef TLS_COMMON_
#define TLS_COMMON_ 1

#include <gnutls/gnutls.h>

extern gnutls_dh_params_t dh_params;
extern gnutls_certificate_credentials_t xcred;
#if LIBGNUTLS_VERSION_NUMBER >= 0x020600
extern gnutls_priority_t priority_cache;
#else
static const int protocol_priority[] =
{
  GNUTLS_TLS1,
  GNUTLS_SSL3,
  0
};

static const int cipher_priority[] =
{
  GNUTLS_CIPHER_RIJNDAEL_128_CBC,
  GNUTLS_CIPHER_3DES_CBC,
  GNUTLS_CIPHER_RIJNDAEL_256_CBC,
  GNUTLS_CIPHER_ARCFOUR,
  0
};

static const int comp_priority[] =
{
  GNUTLS_COMP_ZLIB,
  GNUTLS_COMP_NULL,
  0
};

static const int kx_priority[] =
{
  GNUTLS_KX_DHE_RSA,
  GNUTLS_KX_RSA,
  GNUTLS_KX_DHE_DSS,
  0
};

static const int mac_priority[] =
{
  GNUTLS_MAC_SHA,
  GNUTLS_MAC_MD5,
  0
};
#endif

#endif /* !TLS_COMMON_ */
