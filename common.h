#ifndef COMMON_H_
#define COMMON_H_ 1

#include <gnutls/gnutls.h>

#include "array.h"
#include "tree.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

struct buffer
{
  ARRAY_MEMBERS(char);
};

extern struct tree* config;

extern gnutls_dh_params_t dh_params;
extern gnutls_certificate_credentials_t xcred;
extern gnutls_priority_t priority_cache;

#endif /* !COMMON_H_ */
