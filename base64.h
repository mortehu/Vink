#ifndef BASE64_H_
#define BASE64_H_ 1

#include <stdlib.h>

ssize_t
base64_decode(void *out, const char *in, size_t inlen);

char*
base64_encode(const void *src, int len);

#endif /* !BASE64_H_ */
