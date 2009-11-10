#ifndef RESOLVE_H_
#define RESOLVE_H_ 1

#include "array.h"

struct resolv_result
{
  ARRAY_MEMBERS(struct addrinfo);
};

/**
 * Discovers addrinfos for a TCP service.
 */
int
resolve_srv(const char *node, const char *service, struct resolv_result* res);

#endif /* !RESOLVE_H_ */
