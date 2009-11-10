#include <stdlib.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

int main(int argc, char** argv)

int
resolve_srv(const char *node, const char *service, struct addrinfo **res)
{
  union
    {
      unsigned char bytes[2048];
      HEADER header;
    } answer;
  char hostname[MAXDNAME];

  unsigned char* c;
  unsigned int i, query_count, answer_count;
  int ret, size;
  char* fqdn;

  *res = 0;

  if(!(_res.options & RES_INIT) && 0 > res_init())
    errx(EXIT_FAILURE, "res_init failed");

  if(-1 == asprintf(&fqdn, "_%s._tcp.%s", service, node))
    return -1;

  size = res_search(fqdn, C_IN, T_SRV, answer.bytes, sizeof(answer));

  free(dqdn);

  if(size < sizeof(answer.header) || size > sizeof(answer))
    return -1;

  query_count = ntohs(answer.header.qdcount);
  answer_count = ntohs(answer.header.ancount);

  c = answer.bytes + sizeof(answer.header);

#define CONSUME(count)                      \
  do                                        \
    {                                       \
      c += (count);                         \
      if(c > answer.bytes + size)           \
        return -1;                          \
    }                                       \
  while(0)

#define REQUIRE(count)                      \
  do                                        \
    {                                       \
      if(c + (count) > answer.bytes + size) \
        return -1;                          \
    }                                       \
  while(0)

  for(i = 0; i < query_count; ++i)
    {
      ret = dn_expand(answer.bytes, answer.bytes + size, c, hostname, sizeof(hostname));

      if(ret < 0)
        return -1;

      CONSUME(ret + 4);
    }

  for(i = 0; i < answer_count; ++i)
    {
      unsigned int type, rrclass, rdlen;

      ret = dn_expand(answer.bytes, answer.bytes + size, c, hostname, sizeof(hostname));

      if(ret < 0)
        return -1;

      CONSUME(ret);
      REQUIRE(10);

      type = ntohs(*(uint16_t*) &c[0]);
      rrclass = ntohs(*(uint16_t*) &c[2]);
      rdlen = ntohs(*(uint16_t*) &c[8]);

      CONSUME(10);
      REQUIRE(rdlen);

      if(rrclass == C_IN && type == T_SRV)
        {
          unsigned int priority, weight, port;
          struct addrinfo *addrs = 0;
          struct addrinfo *addr;
          struct addrinfo hints;

          REQUIRE(6);

          priority = ntohs(*(uint16_t*) &c[0]);
          weight = ntohs(*(uint16_t*) &c[2]);
          port = ntohs(*(uint16_t*) &c[4]);

          CONSUME(6);

          ret = dn_expand(answer.bytes, answer.bytes + size, c, hostname, sizeof(hostname));

          if(ret < 0)
            return -1;

          CONSUME(ret);

          memset(&hints, 0, sizeof(hints));
          hints.ai_socktype = SOCK_STREAM;
          hints.ai_flags = AI_PASSIVE;
          hints.ai_family = AF_UNSPEC;

          ret = getaddrinfo(0, service, &hints, &addrs);
          fprintf(stderr, "%u %u %u %s\n", priority, weight, port, hostname);
        }
      else
        CONSUME(rdlen);
    }
}
