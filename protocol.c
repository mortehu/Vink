#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/time.h>
#include <pthread.h>

#include "common.h"
#include "peer.h"
#include "protocol.h"
#include "tree.h"

void
proto_gen_id(char* target)
{
  struct timeval now;

  gettimeofday(&now, 0);

  sprintf(target, "%llx-%x",
          (unsigned long long) now.tv_sec * 1000000
          + (unsigned long long) now.tv_usec,
          (unsigned int) rand());

}

int
proto_request(const char* remote_domain,
              struct proto_stanza* request,
              struct proto_stanza* reply)
{
  struct peer* p;
  char id[32];
  int result;

  p = peer_get(remote_domain);

  fprintf(stderr, "Got peer: %p\n", p);

  if(!p)
    return -1;

  proto_gen_id(id);

  switch(request->type)
    {
    case proto_iq_ping:

      peer_send(p,
                "<iq from='%s' to='%s' id='%s' type='get'>"
                "<ping xmlns='urn:xmpp:ping'/>"
                "</iq>",
                tree_get_string(config, "domain"), remote_domain, id);

      break;

    default:

      assert(!"unhandled request type");
    }

  result = peer_get_reply(p, id, reply);

  peer_release(p);

  return result;
}

int
proto_parse_jid(struct proto_jid *target, char *input)
{
  char* c;

  target->node = 0;
  target->resource = 0;

  c = strchr(input, '@');

  if(c)
    {
      target->node = input;
      *c++ = 0;
      input = c;
    }

  target->domain = input;

  c = strchr(input, '/');

  if(c)
    {
      *c++ = 0;
      target->resource = c;
    }

  return 0;
}
