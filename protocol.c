#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/time.h>
#include <pthread.h>

#include "common.h"
#include "peer.h"
#include "protocol.h"
#include "tree.h"

int
proto_request(const char* remote_domain,
              struct proto_stanza* request,
              struct proto_stanza* reply)
{
  struct timeval now;
  struct peer* p;
  char id[32];
  int result;

  p = peer_get(remote_domain);

  fprintf(stderr, "Got peer: %p\n", p);

  if(!p)
    return -1;

  gettimeofday(&now, 0);

  sprintf(id, "%llx-%x",
          (unsigned long long) now.tv_sec * 1000000
          + (unsigned long long) now.tv_usec,
          (unsigned int) rand());

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
