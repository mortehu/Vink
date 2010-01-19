#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>

#include "array.h"
#include "backend.h"
#include "tree.h"
#include "vink-internal.h"

static const char *spool_path;

static void
email_message (struct vink_message *message)
{
  vink_message_free (message);
}

static int
xmpp_authenticate (struct vink_xmpp_state *state, const char *authzid,
                   const char *user, const char *secret)
{
  return 0;
}

static void
xmpp_message (struct vink_xmpp_state *state, struct vink_message *message)
{
  email_message (message);
}

static void
xmpp_presence (struct vink_xmpp_state *state, const char *jid,
               enum vink_presence presence)
{
  fprintf (stderr, "Got presence for %s\n", jid);
}

static void
xmpp_queue_empty (struct vink_xmpp_state *state)
{
  fprintf (stderr, "Queue is empty\n");
}

void
backend_file_init (struct vink_backend_callbacks *callbacks)
{
  callbacks->xmpp.authenticate = xmpp_authenticate;
  callbacks->xmpp.message = xmpp_message;
  callbacks->xmpp.presence = xmpp_presence;
  callbacks->xmpp.queue_empty = xmpp_queue_empty;
  callbacks->email.message = email_message;

  spool_path = vink_config ("backend.spool-path");
}
