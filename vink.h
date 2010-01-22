#ifndef VINK_H_
#define VINK_H_ 1

#include <stdlib.h>
#include <time.h>

#define VINK_API_VERSION 0x000000

#define VINK_CLIENT 0x00001

#ifdef __GNUC__
#define USE_RESULT __attribute__ ((warn_unused_result))
#else
#define USE_RESULT
#endif

enum vink_protocol
{
  VINK_XMPP  = 0x0001,
  VINK_EPP   = 0x0002,
  VINK_EMAIL = 0x0004 /* SMTP, POP-3, IMAP, ... */
};

enum vink_part_type
{
  VINK_PART_MESSAGE = 0,
  VINK_PART_ALTERNATIVE = 0,
  VINK_PART_ATTACHMENT = 1,
  VINK_PART_MIXED = 2,
  VINK_PART_DIGEST = 3,
  VINK_PART_RELATED = 4,
  VINK_PART_REPORT = 5,
  VINK_PART_SIGNED = 6,
  VINK_PART_ENCRYPTED = 7,
  VINK_PART_FORM_DATA = 8
};

enum vink_presence
{
  VINK_PRESENT = 0,
  VINK_AWAY,
  VINK_CHAT,
  VINK_DND,
  VINK_XA,
  VINK_UNAVAILABLE
};

struct vink_header
{
  const char *key;
  const char *value;
};

struct vink_message
{
  const char *id;

  enum vink_protocol protocol;
  enum vink_part_type part_type;

  time_t sent, received;

  const char *content_type;

  const char *from;
  const char *to;
  const char *subject;
  const char *body;
  size_t body_size;

  const struct vink_header *headers;
  size_t header_count;

  const struct vink_message *parts;
  size_t part_count;

  void *_private;
};

#include "vink-epp.h"
#include "vink-email.h"
#include "vink-xmpp.h"

struct vink_backend_callbacks
{
  struct vink_epp_callbacks epp;
  struct vink_xmpp_callbacks xmpp;
  struct vink_email_callbacks email;

  void (*backend_free)(void *data);
};

/**
 * Initializes the vink library.
 *
 * Pass the value of VINK_API_VERSION in the `version' parameter.
 */
int
vink_init (const char *config_path, unsigned int flags, unsigned int version) USE_RESULT;

void
vink_finish ();

const char *
vink_last_error ();

const char *
vink_config (const char *key);

void
vink_message_free (struct vink_message *message);

/* Client functions */

struct vink_client;

struct vink_client *
vink_client_alloc ();

void *
vink_client_state (struct vink_client *cl);

int
vink_client_connect (struct vink_client *cl, const char *domain,
                     enum vink_protocol protocol) USE_RESULT;

int
vink_client_run (struct vink_client *cl) USE_RESULT;

/* Utility functions */

char *
vink_xml_escape (const char* data, size_t size);

#endif /* !VINK_H_ */
