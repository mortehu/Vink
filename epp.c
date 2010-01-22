#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <syslog.h>
#include <sys/time.h>

#include "vink.h"

#include "epp-internal.h"
#include "vink-internal.h"

#define TRACE 1

struct vink_epp_state *
vink_epp_state_init (int (*write_func)(const void *, size_t, void *),
                     const char *remote_domain, unsigned int flags,
                     void *arg)
{
  struct vink_epp_state *state;

  state = calloc (sizeof (*state), 1);

  state->write_func = write_func;
  state->write_func_arg = arg;

  state->xml_parser = XML_ParserCreateNS ("utf-8", '|');

  if (!state->xml_parser)
    {
      free (state);

      return 0;
    }

  XML_ParserReset (state->xml_parser, "utf-8");
  XML_SetUserData (state->xml_parser, state);
  XML_SetElementHandler (state->xml_parser, epp_start_element, epp_end_element);
  XML_SetCharacterDataHandler (state->xml_parser, epp_character_data);

  state->xml_tag_level = 0;

  return state;
}

void
vink_epp_set_callbacks (struct vink_epp_state *state,
                        struct vink_epp_callbacks *callbacks)
{
  state->callbacks = *callbacks;
}

int
vink_epp_state_data (struct vink_epp_state *state,
                     const void *data, size_t count)
{
  const unsigned char *cdata;
  size_t amount;

  cdata = data;

  while (count)
    {
      if (state->length_bytes < 4)
        {
          state->next_length <<= 8;
          state->next_length |= *cdata;

          if (++state->length_bytes == 4)
            {
              if (state->next_length < 4)
                {
                  epp_stream_error (state, "transport-error",
                                    "Transport packet size less than 4 bytes");

                  return -1;
                }

              state->next_length -= 4;
            }

          ++cdata;
          --count;

          continue;
        }

      if (count > state->next_length)
        {
          amount = state->next_length;
          state->next_length = 0;
          state->length_bytes = 0;
        }
      else
        amount = count;

#if TRACE
      if (amount)
        fprintf (stderr, "REMOTE (%p): \033[1;36m%.*s\033[0m\n", state, (int) amount, (char*) cdata);
#endif

      if (!XML_Parse (state->xml_parser, (char*) cdata, amount, 0))
        {
          epp_xml_error (state, XML_GetErrorCode (state->xml_parser));

          return -1;
        }

      if (state->reset_parser)
        {
          state->reset_parser = 0;

          XML_ParserReset (state->xml_parser, "utf-8");
          XML_SetUserData (state->xml_parser, state);
          XML_SetElementHandler (state->xml_parser, epp_start_element, epp_end_element);
          XML_SetCharacterDataHandler (state->xml_parser, epp_character_data);
        }

      cdata += amount;
      count -= amount;
      state->next_length -= amount;
    }

  return 0;
}

int
vink_epp_state_finished (struct vink_epp_state *state)
{
  return 0;
}

void
vink_epp_state_free (struct vink_epp_state *state)
{
}

static void
epp_xml_error (struct vink_epp_state *state, enum XML_Error error)
{
  const char* message;

  message = XML_ErrorString (error);

  switch (error)
    {
    case XML_ERROR_INVALID_TOKEN:
    case XML_ERROR_UNDECLARING_PREFIX:
    case XML_ERROR_INCOMPLETE_PE:
    case XML_ERROR_TAG_MISMATCH:

      epp_stream_error (state, "xml-not-well-formed", "XML parser reported: %s", message);

      break;

    default:

      epp_stream_error (state, "invalid-xml", "XML parser reported: %s", message);
    }
}

static void
epp_stream_error (struct vink_epp_state *state, const char *type,
                  const char *format, ...)
{
  va_list args;
  char *buf;
  int result;

  epp_write (state, "<error xml:lang='en'>");

  if (format)
    {
      va_start (args, format);

      result = vasprintf (&buf, format, args);

      if (result == -1)
        {
          syslog (LOG_WARNING, "asprintf failed: %s", strerror (errno));

          state->fatal_error = 1;

          return;
        }

      epp_write (state, buf);

      free (buf);
    }

  epp_write (state, "</error>");

  state->fatal_error = 1;
}

static void
epp_writen (struct vink_epp_state *state, const char *data, size_t size)
{
  unsigned char prefix[4];

  if (state->fatal_error)
    return;

#if TRACE
  fprintf (stderr, "LOCAL (%p): \033[1;35m%.*s\033[0m\n", state, (int) size, data);
#endif

  size += 4;
  prefix[0] = (size >> 24) & 0xff;
  prefix[1] = (size >> 16) & 0xff;
  prefix[2] = (size >> 8) & 0xff;
  prefix[3] = size & 0xff;

  if (-1 == state->write_func (prefix, 4, state->write_func_arg)
      || -1 == state->write_func (data, size - 4, state->write_func_arg))
    {
      syslog (LOG_WARNING, "Buffer append error: %s", strerror (errno));

      state->fatal_error = 1;
    }
}

static void
epp_write (struct vink_epp_state *state, const char *data)
{
  epp_writen (state, data, strlen (data));
}

static void
epp_printf (struct vink_epp_state *state, const char *format, ...)
{
  va_list args;
  char *buf;
  int result;

  va_start (args, format);

  result = vasprintf (&buf, format, args);

  if (result == -1)
    {
      syslog (LOG_WARNING, "asprintf failed: %s", strerror (errno));

      epp_stream_error (state, "internal-server-error", 0);

      return;
    }

  epp_write (state, buf);

  free (buf);
}

static int
epp_queue_stanza (struct vink_epp_state *state, const char *format, ...)
{
  struct epp_queued_stanza *qs;
  int result;
  va_list args;
  char *buf;

  va_start (args, format);

  result = vasprintf (&buf, format, args);

  if (result == -1)
    {
      VINK_set_error ("asprintf failed: %s", strerror (errno));

      return -1;
    }

  if (state->ready)
    {
      epp_write (state, buf);
      free (buf);
    }
  else
    {
      qs = malloc (sizeof (*qs));

      if (!qs)
        {
          syslog (LOG_WARNING, "malloc failed: %s", strerror (errno));

          free (buf);

          return -1;
        }

      qs->target = 0;
      qs->data = buf;
      qs->next = 0;

      if (!state->first_queued_stanza)
        {
          state->first_queued_stanza = qs;
          state->last_queued_stanza = qs;
        }
      else
        {
          state->last_queued_stanza->next = qs;
          state->last_queued_stanza = qs;
        }
    }

  return 0;
}

static void
epp_handle_queued_stanzas (struct vink_epp_state *state)
{
  struct epp_queued_stanza *qs, *prev;

  if (!state->ready)
    return;

  if (!state->first_queued_stanza)
    {
      if (state->callbacks.queue_empty)
        state->callbacks.queue_empty (state);

      return;
    }

  qs = state->first_queued_stanza;

  while (qs)
    {
      epp_write (state, qs->data);

      free (qs->data);
      free (qs->target);
      prev = qs;
      qs = qs->next;

      free (prev);
    }

  state->first_queued_stanza = 0;
  state->last_queued_stanza = 0;

  if (state->callbacks.queue_empty)
    state->callbacks.queue_empty (state);
}

static void XMLCALL
epp_start_element (void *user_data, const XML_Char *name,
                   const XML_Char **atts)
{
  struct vink_epp_state *state;
  struct epp_stanza *stanza;
  struct arena_info *arena;
  const XML_Char **attr;

  state = user_data;
  stanza = &state->stanza;
  arena = &stanza->arena;

  if (!state->xml_tag_level)
    memset (&state->stanza, 0, sizeof (state->stanza));

  /* XXX: Guard against multiple stanzas in same document */

  switch (state->xml_tag_level)
    {
    case 1:

      if (!strcmp (name, "urn:ietf:params:xml:ns:epp-1.0|greeting"))
        stanza->type = epp_greeting;
      else if (!strcmp (name, "urn:ietf:params:xml:ns:epp-1.0|response"))
        stanza->type = epp_response;

      break;

    case 2:

      stanza->subtype = epp_sub_unknown;

      switch (stanza->type)
        {
        case epp_response:

          if (!strcmp (name, "urn:ietf:params:xml:ns:epp-1.0|result"))
            {
              stanza->subtype = epp_sub_result;

              for (attr = atts; *attr; attr += 2)
                {
                  if (!strcmp (attr[0], "code"))
                    stanza->u.response.result_code = atoi (attr[1]);
                }
            }
          else if (!strcmp (name, "urn:ietf:params:xml:ns:epp-1.0|trID"))
            stanza->subtype = epp_sub_trID;
          else if (!strcmp (name, "urn:ietf:params:xml:ns:epp-1.0|resData"))
            stanza->subtype = epp_sub_resData;

          break;

        default:;
        }

      break;

    case 3:

      stanza->subsubtype = epp_subsub_unknown;

      switch (stanza->subtype)
        {
        case epp_sub_trID:

          if (!strcmp (name, "urn:ietf:params:xml:ns:epp-1.0|clTRID"))
            stanza->subsubtype = epp_subsub_clTRID;
          else if (!strcmp (name, "urn:ietf:params:xml:ns:epp-1.0|svTRID"))
            stanza->subsubtype = epp_subsub_svTRID;

          break;

        default:;
        }

      break;
    }

  ++state->xml_tag_level;
}

static void XMLCALL
epp_end_element (void *user_data, const XML_Char *name)
{
  struct vink_epp_state *state;
  struct epp_stanza *stanza;

  state = user_data;
  stanza = &state->stanza;

  --state->xml_tag_level;

  switch (state->xml_tag_level)
    {
    case 0:

      state->reset_parser = 1;

      break;

    case 1:

      switch (stanza->type)
        {
        case epp_greeting:

          epp_login (state, vink_config ("epp.user"), vink_config ("epp.password"));

          break;

        case epp_response:

          if (!strcmp (stanza->client_transaction, state->login_trid))
            {
              fprintf (stderr, "Got login response %u\n", stanza->u.response.result_code);

              switch (stanza->u.response.result_code)
                {
                case 1000:

                  state->ready = 1;

                  epp_handle_queued_stanzas (state);

                  break;
                }
            }
          else
            {
              fprintf (stderr, "Got response %u for unknown request\n", stanza->u.response.result_code);
            }

          break;

        case epp_unknown:

          break;
        }

      arena_free (&stanza->arena);

      stanza->type = epp_unknown;

      break;

    case 2: stanza->subtype = epp_sub_unknown; break;
    case 3: stanza->subsubtype = epp_subsub_unknown; break;
    }
}

static void XMLCALL
epp_character_data (void *user_data, const XML_Char *str, int len)
{
  struct vink_epp_state *state;
  struct epp_stanza *stanza;
  struct arena_info *arena;

  state = user_data;
  stanza = &state->stanza;
  arena = &stanza->arena;

  switch (state->xml_tag_level - 1)
    {
    case 3:

      switch (stanza->subsubtype)
        {
        case epp_subsub_clTRID:

          stanza->client_transaction = arena_strndup (arena, str, len);

          break;

        case epp_subsub_svTRID:

          stanza->server_transaction = arena_strndup (arena, str, len);

          break;

        default:;
        }

      break;
    }
}

static void
epp_gen_trid (char *target)
{
  static unsigned int seq;
  struct timeval now;

  gettimeofday (&now, 0);

  sprintf (target, "%llx-%x",
           (unsigned long long) now.tv_sec * 1000000
           + (unsigned long long) now.tv_usec,
           seq++);
}

static void
epp_login (struct vink_epp_state *state, const char *client_id, const char *password)
{
  struct VINK_buffer query;
  size_t i;

  epp_gen_trid (state->login_trid);

  ARRAY_INIT (&query);

  if (-1 == VINK_buffer_addf (&query,
                              "<?xml version='1.0' encoding='UTF-8' standalone='no'?>"
                              "<epp xmlns='urn:ietf:params:xml:ns:epp-1.0'"
                              " xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'"
                              " xsi:schemaLocation='urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd'>"
                              "<command>"
                              "<login>"
                              "<clID>%s</clID>"
                              "<pw>%s</pw>"
                              "<options>"
                              "<version>1.0</version>"
                              "<lang>en</lang>"
                              "</options>"
                              "<svcs>",
                              client_id, password))
    {
      state->fatal_error = 1;

      return;
    }

  for (i = 0; i < ARRAY_COUNT (&state->object_types); ++i)
    {
      const char *uri = ARRAY_GET (&state->object_types, i);

      if (-1 == VINK_buffer_addf (&query, "<objURI>%s</objURI>", uri))
        {
          state->fatal_error = 1;

          ARRAY_FREE (&query);

          return;
        }
    }

  if (-1 == VINK_buffer_addf (&query,
                              "</svcs>"
                              "</login>"
                              "<clTRID>%s</clTRID>"
                              "</command>"
                              "</epp>",
                              state->login_trid))
    {
      state->fatal_error = 1;

      ARRAY_FREE (&query);

      return;
    }


  epp_writen (state, &ARRAY_GET (&query, 0), ARRAY_COUNT (&query));

  ARRAY_FREE (&query);
}

int
vink_epp_register_object_type (struct vink_client *client, const char *urn)
{
  struct vink_epp_state *state;
  char *urn_copy;

  state = vink_client_state (client);

  urn_copy = strdup (urn);

  ARRAY_ADD (&state->object_types, urn_copy);

  if (ARRAY_RESULT (&state->object_types) == -1)
    {
      ARRAY_RESULT (&state->object_types) = 0;

      return -1;
    }

  return ARRAY_COUNT (&state->object_types) - 1;
}

int
vink_epp_check (struct vink_client *client, int type,
                const char **objects, size_t count)
{
  struct vink_epp_state *state;
  struct VINK_buffer query;
  int result;
  size_t i;
  char trid[32];

  state = vink_client_state (client);

  ARRAY_INIT (&query);

  epp_gen_trid (trid);

  if (-1 == VINK_buffer_addf (&query,
                              "<?xml version='1.0' encoding='UTF-8' standalone='no'?>"
                              "<epp xmlns='urn:ietf:params:xml:ns:epp-1.0'"
                              " xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'"
                              " xsi:schemaLocation='urn:ietf:params:xml:ns:epp-1.0"
                              " epp-1.0.xsd'>"
                              "<command>"
                              "<check>"
                              "<obj:check xmlns:obj='%s'>",
                              ARRAY_GET (&state->object_types, type)))
    {
      return -1;
    }

  for (i = 0; i < count; ++i)
    {
      if (-1 == VINK_buffer_addf (&query, "<obj:name>%s</obj:name>", objects[i]))
        {
          ARRAY_FREE (&query);

          return -1;
        }
    }

  if (-1 == VINK_buffer_addf (&query,
                              "</obj:check>"
                              "</check>"
                              "<clTRID>%s</clTRID>"
                              "</command>"
                              "</epp>", trid))
    {
      ARRAY_FREE (&query);

      return -1;
    }

  ARRAY_ADD (&query, 0);

  result = epp_queue_stanza (vink_client_state (client),
                             &ARRAY_GET (&query, 0));

  ARRAY_FREE (&query);

  return result;
}

int
vink_epp_info (struct vink_client *client)
{
  return 0;
}

int
vink_epp_poll (struct vink_client *client)
{
  return 0;
}

int
vink_epp_query_transfer (struct vink_client *client)
{
  return 0;
}

int
vink_epp_create (struct vink_client *client)
{
  return 0;
}

int
vink_epp_delete (struct vink_client *client)
{
  return 0;
}

int
vink_epp_renew (struct vink_client *client)
{
  return 0;
}

int
vink_epp_transfer (struct vink_client *client,
                  enum vink_epp_transfer_operation op)
{
  return 0;
}

int
vink_epp_update (struct vink_client *client)
{
  return 0;
}
