#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <syslog.h>

#include "vink.h"

#include "epp_internal.h"

#define TRACE 1

struct vink_epp_state *
vink_epp_state_init(int (*write_func)(const void *, size_t, void *),
                    const char *remote_domain, unsigned int flags,
                    void *arg)
{
  struct vink_epp_state *state;

  state = calloc(sizeof(*state), 1);

  state->xml_parser = XML_ParserCreateNS("utf-8", '|');

  if(!state->xml_parser)
    {
      free(state);

      return 0;
    }

  XML_ParserReset(state->xml_parser, "utf-8");
  XML_SetUserData(state->xml_parser, state);
  XML_SetElementHandler(state->xml_parser, epp_start_element, epp_end_element);
  XML_SetCharacterDataHandler(state->xml_parser, epp_character_data);

  state->xml_tag_level = 0;

  return state;
}

int
vink_epp_state_data(struct vink_epp_state *state,
                    const void *data, size_t count)
{
#if TRACE
  fprintf(stderr, "REMOTE(%p): \033[1;36m%.*s\033[0m\n", state, (int) count, (char*) data);
#endif

  if(!XML_Parse(state->xml_parser, data, count, 0))
    {
      epp_xml_error(state, XML_GetErrorCode(state->xml_parser));

      return -1;
    }

  return 0;
}

int
vink_epp_state_finished(struct vink_epp_state *state)
{
  return 0;
}

void
vink_epp_state_free(struct vink_epp_state *state)
{
}

static void
epp_xml_error(struct vink_epp_state *state, enum XML_Error error)
{
  const char* message;

  message = XML_ErrorString(error);

  switch(error)
    {
    case XML_ERROR_INVALID_TOKEN:
    case XML_ERROR_UNDECLARING_PREFIX:
    case XML_ERROR_INCOMPLETE_PE:
    case XML_ERROR_TAG_MISMATCH:

      epp_stream_error(state, "xml-not-well-formed", "XML parser reported: %s", message);

      break;

    default:

      epp_stream_error(state, "invalid-xml", "XML parser reported: %s", message);
    }
}

static void
epp_stream_error(struct vink_epp_state *state, const char *type,
                  const char *format, ...)
{
  va_list args;
  char *buf;
  int result;

  epp_write(state, "<error xml:lang='en'>");

  if(format)
    {
      va_start(args, format);

      result = vasprintf(&buf, format, args);

      if(result == -1)
        {
          syslog(LOG_WARNING, "asprintf failed: %s", strerror(errno));

          state->fatal_error = 1;

          return;
        }

      epp_write(state, buf);

      free(buf);
    }

  epp_write(state, "</error>");

  state->fatal_error = 1;
}

static void
epp_writen(struct vink_epp_state *state, const char *data, size_t size)
{
  if(state->fatal_error)
    return;

#if TRACE
  fprintf(stderr, "LOCAL(%p): \033[1;35m%.*s\033[0m\n", state, (int) size, data);
#endif

  if(-1 == state->write_func(data, size, state->write_func_arg))
    {
      syslog(LOG_WARNING, "buffer append error: %s", strerror(errno));

      state->fatal_error = 1;
    }
}

static void
epp_write(struct vink_epp_state *state, const char *data)
{
  epp_writen(state, data, strlen(data));
}


static void XMLCALL
epp_start_element(void *user_data, const XML_Char *name,
                  const XML_Char **atts)
{
}

static void XMLCALL
epp_end_element(void *user_data, const XML_Char *name)
{
}

static void XMLCALL
epp_character_data(void *user_data, const XML_Char *str, int len)
{
}
