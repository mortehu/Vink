#ifndef EPP_INTERNAL_H_
#define EPP_INTERNAL_H_ 1

#include <expat.h>

typedef unsigned int bit;

struct vink_epp_state
{
  XML_Parser xml_parser;
  unsigned int xml_tag_level;

  int (*write_func)(const void*, size_t, void*);
  void* write_func_arg;

  bit fatal_error : 1;
};

static void
epp_xml_error(struct vink_epp_state *state, enum XML_Error error);

static void
epp_stream_error(struct vink_epp_state *state, const char *type,
                  const char *format, ...);

static void
epp_writen(struct vink_epp_state *state, const char *data, size_t size);

static void
epp_write(struct vink_epp_state *state, const char *data);

static void XMLCALL
epp_start_element(void *user_data, const XML_Char *name,
                  const XML_Char **atts);

static void XMLCALL
epp_end_element(void *user_data, const XML_Char *name);

static void XMLCALL
epp_character_data(void *user_data, const XML_Char *str, int len);

#endif /* !EPP_INTERNAL_H_ */
