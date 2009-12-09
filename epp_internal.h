#ifndef EPP_INTERNAL_H_
#define EPP_INTERNAL_H_ 1

#include "arena.h"

#include <expat.h>

typedef unsigned int bit;

enum epp_stanza_type
{
  epp_unknown = 0,
  epp_greeting,
  epp_response
};

enum epp_stanza_sub_type
{
  epp_sub_unknown = 0,
  epp_sub_result,
  epp_sub_trID,
};

enum epp_stanza_subsub_type
{
  epp_subsub_unknown = 0,
  epp_subsub_clTRID,
  epp_subsub_svTRID,
};

struct epp_stanza
{
  enum epp_stanza_type type;
  enum epp_stanza_sub_type subtype;
  enum epp_stanza_subsub_type subsubtype;

  char *client_transaction;
  char *server_transaction;
  union
    {
      struct
        {
          unsigned int result_code;
        } response;
    } u;

  struct arena_info arena;
};

struct vink_epp_state
{
  XML_Parser xml_parser;
  unsigned int xml_tag_level;

  unsigned int length_bytes;
  unsigned int next_length;

  int (*write_func)(const void*, size_t, void*);
  void* write_func_arg;

  bit reset_parser : 1;
  bit sent_login : 1;
  bit fatal_error : 1;

  struct epp_stanza stanza;
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

static void
epp_login(struct vink_epp_state *state, const char *client_id, const char *password);

#endif /* !EPP_INTERNAL_H_ */
