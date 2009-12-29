#include "array.h"

struct tuple
{
  const char *key, *value;
  size_t key_size, value_size;
};

struct tuples
{
  ARRAY_MEMBERS(struct tuple);
};

enum content_type
{
    ct_text_plain,
    ct_message_rfc822,
    ct_multipart_mixed,
    ct_multipart_alternative,
    ct_multipart_related,
    ct_multipart_signed,
    ct_multipart_other,
    ct_other
};

enum content_transfer_encoding
{
    cte_quoted_printable,
    cte_base64,
    cte_literal
};
