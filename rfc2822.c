#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include <iconv.h>

#include "arena.h"
#include "array.h"
#include "base64.h"
#include "vink.h"

#include "mail-internal.h"

static const char*
skip_ws (const char* s)
{
  while (isspace (*s))
    ++s;

  return s;
}

static unsigned int
get_unsigned (const char **_s, int max_length)
{
  int i, ret = 0;
  const char *s = *_s;

  s = skip_ws (s);

  for (i = 0; i < max_length; ++i)
    {
      if (!isdigit (*s))
        break;

      ret *= 10;
      ret += *s++ - '0';
    }

  *_s = skip_ws (s);

  return ret;
}

int
rfc2822_parse_date (time_t* ret, const char* date, const char* end)
{
  int i;
  struct tm tm;
  memset (&tm, 0, sizeof (tm));

  const char* s = memchr (date, ',', end - date);
  if (s)
    date = s + 1;

  tm.tm_mday = get_unsigned (&date, 2);

  /* Month.  Assumes correct speling and locale */
  char mon[3];
  for (i = 0; i < 3; ++i)
    mon[i] = tolower (*date++);

  /* jan feb mar apr may jun jul aug sep oct nov dec
   *   0   1   2   3   4   5   6   7   8   9  10  11
   */

  if (mon[0] == 'j')
    {
      if (mon[1] == 'a')
        tm.tm_mon = 0; /* jan */
      else if (mon[2] == 'n')
        tm.tm_mon = 5; /* jun */
      else
        tm.tm_mon = 6; /* jul */
    }
  else if (mon[0] == 'f')
    tm.tm_mon = 1; /* feb */
  else if (mon[0] == 'm')
    {
      if (mon[2] == 'r')
        tm.tm_mon = 2; /* mar */
      else
        tm.tm_mon = 4; /* may */
    }
  else if (mon[1] == 'p')
    tm.tm_mon = 3; /* apr */
  else if (mon[0] == 'a')
    tm.tm_mon = 7; /* aug */
  else if (mon[0] == 's')
    tm.tm_mon = 8; /* sep */
  else if (mon[0] == 'o')
    tm.tm_mon = 9; /* oct */
  else if (mon[0] == 'n')
    tm.tm_mon = 10; /* nov */
  else
    tm.tm_mon = 11; /* dec */

  tm.tm_year = get_unsigned (&date, 4);

  if (tm.tm_year > 1900)
    tm.tm_year -= 1900;

  /* Fix invalid dates */
  if (tm.tm_year < 70)
    tm.tm_year += 100;

  tm.tm_hour = get_unsigned (&date, 2);

  if (*date++ != ':')
    return -1;

  tm.tm_min = get_unsigned (&date, 2);


  /* Sometimes seconds are missing, they shouldn't
   * but it's easy to handle this */
  if (*date++ == ':')
    tm.tm_sec = get_unsigned (&date, 2);

  /* Check if there's a timezone offset, and parse it */
  int tz_offset = strcspn (date, "-+");

  if (date[tz_offset])
    {
      int offset = atoi (date + tz_offset);
      tm.tm_sec -= ((offset / 100) * 60 + abs (offset) % 100) * 60;
    }

  *ret = timegm (&tm);

  /* XXX: Is this a bad idea?   It makes time travelling spam with far less
   * annoying */
  static time_t recently;
  if (*ret > recently)
    {
      recently = time (NULL);

      if (*ret > recently)
        *ret = recently;
    }

  return 0;
}

void
rfc2822_unfold (char* header)
{
  size_t in = 0;
  size_t out = 0;

  while (header[in])
    {
      if (header[in] == '\n')
        ++in;
      else
        header[out++] = header[in++];
    }

  header[out] = '\0';
}

void
VINK_rfc2822_parse (const char* buf, const char* buf_end,
                    struct tuples *headers, const char** body)
{
  const char* begin = buf;
  const char* end;
  const char* sep;
  size_t i;

  /* Store headers (still folded) in tuples */
  while (begin != buf_end)
    {
      end = memchr (begin, '\n', buf_end - begin);

      if (!end)
        end = buf_end;

      if (begin == end)
        {
          ++begin;
          break;
        }

      if ((*begin != ' ' && *begin != '\t') || begin == buf)
        {
          struct tuple header;

          header.key = begin;
          header.value = 0;

          ARRAY_ADD (headers, header);
        }

      if (end == buf_end)
        break;

      begin = end + 1;
    }

  *body = begin;

  for (i = 0; i < ARRAY_COUNT (headers); ++i)
    {
      struct tuple *h;

      h = &ARRAY_GET (headers, i);

      sep = memchr (h->key, ':', buf_end - h->key);

      /* If there is not ':', this is not a header. */
      if (!sep || sep == h->key)
        {
          ARRAY_COUNT (headers) = i;

          break;
        }

      h->key_size = sep - h->key;
      h->value = ++sep;

      for (;;)
        {
          while (sep != buf_end && *sep != '\n')
            ++sep;

          if (sep == buf_end || (sep[1] != ' ' && sep[1] != '\t'))
            break;

          ++sep;
        }

      h->value_size = sep - h->value;

      while (*h->value == ' ' || *h->value == '\t')
        {
          ++h->value;
          --h->value_size;
        }
    }
}

static void
rtrim (char* string)
{
  char* c = string + strlen (string);

  while (c > string && isspace (*(c - 1)))
    --c;

  *c = 0;
}

static int
convert_to_utf8 (const char* input, size_t input_size, char** ret_output, size_t* output_size, const char* charset)
{
  size_t output_alloc = input_size * 3 / 2; /* UTF-8 is larger than almost any other encoding */
  size_t output_remaining = output_alloc;
  char* output;
  char* o;

  iconv_t cd = iconv_open ("utf-8", charset);

  if (cd == (iconv_t) -1)
    return -1;

  output = malloc (output_alloc);
  o = output;

  while (input_size)
    {
      if ((size_t) -1 == iconv (cd, (char**) &input, &input_size, &o, &output_remaining))
        {
          if (E2BIG == errno || output_remaining == 0)
            {
              size_t old_alloc, old_offset;

              old_alloc = output_alloc;
              old_offset = o - output;
              output_alloc += input_size * 2;
              output_remaining += output_alloc - old_alloc;
              output = realloc (output, output_alloc);
              o = output + old_offset;
            }
          else
            {
              *o++ = '_';
              ++input;
              --input_size;
              --output_remaining;
            }
        }
    }

  *output_size = o - output;
  *ret_output = output;

  assert (*output_size <= output_alloc);

  iconv_close (cd);

  return 0;
}

void
mime_parse_content_type (const char* cts, char* type, size_t type_size,
                         char* subtype, size_t subtype_size,
                         char* charset, size_t charset_size,
                         char* filename, size_t filename_size,
                         char* part_delimiter, size_t part_delimiter_size)
{
  const char* type_delim = strchr (cts, '/');
  size_t type_len;

  if (!type_delim)
    type_delim = cts;

  type_len = type_delim - cts;

  if (type_len >= type_size)
    type_len = type_size - 1;

  strncpy (type, cts, type_len);
  type[type_len] = 0;

  size_t subtype_len = strspn (type_delim + 1, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-");

  if (subtype_len >= subtype_size)
    subtype_len = subtype_size - 1;

  strncpy (subtype, type_delim + 1, subtype_len);
  subtype[subtype_len] = 0;

  char* arg = strchr (type_delim, ';');

  while (arg && *arg)
    {
      char* arg_end;

      ++arg;

      while (isspace (*arg))
        ++arg;

      if (!*arg)
        break;

      arg_end = strchr (arg + 1, ';');

      if (!arg_end)
        arg_end = strchr (arg + 1, 0);

      char* arg_delim = strchr (arg, '=');

      if (!arg_delim)
        break;

      char* key = strndupa (arg, arg_delim - arg);
      char* value = strndupa (arg_delim + 1, arg_end - arg_delim - 1);

      rtrim (value);

      if (value[0] == '"' && value[strlen (value) - 1] == '"')
        {
          value[strlen (value) - 1] = 0;
          ++value;
        }

      if (part_delimiter && !strcasecmp (key, "boundary"))
        {
          strncpy (part_delimiter, value, part_delimiter_size);
          part_delimiter[part_delimiter_size - 1] = 0;
        }
      else if (filename && !strcasecmp (key, "name"))
        {
          if (strchr (value, '/'))
            strncpy (filename, strrchr (value, '/') + 1, filename_size);
          else
            strncpy (filename, value, filename_size);

          filename[filename_size - 1] = 0;
        }
      else if (!strcasecmp (key, "charset"))
        {
          strncpy (charset, value, charset_size);
          charset[charset_size - 1] = 0;
        }

      arg = arg_end;
    }
}

void
mime_parse_content_disposition (const char* arg, char* filename,
                                size_t filename_size)
{
  while (arg && *arg)
    {
      char* arg_end;

      ++arg;

      while (isspace (*arg))
        ++arg;

      if (!*arg)
        break;

      arg_end = strchr (arg + 1, ';');

      if (!arg_end)
        arg_end = strchr (arg + 1, 0);

      char* arg_delim = strchr (arg, '=');

      if (!arg_delim)
        break;

      char* key = strndupa (arg, arg_delim - arg);
      char* value = strndupa (arg_delim + 1, arg_end - arg_delim - 1);

      rtrim (value);

      if (value[0] == '"' && value[strlen (value) - 1] == '"')
        {
          value[strlen (value) - 1] = 0;
          ++value;
        }

      if (filename && !strcasecmp (key, "filename"))
        {
          if (strchr (value, '/'))
            strncpy (filename, strrchr (value, '/') + 1, filename_size);
          else
            strncpy (filename, value, filename_size);

          filename[filename_size - 1] = 0;
        }

      arg = arg_end;
    }
}

void
mime_parse (struct vink_message* result, struct arena_info *arena,
            const char* input, size_t input_size)
{
  char part_delimiter[256] = { 0 };
  char filename[64] = { 0 };
  char type[32] = "text";
  char subtype[32] = "plain";
  char charset[16] = { 0 };

  struct tuples headers;
  const char* end;
  const char* body;
  size_t i;
  const struct tuple *content_type_header = 0;
  const struct tuple *transfer_encoding_header = 0;
  const struct tuple *content_disposition_header = 0;

  end = input + input_size;

  result->protocol = VINK_EMAIL;
  result->part_type = VINK_PART_MESSAGE;
#if 0
  message->sent = time (0);
  message->received = time (0);
  message->content_type = "text/plain";
  message->id = arena_strdup (&arena, stanza->id);
  message->from = arena_strdup (&arena, stanza->from);
  message->to = arena_strdup (&arena, stanza->to);
  message->body = arena_strdup (&arena, pm->body);
  message->body_size = strlen (message->body);
#endif

  ARRAY_INIT (&headers);

  VINK_rfc2822_parse (input, end, &headers, &body);

  for (i = 0; i < ARRAY_COUNT (&headers); ++i)
    {
      const struct tuple *h;

      h = &ARRAY_GET (&headers, i);

      if (!strncasecmp (h->key, "content-type", h->key_size))
        content_type_header = h;
      else if (!strncasecmp (h->key, "content-transfer-encoding", h->key_size))
        transfer_encoding_header = h;
      else if (!strncasecmp (h->key, "content-disposition", h->key_size))
        content_disposition_header = h;
    }

  enum content_type ct = ct_other;
  enum content_transfer_encoding cte = cte_literal;

  if (content_type_header)
    {
      char* cts = strndupa (content_type_header->value, content_type_header->value_size);

      mime_parse_content_type (cts, type, sizeof (type), subtype, sizeof (subtype), charset, sizeof (charset), filename, sizeof (filename), part_delimiter, sizeof (part_delimiter));

      if (!strcasecmp (type, "text"))
        {
          if (!strcasecmp (subtype, "plain"))
            ct = ct_text_plain;
        }
      else if (!strcasecmp (type, "message"))
        {
          if (!strcasecmp (subtype, "rfc822"))
            ct = ct_message_rfc822;
        }
      else if (!strcasecmp (type, "multipart"))
        {
          if (!strcasecmp (subtype, "mixed"))
            ct = ct_multipart_mixed;
          else if (!strcasecmp (subtype, "alternative"))
            ct = ct_multipart_alternative;
          else if (!strcasecmp (subtype, "related"))
            ct = ct_multipart_related;
          else if (!strcasecmp (subtype, "signed"))
            ct = ct_multipart_signed;
          else
            ct = ct_multipart_other;
        }
    }
  else
    ct = ct_text_plain;

  if (!charset[0])
    strcpy (charset, "US-ASCII");

  if (transfer_encoding_header)
    {
      char* ctes = strndupa (transfer_encoding_header->value, transfer_encoding_header->value_size);
      rfc2822_unfold (ctes);

      if (!strcasecmp (ctes, "quoted-printable"))
        cte = cte_quoted_printable;
      else if (!strcasecmp (ctes, "base64"))
        cte = cte_base64;
    }

  if (content_disposition_header)
    {
      char* cd = strndupa (content_disposition_header->value, content_disposition_header->value_size);

      mime_parse_content_disposition (cd, filename, sizeof (filename));
    }

  if (   ct == ct_multipart_mixed
      || ct == ct_multipart_alternative
      || ct == ct_multipart_related
      || ct == ct_multipart_signed
      || ct == ct_multipart_other)
    {
      struct vink_message *parts = 0;
      const char *i, *part_begin = 0, *part_end = 0;
      size_t part_delimiter_len;
      size_t pass, part_idx;

      if (!part_delimiter[0])
        return;

      part_delimiter_len = strlen (part_delimiter);

      for (pass = 0; pass < 2; ++pass)
        {
          part_idx = 0;

          for (i = body; i < end - part_delimiter_len - 2; ++i)
            {
              if ((i == body || *(i - 1) == '\n')
                  && *i == '-' && *(i + 1) == '-'
                  && !memcmp (i + 2, part_delimiter, part_delimiter_len))
                {
                  if (part_begin)
                    {
                      part_end = i;

                      if (part_begin != part_end)
                        {
                          if (pass == 0)
                            ++result->part_count;
                          else
                            mime_parse (&parts[part_idx], arena,
                                        part_begin, part_end - part_begin);

                          ++part_idx;
                        }
                    }

                  part_begin = i + part_delimiter_len + 2;

                  while (isspace (*part_begin) && *part_begin != '\n')
                    ++part_begin;

                  if (*part_begin == '\n')
                    ++part_begin;
                }
            }

          if (pass == 0)
            parts = arena_calloc (arena, sizeof (*result->parts) * result->part_count);
        }

      result->parts = parts;
    }
  else if (ct == ct_text_plain)
    {
      const char* decoded_body = body;
      size_t body_size = end - body;

      if (cte == cte_quoted_printable)
        {
          char* tmp = malloc (body_size);
          const char* i = body;
          char* o = tmp;

          while (i != end)
            {
              if (*i == '=' && i + 2 < end)
                {
                  if (isspace (i[1]))
                    i += 2;
                  else
                    {
                      if (i[1] >= '0' && i[1] <= '9')
                        *o = (i[1] - '0') << 4;
                      else
                        *o = (i[1] - 'A' + 0xA) << 4;

                      if (i[2] >= '0' && i[2] <= '9')
                        *o |= (i[2] - '0');
                      else
                        *o |= (i[2] - 'A' + 0xA);

                      ++o;
                      i += 3;
                    }
                }
              else
                *o++ = *i++;
            }

          body_size = o - tmp;
          decoded_body = tmp;
        }
      else if (cte == cte_base64)
        {
          char* tmp = malloc (body_size);
          int result;

          result = base64_decode (tmp, decoded_body, body_size);

          if (result >= 0)
            {
              body_size = result;
              decoded_body = tmp;
            }
        }

      if (strcasecmp (charset, "utf-8") && strcasecmp (charset, "us-ascii"))
        {
          char* tmp;
          size_t new_size;

          if (-1 != convert_to_utf8 (decoded_body, body_size, &tmp, &new_size, charset))
            {
              if (decoded_body != body)
                free ((char*) decoded_body);

              decoded_body = tmp;
              body_size = new_size;
            }
        }

      if (decoded_body != body)
        free ((char*) decoded_body);
    }
}

struct vink_message *
vink_email_parse (const char *data, size_t size)
{
  struct arena_info arena, *arena_copy;
  struct vink_message *message;

  arena_init (&arena);
  message = arena_calloc (&arena, sizeof (*message));

  mime_parse (message, &arena, data, size);

  arena_copy = arena_alloc (&arena, sizeof (arena));
  memcpy (arena_copy, &arena, sizeof (arena));
  message->_private = arena_copy;

  return message;
}
