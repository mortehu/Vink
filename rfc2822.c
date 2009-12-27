#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include "mail-internal.h"

static const char*
skip_ws(const char* s)
{
  while (isspace(*s))
    ++s;

  return s;
}

static unsigned int
get_unsigned(const char **_s, int max_length)
{
  int i, ret = 0;
  const char *s = *_s;

  s = skip_ws(s);

  for (i = 0; i < max_length; ++i)
    {
      if (!isdigit(*s))
        break;

      ret *= 10;
      ret += *s++ - '0';
    }

  *_s = skip_ws(s);

  return ret;
}

int
rfc2822_parse_date(time_t* ret, const char* date, const char* end)
{
  int i;
  struct tm tm;
  memset(&tm, 0, sizeof(tm));

  const char* s = memchr(date, ',', end - date);
  if (s)
    date = s + 1;

  tm.tm_mday = get_unsigned(&date, 2);

  /* Month.  Assumes correct speling and locale */
  char mon[3];
  for (i = 0; i < 3; ++i)
    mon[i] = tolower(*date++);

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

  tm.tm_year = get_unsigned(&date, 4);

  if (tm.tm_year > 1900)
    tm.tm_year -= 1900;

  /* Fix invalid dates */
  if (tm.tm_year < 70)
    tm.tm_year += 100;

  tm.tm_hour = get_unsigned(&date, 2);

  if (*date++ != ':')
    return -1;

  tm.tm_min = get_unsigned(&date, 2);


  /* Sometimes seconds are missing, they shouldn't
   * but it's easy to handle this */
  if (*date++ == ':')
    tm.tm_sec = get_unsigned(&date, 2);

  /* Check if there's a timezone offset, and parse it */
  int tz_offset = strcspn(date, "-+");

  if (date[tz_offset])
    {
      int offset = atoi(date + tz_offset);
      tm.tm_sec -= ((offset / 100) * 60 + abs(offset) % 100) * 60;
    }

  *ret = timegm(&tm);

  /* XXX: Is this a bad idea?   It makes time travelling spam with far less
   * annoying */
  static time_t recently;
  if (*ret > recently)
    {
      recently = time(NULL);

      if (*ret > recently)
        *ret = recently;
    }

  return 0;
}

void
rfc2822_unfold(char* header)
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
VINK_rfc2822_parse(const char* buf, const char* buf_end,
                   struct tuples *headers, const char** body)
{
  const char* begin = buf;
  const char* end;
  const char* sep;
  size_t i;

  /* Store headers (still folded) in tuples */
  while (begin != buf_end)
    {
      end = memchr(begin, '\n', buf_end - begin);

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

          ARRAY_ADD(headers, header);
        }

      if (end == buf_end)
        break;

      begin = end + 1;
    }

  *body = begin;

  for(i = 0; i < ARRAY_COUNT(headers); ++i)
    {
      struct tuple *h;

      h = &ARRAY_GET(headers, i);

      sep = memchr(h->key, ':', buf_end - h->key);

      /* If there is not ':', this is not a header. */
      if (!sep || sep == h->key)
        {
          ARRAY_COUNT(headers) = i;

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

/* vim: set sts=2 sw=2 et :*/
