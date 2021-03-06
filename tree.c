#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "io.h"
#include "vink-arena.h"
#include "vink-internal.h"
#include "vink-tree.h"
#include "vink.h"

struct vink_tree_node
{
  char* path;
  char* value;
};

struct vink_tree
{
  struct vink_arena arena;

  char* name;

  struct vink_tree_node* nodes;
  size_t node_count;
  size_t node_alloc;
};

struct vink_tree*
vink_tree_create (const char* name)
{
  struct vink_tree* result;
  struct vink_arena arena;

  vink_arena_init (&arena);

  result = vink_arena_calloc (&arena, sizeof (*result));

  if (!result)
    errx(EX_OSERR, "Arena allocation failed: %s", vink_last_error());

  result->arena = arena;
  result->name = vink_arena_strdup (&result->arena, name);

  return result;
}

void
vink_tree_destroy (struct vink_tree* t)
{
  free (t->nodes);
  vink_arena_free (&t->arena);
}

void
vink_tree_create_node (struct vink_tree* t, const char* path, const char* value)
{
  size_t i;

  if(t->node_count == t->node_alloc)
    {
      t->node_alloc = t->node_alloc * 4 / 3 + 16;

      t->nodes = realloc(t->nodes, sizeof(*t->nodes) * t->node_alloc);

      if(!t->nodes)
        errx(EX_OSERR, "failed to allocate memory for tree nodes");
    }

  i = t->node_count++;

  t->nodes[i].path = vink_arena_strdup (&t->arena, path);
  t->nodes[i].value = vink_arena_strdup (&t->arena, value);
}

long long int
vink_tree_get_integer (const struct vink_tree* t, const char* path)
{
  char* tmp;
  long long int result;
  size_t i;

  for(i = 0; i < t->node_count; ++i)
    {
      if(!strcmp(t->nodes[i].path, path))
        {
          result = strtoll(t->nodes[i].value, &tmp, 0);

          if(*tmp)
            errx(EX_DATAERR, "%s: expected integer value in '%s', found '%s'",
                 t->name, path, t->nodes[i].value);

          return result;
        }
    }

  errx(EX_DATAERR, "%s: could not find symbol '%s'", t->name, path);
}

long long int
vink_tree_get_integer_default (const struct vink_tree* t, const char* path, long long int def)
{
  char* tmp;
  long long int result;
  size_t i;

  for(i = 0; i < t->node_count; ++i)
    {
      if(!strcmp(t->nodes[i].path, path))
        {
          result = strtoll(t->nodes[i].value, &tmp, 0);

          if(*tmp)
            {
              fprintf(stderr, "%s: expected integer value in '%s', found '%s'\n",
                      t->name, path, t->nodes[i].value);

              return def;
            }

          return result;
        }
    }

  return def;
}

int
vink_tree_get_bool (const struct vink_tree* t, const char* path)
{
  const char* value;
  size_t i;

  for(i = 0; i < t->node_count; ++i)
    {
      if(!strcmp(t->nodes[i].path, path))
        {
          value = t->nodes[i].value;

          if(!strcmp(value, "0")
             || !strcasecmp(value, "false")
             || !strcasecmp(value, "no"))
            return 0;

          if(!strcmp(value, "1")
             || !strcasecmp(value, "true")
             || !strcasecmp(value, "yes"))
            return 1;

          errx(EX_DATAERR, "%s: expected boolean value in '%s', found '%s'",
               t->name, path, t->nodes[i].value);
        }
    }

  errx(EX_DATAERR, "%s: could not find symbol '%s'", t->name, path);
}

int
vink_tree_get_bool_default (const struct vink_tree* t, const char* path, int def)
{
  const char* value;
  size_t i;

  for(i = 0; i < t->node_count; ++i)
    {
      if(!strcmp(t->nodes[i].path, path))
        {
          value = t->nodes[i].value;

          if(!strcmp(value, "0")
             || !strcasecmp(value, "false")
             || !strcasecmp(value, "no"))
            return 0;

          if(!strcmp(value, "1")
             || !strcasecmp(value, "true")
             || !strcasecmp(value, "yes"))
            return 1;

          fprintf(stderr, "%s: expected boolean value in '%s', found '%s'\n",
                  t->name, path, t->nodes[i].value);

          return def;
        }
    }

  return def;
}

const char*
vink_tree_get_string (const struct vink_tree* t, const char* path)
{
  size_t i;

  for(i = 0; i < t->node_count; ++i)
    {
      if(!strcmp(t->nodes[i].path, path))
        return t->nodes[i].value;
    }

  errx(EX_DATAERR, "%s: could not find symbol '%s'", t->name, path);
}

size_t
vink_tree_get_strings (const struct vink_tree* t, const char* path, char*** result)
{
  size_t i, count = 0;

  *result = 0;

  for(i = 0; i < t->node_count; ++i)
    {
      if(!strcmp(t->nodes[i].path, path))
        {
          *result = realloc(*result, sizeof(*result) * (count + 1));

          (*result)[count++] = t->nodes[i].value;
        }
    }

  return count;
}

const char*
vink_tree_get_string_default (const struct vink_tree* t, const char* path, const char* def)
{
  size_t i;

  for(i = 0; i < t->node_count; ++i)
    {
      if(!strcmp(t->nodes[i].path, path))
        return t->nodes[i].value;
    }

  return def;
}

static int
is_symbol_char(int ch)
{
  return isalnum(ch) || ch == '-' || ch == '_' || ch == '!';
}

struct vink_tree*
vink_tree_load_cfg (const char* path)
{
  struct vink_tree* result;
  char* data;
  off_t size;
  int fd;

  char symbol[4096];
  size_t symbol_len = 0;

  size_t section_stack[32];
  size_t section_stackp = 0;
  int expecting_symbol = 1;

  char* c;
  int lineno = 1;

  result = vink_tree_create (path);

  if(-1 == (fd = open(path, O_RDONLY)))
    return result;

  if(-1 == (size = lseek(fd, 0, SEEK_END)))
    err(EX_OSERR, "%s: failed to seek to end of file", path);

  if(-1 == lseek(fd, 0, SEEK_SET))
    err(EX_OSERR, "%s: failed to seek to start of file", path);

  if(0 == (data = malloc(size + 1)))
    err(EX_OSERR, "%s: failed to allocate %zu bytes for parsing", path,
        (size_t) (size + 1));

  read_all(fd, data, size, path);
  data[size] = 0;

  close(fd);

  c = data;

  while(*c)
    {
      while(isspace(*c))
        {
          if(*c++ == '\n')
            ++lineno;
        }

      if(!*c)
        break;

      if(*c == '#')
        {
          while(*c && *c != '\n')
            ++c;

          ++lineno;

          continue;
        }

      if(*c == '}')
        {
          if(!section_stackp)
            errx(EX_DATAERR, "%s:%d: unexpected '}'", path, lineno);

          if(!--section_stackp)
            symbol_len = 0;
          else
            symbol_len = section_stack[section_stackp - 1];

          ++c;

          continue;
        }

      if(expecting_symbol)
        {
          if(!is_symbol_char(*c))
            {
              if(isprint(*c))
                errx(EX_DATAERR, "%s:%d: unexpected '%c' while looking for symbol",
                     path, lineno, *c);
              else
                errx(EX_DATAERR, "%s:%d: unexpected 0x%02x while looking for symbol",
                     path, lineno, *c);
            }

          if(symbol_len)
            {
              if(symbol_len + 1 == ARRAY_SIZE(symbol))
                errx(EX_DATAERR, "%s:%d: symbol stack overflow", path, lineno);

              symbol[symbol_len++] = '.';
            }

          while(is_symbol_char(*c))
            {
              if(symbol_len + 1 == ARRAY_SIZE(symbol))
                errx(EX_DATAERR, "%s:%d: symbol stack overflow", path, lineno);

              symbol[symbol_len++] = *c++;
            }

          if(isspace(*c))
            {
              *c++ = 0;
              while(isspace(*c))
                ++c;
            }

          switch(*c)
            {
            case 0:

              errx(EX_DATAERR, "%s:%d: unexpected end-of-file after symbol",
                   path, lineno);

            case '.':

              expecting_symbol = 1;
              *c++ = 0;

              break;

            case '{':

              if(section_stackp == ARRAY_SIZE(section_stack))
                errx(EX_DATAERR, "%s:%d: too many nested sections", path,
                     lineno);

              section_stack[section_stackp++] = symbol_len;
              expecting_symbol = 1;
              *c++ = 0;

              break;

            case '}':

              errx(EX_DATAERR, "%s:%d: unexpected '%c' after symbol", path,
                   lineno, *c);

            default:

              expecting_symbol = 0;
            }
        }
      else /* !expecting_symbol */
        {
          char* value = c;

          if(*c == '"')
            {
              char* o;

              o = value = ++c;

              for(;;)
                {
                  if(!*c)
                    {
                      errx(EX_DATAERR, "%s:%d: unexpected end-of-file in "
                           "string", path, lineno);
                    }

                  if(*c == '\\')
                    {
                      if(!*(c + 1))
                        errx(EX_DATAERR, "%s:%d: unexpected end-of-file in "
                             "string", path, lineno);

                      ++c;
                      *o++ = *c++;
                    }
                  else if(*c == '"')
                    break;
                  else
                    *o++ = *c++;
                }

              *c++ = 0;
            }
          else
            {
              while(*c && !isspace(*c))
                ++c;

              if(*c)
                *c++ = 0;
            }

          symbol[symbol_len] = 0;

          vink_tree_create_node (result, symbol, value);

          if(section_stackp)
            symbol_len = section_stack[section_stackp - 1];
          else
            symbol_len = 0;

          expecting_symbol = 1;
        }
    }

  free(data);

  return result;
}
