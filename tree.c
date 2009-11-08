#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "arena.h"
#include "common.h"
#include "io.h"
#include "tree.h"

struct tree_node
{
  char* path;
  char* value;
};

struct tree
{
  struct arena_info arena;

  char* name;

  struct tree_node* nodes;
  size_t node_count;
  size_t node_alloc;
};

struct tree*
tree_create(const char* name)
{
  struct tree* result;
  struct arena_info arena;

  arena_init(&arena);

  result = arena_calloc(&arena, sizeof(*result));
  result->arena = arena;
  result->name = arena_strdup(&result->arena, name);

  return result;
}

void
tree_destroy(struct tree* t)
{
  arena_free(&t->arena);
}

void
tree_create_node(struct tree* t, const char* path, const char* value)
{
  size_t i;

  if(t->node_count == t->node_alloc)
    {
      t->node_alloc = t->node_alloc * 4 / 3 + 16;

      t->nodes = realloc(t->nodes, sizeof(*t->nodes) * t->node_alloc);

      if(!t->nodes)
        errx(EXIT_FAILURE, "failed to allocate memory for tree nodes");
    }

  i = t->node_count++;

  t->nodes[i].path = arena_strdup(&t->arena, path);
  t->nodes[i].value = arena_strdup(&t->arena, value);
}


long long int
tree_get_integer(const struct tree* t, const char* path)
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
            errx(EXIT_FAILURE, "%s: expected integer value in '%s', found '%s'",
                 t->name, path, t->nodes[i].value);

          return result;
        }
    }

  errx(EXIT_FAILURE, "%s: could not find symbol '%s'", t->name, path);
}

int
tree_get_bool(const struct tree* t, const char* path)
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

          errx(EXIT_FAILURE, "%s: expected boolean value in '%s', found '%s'",
               t->name, path, t->nodes[i].value);
        }
    }

  errx(EXIT_FAILURE, "%s: could not find symbol '%s'", t->name, path);
}

const char*
tree_get_string(const struct tree* t, const char* path)
{
  size_t i;

  for(i = 0; i < t->node_count; ++i)
    {
      if(!strcmp(t->nodes[i].path, path))
        return t->nodes[i].value;
    }

  errx(EXIT_FAILURE, "%s: could not find symbol '%s'", t->name, path);
}

static int
is_symbol_char(int ch)
{
  return isalnum(ch) || ch == '-' || ch == '_' || ch == '!';
}

struct tree*
tree_load_cfg(const char* path)
{
  struct tree* result;
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

  result = tree_create(path);

  if(-1 == (fd = open(path, O_RDONLY)))
    return result;

  if(-1 == (size = lseek(fd, 0, SEEK_END)))
    err(EXIT_FAILURE, "%s: failed to seek to end of file", path);

  if(-1 == lseek(fd, 0, SEEK_SET))
    err(EXIT_FAILURE, "%s: failed to seek to start of file", path);

  if(0 == (data = malloc(size + 1)))
    err(EXIT_FAILURE, "%s: failed to allocate %zu bytes for parsing", path,
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
            errx(EXIT_FAILURE, "%s:%d: unexpected '}'", path, lineno);

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
                errx(EXIT_FAILURE, "%s:%d: unexpected '%c' while looking for symbol",
                     path, lineno, *c);
              else
                errx(EXIT_FAILURE, "%s:%d: unexpected 0x%02x while looking for symbol",
                     path, lineno, *c);
            }

          if(symbol_len)
            {
              if(symbol_len + 1 == ARRAY_SIZE(symbol))
                errx(EXIT_FAILURE, "%s:%d: symbol stack overflow", path, lineno);

              symbol[symbol_len++] = '.';
            }

          while(is_symbol_char(*c))
            {
              if(symbol_len + 1 == ARRAY_SIZE(symbol))
                errx(EXIT_FAILURE, "%s:%d: symbol stack overflow", path, lineno);

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

              errx(EXIT_FAILURE, "%s:%d: unexpected end-of-file after symbol",
                   path, lineno);

            case '.':

              expecting_symbol = 1;
              *c++ = 0;

              break;

            case '{':

              if(section_stackp == ARRAY_SIZE(section_stack))
                errx(EXIT_FAILURE, "%s:%d: too many nested sections", path,
                     lineno);

              section_stack[section_stackp++] = symbol_len;
              expecting_symbol = 1;
              *c++ = 0;

              break;

            case '}':

              errx(EXIT_FAILURE, "%s:%d: unexpected '%c' after symbol", path,
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
                      errx(EXIT_FAILURE, "%s:%d: unexpected end-of-file in "
                           "string", path, lineno);
                    }

                  if(*c == '\\')
                    {
                      if(!*(c + 1))
                        errx(EXIT_FAILURE, "%s:%d: unexpected end-of-file in "
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

          tree_create_node(result, symbol, value);

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
