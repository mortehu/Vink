#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "vink-arena.h"
#include "vink-internal.h"

static const size_t ARENA_BLOCK_SIZE = 256 * 1024;

void
vink_arena_init (struct vink_arena* arena)
{
  memset (arena, 0, sizeof (*arena));
}

void
vink_arena_free (struct vink_arena* arena)
{
  struct vink_arena* node;

  node = arena->next;

  while (node)
    {
      struct vink_arena* tmp;

      tmp = node;
      node = node->next;

      free (tmp->data);
      free (tmp);
    }

  /* Free self last, in case we are stored there */
  free (arena->data);
}

void*
vink_arena_alloc (struct vink_arena* arena, size_t size)
{
  void* result;
  struct vink_arena* node;

  if (!size)
    return 0;

  size = (size + 3) & ~3;

  if (size > ARENA_BLOCK_SIZE)
    {
      struct vink_arena* new_arena;

      new_arena = malloc (sizeof (*new_arena));

      if (!new_arena)
        {
          VINK_set_error ("Failed to allocate %zu bytes: %s",
                          sizeof (*new_arena), strerror (errno));

          return 0;
        }

      new_arena->data = malloc (size);

      if (!new_arena->data)
        {
          VINK_set_error ("Failed to allocate %zu bytes: %s",
                          size, strerror (errno));

          free (new_arena);

          return 0;
        }

      new_arena->size = size;
      new_arena->used = size;
      new_arena->next = 0;

      if (!arena->last)
        {
          arena->next = new_arena;
          arena->last = new_arena;
        }
      else
        {
          arena->last->next = new_arena;
          arena->last = new_arena;
        }

      return new_arena->data;
    }

  if (arena->last)
    node = arena->last;
  else
    {
      if (!arena->data)
        {
          arena->data = malloc (ARENA_BLOCK_SIZE);

          if (!arena->data)
            {
              VINK_set_error ("Failed to allocate %zu bytes: %s",
                              ARENA_BLOCK_SIZE, strerror (errno));

              return 0;
            }

          arena->size = ARENA_BLOCK_SIZE;
        }

      node = arena;
    }

  if (size > node->size - node->used)
    {
      struct vink_arena* new_arena;

      new_arena = malloc (sizeof (*new_arena));

      if (!new_arena)
        {
          VINK_set_error ("Failed to allocate %zu bytes: %s",
                          sizeof (*new_arena), strerror (errno));

          return 0;
        }

      new_arena->data = malloc (ARENA_BLOCK_SIZE);

      if (!new_arena->data)
        {
          VINK_set_error ("Failed to allocate %zu bytes: %s",
                          ARENA_BLOCK_SIZE, strerror (errno));

          free (new_arena);

          return 0;
        }

      new_arena->size = ARENA_BLOCK_SIZE;
      new_arena->used = 0;
      new_arena->next = 0;

      if (!arena->last)
        {
          arena->next = new_arena;
          arena->last = new_arena;
        }
      else
        {
          arena->last->next = new_arena;
          arena->last = new_arena;
        }

      node = new_arena;
    }

  assert (node->size == ARENA_BLOCK_SIZE);
  assert (node->used < node->size);
  assert (size <= node->size - node->used);

  result = (char*) node->data + node->used;
  node->used += size;

  return result;
}

void*
vink_arena_calloc (struct vink_arena* arena, size_t size)
{
  void* result;

  result = vink_arena_alloc (arena, size);

  if (!result)
    return 0;

  memset (result, 0, size);

  return result;
}

char*
vink_arena_strdup (struct vink_arena* arena, const char* string)
{
  char* result;

  result = vink_arena_alloc (arena, strlen (string) + 1);

  if (!result)
    return 0;

  strcpy (result, string);

  return result;
}

char*
vink_arena_strndup (struct vink_arena* arena, const char* string,
                    size_t length)
{
  char* result;

  result = vink_arena_alloc (arena, length + 1);

  if (!result)
    return 0;

  memcpy (result, string, length);
  result[length] = 0;

  return result;
}
