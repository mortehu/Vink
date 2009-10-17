#include <assert.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "arena.h"

#define ARENA_BLOCK_SIZE (256 * 1024)

void
arena_init(struct arena_info* arena)
{
  memset(arena, 0, sizeof(*arena));
}

void
arena_free(struct arena_info* arena)
{
  struct arena_info* node;

  node = arena->next;

  while(node)
  {
    struct arena_info* tmp;

    tmp = node;
    node = node->next;

    free(tmp->data);
    free(tmp);
  }

  free(arena->data);

  memset(arena, 0, sizeof(*arena));
}

void*
arena_alloc(struct arena_info* arena, size_t size)
{
  void* result;
  struct arena_info* node;

  if(!size)
    return 0;

  size = (size + 3) & ~3;

  if(size > ARENA_BLOCK_SIZE)
  {
    struct arena_info* new_arena;

    new_arena = malloc(sizeof(*new_arena));

    if(!new_arena)
      err(EXIT_SUCCESS, "failed to allocate memory for arena object");

    new_arena->data = malloc(size);

    if(!new_arena->data)
      err(EXIT_SUCCESS, "failed to allocate memory for arena data");

    new_arena->size = size;
    new_arena->used = size;
    new_arena->next = 0;

    if(!arena->last)
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

  if(arena->last)
    node = arena->last;
  else
  {
    if(!arena->data)
    {
      arena->data = malloc(ARENA_BLOCK_SIZE);

      if(!arena->data)
        err(EXIT_SUCCESS, "failed to allocate memory for arena data");

      arena->size = ARENA_BLOCK_SIZE;
    }

    node = arena;
  }

  if(size > node->size - node->used)
  {
    struct arena_info* new_arena;

    new_arena = malloc(sizeof(*new_arena));

    if(!new_arena)
      err(EXIT_SUCCESS, "failed to allocate memory for arena object");

    new_arena->data = malloc(ARENA_BLOCK_SIZE);

    if(!new_arena->data)
      err(EXIT_SUCCESS, "failed to allocate memory for arena data");

    new_arena->size = ARENA_BLOCK_SIZE;
    new_arena->used = 0;
    new_arena->next = 0;

    if(!arena->last)
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

  assert(node->size == ARENA_BLOCK_SIZE);
  assert(node->used < node->size);
  assert(size <= node->size - node->used);

  result = (char*) node->data + node->used;
  node->used += size;

  return result;
}

void*
arena_calloc(struct arena_info* arena, size_t size)
{
  void* result;

  result = arena_alloc(arena, size);

  memset(result, 0, size);

  return result;
}

char*
arena_strdup(struct arena_info* arena, const char* string)
{
  char* result;

  result = arena_alloc(arena, strlen(string) + 1);

  strcpy(result, string);

  return result;
}
