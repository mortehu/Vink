#ifndef VINK_ARENA_H_
#define VINK_ARENA_H_ 1

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct vink_arena
{
  void* data;
  size_t size;
  size_t used;

  struct vink_arena* next;
  struct vink_arena* last;
};

void
vink_arena_init (struct vink_arena* arena);

void
vink_arena_free (struct vink_arena* arena);

void*
vink_arena_alloc (struct vink_arena* arena, size_t size);

void*
vink_arena_calloc (struct vink_arena* arena, size_t size);

char*
vink_arena_strdup (struct vink_arena* arena, const char* string);

char*
vink_arena_strndup (struct vink_arena* arena, const char* string,
                    size_t length);

#ifdef __cplusplus
}
#endif

#endif /* !VINK_ARENA_H_ */
