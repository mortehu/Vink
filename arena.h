#ifndef BROVSER_ARENA_H_
#define BROVSER_ARENA_H_ 1

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct arena_info
{
  void* data;
  size_t size;
  size_t used;

  struct arena_info* next;
  struct arena_info* last;
};

void
arena_init(struct arena_info* arena);

void
arena_free(struct arena_info* arena);

void*
arena_alloc(struct arena_info* arena, size_t size);

void*
arena_calloc(struct arena_info* arena, size_t size);

char*
arena_strdup(struct arena_info* arena, const char* string);

#ifdef __cplusplus
}
#endif

#endif /* !BROVSER_ARENA_H_ */
