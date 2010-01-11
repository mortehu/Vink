#include "array.h"

int
array_grow(void* elements, size_t* alloc, size_t new_alloc, size_t element_size)
{
  void *tmp, **e = elements;

  tmp = realloc(*e, element_size * new_alloc);

  if(!tmp)
    return -1;

  *alloc = new_alloc;
  *e = tmp;

  return 0;
}
