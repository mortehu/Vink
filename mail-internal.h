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
