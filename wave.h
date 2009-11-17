#ifndef WAVE_H_
#define WAVE_H_ 1

#include "array.h"

struct wave_message
{
  ARRAY_MEMBERS(unsigned char);
};

struct wave_key_value
{
  const char *key;
  const char *value;
};

struct wave_key_value_update
{
  const char *key;
  const char *old_value;
  const char *new_value;
};

struct wave_annotation_boundary
{
  const char **ends;
  size_t end_count;

  struct wave_key_value_update* changes;
  size_t change_count;
};

#endif /* !WAVE_H_ */
