#ifndef WAVE_H_
#define WAVE_H_ 1

#include "arena.h"

struct wave_wavelet
{
  struct wave_participant *participants;
  struct wave_document *documents;

  struct arena_info arena;
};

struct wave_participant
{
  char *address;

  struct wave_participant *next;
};

struct wave_document
{
  char *id;

  struct wave_item *items;

  struct wave_document *next;
};

enum wave_item_type
{
  WAVE_ITEM_CHARACTERS = 0,
  WAVE_ITEM_TAG_START = 1,
  WAVE_ITEM_TAG_END = 2
};

struct wave_item
{
  enum wave_item_type type;

  union
    {
      char *characters;
      struct
        {
          char *name;
          char **attributes;
        } tag_start;
    } u;

  char **annotations;

  struct wave_item *next;
};

struct wave_wavelet *
wave_wavelet_create();

int
wave_apply_delta(struct wave_wavelet *wavelet,
                 const void *data, size_t size,
                 const char *wavelet_name);

#endif /* !WAVE_H_ */
