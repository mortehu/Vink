#ifndef VINK_WAVE_H_
#define VINK_WAVE_H_ 1

#include "vink-arena.h"

struct vink_wave_wavelet
{
  struct vink_wave_participant *participants;
  struct vink_wave_document *documents;

  struct vink_arena arena;
};

struct vink_wave_participant
{
  char *address;

  struct vink_wave_participant *next;
};

struct vink_wave_document
{
  char *id;

  struct vink_wave_item *items;

  struct vink_wave_document *next;
};

enum vink_wave_item_type
{
  WAVE_ITEM_CHARACTERS = 0,
  WAVE_ITEM_TAG_START = 1,
  WAVE_ITEM_TAG_END = 2
};

struct vink_wave_item
{
  enum vink_wave_item_type type;

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

  struct vink_wave_item *next;
};

struct vink_wave_wavelet *
vink_wave_wavelet_create ();

void
vink_wave_wavelet_free (struct vink_wave_wavelet *wavelet);

int
vink_wave_apply_delta (struct vink_wave_wavelet *wavelet,
                       const void *data, size_t size,
                       const char *wavelet_name);

struct vink_message *
vink_wavelet_to_message (const struct vink_wave_wavelet *wavelet);

#endif /* !VINK_WAVE_H_ */
