#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "vink-internal.h"
#include "wave.h"
#include "wave.pb-c.h"

struct wave_wavelet *
wave_wavelet_create ()
{
  struct wave_wavelet *result = 0;
  struct arena_info arena;

  arena_init (&arena);

  result = arena_calloc (&arena, sizeof (*result));

  if (!result)
    return 0;

  memcpy (&result->arena, &arena, sizeof (arena));

  return result;
}

void
wave_wavelet_free(struct wave_wavelet *wavelet)
{
  arena_free (&wavelet->arena);
}

static void
split_item (struct arena_info *arena, struct wave_item **prev,
            struct wave_item **item, char **ch)
{
  struct wave_item *new_item;

  /* Not at a character item */
  if (!*item || (*item)->type != WAVE_ITEM_CHARACTERS)
    return;

  assert (*ch);
  assert (**ch);

  /* Already between items */
  if (*ch == (*item)->u.characters)
    return;

  new_item = arena_calloc (arena, sizeof (*new_item));
  new_item->type = WAVE_ITEM_CHARACTERS;
  new_item->u.characters = arena_strdup (arena, *ch);

  **ch = 0;

  new_item->next = (*item)->next;
  (*item)->next = new_item;

  *prev = *item;
  *item = new_item;
  *ch = (*item)->u.characters;
}

static int
update_annotation_update (struct arena_info *arena, char ***annotations,
                          Wave__DocumentOperation__Component__AnnotationBoundary *ab)
{
  char **result, **c, **o;
  char **old_annotations;
  size_t i, count = 0;

  old_annotations = *annotations;

  if (old_annotations)
    {
      for (c = old_annotations; c[0]; c += 2)
        ++count;

      for (i = 0; i < ab->n_end; ++i)
        {
          for (c = old_annotations; c[0]; c += 2)
            {
              if (!strcmp (c[0], ab->end[i]))
                break;
            }

          if (!c[0])
            {
              VINK_set_error ("'Update annotations' message tried to remove "
                              "non-existant key '%s'", ab->end[i]);

              return -1;
            }

          --count;
        }

      for (i = 0; i < ab->n_change; ++i)
        {
          for (c = old_annotations; c[0]; c += 2)
            {
              if (!strcmp (c[0], ab->change[i]->key))
                break;
            }

          /* XXX: Compare change->oldvalue */

          if (!c[0])
            {
              if (ab->change[i]->oldvalue)
                {
                  VINK_set_error ("'Update annotations' message contained "
                                  "non-matching old value");

                  return -1;
                }

              ++count;
            }
        }
    }
  else
    {
      if (ab->n_end)
        {
          VINK_set_error ("'Update annotations' message tried to remove keys "
                          "from an empty annotation update");

          return -1;
        }

      count = ab->n_change;
    }

  if (!count)
    {
      *annotations = 0;

      return 0;
    }

  result = arena_alloc (arena, sizeof (*result) * 2 * (count + 1));
  o = result;

  if (old_annotations)
    {
      for (c = old_annotations; c[0]; c += 2)
        {
          for (i = 0; i < ab->n_end; ++i)
            {
              if (!strcmp (c[0], ab->end[i]))
                break;
            }

          if (i != ab->n_end)
            continue;

          for (i = 0; i < ab->n_change; ++i)
            {
              if (!strcmp (c[0], ab->change[i]->key))
                break;
            }

          if (i == ab->n_change)
            {
              o[0] = c[0];
              o[1] = c[1];
            }
          else
            {
              o[0] = c[0];

              if (ab->change[i]->newvalue)
                o[1] = arena_strdup (arena, ab->change[i]->newvalue);
              else
                o[1] = 0;
            }

          o += 2;
        }
    }

  for (i = 0; i < ab->n_change; ++i)
    {
      for (c = result; c != o; c += 2)
        {
          if (!strcmp (c[0], ab->change[i]->key))
            break;
        }

      if (c != o)
        continue;

      o[0] = arena_strdup (arena, ab->change[i]->key);

      if (ab->change[i]->newvalue)
        o[1] = arena_strdup (arena, ab->change[i]->newvalue);
      else
        o[1] = 0;

      o += 2;
    }

  assert (o - result == count * 2);

  o[0] = 0;
  o[1] = 0;

  *annotations = result;

  return 0;
}

static void
insert_annotations (struct arena_info *arena,
                    struct wave_item *item,
                    const struct wave_item *prev,
                    char **annotation_update)
{
  char **o, **p, **i;
  size_t count = 0;

  /*
     The inserted items are annotated with the new values from the annotations
     update in addition to any annotations on the item to the left of the
     cursor with keys that are not part of the annotations update.

     If the cursor is at the beginning of the document, the old values in the
     annotations update are null, and the inserted items are annotated with the
     new values from the annotations update.
   */

  if (!prev || !prev->annotations)
    {
      item->annotations = annotation_update;

      return;
    }

  if (!annotation_update)
    {
      item->annotations = prev->annotations;

      return;
    }

  for (i = annotation_update; i[0]; i += 2)
    ++count;

  for (p = prev->annotations; p[0]; p += 2)
    {
      for (i = annotation_update; i[0]; i += 2)
        {
          if (!strcmp (p[0], i[0]))
            break;
        }

      if (!i[0])
        ++count;
    }

  item->annotations = arena_alloc (arena, sizeof (*item->annotations) * 2 * (count + 1));
  o = item->annotations;

  for (i = annotation_update; i[0]; i += 2)
    {
      o[0] = i[0];
      o[1] = i[1];
      o += 2;
    }

  for (p = prev->annotations; p[0]; p += 2)
    {
      for (i = annotation_update; i[0]; i += 2)
        {
          if (!strcmp (p[0], i[0]))
            break;
        }

      if (i[0])
        continue;

      o[0] = p[0];
      o[1] = p[1];
      o += 2;
    }

  o[0] = 0;
  o[1] = 0;
}

static void
update_annotations (struct wave_item *item,
                    char **annotation_update)
{
  char **o, **i;

  if (!annotation_update)
    return;

  for (i = annotation_update; i[0]; i += 2)
    {
      for (o = item->annotations; o && o[0]; o += 2)
        {
          if (!strcmp (o[0], i[0]))
            {
              o[1] = i[1];

              break;
            }
        }

      if (o && o[0])
        continue;
    }
}

int
wave_apply_delta (struct wave_wavelet *wavelet,
                  const void *data, size_t size,
                  const char *wavelet_name)
{
  Wave__AppliedWaveletDelta *applied_delta;
  Wave__WaveletDelta *delta;
  size_t i, operation_idx;
  struct arena_info *arena;

  arena = &wavelet->arena;

  applied_delta = wave__applied_wavelet_delta__unpack (&protobuf_c_system_allocator, size, data);

  delta = applied_delta->signedoriginaldelta->delta;

  fprintf (stderr, "Version: %llu\n", (unsigned long long) delta->hashedversion->version);
  fprintf (stderr, "Author: %s\n", delta->author);
  fprintf (stderr, "Operations: %zu\n", delta->n_operation);

  for (operation_idx = 0; operation_idx < delta->n_operation; ++operation_idx)
    {
      Wave__WaveletOperation *op;

      op = delta->operation[operation_idx];

      if (op->addparticipant)
        {
          struct wave_participant *p;

          p = arena_alloc (arena, sizeof (*p));

          if (!p)
            goto fail;

          p->address = arena_strdup (arena, op->addparticipant);
          p->next = wavelet->participants;
          wavelet->participants = p;
        }
      else if (op->removeparticipant)
        {
          struct wave_participant *p, *prev;

          for (p = wavelet->participants; p; p = p->next)
            {
              if (!strcmp (p->address, op->removeparticipant))
                break;

              prev = p;
            }

          if (!prev)
            wavelet->participants = p->next;
          else
            prev->next = p->next;
        }
      else if (op->mutatedocument)
        {
          Wave__DocumentOperation *doc_op;
          size_t component_idx;

          struct wave_document *doc;
          struct wave_item *item, *prev = 0;
          char *ch = 0;
          char **annotation_update = 0;

          doc_op = op->mutatedocument->documentoperation;

          for (doc = wavelet->documents; doc; doc = doc->next)
            {
              if (!strcmp (doc->id, op->mutatedocument->documentid))
                break;
            }

          if (!doc)
            {
              fprintf (stderr, "New document: %s\n", op->mutatedocument->documentid);
              doc = arena_calloc (arena, sizeof (*doc));
              doc->id = arena_strdup (arena, op->mutatedocument->documentid);
              doc->next = wavelet->documents;
              wavelet->documents = doc;
            }
          else
            fprintf (stderr, "Old document: %s\n", op->mutatedocument->documentid);

          item = doc->items;
          ch = (item && item->type == WAVE_ITEM_CHARACTERS) ? item->u.characters : 0;

          for (component_idx = 0; component_idx < doc_op->n_component; ++component_idx)
            {
              Wave__DocumentOperation__Component *c;
              struct wave_item *new_item = 0;

              c = doc_op->component[component_idx];

              if (item && item->type == WAVE_ITEM_CHARACTERS)
                assert (ch);

              if (c->annotationboundary)
                {
                  if (-1 == update_annotation_update (arena, &annotation_update,
                                                      c->annotationboundary))
                    goto fail;

                  split_item (arena, &prev, &item, &ch);
                }
              else if (c->characters)
                {
                  if (!c->characters[0])
                    {
                      VINK_set_error ("Wave character message contained empty string");

                      goto fail;
                    }

                  new_item = arena_calloc (arena, sizeof (*new_item));
                  new_item->type = WAVE_ITEM_CHARACTERS;
                  new_item->u.characters = arena_strdup (arena, c->characters);
                }
              else if (c->elementstart)
                {
                  Wave__DocumentOperation__Component__ElementStart *es;
                  char** attributes;

                  es = c->elementstart;

                  new_item = arena_calloc (arena, sizeof (*new_item));
                  new_item->type = WAVE_ITEM_TAG_START;
                  new_item->u.tag_start.name = arena_strdup (arena, es->type);
                  attributes = arena_alloc (arena, sizeof (char*) * (es->n_attribute + 1));

                  for (i = 0; i < es->n_attribute; ++i)
                    {
                      attributes[i * 2] = arena_strdup (arena, es->attribute[i]->key);
                      attributes[i * 2 + 1] = arena_strdup (arena, es->attribute[i]->value);
                    }

                  attributes[i * 2] = 0;
                  attributes[i * 2 + 1] = 0;

                  new_item->u.tag_start.attributes = attributes;
                }
              else if (c->has_elementend)
                {
                  new_item = arena_calloc (arena, sizeof (*new_item));
                  new_item->type = WAVE_ITEM_TAG_END;
                }
              else if (c->has_retainitemcount)
                {
                  for (i = 0; i < c->retainitemcount; ++i)
                    {
                      if (!item)
                        {
                          VINK_set_error ("Wave message 'retain items' went past the end of a document");

                          goto fail;
                        }

                      update_annotations (item, annotation_update);

                      if (ch && *ch)
                        {
                          if (!*++ch)
                            {
                              prev = item;
                              item = item->next;
                              ch = (item && item->type == WAVE_ITEM_CHARACTERS) ? item->u.characters : 0;
                            }
                        }
                      else
                        {
                          prev = item;
                          item = item->next;
                          ch = (item && item->type == WAVE_ITEM_CHARACTERS) ? item->u.characters : 0;
                        }
                    }
                }
              else if (c->deletecharacters)
                {
                  if (!item)
                    {
                      VINK_set_error ("Wave message 'delete characters' encountered past the end of a document");

                      goto fail;
                    }

                  if (item->type != WAVE_ITEM_CHARACTERS)
                    {
                      VINK_set_error ("Wave message 'delete characters' encountered on a non-character item");

                      goto fail;
                    }

                  split_item (arena, &prev, &item, &ch);

                  if (strcmp (item->u.characters, c->deletecharacters))
                    {
                      VINK_set_error ("Characters in wave message 'delete characters' does not match those in the document");

                      goto fail;
                    }

                  if (prev)
                    prev->next = item->next;
                  else
                    doc->items = item->next;

                  item = item->next;
                  ch = (item && item->type == WAVE_ITEM_CHARACTERS) ? item->u.characters : 0;
                }
              else if (c->deleteelementstart)
                {
                  Wave__DocumentOperation__Component__ElementStart *es;

                  es = c->deleteelementstart;

                  if (!item)
                    {
                      VINK_set_error ("Wave message 'delete element start' encountered past the end of a document");

                      goto fail;
                    }

                  if (item->type != WAVE_ITEM_TAG_START)
                    {
                      VINK_set_error ("Wave message 'delete element start' encountered on an unsupported item");

                      goto fail;
                    }

                  if (strcmp (item->u.tag_start.name, es->type))
                    {
                      VINK_set_error ("Wave message 'delete element start' encountered on element with non-matching name");

                      goto fail;
                    }

                  /* XXX: Does it hurt us to assume that the attributes were the same? */

                  if (prev)
                    prev->next = item->next;
                  else
                    doc->items = item->next;

                  item = item->next;
                  ch = (item && item->type == WAVE_ITEM_CHARACTERS) ? item->u.characters : 0;
                }
              else if (c->has_deleteelementend)
                {
                  if (!item)
                    {
                      VINK_set_error ("Wave message 'delete element end' encountered past the end of a document");

                      goto fail;
                    }

                  if (item->type != WAVE_ITEM_TAG_END)
                    {
                      VINK_set_error ("Wave message 'delete element end' encountered on an unsupported item");

                      goto fail;
                    }

                  if (prev)
                    prev->next = item->next;
                  else
                    doc->items = item->next;

                  item = item->next;
                  ch = (item && item->type == WAVE_ITEM_CHARACTERS) ? item->u.characters : 0;
                }
              else if (c->replaceattributes)
                {
                  Wave__DocumentOperation__Component__ReplaceAttributes* ra;

                  ra = c->replaceattributes;

                  if (!item)
                    {
                      VINK_set_error ("Wave message 'replace attributes' encountered past the end of a document");

                      goto fail;
                    }

                  update_annotations (item, annotation_update);

                  if (item->type != WAVE_ITEM_TAG_START)
                    {
                      VINK_set_error ("Wave message 'replace attributes' encountered on an unsupported item");

                      goto fail;
                    }

                  /* XXX: Does it hurt us to assume that the attributes were the same? */

                  if (ra->n_newattribute)
                    {
                      char **attributes;

                      attributes = arena_alloc (arena, sizeof (char*) * (ra->n_newattribute + 1));

                      for (i = 0; i < ra->n_newattribute; ++i)
                        {
                          attributes[i * 2] = arena_strdup (arena, ra->newattribute[i]->key);
                          attributes[i * 2 + 1] = arena_strdup (arena, ra->newattribute[i]->value);
                        }

                      attributes[i * 2] = 0;
                      attributes[i * 2 + 1] = 0;

                      item->u.tag_start.attributes = attributes;
                    }
                  else
                    item->u.tag_start.attributes = 0;
                }
              else if (c->updateattributes)
                {
                  Wave__DocumentOperation__Component__UpdateAttributes *ua;
                  size_t update_idx;
                  char **attr;

                  ua = c->updateattributes;

                  if (!item)
                    {
                      VINK_set_error ("Wave message 'update attributes' encountered past the end of a document");

                      goto fail;
                    }

                  update_annotations (item, annotation_update);

                  if (item->type != WAVE_ITEM_TAG_START)
                    {
                      VINK_set_error ("Wave message 'update attributes' encountered on an unsupported item");

                      goto fail;
                    }

                  for (update_idx = 0; update_idx < ua->n_attributeupdate;
                       ++update_idx)
                    {
                      Wave__DocumentOperation__Component__KeyValueUpdate *update;

                      update = ua->attributeupdate[update_idx];

                      for (attr = item->u.tag_start.attributes; attr[0]; attr += 2)
                        {
                          if (!strcmp (attr[0], update->key))
                            {
                              if (strcmp (attr[1], update->oldvalue))
                                {
                                  VINK_set_error ("Wave message 'update attributes' has mismatching old-value");

                                  goto fail;
                                }

                              attr[1] = arena_strdup (arena, update->newvalue);

                              break;
                            }
                        }
                    }

                  fprintf (stderr, "    Update attributes\n");
                }
              else
                {
                  VINK_set_error ("Wave document delta contains unrecognized component");

                  goto fail;
                }

              if (new_item)
                {
                  split_item (arena, &prev, &item, &ch);

                  if (prev)
                    {
                      assert (prev->next == item);

                      new_item->next = item;
                      prev->next = new_item;
                    }
                  else
                    {
                      new_item->next = doc->items;
                      doc->items = new_item;
                    }

                  insert_annotations (arena, new_item, prev, annotation_update);

                  prev = new_item;
                  item = new_item->next;
                  ch = (item && item->type == WAVE_ITEM_CHARACTERS) ? item->u.characters : 0;
                }
            }

          if (item)
            {
              VINK_set_error ("Wave document delta didn't run through entire document");

              goto fail;
            }

          if (annotation_update)
            {
              VINK_set_error ("Wave document delta didn't have empty annotation update at the end");

              goto fail;
            }

          fprintf (stderr, "\n");
        }
    }

  fprintf (stderr, "Operations applied: %llu\n", (unsigned long long) applied_delta->operationsapplied);
  fprintf (stderr, "Timestamp: %llu\n", (unsigned long long) applied_delta->applicationtimestamp);

  wave__applied_wavelet_delta__free_unpacked (applied_delta, &protobuf_c_system_allocator);

  return 0;

fail:

  return -1;
}

#include "wave.pb-c.c"
