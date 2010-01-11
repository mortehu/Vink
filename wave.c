#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "vink-internal.h"
#include "wave.h"
#include "wave.pb-c.h"

#if 0
static void
wave_init_message(struct wave_message *msg)
{
  ARRAY_INIT(msg);
}

static void
wave_free_message(struct wave_message *msg)
{
  ARRAY_FREE(msg);
}

static int
wave_add_varint(struct wave_message *msg, unsigned int field, uint64_t value)
{
  ARRAY_ADD(msg, (field << 3) | 0);

  do
    {
      if(value > 0x7F)
        ARRAY_ADD(msg, 0x80 | (value & 0x7f));
      else
        ARRAY_ADD(msg, value & 0x7f);

      value >>= 7;
    }
  while(value);

  return ARRAY_RESULT(msg);
}

static int
wave_add_varint_signed(struct wave_message *msg, unsigned int field, int64_t value)
{
  uint64_t uvalue;

  if(value >= 0)
    uvalue *= 2;
  else
    uvalue = -value * 2 - 1;

  return wave_add_varint(msg, field, uvalue);
}

static int
wave_add_int64(struct wave_message *msg, unsigned int field, uint64_t value)
{
  ARRAY_ADD(msg, (field << 3) | 1);

  ARRAY_ADD(msg, (value >> 56));
  ARRAY_ADD(msg, (value >> 48));
  ARRAY_ADD(msg, (value >> 40));
  ARRAY_ADD(msg, (value >> 32));
  ARRAY_ADD(msg, (value >> 24));
  ARRAY_ADD(msg, (value >> 16));
  ARRAY_ADD(msg, (value >> 8));
  ARRAY_ADD(msg, (value));

  return ARRAY_RESULT(msg);
}

static int
wave_add_double(struct wave_message *msg, unsigned int field, double value)
{
  wave_add_int64(msg, field, *(uint64_t*) &value);

  return ARRAY_RESULT(msg);
}

static int
wave_add_bytes(struct wave_message *msg, unsigned int field, const void* string, size_t count)
{
  size_t tmp;

  ARRAY_ADD(msg, (field << 3) | 2);

  tmp = count;

  do
    {
      if(tmp > 0x7F)
        ARRAY_ADD(msg, 0x80 | (tmp & 0x7f));
      else
        ARRAY_ADD(msg, tmp & 0x7f);

      tmp >>= 7;
    }
  while(tmp);

  ARRAY_ADD_SEVERAL(msg, string, count);

  return ARRAY_RESULT(msg);
}

static int
wave_add_message(struct wave_message *target, unsigned int field, const struct wave_message *source)
{
  return wave_add_bytes(target, field, &ARRAY_GET(source, 0), ARRAY_COUNT(source));
}

static void
wave_add_hashed_version(struct wave_message *target, unsigned int field,
                        uint64_t version, const char* hash)
{
  struct wave_message hashed_version;

  wave_init_message(&hashed_version);

  wave_add_varint(&hashed_version, 1, version);
  wave_add_bytes(&hashed_version, 2, hash, strlen(hash));

  wave_add_message(target, field, &hashed_version);
  wave_free_message(&hashed_version);
}

void
wave_add_key_value(struct wave_message *target,
                   unsigned int field, const char *key,
                   const char *value)
{
  struct wave_message key_value_pair;

  wave_init_message(&key_value_pair);

  wave_add_bytes(&key_value_pair, 1, key, strlen(key));
  wave_add_bytes(&key_value_pair, 2, value, strlen(value));

  wave_add_message(target, field, &key_value_pair);
  wave_free_message(&key_value_pair);
}

void
wave_add_key_value_update(struct wave_message *target, unsigned int field,
                          const struct wave_key_value_update* data)
{
  struct wave_message key_value_update;

  wave_init_message(&key_value_update);

  wave_add_bytes(&key_value_update, 1, data->key, strlen(data->key));
  wave_add_bytes(&key_value_update, 2, data->old_value,
                 strlen(data->old_value));
  wave_add_bytes(&key_value_update, 3, data->new_value,
                 strlen(data->new_value));

  wave_add_message(target, field, &key_value_update);
  wave_free_message(&key_value_update);
}

void
wave_wavelet_delta(struct wave_message *target, uint64_t version,
                   const char *hash, const char *author,
                   const char *address_path)
{
  wave_add_hashed_version(target, 1, version, hash);
  wave_add_bytes(target, 2, author, strlen(author));

  while(*address_path)
    {
      wave_add_bytes(target, 4, address_path, strlen(address_path));
      address_path = strchr(address_path, 0) + 1;
    }
}

void
wave_wavelet_add_participant(struct wave_message *delta,
                             const char *address)
{
  struct wave_message operation;

  wave_init_message(&operation);
  wave_add_bytes(&operation, 1, address, strlen(address));
  wave_add_message(delta, 3, &operation);
  wave_free_message(&operation);
}

void
wave_wavelet_remove_participant(struct wave_message *delta,
                                const char *address)
{
  struct wave_message operation;

  wave_init_message(&operation);
  wave_add_bytes(&operation, 2, address, strlen(address));
  wave_add_message(delta, 3, &operation);
  wave_free_message(&operation);
}

void
wave_wavelet_mutate_document(struct wave_message *delta,
                             const char *doc_id,
                             const struct wave_message *doc_operation)
{
  struct wave_message operation;
  struct wave_message mutate_document;

  wave_init_message(&operation);
  wave_init_message(&mutate_document);

  wave_add_bytes(&mutate_document, 1, doc_id, strlen(doc_id));
  wave_add_message(&mutate_document, 2, doc_operation);

  wave_add_message(&operation, 3, &mutate_document);
  wave_add_message(delta, 3, &operation);
  wave_free_message(&mutate_document);
  wave_free_message(&operation);
}

void
wave_wavelet_noop(struct wave_message *delta)
{
  struct wave_message operation;

  wave_init_message(&operation);

  wave_add_varint(&operation, 4, 1);

  wave_add_message(delta, 3, &operation);
  wave_free_message(&operation);
}

void
wave_wavelet_annotation_boundary(struct wave_message *doc_operation,
                                 struct wave_annotation_boundary *data)
{
  struct wave_message component;
  struct wave_message annotation_boundary;
  size_t i;

  wave_init_message(&component);
  wave_init_message(&annotation_boundary);

  if(!data->end_count && !data->change_count)
    {
      wave_add_varint(&annotation_boundary, 1, 1);
    }
  else
    {
      for(i = 0; i < data->end_count; ++i)
        wave_add_bytes(&annotation_boundary, 2, data->ends[i], strlen(data->ends[i]));

      for(i = 0; i < data->change_count; ++i)
        wave_add_key_value_update(&annotation_boundary, 3, &data->changes[i]);
    }

  wave_add_message(&component, 1, &annotation_boundary);
  wave_add_message(doc_operation, 1, &component);
  wave_free_message(&annotation_boundary);
  wave_free_message(&component);
}

void
wave_wavelet_characters(struct wave_message *doc_operation,
                        const char *data)
{
  struct wave_message component;

  wave_init_message(&component);

  wave_add_bytes(&component, 2, data, strlen(data));

  wave_add_message(doc_operation, 1, &component);
  wave_free_message(&component);
}

void
wave_wavelet_element_end(struct wave_message *doc_operation)
{
  struct wave_message component;

  wave_init_message(&component);

  wave_add_varint(&component, 4, 1);

  wave_add_message(doc_operation, 1, &component);
  wave_free_message(&component);
}

void
wave_wavelet_retain_item_count(struct wave_message *doc_operation,
                               int data)
{
  struct wave_message component;

  wave_init_message(&component);

  wave_add_varint(&component, 5, data);

  wave_add_message(doc_operation, 1, &component);
  wave_free_message(&component);
}

void
wave_wavelet_delete_element_end(struct wave_message *doc_operation)
{
  struct wave_message component;

  wave_init_message(&component);

  wave_add_varint(&component, 8, 1);

  wave_add_message(doc_operation, 1, &component);
  wave_free_message(&component);
}

void
wave_wavelet_delete_characters(struct wave_message *doc_operation,
                               const char *data)
{
  struct wave_message component;

  wave_init_message(&component);

  wave_add_bytes(&component, 6, data, strlen(data));

  wave_add_message(doc_operation, 1, &component);
  wave_free_message(&component);
}
#endif

struct wave_wavelet *
wave_wavelet_create()
{
  struct wave_wavelet *result = 0;
  struct arena_info arena;

  arena_init(&arena);

  result = arena_calloc(&arena, sizeof(*result));

  if(!result)
      return 0;

  memcpy(&result->arena, &arena, sizeof(arena));

  return result;
}

int
wave_apply_delta(struct wave_wavelet *wavelet,
                 const void *data, size_t size,
                 const char *wavelet_name)
{
  Wave__AppliedWaveletDelta *applied_delta;
  Wave__WaveletDelta *delta;
  size_t i, operation_idx;
  struct arena_info *arena;

  arena = &wavelet->arena;

  applied_delta = wave__applied_wavelet_delta__unpack(&protobuf_c_system_allocator, size, data);

  delta = applied_delta->signedoriginaldelta->delta;

  fprintf(stderr, "Version: %llu\n", (unsigned long long) delta->hashedversion->version);
  fprintf(stderr, "Author: %s\n", delta->author);
  fprintf(stderr, "Operations: %zu\n", delta->n_operation);

  for(operation_idx = 0; operation_idx < delta->n_operation; ++operation_idx)
    {
      Wave__WaveletOperation *op;

      op = delta->operation[operation_idx];

      if(op->addparticipant)
        {
          struct wave_participant *p;

          p = arena_alloc(arena, sizeof(*p));

          if(!p)
            goto fail;

          p->address = arena_strdup(arena, op->addparticipant);
          p->next = wavelet->participants;
          wavelet->participants = p;
        }
      else if(op->removeparticipant)
        {
          struct wave_participant *p, *prev;

          for(p = wavelet->participants; p; p = p->next)
            {
              if(!strcmp(p->address, op->removeparticipant))
                break;

              prev = p;
            }

          if(!prev)
            wavelet->participants = p->next;
          else
            prev->next = p->next;
        }
      else if(op->mutatedocument)
        {
          Wave__DocumentOperation *doc_op;
          size_t component_idx;

          struct wave_document *doc;
          struct wave_item *item, *prev = 0;

#ifndef NDEBUG
          size_t target_count = 0, after_count;
          struct wave_item *tmp_item;
#endif

          doc_op = op->mutatedocument->documentoperation;

          for(doc = wavelet->documents; doc; doc = doc->next)
            {
              if(!strcmp(doc->id, op->mutatedocument->documentid))
                break;
            }

          if(!doc)
            {
              fprintf(stderr, "New document: %s\n", op->mutatedocument->documentid);
              doc = arena_calloc(arena, sizeof(*doc));
              doc->id = arena_strdup(arena, op->mutatedocument->documentid);
              doc->next = wavelet->documents;
              wavelet->documents = doc;
            }
          else
            fprintf(stderr, "Old document: %s\n", op->mutatedocument->documentid);

#ifndef NDEBUG
          for(tmp_item = doc->items; tmp_item; tmp_item = tmp_item->next)
            ++target_count;
#endif

          item = doc->items;

          for(component_idx = 0; component_idx < doc_op->n_component; ++component_idx)
            {
              Wave__DocumentOperation__Component *c;
              struct wave_item *new_item = 0;

              c = doc_op->component[component_idx];

              if(c->annotationboundary)
                {
                  Wave__DocumentOperation__Component__AnnotationBoundary *ab;

                  fprintf(stderr, "Annotation boundary\n");

                  ab = c->annotationboundary;

#if 0
                  if(ab->has_empty)
                    fprintf(stderr, "<annotation/>\n");
                  else if(ab->n_end)
                    {
                      size_t end_idx;

                      fprintf(stderr, "<annotation-end");

                      for(end_idx = 0; end_idx < ab->n_end; ++end_idx)
                        {
                          fprintf(stderr,  " %1$s='%1$s'\n",
                                  ab->end[end_idx]);
                        }
                      fprintf(stderr, "/>");
                    }
                  else if(ab->n_change)
                    {
                      size_t change_idx;

                      for(change_idx = 0; change_idx < ab->n_change; ++change_idx)
                        {
                          fprintf(stderr, "    Annotation change: %s => %s (was %s)\n",
                                  ab->change[change_idx]->key,
                                  ab->change[change_idx]->newvalue,
                                  ab->change[change_idx]->oldvalue);
                        }
                    }
#endif
                }
              else if(c->characters)
                {
                  fprintf(stderr, "Characters\n");

#ifndef NDEBUG
                  ++target_count;
#endif

                  new_item = arena_calloc(arena, sizeof(*new_item));
                  new_item->type = WAVE_ITEM_CHARACTERS;
                  new_item->u.characters = arena_strdup(arena, c->characters);
                }
              else if(c->elementstart)
                {
                  fprintf(stderr, "Element start\n");

                  Wave__DocumentOperation__Component__ElementStart *es;
                  char** attributes;

#ifndef NDEBUG
                  ++target_count;
#endif

                  es = c->elementstart;

                  new_item = arena_calloc(arena, sizeof(*new_item));
                  new_item->type = WAVE_ITEM_TAG_START;
                  new_item->u.tag_start.name = arena_strdup(arena, es->type);
                  attributes = arena_alloc(arena, sizeof(char*) * (es->n_attribute + 1));

                  for(i = 0; i < es->n_attribute; ++i)
                    {
                      attributes[i * 2] = arena_strdup(arena, es->attribute[i]->key);
                      attributes[i * 2 + 1] = arena_strdup(arena, es->attribute[i]->value);
                    }

                  attributes[i * 2] = 0;
                  attributes[i * 2 + 1] = 0;

                  new_item->u.tag_start.attributes = attributes;
                }
              else if(c->has_elementend)
                {
                  fprintf(stderr, "Element end\n");

#ifndef NDEBUG
                  ++target_count;
#endif

                  new_item = arena_calloc(arena, sizeof(*new_item));
                  new_item->type = WAVE_ITEM_TAG_END;
                }
              else if(c->has_retainitemcount)
                {
                  fprintf(stderr, "Retain %zu items\n", (size_t) c->retainitemcount);

                  for(i = 0; i < c->retainitemcount; ++i)
                    {
                      if(!item)
                        {
                          VINK_set_error("Wave message 'retain items' went past the end of a document");

                          goto fail;
                        }

                      prev = item;
                      item = item->next;
                    }
                }
              else if(c->deletecharacters)
                {
                  fprintf(stderr, "Delete characters\n");

#ifndef NDEBUG
                  --target_count;
#endif

                  if(!item)
                    {
                      VINK_set_error("Wave message 'delete characters' encountered past the end of a document");

                      goto fail;
                    }

                  if(item->type != WAVE_ITEM_CHARACTERS)
                    {
                      VINK_set_error("Wave message 'delete characters' encountered on a non-character item");

                      goto fail;
                    }

                  if(strcmp(item->u.characters, c->deletecharacters))
                    {
                      VINK_set_error("Characters in wave message 'delete characters' does not match those in the document");

                      goto fail;
                    }

                  if(prev)
                    prev->next = item->next;
                  else
                    doc->items = item->next;

                  item = item->next;
                }
              else if(c->deleteelementstart)
                {
                  fprintf(stderr, "Delete element start\n");

                  Wave__DocumentOperation__Component__ElementStart *es;

#ifndef NDEBUG
                  --target_count;
#endif

                  es = c->deleteelementstart;

                  if(!item)
                    {
                      VINK_set_error("Wave message 'delete element start' encountered past the end of a document");

                      goto fail;
                    }

                  if(item->type != WAVE_ITEM_TAG_START)
                    {
                      VINK_set_error("Wave message 'delete element start' encountered on an unsupported item");

                      goto fail;
                    }

                  if(strcmp(item->u.tag_start.name, es->type))
                    {
                      VINK_set_error("Wave message 'delete element start' encountered on element with non-matching name");

                      goto fail;
                    }

                  /* XXX: Does it hurt us to assume that the attributes were the same? */

                  if(prev)
                    prev->next = item->next;
                  else
                    doc->items = item->next;

                  item = item->next;
                }
              else if(c->has_deleteelementend)
                {
                  fprintf(stderr, "Delete element end\n");

#ifndef NDEBUG
                  --target_count;
#endif

                  if(!item)
                    {
                      VINK_set_error("Wave message 'delete element end' encountered past the end of a document");

                      goto fail;
                    }

                  if(item->type != WAVE_ITEM_TAG_END)
                    {
                      VINK_set_error("Wave message 'delete element end' encountered on an unsupported item");

                      goto fail;
                    }

                  if(prev)
                    prev->next = item->next;
                  else
                    doc->items = item->next;

                  item = item->next;
                }
              else if(c->replaceattributes)
                {
                  fprintf(stderr, "Replace attributes\n");

                  Wave__DocumentOperation__Component__ReplaceAttributes* ra;

                  ra = c->replaceattributes;

                  if(!item)
                    {
                      VINK_set_error("Wave message 'replace attributes' encountered past the end of a document");

                      goto fail;
                    }

                  if(item->type != WAVE_ITEM_TAG_START)
                    {
                      VINK_set_error("Wave message 'replace attributes' encountered on an unsupported item");

                      goto fail;
                    }

                  /* XXX: Does it hurt us to assume that the attributes were the same? */

                  if(ra->n_newattribute)
                    {
                      char **attributes;

                      attributes = arena_alloc(arena, sizeof(char*) * (ra->n_newattribute + 1));

                      for(i = 0; i < ra->n_newattribute; ++i)
                        {
                          attributes[i * 2] = arena_strdup(arena, ra->newattribute[i]->key);
                          attributes[i * 2 + 1] = arena_strdup(arena, ra->newattribute[i]->value);
                        }

                      attributes[i * 2] = 0;
                      attributes[i * 2 + 1] = 0;

                      item->u.tag_start.attributes = attributes;
                    }
                  else
                    item->u.tag_start.attributes = 0;
                }
              else if(c->updateattributes)
                fprintf(stderr, "    Update attributes\n");
              else
                fprintf(stderr, "    ????\n");

              if(new_item)
                {
                  if(prev)
                    {
                      assert(prev->next == item);

                      new_item->next = item;
                      prev->next = new_item;
                    }
                  else
                    {
                      new_item->next = doc->items;
                      doc->items = new_item;
                    }

                  prev = new_item;
                  item = new_item->next;
                }

#ifndef NDEBUG
              after_count = 0;

              for(tmp_item = doc->items; tmp_item; tmp_item = tmp_item->next)
                ++after_count;

              assert(after_count == target_count);
#endif
            }

          assert(!item);

          if(item)
            {
              VINK_set_error("Wave document delta didn't run through entire document (%zu items)", target_count);

              goto fail;
            }

          fprintf(stderr, "\n");
        }
    }

  fprintf(stderr, "Operations applied: %llu\n", (unsigned long long) applied_delta->operationsapplied);
  fprintf(stderr, "Timestamp: %llu\n", (unsigned long long) applied_delta->applicationtimestamp);

  return 0;

fail:

  return -1;
}

#include "wave.pb-c.c"
