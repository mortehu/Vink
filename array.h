#ifndef ARRAY_H_
#define ARRAY_H_ 1

#include <assert.h>

#define ARRAY_MEMBERS(type)       \
      type* array_elements;       \
      size_t array_element_count; \
      size_t array_element_alloc; \
      int array_result;           \

#define ARRAY(type)               \
  struct                          \
    {                             \
      ARRAY_MEMBERS(type);        \
    }                             \

#define ARRAY_INIT(array)                                                     \
  do                                                                          \
    {                                                                         \
      (array)->array_elements = 0;                                            \
      (array)->array_element_count = 0;                                       \
      (array)->array_element_alloc = 0;                                       \
      (array)->array_result = 0;                                              \
    }                                                                         \
  while(0)

#define ARRAY_RESERVE(array, count)                                           \
  do                                                                          \
    {                                                                         \
      size_t ccount = (count);                                                \
      if((array)->array_element_alloc < ccount)                               \
        {                                                                     \
          void* tmp;                                                          \
          tmp = realloc((array)->array_elements,                              \
                        ccount * sizeof(*(array)->array_elements));           \
          if(!tmp)                                                            \
            {                                                                 \
              (array)->array_result = -1;                                     \
              break;                                                          \
            }                                                                 \
          (array)->array_elements = tmp;                                      \
          (array)->array_element_alloc = ccount;                              \
        }                                                                     \
    }                                                                         \
  while(0)

#define ARRAY_ADD(array, value)                                               \
  do                                                                          \
    {                                                                         \
      assert((array)->array_result == 0);                                     \
      if((array)->array_element_count == (array)->array_element_alloc)        \
        {                                                                     \
          void* tmp;                                                          \
          size_t new_alloc;                                                   \
          new_alloc = (array)->array_element_alloc * 3 / 2 + 16;              \
          tmp = realloc((array)->array_elements,                              \
                        new_alloc * sizeof(*(array)->array_elements));        \
          if(!tmp)                                                            \
            {                                                                 \
              (array)->array_result = -1;                                     \
              break;                                                          \
            }                                                                 \
          (array)->array_elements = tmp;                                      \
          (array)->array_element_alloc = new_alloc;                           \
        }                                                                     \
      (array)->array_elements[(array)->array_element_count++] = value;        \
    }                                                                         \
  while(0)

#define ARRAY_ADD_SEVERAL(array, values, count)                               \
  do                                                                          \
    {                                                                         \
      size_t total;                                                           \
      assert((array)->array_result == 0);                                     \
      total = (array)->array_element_count + (count);                         \
      if(total > (array)->array_element_alloc)                                \
        {                                                                     \
          void* tmp;                                                          \
          size_t new_alloc = total * 3 / 2;                                   \
          tmp = realloc((array)->array_elements,                              \
                        new_alloc * sizeof(*(array)->array_elements));        \
          if(!tmp)                                                            \
            {                                                                 \
              (array)->array_result = -1;                                     \
              break;                                                          \
            }                                                                 \
          (array)->array_elements = tmp;                                      \
          (array)->array_element_alloc = new_alloc;                           \
        }                                                                     \
      memcpy((array)->array_elements + (array)->array_element_count,          \
             (values), (count) * sizeof(*(array)->array_elements));           \
      (array)->array_element_count += (count);                                \
    }                                                                         \
  while(0)

#define ARRAY_INSERT_SEVERAL(array, index, values, count)                     \
  do                                                                          \
    {                                                                         \
      size_t total, cindex, ccount;                                           \
      assert((array)->array_result == 0);                                     \
      cindex = (index);                                                       \
      ccount = (count);                                                       \
      total = (array)->array_element_count + ccount;                          \
      if(total > (array)->array_element_alloc)                                \
        {                                                                     \
          void* tmp;                                                          \
          size_t new_alloc = total * 3 / 2;                                   \
          tmp = realloc((array)->array_elements,                              \
                        new_alloc * sizeof(*(array)->array_elements));        \
          if(!tmp)                                                            \
            {                                                                 \
              (array)->array_result = -1;                                     \
              break;                                                          \
            }                                                                 \
          (array)->array_elements = tmp;                                      \
          (array)->array_element_alloc = new_alloc;                           \
        }                                                                     \
      memmove((array)->array_elements + cindex + ccount,                      \
              (array)->array_elements + cindex,                               \
              (((array)->array_element_count - cindex)                        \
              * sizeof(*(array)->array_elements)));                           \
      memcpy((array)->array_elements + cindex,                                \
             (values), ccount * sizeof(*(array)->array_elements));            \
      (array)->array_element_count += (count);                                \
    }                                                                         \
  while(0)

#define ARRAY_CONSUME(array, count)                                           \
  do                                                                          \
    {                                                                         \
      (array)->array_element_count -= (count);                                \
      memmove((array)->array_elements,                                        \
              (array)->array_elements + count,                                \
              (array)->array_element_count);                                  \
    }                                                                         \
  while(0)

#define ARRAY_COUNT(array) (array)->array_element_count

#define ARRAY_GET(array, index) (array)->array_elements[(index)]

#define ARRAY_RESULT(array) (array)->array_result

#define ARRAY_RESET(array) do { (array)->array_element_count = 0; } while(0)

#define ARRAY_FREE(array)                                                     \
  do                                                                          \
    {                                                                         \
      free((array)->array_elements);                                          \
      (array)->array_elements = 0;                                            \
      (array)->array_element_count = 0;                                       \
      (array)->array_element_alloc = 0;                                       \
      (array)->array_result = 0;                                              \
    }                                                                         \
  while(0)

#endif /* !ARRAY_H_ */
