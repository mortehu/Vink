#ifndef ARRAY_H_
#define ARRAY_H_ 1

#define ARRAY_MEMBERS(type)       \
      type* array_elements;       \
      size_t array_element_count; \
      size_t array_element_alloc; \
      int array_result;           \

#define ARRAY_INIT(array)                                                     \
  do                                                                          \
    {                                                                         \
      memset((array), 0, sizeof(*(array)));                                   \
    }                                                                         \
  while(0)

#define ARRAY_ADD(array, value)                                               \
  do                                                                          \
    {                                                                         \
      assert((array)->array_result == 0);                                     \
      if((array)->array_element_count == (array)->array_element_alloc)        \
        {                                                                     \
          void* tmp;                                                          \
          (array)->array_element_alloc                                        \
            = (array)->array_element_alloc * 3 / 2 + 16;                      \
          tmp = realloc((array)->array_elements,                              \
                        (array)->array_element_alloc                          \
                        * sizeof(*(array)->array_elements));                  \
          if(!tmp)                                                            \
            {                                                                 \
              (array)->array_result = -1;                                     \
              break;                                                          \
            }                                                                 \
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
          (array)->array_element_alloc = total * 3 / 2;                       \
          tmp = realloc((array)->array_elements,                              \
                        (array)->array_element_alloc                          \
                        * sizeof(*(array)->array_elements));                  \
          if(!tmp)                                                            \
            {                                                                 \
              (array)->array_result = -1;                                     \
              break;                                                          \
            }                                                                 \
        }                                                                     \
      memcpy((array)->array_elements + (array)->array_element_count,          \
             (values), (count) * sizeof(*(array)->array_elements));           \
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

#define ARRAY_FREE(array)                                                     \
  do                                                                          \
    {                                                                         \
      free((array)->array_elements);                                          \
      memset((array), 0, sizeof(*(array)));                                   \
    }                                                                         \
  while(0)

#endif /* !ARRAY_H_ */