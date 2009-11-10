#ifndef ARRAY_H_
#define ARRAY_H_ 1

#define ARRAY_MEMBERS(type)       \
      type* array_elements;       \
      size_t array_element_count; \
      size_t array_element_alloc; \
      int array_result;           \

#define ARRAY_DECLARE(type_name, array) \
  struct type_name array

#define ARRAY_INIT(array)                                                     \
  do                                                                          \
    {                                                                         \
      memset((array), 0, sizeof(*(array)));                                   \
    }                                                                         \
  while(0)

#define ARRAY_ADD(array, value)                                               \
  do                                                                          \
    {                                                                         \
      assert((array)->result == 0);                                           \
      if((array)->element_count == (array)->element_alloc)                    \
        {                                                                     \
          void* tmp;                                                          \
          size_t size;                                                        \
          (array)->element_alloc = (array)->element_alloc * 3 / 2 + 16;       \
          tmp = realloc((array)->array_elements,                              \
                        (array)->element_alloc * sizeof(*(array)->elements)); \
          if(!tmp)                                                            \
            {                                                                 \
              (array)->result = -1;                                           \
              break;                                                          \
            }                                                                 \
          (array)->elements[(array)->element_count++] = value;                \
        }                                                                     \
    }                                                                         \
  while(0)

#define ARRAY_GET(array, index) (array)->elements[(index)]

#define ARRAY_FREE(array)                                                     \
  do                                                                          \
    {                                                                         \
      free((array)->elements);                                                \
      memset((array), 0, sizeof(*(array)));                                   \
    }                                                                         \
  while(0)

#endif /* !ARRAY_H_ */
