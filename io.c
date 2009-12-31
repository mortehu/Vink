#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "io.h"
#include "vink-internal.h"

int
read_all(int fd, void* buf, size_t total, const char* path)
{
  char* cbuf = buf;
  size_t offset = 0;
  int ret;

  while(offset < total)
    {
      ret = read(fd, cbuf, total - offset);

      if(ret == -1)
        {
          VINK_set_error("Error reading %zu bytes from '%s': %s",
                         total - offset, path, strerror(errno));

          return -1;
        }

      if(ret == 0)
        {
          VINK_set_error("Error reading %zu bytes from '%s': read returned 0",
                         total - offset, path);

          return -1;
        }

      offset += ret;
    }

  return 0;
}

int
write_all(int fd, void* buf, size_t total, const char* path)
{
  char* cbuf = buf;
  size_t offset = 0;
  int ret;

  while(offset < total)
    {
      ret = write(fd, cbuf, total - offset);

      if(ret == -1)
        {
          VINK_set_error("Error writing %zu bytes to '%s': %s",
                         total - offset, path, strerror(errno));

          return -1;
        }

      if(ret == 0)
        {
          VINK_set_error("Error writing %zu bytes to '%s': write returned 0",
                         total - offset, path);

          return -1;
        }

      offset += ret;
    }

  return 0;
}
