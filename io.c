#include <err.h>
#include <stdlib.h>
#include <unistd.h>

#include "io.h"

void
read_all(int fd, void* buf, size_t total, const char* path)
{
  char* cbuf = buf;
  size_t offset = 0;
  int ret;

  while(offset < total)
    {
      ret = read(fd, cbuf, total - offset);

      if(ret == -1)
        err(EXIT_FAILURE, "%s: read error", path);

      if(ret == 0)
        errx(EXIT_FAILURE, "%s: file was truncated while reading (read returned 0)", path);

      offset += ret;
    }
}
