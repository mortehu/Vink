#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <err.h>

#include "backend.h"

void
backend_init (struct vink_backend_callbacks *callbacks)
{
  const char *backend;

  backend = vink_config ("backend.type");

  if (!strcasecmp (backend, "postgresql"))
    backend_postgresql_init (callbacks);
  else if (!strcasecmp (backend, "file"))
    backend_file_init (callbacks);
  else
    errx (EXIT_FAILURE, "Unsupported backend type '%s'", backend);
}
