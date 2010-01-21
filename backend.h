#ifndef BACKEND_H_
#define BACKEND_H_ 1

#include "vink.h"

void
backend_init(struct vink_backend_callbacks *callbacks);

void
backend_postgresql_init(struct vink_backend_callbacks *callbacks);

void
backend_file_init(struct vink_backend_callbacks *callbacks);

#endif /* !BACKEND_H_ */
