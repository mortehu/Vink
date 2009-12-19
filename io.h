#ifndef VINK_IO_H_
#define VINK_IO_H_ 1

int
read_all(int fd, void* buf, size_t total, const char* path);

int
write_all(int fd, void* buf, size_t total, const char* path);

#endif /* !VINK_IO_H_ */
