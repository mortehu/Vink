#ifndef DATA_H_
#define DATA_H_ 1

struct wave;
struct wavelet;

void
data_init();

struct wave*
data_wave_create(const char* domain, const char* id);

struct wavelet*
data_wavelet_create(struct wave* wa, const char* domain, const char* id);

int
data_wavelet_add_participant(struct wavelet* wl, const char* participant);

#endif /* !DATA_H_ */
