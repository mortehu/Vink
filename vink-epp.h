#ifndef VINK_EPP_H_
#define VINK_EPP_H_ 1

struct vink_epp_state;

struct vink_epp_state *
vink_epp_state_init(int (*write_func)(const void*, size_t, void*),
                    const char *remote_domain, unsigned int flags,
                    void* arg);

int
vink_epp_state_data(struct vink_epp_state *state,
                    const void *data, size_t count);

int
vink_epp_state_finished(struct vink_epp_state *state);

void
vink_epp_state_free(struct vink_epp_state *state);

#endif /* !VINK_EPP_H_ */
