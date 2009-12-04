#ifndef VINK_H_
#define VINK_H_ 1

struct vink_client;

void
vink_init();

/* Client functions */

struct vink_client *
vink_client_alloc();

struct xmpp_state *
vink_client_state(struct vink_client *cl);

int
vink_client_connect(struct vink_client *cl, const char *domain);

void
vink_client_run(struct vink_client *cl);

/* Utility functions */
char*
vink_xml_escape(const char* data, size_t size);

#endif /* !VINK_H_ */
