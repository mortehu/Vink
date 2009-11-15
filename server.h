#ifndef SERVER_H_
#define SERVER_H_ 1

/**
 * Starts listening and processing peer sockets.
 *
 * Called exactly once.
 */
void
server_run();

/**
 * Returns the index of the peer added, or -1 on error.
 */
int
server_connect(const char *domain);

/**
 * Returns the number of connected peers at the moment.
 */
int
server_peer_count();

/**
 * Returns the XMPP state structure of a given peer.
 */
struct xmpp_state*
server_peer_get_state(unsigned int peer_index);

#endif /* !SERVER_H_ */
