#ifndef LIGHTNING_COMMON_PER_PEER_STATE_H
#define LIGHTNING_COMMON_PER_PEER_STATE_H
#include "config.h"

#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <common/crypto_state.h>

/* Things we hand between daemons to talk to peers. */
struct per_peer_state {
	/* If not -1, closed on freeing */
	int peer_fd;
};

/* Allocate a new per-peer state and add destructor to close fds if set;
 * sets peer_fd to -1. */
struct per_peer_state *new_per_peer_state(const tal_t *ctx);

/* Initialize the fds (must be -1 previous) */
void per_peer_state_set_fd(struct per_peer_state *pps, int peer_fd);

void per_peer_state_fdpass_send(int fd, const struct per_peer_state *pps);

#endif /* LIGHTNING_COMMON_PER_PEER_STATE_H */
