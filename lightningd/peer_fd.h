#ifndef LIGHTNING_LIGHTNINGD_PEER_FD_H
#define LIGHTNING_LIGHTNINGD_PEER_FD_H
#include "config.h"
#include <ccan/tal/tal.h>

/* This name is a little preemptive: it still contains the gossip_fd
 * for now! */
struct peer_fd {
	/* If not -1, closed on freeing */
	int fd;
	int gossip_fd;
};

/* Allocate a new per-peer state and add destructor to close fds if set;
 * sets fds to -1. */
struct peer_fd *new_peer_fd(const tal_t *ctx, int peer_fd, int gossip_fd);

/* Array version of above: tal_count(fds) must be 2 */
struct peer_fd *new_peer_fd_arr(const tal_t *ctx, const int *fds);

#endif /* LIGHTNING_LIGHTNINGD_PEER_FD_H */
