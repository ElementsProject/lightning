#ifndef LIGHTNING_LIGHTNINGD_PEER_FD_H
#define LIGHTNING_LIGHTNINGD_PEER_FD_H
#include "config.h"
#include <ccan/tal/tal.h>

/* Tal wrapper for fd connecting subd to connectd */
struct peer_fd {
	/* If not -1, closed on freeing */
	int fd;
};

/* Allocate a new per-peer state and add destructor to close fd if set. */
struct peer_fd *new_peer_fd(const tal_t *ctx, int peer_fd);

/* Array version of above: tal_count(fds) must be 1 */
struct peer_fd *new_peer_fd_arr(const tal_t *ctx, const int *fd);

#endif /* LIGHTNING_LIGHTNINGD_PEER_FD_H */
