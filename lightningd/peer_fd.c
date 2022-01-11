#include "config.h"
#include <assert.h>
#include <lightningd/peer_fd.h>
#include <unistd.h>

static void destroy_peer_fd(struct peer_fd *peer_fd)
{
	if (peer_fd->fd != -1)
		close(peer_fd->fd);
	if (peer_fd->gossip_fd != -1)
		close(peer_fd->gossip_fd);
}

struct peer_fd *new_peer_fd(const tal_t *ctx, int peer_fdnum, int gossip_fd)
{
	struct peer_fd *peer_fd = tal(ctx, struct peer_fd);

	peer_fd->fd = peer_fdnum;
	peer_fd->gossip_fd = gossip_fd;
	tal_add_destructor(peer_fd, destroy_peer_fd);
	return peer_fd;
}

struct peer_fd *new_peer_fd_arr(const tal_t *ctx, const int *fds)
{
	/* We expect 2 fds. */
	assert(tal_count(fds) == 2);
	return new_peer_fd(ctx, fds[0], fds[1]);
}
