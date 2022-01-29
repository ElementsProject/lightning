#include "config.h"
#include <assert.h>
#include <lightningd/peer_fd.h>
#include <unistd.h>

static void destroy_peer_fd(struct peer_fd *peer_fd)
{
	if (peer_fd->fd != -1)
		close(peer_fd->fd);
}

struct peer_fd *new_peer_fd(const tal_t *ctx, int peer_fdnum)
{
	struct peer_fd *peer_fd = tal(ctx, struct peer_fd);

	peer_fd->fd = peer_fdnum;
	tal_add_destructor(peer_fd, destroy_peer_fd);
	return peer_fd;
}

struct peer_fd *new_peer_fd_arr(const tal_t *ctx, const int *fd)
{
	/* We expect 1 fd. */
	assert(tal_count(fd) == 1);
	return new_peer_fd(ctx, fd[0]);
}
