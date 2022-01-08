#include "config.h"
#include <assert.h>
#include <ccan/fdpass/fdpass.h>
#include <common/gossip_constants.h>
#include <common/per_peer_state.h>
#include <unistd.h>
#include <wire/wire.h>

bool dev_fast_gossip = false;

static void destroy_per_peer_state(struct per_peer_state *pps)
{
	if (pps->peer_fd != -1)
		close(pps->peer_fd);
	if (pps->gossip_fd != -1)
		close(pps->gossip_fd);
}

struct per_peer_state *new_per_peer_state(const tal_t *ctx)
{
	struct per_peer_state *pps = tal(ctx, struct per_peer_state);

	pps->peer_fd = pps->gossip_fd = -1;
	tal_add_destructor(pps, destroy_per_peer_state);
	return pps;
}

void per_peer_state_set_fds(struct per_peer_state *pps,
			    int peer_fd, int gossip_fd)
{
	assert(pps->peer_fd == -1);
	assert(pps->gossip_fd == -1);
	pps->peer_fd = peer_fd;
	pps->gossip_fd = gossip_fd;
}

void per_peer_state_set_fds_arr(struct per_peer_state *pps, const int *fds)
{
	/* We expect 2 fds. */
	assert(tal_count(fds) == 2);
	per_peer_state_set_fds(pps, fds[0], fds[1]);
}

void per_peer_state_fdpass_send(int fd, const struct per_peer_state *pps)
{
	assert(pps->peer_fd != -1);
	assert(pps->gossip_fd != -1);
	fdpass_send(fd, pps->peer_fd);
	fdpass_send(fd, pps->gossip_fd);
}
