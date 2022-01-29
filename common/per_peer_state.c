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
}

struct per_peer_state *new_per_peer_state(const tal_t *ctx)
{
	struct per_peer_state *pps = tal(ctx, struct per_peer_state);

	pps->peer_fd = -1;
	tal_add_destructor(pps, destroy_per_peer_state);
	return pps;
}

void per_peer_state_set_fd(struct per_peer_state *pps, int peer_fd)
{
	assert(pps->peer_fd == -1);
	pps->peer_fd = peer_fd;
}

void per_peer_state_fdpass_send(int fd, const struct per_peer_state *pps)
{
	assert(pps->peer_fd != -1);
	fdpass_send(fd, pps->peer_fd);
}
