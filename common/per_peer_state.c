#include <assert.h>
#include <ccan/fdpass/fdpass.h>
#include <common/per_peer_state.h>
#include <unistd.h>

static void destroy_per_peer_state(struct per_peer_state *pps)
{
	if (pps->peer_fd != -1)
		close(pps->peer_fd);
	if (pps->gossip_fd != -1)
		close(pps->gossip_fd);
	if (pps->gossip_store_fd != -1)
		close(pps->gossip_store_fd);
}

struct per_peer_state *new_per_peer_state(const tal_t *ctx,
					  const struct crypto_state *cs)
{
	struct per_peer_state *pps = tal(ctx, struct per_peer_state);

	pps->cs = *cs;
	pps->peer_fd = pps->gossip_fd = pps->gossip_store_fd = -1;
	tal_add_destructor(pps, destroy_per_peer_state);
	return pps;
}

void per_peer_state_set_fds(struct per_peer_state *pps,
			    int peer_fd, int gossip_fd, int gossip_store_fd)
{
	assert(pps->peer_fd == -1);
	assert(pps->gossip_fd == -1);
	assert(pps->gossip_store_fd == -1);
	pps->peer_fd = peer_fd;
	pps->gossip_fd = gossip_fd;
	pps->gossip_store_fd = gossip_store_fd;
}

void per_peer_state_set_fds_arr(struct per_peer_state *pps, const int *fds)
{
	/* We expect 3 fds. */
	assert(tal_count(fds) == 3);
	per_peer_state_set_fds(pps, fds[0], fds[1], fds[2]);
}

void towire_per_peer_state(u8 **pptr, const struct per_peer_state *pps)
{
	towire_crypto_state(pptr, &pps->cs);
}

void per_peer_state_fdpass_send(int fd, const struct per_peer_state *pps)
{
	assert(pps->peer_fd != -1);
	assert(pps->gossip_fd != -1);
	assert(pps->gossip_store_fd != -1);
	fdpass_send(fd, pps->peer_fd);
	fdpass_send(fd, pps->gossip_fd);
	fdpass_send(fd, pps->gossip_store_fd);
}

struct per_peer_state *fromwire_per_peer_state(const tal_t *ctx,
					       const u8 **cursor, size_t *max)
{
	struct crypto_state cs;

	fromwire_crypto_state(cursor, max, &cs);
	return new_per_peer_state(ctx, &cs);
}
