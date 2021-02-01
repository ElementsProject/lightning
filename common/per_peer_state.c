#include "config.h"
#include <assert.h>
#include <ccan/fdpass/fdpass.h>
#include <common/gossip_constants.h>
#include <common/gossip_rcvd_filter.h>
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
	if (pps->gossip_store_fd != -1)
		close(pps->gossip_store_fd);
}

struct per_peer_state *new_per_peer_state(const tal_t *ctx,
					  const struct crypto_state *cs)
{
	struct per_peer_state *pps = tal(ctx, struct per_peer_state);

	pps->cs = *cs;
	pps->gs = NULL;
	pps->peer_fd = pps->gossip_fd = pps->gossip_store_fd = -1;
	pps->grf = new_gossip_rcvd_filter(pps);
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

void towire_gossip_state(u8 **pptr, const struct gossip_state *gs)
{
	towire_u64(pptr, gs->next_gossip.ts.tv_sec);
	towire_u64(pptr, gs->next_gossip.ts.tv_nsec);
	towire_u32(pptr, gs->timestamp_min);
	towire_u32(pptr, gs->timestamp_max);
}

void fromwire_gossip_state(const u8 **cursor, size_t *max,
			   struct gossip_state *gs)
{
	gs->next_gossip.ts.tv_sec = fromwire_u64(cursor, max);
	gs->next_gossip.ts.tv_nsec = fromwire_u64(cursor, max);
	gs->timestamp_min = fromwire_u32(cursor, max);
	gs->timestamp_max = fromwire_u32(cursor, max);
}

void towire_per_peer_state(u8 **pptr, const struct per_peer_state *pps)
{
	towire_crypto_state(pptr, &pps->cs);
	towire_bool(pptr, pps->gs != NULL);
	if (pps->gs)
		towire_gossip_state(pptr, pps->gs);
	/* We don't pass the gossip_rcvd_filter: it's merely an optimization */
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
	struct per_peer_state *pps;

	fromwire_crypto_state(cursor, max, &cs);
	pps = new_per_peer_state(ctx, &cs);
	if (fromwire_bool(cursor, max)) {
		pps->gs = tal(pps, struct gossip_state);
		fromwire_gossip_state(cursor, max, pps->gs);
	}
	return pps;
}

/* FIXME: Put in ccan/time */
/* Is a after b? */
static inline bool timemono_after(struct timemono a, struct timemono b)
{
	return time_greater_(a.ts, b.ts);
}

bool time_to_next_gossip(const struct per_peer_state *pps,
			 struct timerel *t)
{
	if (!pps->gs)
		return false;

	struct timemono now = time_mono();
	if (timemono_after(now, pps->gs->next_gossip))
		*t = time_from_sec(0);
	else
		*t = timemono_between(pps->gs->next_gossip, now);
	return true;
}

/* BOLT #7:
 *
 * A node:
 *...
 *  - SHOULD flush outgoing gossip messages once every 60 seconds,
 *    independently of the arrival times of the messages.
 *    - Note: this results in staggered announcements that are unique
 *      (not duplicated).
 */
void per_peer_state_reset_gossip_timer(struct per_peer_state *pps)
{
	struct timerel t = time_from_sec(GOSSIP_FLUSH_INTERVAL(dev_fast_gossip));

	pps->gs->next_gossip = timemono_add(time_mono(), t);
	gossip_rcvd_filter_age(pps->grf);
}
