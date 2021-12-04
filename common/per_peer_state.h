#ifndef LIGHTNING_COMMON_PER_PEER_STATE_H
#define LIGHTNING_COMMON_PER_PEER_STATE_H
#include "config.h"

#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <common/crypto_state.h>

struct gossip_state {
	/* Time for next gossip burst. */
	struct timemono next_gossip;
	/* Timestamp filtering for gossip. */
	u32 timestamp_min, timestamp_max;
};

/* Things we hand between daemons to talk to peers. */
struct per_peer_state {
	/* Cryptographic state needed to exchange messages with the peer (as
	 * featured in BOLT #8) */
	struct crypto_state cs;
	/* NULL if it's not initialized yet */
	struct gossip_state *gs;
	/* Cache of msgs we have received, to avoid re-xmitting from store */
	struct gossip_rcvd_filter *grf;
	/* If not -1, closed on freeing */
	int peer_fd, gossip_fd, gossip_store_fd;
};

/* Allocate a new per-peer state and add destructor to close fds if set;
 * sets fds to -1 and ->gs to NULL.. */
struct per_peer_state *new_per_peer_state(const tal_t *ctx,
					  const struct crypto_state *cs);

/* Initialize the fds (must be -1 previous) */
void per_peer_state_set_fds(struct per_peer_state *pps,
			    int peer_fd, int gossip_fd, int gossip_store_fd);

/* Array version of above: tal_count(fds) must be 3 */
void per_peer_state_set_fds_arr(struct per_peer_state *pps, const int *fds);

/* These routines do *part* of the work: you need to per_peer_state_fdpass_send
 * or receive the three fds afterwards! */
void towire_per_peer_state(u8 **pptr, const struct per_peer_state *pps);
void per_peer_state_fdpass_send(int fd, const struct per_peer_state *pps);

struct per_peer_state *fromwire_per_peer_state(const tal_t *ctx,
					       const u8 **cursor, size_t *max);

void towire_gossip_state(u8 **pptr, const struct gossip_state *gs);
void fromwire_gossip_state(const u8 **cursor, size_t *max,
			   struct gossip_state *gs);

/* How long until we have to check gossip store, if any? */
bool time_to_next_gossip(const struct per_peer_state *pps,
			 struct timerel *t);

/* Reset pps->next_gossip now we've drained gossip_store */
void per_peer_state_reset_gossip_timer(struct per_peer_state *pps);

/* Used to speed up gossip iff DEVELOPER*/
extern bool dev_fast_gossip;

#endif /* LIGHTNING_COMMON_PER_PEER_STATE_H */
