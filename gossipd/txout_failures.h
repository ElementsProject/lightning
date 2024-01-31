#ifndef LIGHTNING_GOSSIPD_TXOUT_FAILURES_H
#define LIGHTNING_GOSSIPD_TXOUT_FAILURES_H
#include "config.h"
#include <ccan/intmap/intmap.h>

/* Cache for txout queries that failed. Allows us to skip failed
 * checks if we get another announcement for the same scid. */
struct txout_failures {
	/* Cache for txout queries that failed. Allows us to skip failed
	 * checks if we get another announcement for the same scid. */
	size_t num;
	UINTMAP(bool) failures[2];
	struct oneshot *age_timer;

	/* For access to timers */
	struct daemon *daemon;
};

/**
 * txout_failures_new: allocate a new failure set.
 * @ctx: tal context
 * @daemon: global daemon struct
 */
struct txout_failures *txout_failures_new(const tal_t *ctx, struct daemon *daemon);

/**
 * txout_failures_add: add a failed scid to the set.
 * @txf: the struct txout_failures.
 * @scid: the short_channel_id to add.
 */
void txout_failures_add(struct txout_failures *txf,
			const struct short_channel_id scid);

/**
 * in_txout_failures: is this scid in the set?
 * @txf: the struct txout_failures.
 * @scid: the short_channel_id to test.
 */
bool in_txout_failures(struct txout_failures *txf,
		       const struct short_channel_id scid);

#endif /* LIGHTNING_GOSSIPD_TXOUT_FAILURES_H */
