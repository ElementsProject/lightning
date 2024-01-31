#include "config.h"
#include <common/timeout.h>
#include <gossipd/gossipd.h>
#include <gossipd/txout_failures.h>

/* Convenience to tell the two failure maps apart */
#define RECENT 0
#define AGED 1

#define MAX_ENTRIES 10000

/* Once an hour, or at 10000 entries, we expire old ones */
static void txout_failures_age(struct txout_failures *txf)
{
	uintmap_clear(&txf->failures[AGED]);
	txf->failures[AGED] = txf->failures[RECENT];
	uintmap_init(&txf->failures[RECENT]);
	txf->num = 0;

	txf->age_timer = new_reltimer(&txf->daemon->timers, txf,
				      time_from_sec(3600),
				      txout_failures_age, txf);
}

struct txout_failures *txout_failures_new(const tal_t *ctx, struct daemon *daemon)
{
	struct txout_failures *txf = tal(ctx, struct txout_failures);

	txf->daemon = daemon;
	uintmap_init(&txf->failures[RECENT]);
	uintmap_init(&txf->failures[AGED]);

	txout_failures_age(txf);
	return txf;
}

void txout_failures_add(struct txout_failures *txf,
			const struct short_channel_id scid)
{
	if (uintmap_add(&txf->failures[RECENT], scid.u64, true)
	    && ++txf->num == MAX_ENTRIES) {
		tal_free(txf->age_timer);
		txout_failures_age(txf);
	}
}

bool in_txout_failures(struct txout_failures *txf,
		       const struct short_channel_id scid)
{
	if (uintmap_get(&txf->failures[RECENT], scid.u64))
		return true;

	/* If we were going to expire it, we no longer are. */
	if (uintmap_get(&txf->failures[AGED], scid.u64)) {
		txout_failures_add(txf, scid);
		return true;
	}
	return false;
}
