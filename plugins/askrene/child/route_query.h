#ifndef LIGHTNING_PLUGINS_ASKRENE_CHILD_ROUTE_QUERY_H
#define LIGHTNING_PLUGINS_ASKRENE_CHILD_ROUTE_QUERY_H
#include "config.h"
#include <ccan/bitmap/bitmap.h>
/* Child-safe access routines for the route query. */

/* Information for a single route query. */
struct route_query {
	/* This is *not* updated during a query!  Has all layers applied. */
	const struct gossmap *gossmap;

	/* command id to use for reservations we create. */
	const char *cmd_id;

	/* Array of layers we're applying */
	const struct layer **layers;

	/* Compact cache of biases */
	const s8 *biases;

	/* Additional per-htlc cost for local channels */
	const struct additional_cost_htable *additional_costs;

	/* We need to take in-flight payments into account (this is
	 * askrene->reserved, so make sure to undo changes! */
	struct reserve_htable *reserved;

	/* Cache of channel capacities for non-reserved, unknown channels. */
	fp16_t *capacities;

	/* channels we disable during computation to meet constraints */
	bitmap *disabled_chans;
};

/* Given a gossmap channel, get the current known min/max */
void get_constraints(const struct route_query *rq,
		     const struct gossmap_chan *chan,
		     int dir,
		     struct amount_msat *min,
		     struct amount_msat *max);

/* Is there a known additional per-htlc cost for this channel? */
struct amount_msat get_additional_per_htlc_cost(const struct route_query *rq,
						const struct short_channel_id_dir *scidd);

#endif /* LIGHTNING_PLUGINS_ASKRENE_CHILD_ROUTE_QUERY_H */
