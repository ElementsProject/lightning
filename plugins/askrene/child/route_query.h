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

	/* Cache of channel bounds across the selected layers. */
	struct channel_bounds_htable *bounds_htable;
};

/* Given a gossmap channel, get the current known min/max.  Called
 * get_constraints for historical reasons, it combines observations, user
 * constraints and reservations. */
void get_constraints(const struct route_query *rq,
		     const struct gossmap_chan *chan,
		     int dir,
		     struct amount_msat *min,
		     struct amount_msat *max);

/* Get the min/max derived from the layers alone (no reservations), and the
 * layer responsible for the max (NULL if none).  Returns false if no layer
 * has information about this channel. */
bool get_layer_bounds(const struct route_query *rq,
		      const struct short_channel_id_dir *scidd,
		      struct amount_msat *min,
		      struct amount_msat *max,
		      const struct layer **layer);

/* Is there a known additional per-htlc cost for this channel? */
struct amount_msat get_additional_per_htlc_cost(const struct route_query *rq,
						const struct short_channel_id_dir *scidd);

struct route_query *new_route_query(const tal_t *ctx,
				    const struct gossmap *gossmap,
				    const char *cmd_id,
				    const struct layer **layers,
				    const s8 *biases,
				    const struct additional_cost_htable *additional_costs,
				    struct reserve_htable *reserved,
				    fp16_t *capacities TAKES);

#endif /* LIGHTNING_PLUGINS_ASKRENE_CHILD_ROUTE_QUERY_H */
