#ifndef LIGHTNING_PLUGINS_ASKRENE_ASKRENE_H
#define LIGHTNING_PLUGINS_ASKRENE_ASKRENE_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/list/list.h>
#include <common/amount.h>
#include <common/fp16.h>

struct gossmap_chan;

/* A single route. */
struct route {
	/* Actual path to take */
	struct route_hop *hops;
	/* Probability estimate (0-1) */
	double success_prob;
};

/* Grab-bag of "globals" for this plugin */
struct askrene {
	struct plugin *plugin;
	struct gossmap *gossmap;
	/* List of layers */
	struct list_head layers;
	/* In-flight payment attempts */
	struct reserve_hash *reserved;
	/* Compact cache of gossmap capacities */
	fp16_t *capacities;
};

/* Information for a single route query. */
struct route_query {
	/* Plugin pointer, for logging mainly */
	struct plugin *plugin;

	/* This is *not* updated during a query!  Has all layers applied. */
	const struct gossmap *gossmap;

	/* We need to take in-flight payments into account */
	const struct reserve_hash *reserved;

	/* Array of layers we're applying */
	const struct layer **layers;

	/* Cache of channel capacities for non-reserved, unknown channels. */
	fp16_t *capacities;
};

/* Given a gossmap channel, get the current known min/max */
void get_constraints(const struct route_query *rq,
		     const struct gossmap_chan *chan,
		     int dir,
		     struct amount_msat *min,
		     struct amount_msat *max);

#endif /* LIGHTNING_PLUGINS_ASKRENE_ASKRENE_H */
