#ifndef LIGHTNING_PLUGINS_ASKRENE_ASKRENE_H
#define LIGHTNING_PLUGINS_ASKRENE_ASKRENE_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/bitmap/bitmap.h>
#include <ccan/htable/htable_type.h>
#include <ccan/list/list.h>
#include <common/amount.h>
#include <common/fp16.h>
#include <common/node_id.h>
#include <plugins/libplugin.h>

struct gossmap_chan;

/* Grab-bag of "globals" for this plugin */
struct askrene {
	struct plugin *plugin;
	struct gossmap *gossmap;
	/* Hash table of layers by name */
	struct layer_name_hash *layers;
	/* In-flight payment attempts */
	struct reserve_htable *reserved;
	/* Compact cache of gossmap capacities */
	fp16_t *capacities;
	/* My own id */
	struct node_id my_id;
	/* Aux command for layer */
	struct command *layer_cmd;
	/* How long before we abort trying to find a route? */
	u32 route_seconds;
};

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

/* Useful plugin->askrene mapping */
static inline struct askrene *get_askrene(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct askrene);
}
#endif /* LIGHTNING_PLUGINS_ASKRENE_ASKRENE_H */
