#ifndef LIGHTNING_PLUGINS_ASKRENE_ASKRENE_H
#define LIGHTNING_PLUGINS_ASKRENE_ASKRENE_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/htable/htable_type.h>
#include <ccan/list/list.h>
#include <common/amount.h>
#include <common/fp16.h>
#include <common/node_id.h>
#include <plugins/libplugin.h>

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
	struct reserve_htable *reserved;
	/* Compact cache of gossmap capacities */
	fp16_t *capacities;
	/* My own id */
	struct node_id my_id;
};

/* Information for a single route query. */
struct route_query {
	/* Command pointer, mainly for command id. */
	struct command *cmd;

	/* Plugin pointer, for logging mainly */
	struct plugin *plugin;

	/* This is *not* updated during a query!  Has all layers applied. */
	const struct gossmap *gossmap;

	/* We need to take in-flight payments into account */
	const struct reserve_htable *reserved;

	/* Array of layers we're applying */
	const struct layer **layers;

	/* Cache of channel capacities for non-reserved, unknown channels. */
	fp16_t *capacities;

	/* Additional per-htlc cost for local channels */
	const struct additional_cost_htable *additional_costs;
};

/* Given a gossmap channel, get the current known min/max */
void get_constraints(const struct route_query *rq,
		     const struct gossmap_chan *chan,
		     int dir,
		     struct amount_msat *min,
		     struct amount_msat *max);

/* Say something about this route_query */
const char *rq_log(const tal_t *ctx,
		   const struct route_query *rq,
		   enum log_level level,
		   const char *fmt,
		   ...)
	PRINTF_FMT(4, 5);

/* Is there a known additional per-htlc cost for this channel? */
struct amount_msat get_additional_per_htlc_cost(const struct route_query *rq,
						const struct short_channel_id_dir *scidd);

/* Useful plugin->askrene mapping */
static inline struct askrene *get_askrene(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct askrene);
}

/* Convenience routine for hash tables */
static inline size_t hash_scidd(const struct short_channel_id_dir *scidd)
{
	/* scids cost money to generate, so simple hash works here */
	return (scidd->scid.u64 >> 32) ^ (scidd->scid.u64 >> 16) ^ (scidd->scid.u64 << 1) ^ scidd->dir;
}

#endif /* LIGHTNING_PLUGINS_ASKRENE_ASKRENE_H */
