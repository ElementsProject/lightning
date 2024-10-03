#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/route.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/explain_failure.h>
#include <plugins/askrene/layer.h>
#include <plugins/askrene/reserve.h>

#define NO_USABLE_PATHS_STRING "We could not find a usable set of paths."

/* Dijkstra, reduced to ignore anything but connectivity */
static bool always_true(const struct gossmap *map,
			const struct gossmap_chan *c,
			int dir,
			struct amount_msat amount,
			void *unused)
{
	return true;
}

static u64 route_score_one(struct amount_msat fee UNUSED,
			   struct amount_msat risk UNUSED,
			   struct amount_msat total UNUSED,
			   int dir UNUSED,
			   const struct gossmap_chan *c UNUSED)
{
	return 1;
}

/* This mirrors get_constraints() */
static const char *why_max_constrained(const tal_t *ctx,
				       const struct route_query *rq,
				       struct short_channel_id_dir *scidd,
				       struct amount_msat amount)
{
	char *ret = NULL;
	const char *reservations;
	const struct layer *constrains = NULL;
	struct amount_msat max = amount;

	/* Figure out the layer that constrains us (most) */
	for (size_t i = 0; i < tal_count(rq->layers); i++) {
		struct amount_msat min = AMOUNT_MSAT(0), new_max = max;

		layer_apply_constraints(rq->layers[i], scidd, &min, &new_max);
		if (!amount_msat_eq(new_max, max))
			constrains = rq->layers[i];
		max = new_max;
	}

	if (constrains) {
		if (!ret)
			ret = tal_strdup(ctx, "");
		else
			tal_append_fmt(&ret, ", ");
		tal_append_fmt(&ret, "layer %s says max is %s",
			       layer_name(constrains),
			       fmt_amount_msat(tmpctx, max));
	}

	reservations = fmt_reservations(tmpctx, rq->reserved, scidd);
	if (reservations) {
		if (!ret)
			ret = tal_strdup(ctx, "");
		else
			tal_append_fmt(&ret, " and ");
		tal_append_fmt(&ret, "already reserved %s", reservations);
	}

	/* If that doesn't explain it, perhaps it violates htlc_max? */
	if (!ret) {
		struct gossmap_chan *c = gossmap_find_chan(rq->gossmap, &scidd->scid);
		fp16_t htlc_max = c->half[scidd->dir].htlc_max;
		if (amount_msat_greater_fp16(amount, htlc_max))
			ret = tal_fmt(ctx, "exceeds htlc_maximum_msat ~%s",
				      fmt_amount_msat(tmpctx,
						      amount_msat(fp16_to_u64(htlc_max))));
	}

	/* This seems unlikely, but don't return NULL. */
	if (!ret)
		ret = tal_fmt(ctx, "is constrained");
	return ret;
}

struct stat {
	size_t num_channels;
	struct amount_msat capacity;
};

struct node_stats {
	struct stat total, gossip_known, enabled;
};

enum node_direction {
	INTO_NODE,
	OUT_OF_NODE,
};

static void add_stat(struct stat *stat,
		     struct amount_msat amount)
{
	stat->num_channels++;
	if (!amount_msat_accumulate(&stat->capacity, amount))
		abort();
}

static void node_stats(const struct route_query *rq,
		       const struct gossmap_node *node,
		       enum node_direction node_direction,
		       struct node_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	for (size_t i = 0; i < node->num_chans; i++) {
		int dir;
		struct gossmap_chan *c;
		struct amount_msat cap_msat;

		c = gossmap_nth_chan(rq->gossmap, node, i, &dir);
		cap_msat = gossmap_chan_get_capacity(rq->gossmap, c);

		if (node_direction == INTO_NODE)
			dir = !dir;

		add_stat(&stats->total, cap_msat);
		if (gossmap_chan_set(c, dir))
			add_stat(&stats->gossip_known, cap_msat);
		if (c->half[dir].enabled)
			add_stat(&stats->enabled, cap_msat);
	}
}

static const char *check_capacity(const tal_t *ctx,
				  const struct route_query *rq,
				  const struct gossmap_node *node,
				  enum node_direction node_direction,
				  struct amount_msat amount,
				  const char *name)
{
	struct node_stats stats;

	node_stats(rq, node, node_direction, &stats);
	if (amount_msat_greater(amount, stats.total.capacity)) {
		return tal_fmt(ctx,
			       NO_USABLE_PATHS_STRING
			       "  Total %s capacity is only %s"
			       " (in %zu channels).",
			       name,
			       fmt_amount_msat(tmpctx, stats.total.capacity),
			       stats.total.num_channels);
	}
	if (amount_msat_greater(amount, stats.gossip_known.capacity)) {
		return tal_fmt(ctx,
			       NO_USABLE_PATHS_STRING
			       "  Missing gossip for %s: only known %zu/%zu channels, leaving capacity only %s of %s.",
			       name,
			       stats.gossip_known.num_channels,
			       stats.total.num_channels,
			       fmt_amount_msat(tmpctx, stats.gossip_known.capacity),
			       fmt_amount_msat(tmpctx, stats.total.capacity));
	}
	if (amount_msat_greater(amount, stats.enabled.capacity)) {
		return tal_fmt(ctx,
			       NO_USABLE_PATHS_STRING
			       "  The %s has disabled %zu of %zu channels, leaving capacity only %s of %s.",
			       name,
			       stats.total.num_channels - stats.enabled.num_channels,
			       stats.total.num_channels,
			       fmt_amount_msat(tmpctx, stats.enabled.capacity),
			       fmt_amount_msat(tmpctx, stats.total.capacity));
	}
	return NULL;
}

/* Return description of why scidd is disabled scidd */
static const char *describe_disabled(const tal_t *ctx,
				  const struct route_query *rq,
				  const struct short_channel_id_dir *scidd)
{
	for (int i = tal_count(rq->layers) - 1; i >= 0; i--) {
		if (layer_disables(rq->layers[i], scidd)) {
			return tal_fmt(ctx, "marked disabled by layer %s.",
				       layer_name(rq->layers[i]));
		}
	}

	return tal_fmt(ctx, "marked disabled by gossip message.");
}

static const char *describe_capacity(const tal_t *ctx,
				     const struct route_query *rq,
				     const struct short_channel_id_dir *scidd,
				     struct amount_msat amount)
{
	for (int i = tal_count(rq->layers) - 1; i >= 0; i--) {
		if (layer_created(rq->layers[i], scidd->scid)) {
			return tal_fmt(ctx, " (created by layer %s) isn't big enough to carry %s.",
				       layer_name(rq->layers[i]),
				       fmt_amount_msat(tmpctx, amount));
		}
	}

	return tal_fmt(ctx, "isn't big enough to carry %s.",
		       fmt_amount_msat(tmpctx, amount));
}

/* We failed to find a flow at all.  Why? */
const char *explain_failure(const tal_t *ctx,
			    const struct route_query *rq,
			    const struct gossmap_node *srcnode,
			    const struct gossmap_node *dstnode,
			    struct amount_msat amount)
{
	const struct route_hop *hops;
	const struct dijkstra *dij;
	char *path;
	const char *cap_check;

	/* Do we have enough funds? */
	cap_check = check_capacity(ctx, rq, srcnode, OUT_OF_NODE,
				   amount, "source");
	if (cap_check)
		return cap_check;

	/* Does destination have enough capacity? */
	cap_check = check_capacity(ctx, rq, dstnode, INTO_NODE,
				   amount, "destination");
	if (cap_check)
		return cap_check;

	/* OK, fall back to telling them why didn't shortest path
	 * work.  This covers the "but I have a direct channel!"
	 * case. */
	dij = dijkstra(tmpctx, rq->gossmap, dstnode, AMOUNT_MSAT(0), 0,
		       always_true, route_score_one, NULL);
	hops = route_from_dijkstra(tmpctx, rq->gossmap, dij, srcnode,
				   AMOUNT_MSAT(0), 0);
	if (!hops)
		return tal_fmt(ctx, "There is no connection between source and destination at all");

	/* Description of shortest path */
	path = tal_strdup(tmpctx, "");
	for (size_t i = 0; i < tal_count(hops); i++) {
		tal_append_fmt(&path, "%s%s",
			       i > 0 ? "->" : "",
			       fmt_short_channel_id(tmpctx, hops[i].scid));
	}

	/* Now walk through this: is it disabled?  Insuff capacity? */
	for (size_t i = 0; i < tal_count(hops); i++) {
		const char *explanation;
		struct short_channel_id_dir scidd;
		struct gossmap_chan *c;
		struct amount_msat cap_msat;

		scidd.scid = hops[i].scid;
		scidd.dir = hops[i].direction;
		c = gossmap_find_chan(rq->gossmap, &scidd.scid);
		cap_msat = gossmap_chan_get_capacity(rq->gossmap, c);
		if (!gossmap_chan_set(c, scidd.dir))
			explanation = "has no gossip";
		else if (!c->half[scidd.dir].enabled)
			explanation = describe_disabled(tmpctx, rq, &scidd);
		else if (amount_msat_greater(amount, cap_msat))
			explanation = describe_capacity(tmpctx, rq, &scidd, amount);
		else {
			struct amount_msat min, max;
			get_constraints(rq, c, scidd.dir, &min, &max);
			if (amount_msat_less(max, amount)) {
				explanation = why_max_constrained(tmpctx, rq,
								  &scidd, amount);
			} else
				continue;
		}

		return tal_fmt(ctx,
			       NO_USABLE_PATHS_STRING
			       "  The shortest path is %s, but %s %s",
			       path,
			       fmt_short_channel_id_dir(tmpctx, &scidd),
			       explanation);
	}

	return tal_fmt(ctx,
		       "Actually, I'm not sure why we didn't find the"
		       " obvious route %s: perhaps this is a bug?",
		       path);
}
