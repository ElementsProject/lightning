#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/route.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <errno.h>
#include <inttypes.h>
#include <plugins/libplugin.h>

/* Access via get_gossmap() */
static struct node_id local_id;
static struct plugin *plugin;

/* We load this on demand, since we can start before gossipd. */
static struct gossmap *get_gossmap(void)
{
	static struct gossmap *gossmap;

	if (gossmap)
		gossmap_refresh(gossmap);
	else {
		gossmap = notleak_with_children(gossmap_load(NULL,
					    GOSSIP_STORE_FILENAME));
		if (!gossmap)
			plugin_err(plugin, "Could not load gossmap %s: %s",
				   GOSSIP_STORE_FILENAME, strerror(errno));
	}
	return gossmap;
}

/* Convenience global since route_score_fuzz doesn't take args. 0 to 1. */
static double fuzz;

enum exclude_entry_type {
	EXCLUDE_CHANNEL = 1,
	EXCLUDE_NODE = 2
};

struct exclude_entry {
	enum exclude_entry_type type;
	union {
		struct short_channel_id_dir chan_id;
		struct node_id node_id;
	} u;
};

/* Prioritize costs over distance, but with fuzz.  Cost must be
 * the same when the same channel queried, so we base it on that. */
static u64 route_score_fuzz(u32 distance,
			    struct amount_msat cost,
			    struct amount_msat risk,
			    const struct gossmap_chan *c)
{
	u64 costs = cost.millisatoshis + risk.millisatoshis; /* Raw: score */
	/* Use the literal pointer, since it's stable. */
	u64 h = siphash24(siphash_seed(), &c, sizeof(c));

	/* Use distance as the tiebreaker */
	costs += distance;

	/* h / (UINT64_MAX / 2.0) is between 0 and 2. */
	costs *= (h / (double)(UINT64_MAX / 2) - 1) * fuzz;

	return costs;
}

static bool can_carry(const struct gossmap *map,
		      const struct gossmap_chan *c,
		      int dir,
		      struct amount_msat amount,
		      const struct exclude_entry **excludes)
{
	struct node_id dstid;

	/* First do generic check */
	if (!route_can_carry(map, c, dir, amount, NULL)) {
		plugin_log(plugin, LOG_DBG, "cannot carry %s across %p",
			   type_to_string(tmpctx, struct amount_msat, &amount),
			   c);
		return false;
	}

	/* Now check exclusions.  Premature optimization: */
	if (!tal_count(excludes)) {
		plugin_log(plugin, LOG_DBG, "CAN carry %s across %p",
			   type_to_string(tmpctx, struct amount_msat, &amount),
			   c);
		return true;
	}

	gossmap_node_get_id(map, gossmap_nth_node(map, c, !dir), &dstid);
	for (size_t i = 0; i < tal_count(excludes); i++) {
		struct short_channel_id scid;

		switch (excludes[i]->type) {
		case EXCLUDE_CHANNEL:
			scid = gossmap_chan_scid(map, c);
			if (short_channel_id_eq(&excludes[i]->u.chan_id.scid, &scid)
			    && dir == excludes[i]->u.chan_id.dir)
				return false;
			continue;

		case EXCLUDE_NODE:
			if (node_id_eq(&dstid, &excludes[i]->u.node_id))
				return false;
			continue;
		}
		/* No other cases should be possible! */
		plugin_err(plugin, "Invalid type %i in exclusion[%zu]",
			   excludes[i]->type, i);
	}
	return true;
}

static void json_add_route_hop_style(struct json_stream *response,
				     const char *fieldname,
				     enum route_hop_style style)
{
	switch (style) {
	case ROUTE_HOP_LEGACY:
		json_add_string(response, fieldname, "legacy");
		return;
	case ROUTE_HOP_TLV:
		json_add_string(response, fieldname, "tlv");
		return;
	}
	abort();
}

/* Output a route hop */
static void json_add_route_hop(struct json_stream *js,
			       const char *fieldname,
			       const struct route_hop *r)
{
	/* Imitate what getroute/sendpay use */
	json_object_start(js, fieldname);
	json_add_node_id(js, "id", &r->node_id);
	json_add_short_channel_id(js, "channel", &r->scid);
	json_add_num(js, "direction", r->direction);
	json_add_amount_msat_compat(js, r->amount, "msatoshi", "amount_msat");
	json_add_num(js, "delay", r->delay);
	json_add_route_hop_style(js, "style", r->style);
	json_object_end(js);
}

static struct command_result *json_getroute(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *params)
{
	struct node_id *destination;
	struct node_id *source;
	const jsmntok_t *excludetok;
	struct amount_msat *msat;
	u32 *cltv;
	/* risk factor 12.345% -> riskfactor_millionths = 12345000 */
	u64 *riskfactor_millionths, *fuzz_millionths;
	const struct exclude_entry **excluded;
	u32 *max_hops;
	const struct dijkstra *dij;
	struct route_hop *route;
	struct gossmap_node *src, *dst;
	struct json_stream *js;
	struct gossmap *gossmap;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &destination),
		   p_req("msatoshi", param_msat, &msat),
		   p_req("riskfactor", param_millionths, &riskfactor_millionths),
		   p_opt_def("cltv", param_number, &cltv, 9),
		   p_opt_def("fromid", param_node_id, &source, local_id),
		   p_opt_def("fuzzpercent", param_millionths, &fuzz_millionths,
			     5000000),
		   p_opt("exclude", param_array, &excludetok),
		   p_opt_def("maxhops", param_number, &max_hops, ROUTING_MAX_HOPS),
		   NULL))
		return command_param_failed();

	/* Convert from percentage */
	fuzz = *fuzz_millionths / 100.0 / 1000000.0;
	if (fuzz > 1.0)
		return command_fail_badparam(cmd, "fuzzpercent",
					     buffer, params,
					     "should be <= 100");

	if (excludetok) {
		const jsmntok_t *t;
		size_t i;

		excluded = tal_arr(cmd, const struct exclude_entry *, 0);

		json_for_each_arr(i, t, excludetok) {
			struct exclude_entry *entry = tal(excluded, struct exclude_entry);
			struct short_channel_id_dir *chan_id = tal(tmpctx, struct short_channel_id_dir);
			if (!short_channel_id_dir_from_str(buffer + t->start,
							   t->end - t->start,
							   chan_id)) {
				struct node_id *node_id = tal(tmpctx, struct node_id);

				if (!json_to_node_id(buffer, t, node_id))
					return command_fail_badparam(cmd, "exclude",
								     buffer, t,
								     "should be short_channel_id or node_id");

				entry->type = EXCLUDE_NODE;
				entry->u.node_id = *node_id;
			} else {
				entry->type = EXCLUDE_CHANNEL;
				entry->u.chan_id = *chan_id;
			}

			tal_arr_expand(&excluded, entry);
		}
	} else {
		excluded = NULL;
	}

	gossmap = get_gossmap();
	src = gossmap_find_node(gossmap, source);
	if (!src)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s: unknown source node_id (no public channels?)",
				    type_to_string(tmpctx, struct node_id, source));

	dst = gossmap_find_node(gossmap, destination);
	if (!dst)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s: unknown destination node_id (no public channels?)",
				    type_to_string(tmpctx, struct node_id, destination));

	fuzz = 0;
	dij = dijkstra(tmpctx, gossmap, dst, *msat,
		       *riskfactor_millionths / 1000000.0,
		       can_carry, route_score_fuzz, excluded);
	route = route_from_dijkstra(dij, gossmap, dij, src, *msat, *cltv);
	if (!route)
		return command_fail(cmd, PAY_ROUTE_NOT_FOUND, "Could not find a route");

	/* If it's too far, fall back to using shortest path. */
	if (tal_count(route) > *max_hops) {
		plugin_notify_message(cmd, LOG_INFORM, "Cheapest route %zu hops: seeking shorter (no fuzz)",
				      tal_count(route));
		dij = dijkstra(tmpctx, gossmap, dst, *msat,
			       *riskfactor_millionths / 1000000.0,
			       can_carry, route_score_shorter, excluded);
		route = route_from_dijkstra(dij, gossmap, dij, src, *msat, *cltv);
		if (tal_count(route) > *max_hops)
			return command_fail(cmd, PAY_ROUTE_NOT_FOUND, "Shortest route was %zu",
					    tal_count(route));
	}

	js = jsonrpc_stream_success(cmd);
	json_array_start(js, "route");
	for (size_t i = 0; i < tal_count(route); i++) {
		json_add_route_hop(js, NULL, &route[i]);
	}
	json_array_end(js);

	return command_finished(cmd, js);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	plugin = p;
	rpc_scan(p, "getinfo",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_node_id, &local_id));

	return NULL;
}

static const struct plugin_command commands[] = {
	{
		"getroute",
		"channels",
		"Primitive route command",
		"Show route to {id} for {msatoshi}, using {riskfactor} and optional {cltv} (default 9). "
		"If specified search from {fromid} otherwise use this node as source. "
		"Randomize the route with up to {fuzzpercent} (default 5.0). "
		"{exclude} an array of short-channel-id/direction (e.g. [ '564334x877x1/0', '564195x1292x0/1' ]) "
		"or node-id from consideration. "
		"Set the {maxhops} the route can take (default 20).",
		json_getroute,
	},
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_STATIC, true, NULL, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0, NULL);
}
