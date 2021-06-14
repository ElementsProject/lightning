#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/json_escape/json_escape.h>
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
#include <common/wireaddr.h>
#include <errno.h>
#include <inttypes.h>
#include <plugins/libplugin.h>
#include <wire/peer_wire.h>

/* Access via get_gossmap() */
static struct gossmap *global_gossmap;
static struct node_id local_id;
static struct plugin *plugin;

/* We load this on demand, since we can start before gossipd. */
static struct gossmap *get_gossmap(void)
{
	gossmap_refresh(global_gossmap);
	return global_gossmap;
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

static const struct node_id *node_id_keyof(const struct node_id *id)
{
	return id;
}

static size_t node_id_hash(const struct node_id *id)
{
	return siphash24(siphash_seed(), id->k, sizeof(id->k));
}


HTABLE_DEFINE_TYPE(struct node_id, node_id_keyof, node_id_hash, node_id_eq,
		   node_map);

/* To avoid multiple fetches, we represent directions as a bitmap
 * so we can do two at once. */
static void json_add_halfchan(struct json_stream *response,
			      struct gossmap *gossmap,
			      const struct node_map *connected,
			      const struct gossmap_chan *c,
			      int dirbits)
{
	struct short_channel_id scid;
	struct node_id node_id[2];
	const u8 *chanfeatures;
	struct amount_sat capacity;
	bool local_disable;

	/* These are channel (not per-direction) properties */
	chanfeatures = gossmap_chan_get_features(tmpctx, gossmap, c);
	scid = gossmap_chan_scid(gossmap, c);
	for (size_t i = 0; i < 2; i++)
		gossmap_node_get_id(gossmap, gossmap_nth_node(gossmap, c, i),
				    &node_id[i]);

	/* This can theoretically happen on partial write races. */
	if (!gossmap_chan_get_capacity(gossmap, c, &capacity))
		capacity = AMOUNT_SAT(0);

	/* Local channels are not "active" unless peer is connected. */
	if (node_id_eq(&node_id[0], &local_id))
		local_disable = !node_map_get(connected, &node_id[1]);
	else if (node_id_eq(&node_id[1], &local_id))
		local_disable = !node_map_get(connected, &node_id[0]);
	else
		local_disable = false;

	for (int dir = 0; dir < 2; dir++) {
		u32 timestamp;
		u8 message_flags, channel_flags;
		u32 fee_base_msat, fee_proportional_millionths;
		struct amount_msat htlc_minimum_msat, htlc_maximum_msat;

		if (!((1 << dir) & dirbits))
			continue;

		if (!gossmap_chan_set(c, dir))
			continue;

		json_object_start(response, NULL);
		json_add_node_id(response, "source", &node_id[dir]);
		json_add_node_id(response, "destination", &node_id[!dir]);
		json_add_short_channel_id(response, "short_channel_id", &scid);
		json_add_bool(response, "public", !c->private);

		gossmap_chan_get_update_details(gossmap, c, dir,
						&timestamp,
						&message_flags,
						&channel_flags,
						&fee_base_msat,
						&fee_proportional_millionths,
						&htlc_minimum_msat,
						&htlc_maximum_msat);

		json_add_amount_sat_compat(response, capacity,
					   "satoshis", "amount_msat");
		json_add_num(response, "message_flags", message_flags);
		json_add_num(response, "channel_flags", channel_flags);

		json_add_bool(response, "active",
			      c->half[dir].enabled && !local_disable);
		json_add_num(response, "last_update", timestamp);
		json_add_num(response, "base_fee_millisatoshi", fee_base_msat);
		json_add_num(response, "fee_per_millionth",
			     fee_proportional_millionths);
		json_add_num(response, "delay", c->half[dir].delay);
		json_add_amount_msat_only(response, "htlc_minimum_msat",
					  htlc_minimum_msat);

		/* We used to always print this, but that's weird */
		if (deprecated_apis && !(message_flags & 1)) {
			if (!amount_sat_to_msat(&htlc_maximum_msat, capacity))
				plugin_err(plugin,
					   "Channel with impossible capacity %s",
					   type_to_string(tmpctx,
							  struct amount_sat,
							  &capacity));
			message_flags = 1;
		}

		if (message_flags & 1)
			json_add_amount_msat_only(response, "htlc_maximum_msat",
						  htlc_maximum_msat);
		json_add_hex_talarr(response, "features", chanfeatures);
		json_object_end(response);
	}
}

struct listchannels_opts {
	struct node_id *source;
	struct short_channel_id *scid;
};

/* We record which local channels are valid; we could record which are
 * invalid, but our testsuite has some weirdness where it has local
 * channels in the store it knows nothing about. */
static struct node_map *local_connected(const tal_t *ctx,
					const char *buf,
					const jsmntok_t *result)
{
	size_t i;
	const jsmntok_t *t, *peers = json_get_member(buf, result, "peers");
	struct node_map *connected = tal(ctx, struct node_map);

	node_map_init(connected);

	json_for_each_arr(i, t, peers) {
		const jsmntok_t *chans, *c;
		struct node_id id;
		bool is_connected, normal_chan;
		const char *err;
		size_t j;

		err = json_scan(tmpctx, buf, t,
				"{id:%,connected:%}",
				JSON_SCAN(json_to_node_id, &id),
				JSON_SCAN(json_to_bool, &is_connected));
		if (err)
			plugin_err(plugin, "Bad listpeers response (%s): %.*s",
				   err,
				   json_tok_full_len(result),
				   json_tok_full(buf, result));

		if (!is_connected)
			continue;

		/* Must also have a channel in CHANNELD_NORMAL */
		normal_chan = false;
		chans = json_get_member(buf, t, "channels");
		json_for_each_arr(j, c, chans) {
			if (json_tok_streq(buf,
					   json_get_member(buf, c, "state"),
					   "CHANNELD_NORMAL"))
				normal_chan = true;
		}

		if (normal_chan)
			node_map_add(connected,
				     tal_dup(connected, struct node_id, &id));
	}

	return connected;
}

/* We want to combine local knowledge to we know which are actually inactive! */
static struct command_result *listpeers_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct listchannels_opts *opts)
{
	struct node_map *connected;
	struct gossmap_chan *c;
	struct json_stream *js;
	struct gossmap *gossmap = get_gossmap();

	connected = local_connected(opts, buf, result);

	js = jsonrpc_stream_success(cmd);
	json_array_start(js, "channels");
	if (opts->scid) {
		c = gossmap_find_chan(gossmap, opts->scid);
		if (c)
			json_add_halfchan(js, gossmap, connected, c, 3);
	} else if (opts->source) {
		struct gossmap_node *src;

		src = gossmap_find_node(gossmap, opts->source);
		if (src) {
			for (size_t i = 0; i < src->num_chans; i++) {
				int dir;
				c = gossmap_nth_chan(gossmap, src, i, &dir);
				json_add_halfchan(js, gossmap, connected,
						  c, 1 << dir);
			}
		}
	} else {
		for (c = gossmap_first_chan(gossmap);
		     c;
		     c = gossmap_next_chan(gossmap, c)) {
			json_add_halfchan(js, gossmap, connected, c, 3);
		}
	}

	json_array_end(js);

	return command_finished(cmd, js);
}

static struct command_result *json_listchannels(struct command *cmd,
						const char *buffer,
						const jsmntok_t *params)
{
	struct listchannels_opts *opts = tal(cmd, struct listchannels_opts);
	struct out_req *req;

	if (!param(cmd, buffer, params,
		   p_opt("short_channel_id", param_short_channel_id,
			 &opts->scid),
		   p_opt("source", param_node_id, &opts->source),
		   NULL))
		return command_param_failed();

	if (opts->scid && opts->source)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Cannot specify both source and short_channel_id");
	req = jsonrpc_request_start(cmd->plugin, cmd, "listpeers",
				    listpeers_done, forward_error, opts);
	return send_outreq(cmd->plugin, req);
}

static void json_add_node(struct json_stream *js,
			  const struct gossmap *gossmap,
			  const struct gossmap_node *n)
{
	struct node_id node_id;
	u8 *nannounce;

	json_object_start(js, NULL);
	gossmap_node_get_id(gossmap, n, &node_id);
	json_add_node_id(js, "nodeid", &node_id);
	nannounce = gossmap_node_get_announce(tmpctx, gossmap, n);
	if (nannounce) {
		secp256k1_ecdsa_signature signature;
		u8 *features;
		u32 timestamp;
		u8 rgb_color[3], alias[32];
		u8 *addresses;
		struct node_id nid;
		struct wireaddr *addrs;
		struct json_escape *esc;

		if (!fromwire_node_announcement(nannounce, nannounce,
						&signature,
						&features,
						&timestamp,
						&nid,
						rgb_color,
						alias,
						&addresses)) {
			plugin_log(plugin, LOG_BROKEN,
				   "Cannot parse stored node_announcement"
				   " for %s at %u: %s",
				   type_to_string(tmpctx, struct node_id,
						  &node_id),
				   n->nann_off,
				   tal_hex(tmpctx, nannounce));
			goto out;
		}

		esc = json_escape(NULL,
				  take(tal_strndup(NULL,
						   (const char *)alias,
						   ARRAY_SIZE(alias))));
		json_add_escaped_string(js, "alias", take(esc));
		json_add_hex(js, "color", rgb_color, ARRAY_SIZE(rgb_color));
		json_add_u64(js, "last_timestamp", timestamp);
		json_add_hex_talarr(js, "features", features);

		json_array_start(js, "addresses");
		addrs = fromwire_wireaddr_array(nannounce, addresses);
		for (size_t i = 0; i < tal_count(addrs); i++)
			json_add_address(js, NULL, &addrs[i]);
		json_array_end(js);
	}
out:
	json_object_end(js);
}

static struct command_result *json_listnodes(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *params)
{
	struct node_id *id;
	struct json_stream *js;
	struct gossmap *gossmap;

	if (!param(cmd, buffer, params,
		   p_opt("id", param_node_id, &id),
		   NULL))
		return command_param_failed();

	gossmap = get_gossmap();
	js = jsonrpc_stream_success(cmd);
	json_array_start(js, "nodes");
	if (id) {
		struct gossmap_node *n = gossmap_find_node(gossmap, id);
		if (n)
			json_add_node(js, gossmap, n);
	} else {
		for (struct gossmap_node *n = gossmap_first_node(gossmap);
		     n;
		     n = gossmap_next_node(gossmap, n)) {
			json_add_node(js, gossmap, n);
		}
	}
	json_array_end(js);

	return command_finished(cmd, js);
}

/* What is capacity of peer attached to chan #n? */
static struct amount_sat peer_capacity(const struct gossmap *gossmap,
				       const struct gossmap_node *me,
				       const struct gossmap_node *peer,
				       const struct gossmap_chan *ourchan)
{
	struct amount_sat capacity = AMOUNT_SAT(0);

	for (size_t i = 0; i < peer->num_chans; i++) {
		int dir;
		struct gossmap_chan *c;
		c = gossmap_nth_chan(gossmap, peer, i, &dir);
		if (c == ourchan)
			continue;
		if (!c->half[!dir].enabled)
			continue;
		if (!amount_sat_add(&capacity, capacity,
				    amount_sat(fp16_to_u64(c->half[dir]
							   .htlc_max))))
			continue;
	}
	return capacity;
}

static struct command_result *json_listincoming(struct command *cmd,
						const char *buffer,
						const jsmntok_t *params)
{
	struct json_stream *js;
	struct gossmap_node *me;
	struct gossmap *gossmap;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	gossmap = get_gossmap();

	js = jsonrpc_stream_success(cmd);
	json_array_start(js, "incoming");
	me = gossmap_find_node(gossmap, &local_id);
	if (!me)
		goto done;

	for (size_t i = 0; i < me->num_chans; i++) {
		struct node_id peer_id;
		int dir;
		struct gossmap_chan *ourchan;
		struct gossmap_node *peer;
		struct short_channel_id scid;

		ourchan = gossmap_nth_chan(gossmap, me, i, &dir);
		/* If its half is disabled, ignore. */
		if (!ourchan->half[!dir].enabled)
			continue;

		peer = gossmap_nth_node(gossmap, ourchan, !dir);
		scid = gossmap_chan_scid(gossmap, ourchan);

		json_object_start(js, NULL);
		gossmap_node_get_id(gossmap, peer, &peer_id);
		json_add_node_id(js, "id", &peer_id);
		json_add_short_channel_id(js, "short_channel_id", &scid);
		json_add_amount_msat_only(js, "fee_base_msat",
					  amount_msat(ourchan->half[!dir]
						      .base_fee));
		json_add_u32(js, "fee_proportional_millionths",
			     ourchan->half[!dir].proportional_fee);
		json_add_u32(js, "cltv_expiry_delta", ourchan->half[!dir].delay);
		json_add_amount_sat_only(js, "incoming_capacity_msat",
					 peer_capacity(gossmap,
						       me, peer, ourchan));
		json_object_end(js);
	}
done:
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

	global_gossmap = notleak_with_children(gossmap_load(NULL,
					    GOSSIP_STORE_FILENAME));
	if (!global_gossmap)
		plugin_err(plugin, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));

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
	{
		"listchannels",
		"channels",
		"List all known channels in the network",
		"Show channel {short_channel_id} or {source} (or all known channels, if not specified)",
		json_listchannels,
	},
	{
		"listnodes",
		"network",
		"List all known nodes in the network",
		"Show node {id} (or all known nods, if not specified)",
		json_listnodes,
	},
	{
		"listincoming",
		"network",
		"List the channels incoming from our direct peers",
		"Used by invoice code to select peers for routehints",
		json_listincoming,
	},
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_STATIC, true, NULL, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0, NULL);
}
