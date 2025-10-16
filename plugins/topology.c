#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/tal/str/str.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/route.h>
#include <common/wireaddr.h>
#include <errno.h>
#include <inttypes.h>
#include <plugins/libplugin.h>

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

static bool can_carry(const struct gossmap *map,
		      const struct gossmap_chan *c,
		      int dir,
		      struct amount_msat amount,
		      struct route_exclusion **excludes)
{
	struct node_id dstid;

	/* First do generic check */
	if (!route_can_carry(map, c, dir, amount, NULL)) {
		return false;
	}

	/* Now check exclusions.  Premature optimization: */
	if (!tal_count(excludes)) {
		return true;
	}

	gossmap_node_get_id(map, gossmap_nth_node(map, c, !dir), &dstid);
	for (size_t i = 0; i < tal_count(excludes); i++) {
		struct short_channel_id scid;

		switch (excludes[i]->type) {
		case EXCLUDE_CHANNEL:
			scid = gossmap_chan_scid(map, c);
			if (short_channel_id_eq(excludes[i]->u.chan_id.scid, scid)
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

/* Output a route hop */
static void json_add_route_hop(struct json_stream *js,
			       const char *fieldname,
			       const struct route_hop *r)
{
	/* Imitate what getroute/sendpay use */
	json_object_start(js, fieldname);
	json_add_node_id(js, "id", &r->node_id);
	json_add_short_channel_id(js, "channel", r->scid);
	json_add_num(js, "direction", r->direction);
	json_add_amount_msat(js, "amount_msat", r->amount);
	json_add_num(js, "delay", r->delay);
	json_add_string(js, "style", "tlv");
	json_object_end(js);
}

struct getroute_info {
	struct node_id *destination;
	struct node_id *source;
	struct amount_msat *msat;
	u32 *cltv;
	/* risk factor 12.345% -> riskfactor_millionths = 12345000 */
	u64 *riskfactor_millionths;
	struct route_exclusion **excluded;
	u32 *max_hops;
};

static struct command_result *try_route(struct command *cmd,
					struct gossmap *gossmap,
					struct getroute_info *info)
{
	const struct dijkstra *dij;
	struct route_hop *route;
	struct gossmap_node *src, *dst;
	struct json_stream *js;
	src = gossmap_find_node(gossmap, info->source);
	if (!src)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s: unknown source node_id (no public channels?)",
				    fmt_node_id(tmpctx, info->source));

	dst = gossmap_find_node(gossmap, info->destination);
	if (!dst)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s: unknown destination node_id (no public channels?)",
				    fmt_node_id(tmpctx, info->destination));

	dij = dijkstra(tmpctx, gossmap, dst, *info->msat,
		       *info->riskfactor_millionths / 1000000.0,
		       can_carry, route_score_cheaper, info->excluded);
	route = route_from_dijkstra(dij, gossmap, dij, src,
				    *info->msat, *info->cltv);
	if (!route)
		return command_fail(cmd, PAY_ROUTE_NOT_FOUND, "Could not find a route");

	/* If it's too far, fall back to using shortest path. */
	if (tal_count(route) > *info->max_hops) {
		plugin_notify_message(cmd, LOG_INFORM, "Cheapest route %zu hops: seeking shorter",
				      tal_count(route));
		dij = dijkstra(tmpctx, gossmap, dst, *info->msat,
			       *info->riskfactor_millionths / 1000000.0,
			       can_carry, route_score_shorter, info->excluded);
		route = route_from_dijkstra(dij, gossmap, dij, src, *info->msat, *info->cltv);
		if (tal_count(route) > *info->max_hops)
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

static struct command_result *
listpeerchannels_getroute_done(struct command *cmd,
			       const char *method,
			       const char *buf,
			       const jsmntok_t *result,
			       struct getroute_info *info)
{
	struct gossmap *gossmap;
	struct gossmap_localmods *mods;
	struct command_result *res;

	/* Get local knowledge */
	mods = gossmods_from_listpeerchannels(tmpctx, &local_id,
					      buf, result, true,
					      gossmod_add_localchan, NULL);

	/* Overlay local knowledge for dijkstra */
	gossmap = get_gossmap();
	gossmap_apply_localmods(gossmap, mods);
	res = try_route(cmd, gossmap, info);
	gossmap_remove_localmods(gossmap, mods);

	return res;
}

static struct command_result *json_getroute(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *params)
{
	struct getroute_info *info = tal(cmd, struct getroute_info);
	struct out_req *req;
	u64 *fuzz_ignored;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &info->destination),
		   p_req("amount_msat", param_msat, &info->msat),
		   p_req("riskfactor", param_millionths, &info->riskfactor_millionths),
		   p_opt_def("cltv", param_number, &info->cltv, 9),
		   p_opt_def("fromid", param_node_id, &info->source, local_id),
		   p_opt("fuzzpercent", param_millionths, &fuzz_ignored),
		   p_opt("exclude", param_route_exclusion_array, &info->excluded),
		   p_opt_def("maxhops", param_number, &info->max_hops, ROUTING_MAX_HOPS),
		   NULL))
		return command_param_failed();

	/* Add local info */
	req = jsonrpc_request_start(cmd, "listpeerchannels",
				    listpeerchannels_getroute_done,
				    plugin_broken_cb, info);
	return send_outreq(req);
}

/* To avoid multiple fetches, we represent directions as a bitmap
 * so we can do two at once. */
static void json_add_halfchan(struct json_stream *response,
			      struct gossmap *gossmap,
			      const struct gossmap_chan *c,
			      int dirbits)
{
	struct short_channel_id scid;
	struct node_id node_id[2];
	const u8 *chanfeatures;
	struct amount_msat capacity_msat;

	/* These are channel (not per-direction) properties */
	chanfeatures = gossmap_chan_get_features(tmpctx, gossmap, c);
	scid = gossmap_chan_scid(gossmap, c);
	for (size_t i = 0; i < 2; i++)
		gossmap_node_get_id(gossmap, gossmap_nth_node(gossmap, c, i),
				    &node_id[i]);

	capacity_msat = gossmap_chan_get_capacity(gossmap, c);

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
		json_add_short_channel_id(response, "short_channel_id", scid);
		json_add_num(response, "direction", dir);
		json_add_bool(response, "public", !gossmap_chan_is_localmod(gossmap, c));

		gossmap_chan_get_update_details(gossmap, c, dir,
						&timestamp,
						&message_flags,
						&channel_flags,
						NULL,
						&fee_base_msat,
						&fee_proportional_millionths,
						&htlc_minimum_msat,
						&htlc_maximum_msat);

		json_add_amount_msat(response, "amount_msat", capacity_msat);
		json_add_num(response, "message_flags", message_flags);
		json_add_num(response, "channel_flags", channel_flags);

		json_add_bool(response, "active", c->half[dir].enabled);
		json_add_num(response, "last_update", timestamp);
		json_add_num(response, "base_fee_millisatoshi", fee_base_msat);
		json_add_num(response, "fee_per_millionth",
			     fee_proportional_millionths);
		json_add_num(response, "delay", c->half[dir].delay);
		json_add_amount_msat(response, "htlc_minimum_msat",
				     htlc_minimum_msat);
		json_add_amount_msat(response, "htlc_maximum_msat",
				     htlc_maximum_msat);
		json_add_hex_talarr(response, "features", chanfeatures);
		json_object_end(response);
	}
}

static struct command_result *json_listchannels(struct command *cmd,
						const char *buffer,
						const jsmntok_t *params)
{
	struct node_id *source;
	struct node_id *destination;
	struct short_channel_id *scid;
	struct gossmap_chan *c;
	struct json_stream *js;
	struct gossmap *gossmap;

	if (!param(cmd, buffer, params,
		   p_opt("short_channel_id", param_short_channel_id,
			 &scid),
		   p_opt("source", param_node_id, &source),
		   p_opt("destination", param_node_id, &destination),
		   NULL))
		return command_param_failed();

	if (!!scid + !!source + !!destination > 1)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can only specify one of "
				    "`short_channel_id`, "
				    "`source` or `destination`");

	gossmap = get_gossmap();
	js = jsonrpc_stream_success(cmd);
	json_array_start(js, "channels");
	if (scid) {
		c = gossmap_find_chan(gossmap, scid);
		if (c)
			json_add_halfchan(js, gossmap, c, 3);
	} else if (source) {
		struct gossmap_node *src;

		src = gossmap_find_node(gossmap, source);
		if (src) {
			for (size_t i = 0; i < src->num_chans; i++) {
				int dir;
				c = gossmap_nth_chan(gossmap, src, i, &dir);
				json_add_halfchan(js, gossmap,
						  c, 1 << dir);
			}
		}
	} else if (destination) {
		struct gossmap_node *dst;

		dst = gossmap_find_node(gossmap, destination);
		if (dst) {
			for (size_t i = 0; i < dst->num_chans; i++) {
				int dir;
				c = gossmap_nth_chan(gossmap, dst, i, &dir);
				json_add_halfchan(js, gossmap,
						  c, 1 << !dir);
			}
		}
	} else {
		for (c = gossmap_first_chan(gossmap);
		     c;
		     c = gossmap_next_chan(gossmap, c)) {
			json_add_halfchan(js, gossmap, c, 3);
		}
	}

	json_array_end(js);
	return command_finished(cmd, js);
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
		struct tlv_node_ann_tlvs *na_tlvs;

		if (!fromwire_node_announcement(nannounce, nannounce,
						&signature,
						&features,
						&timestamp,
						&nid,
						rgb_color,
						alias,
						&addresses,
						&na_tlvs)) {
			plugin_log(plugin, LOG_BROKEN,
				   "Cannot parse stored node_announcement"
				   " for %s at %"PRIu64": %s",
				   fmt_node_id(tmpctx, &node_id),
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

		if (na_tlvs->option_will_fund) {
			json_object_start(js, "option_will_fund");
			json_add_lease_rates(js, na_tlvs->option_will_fund);
			/* As a convenience, add a hexstring version
			 * of this info */
			json_add_string(js, "compact_lease",
					lease_rates_tohex(tmpctx,
							  na_tlvs->option_will_fund));
			json_object_end(js);
		}
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
static struct amount_msat peer_capacity(const struct gossmap *gossmap,
				       const struct gossmap_node *me,
				       const struct gossmap_node *peer,
				       const struct gossmap_chan *ourchan)
{
	struct amount_msat capacity = AMOUNT_MSAT(0);

	for (size_t i = 0; i < peer->num_chans; i++) {
		int dir;
		struct gossmap_chan *c;
		c = gossmap_nth_chan(gossmap, peer, i, &dir);
		if (c == ourchan)
			continue;
		if (!c->half[!dir].enabled)
			continue;
		if (!amount_msat_accumulate(&capacity,
					    amount_msat(fp16_to_u64(c->half[!dir].htlc_max))))
			continue;
	}
	return capacity;
}

static struct command_result *
listpeerchannels_listincoming_done(struct command *cmd,
				   const char *method,
				   const char *buffer,
				   const jsmntok_t *result,
				   void *unused)
{
	struct json_stream *js;
	struct gossmap_node *me;
	struct gossmap *gossmap;
	struct gossmap_localmods *mods;

	/* Get local knowledge */
	mods = gossmods_from_listpeerchannels(tmpctx, &local_id,
					      buffer, result, false,
					      gossmod_add_localchan,
					      NULL);

	/* Overlay local knowledge */
	gossmap = get_gossmap();
	gossmap_apply_localmods(gossmap, mods);

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
		const u8 *peer_features;

		ourchan = gossmap_nth_chan(gossmap, me, i, &dir);
		/* Entirely missing?  Ignore. */
		if (ourchan->cupdate_off[!dir] == 0)
			continue;
		/* We used to ignore if the peer said it was disabled,
		 * but we have a report of LND telling us our unannounced
		 * channel is disabled, so we still use them. */
		peer = gossmap_nth_node(gossmap, ourchan, !dir);
		scid = gossmap_chan_scid(gossmap, ourchan);

		json_object_start(js, NULL);
		gossmap_node_get_id(gossmap, peer, &peer_id);
		json_add_node_id(js, "id", &peer_id);
		json_add_short_channel_id(js, "short_channel_id", scid);
		json_add_amount_msat(js, "fee_base_msat",
				     amount_msat(ourchan->half[!dir].base_fee));
		json_add_amount_msat(js, "htlc_min_msat",
				     amount_msat(fp16_to_u64(ourchan->half[!dir]
							     .htlc_min)));
		json_add_amount_msat(js, "htlc_max_msat",
				     amount_msat(fp16_to_u64(ourchan->half[!dir]
							     .htlc_max)));
		json_add_u32(js, "fee_proportional_millionths",
			     ourchan->half[!dir].proportional_fee);
		json_add_u32(js, "cltv_expiry_delta", ourchan->half[!dir].delay);
		json_add_amount_msat(js, "incoming_capacity_msat",
				     peer_capacity(gossmap, me, peer, ourchan));
		json_add_bool(js, "public", !gossmap_chan_is_localmod(gossmap, ourchan));
		peer_features = gossmap_node_get_features(tmpctx, gossmap, peer);
		if (peer_features)
			json_add_hex_talarr(js, "peer_features", peer_features);
		json_add_bool(js, "enabled", ourchan->half[!dir].enabled);
		json_object_end(js);
	}
done:
	json_array_end(js);

	gossmap_remove_localmods(gossmap, mods);
	return command_finished(cmd, js);
}

static struct command_result *json_listincoming(struct command *cmd,
						const char *buffer,
						const jsmntok_t *params)
{
	struct out_req *req;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	/* Add local info */
	req = jsonrpc_request_start(cmd, "listpeerchannels",
				    listpeerchannels_listincoming_done,
				    plugin_broken_cb, NULL);
	return send_outreq(req);
}

static void memleak_mark(struct plugin *p, struct htable *memtable)
{
	memleak_scan_obj(memtable, global_gossmap);
}

static const char *init(struct command *init_cmd,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	plugin = init_cmd->plugin;
	rpc_scan(init_cmd, "getinfo",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_node_id, &local_id));

	global_gossmap = gossmap_load(NULL,
				      GOSSIP_STORE_FILENAME,
				      plugin_gossmap_logcb, plugin);
	if (!global_gossmap)
		plugin_err(plugin, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));

 	plugin_set_memleak_handler(plugin, memleak_mark);
	return NULL;
}

static const struct plugin_command commands[] = {
	{
		"getroute",
		json_getroute,
	},
	{
		"listchannels",
		json_listchannels,
	},
	{
		"listnodes",
		json_listnodes,
	},
	{
		"listincoming",
		json_listincoming,
	},
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, NULL, PLUGIN_STATIC, true, NULL, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0, NULL);
}
