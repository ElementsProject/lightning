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
#include <plugins/libplugin.h>

/* Access via get_gossmap() */
static struct gossmap *global_gossmap;
static struct node_id local_id;
static struct plugin *plugin;

/* We load this on demand, since we can start before gossipd. */
static struct gossmap *get_gossmap(void)
{
	gossmap_refresh(global_gossmap, NULL);
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

static struct command_result *listpeerchannels_err(struct command *cmd,
						   const char *buf,
						   const jsmntok_t *result,
						   void *unused)
{
	plugin_err(cmd->plugin,
		   "Bad listpeerchannels: %.*s",
		   json_tok_full_len(result),
		   json_tok_full(buf, result));
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
	req = jsonrpc_request_start(cmd->plugin, cmd, "listpeerchannels",
				    listpeerchannels_getroute_done,
				    listpeerchannels_err, info);
	return send_outreq(cmd->plugin, req);
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

	/* Deprecated: local channels are not "active" unless peer is connected. */
	if (connected && node_id_eq(&node_id[0], &local_id))
		local_disable = !node_map_get(connected, &node_id[1]);
	else if (connected && node_id_eq(&node_id[1], &local_id))
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
		json_add_short_channel_id(response, "short_channel_id", scid);
		json_add_num(response, "direction", dir);
		json_add_bool(response, "public", !gossmap_chan_is_localmod(gossmap, c));

		if (gossmap_chan_is_localmod(gossmap, c)) {
			/* Local additions don't have a channel_update
			 * in gossmap.  This is deprecated anyway, but
			 * fill in values from entry we added. */
			timestamp = time_now().ts.tv_sec;
			message_flags = (ROUTING_OPT_HTLC_MAX_MSAT|ROUTING_OPT_DONT_FORWARD);
			channel_flags = node_id_idx(&node_id[dir], &node_id[!dir]);
			fee_base_msat = c->half[dir].base_fee;
			fee_proportional_millionths = c->half[dir].proportional_fee;
			htlc_minimum_msat = amount_msat(fp16_to_u64(c->half[dir].htlc_min));
			htlc_maximum_msat = amount_msat(fp16_to_u64(c->half[dir].htlc_max));
		} else {
			gossmap_chan_get_update_details(gossmap, c, dir,
							&timestamp,
							&message_flags,
							&channel_flags,
							&fee_base_msat,
							&fee_proportional_millionths,
							&htlc_minimum_msat,
							&htlc_maximum_msat);
		}

		json_add_amount_sat_msat(response, "amount_msat", capacity);
		json_add_num(response, "message_flags", message_flags);
		json_add_num(response, "channel_flags", channel_flags);

		json_add_bool(response, "active",
			      c->half[dir].enabled && !local_disable);
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

struct listchannels_opts {
	struct node_id *source;
	struct node_id *destination;
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
	const jsmntok_t *channel, *channels = json_get_member(buf, result, "channels");
	struct node_map *connected = tal(ctx, struct node_map);

	node_map_init(connected);
	tal_add_destructor(connected, node_map_clear);

	json_for_each_arr(i, channel, channels) {
		struct node_id id;
		bool is_connected;
		const char *err, *state;

		err = json_scan(tmpctx, buf, channel,
				"{peer_id:%,peer_connected:%,state:%}",
				JSON_SCAN(json_to_node_id, &id),
				JSON_SCAN(json_to_bool, &is_connected),
				JSON_SCAN_TAL(tmpctx, json_strdup, &state));
		if (err)
			plugin_err(plugin, "Bad listpeerchannels response (%s): %.*s",
				   err,
				   json_tok_full_len(result),
				   json_tok_full(buf, result));

		if (!is_connected)
			continue;

		/* Must also have a channel in CHANNELD_NORMAL/splice */
		if (streq(state, "CHANNELD_NORMAL")
		    || streq(state, "CHANNELD_AWAITING_SPLICE")) {
			node_map_add(connected,
				     tal_dup(connected, struct node_id, &id));
		}
	}

	return connected;
}

/* Only add a local entry if it's unknown publicly */
static void gossmod_add_unknown_localchan(struct gossmap_localmods *mods,
					  const struct node_id *self,
					  const struct node_id *peer,
					  const struct short_channel_id_dir *scidd,
					  struct amount_msat min,
					  struct amount_msat max,
					  struct amount_msat spendable,
					  struct amount_msat fee_base,
					  u32 fee_proportional,
					  u32 cltv_delta,
					  bool enabled,
					  const char *buf UNUSED,
					  const jsmntok_t *chantok UNUSED,
					  struct gossmap *gossmap)
{
	if (gossmap_find_chan(gossmap, &scidd->scid))
		return;

	gossmod_add_localchan(mods, self, peer, scidd, min, max, spendable,
			      fee_base, fee_proportional, cltv_delta, enabled,
			      buf, chantok, gossmap);
}

/* FIXME: We don't need this listpeerchannels at all if not deprecated! */
static struct command_result *listpeerchannels_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct listchannels_opts *opts)
{
	struct node_map *connected;
	struct gossmap_chan *c;
	struct json_stream *js;
	struct gossmap *gossmap = get_gossmap();
	struct gossmap_localmods *mods;

	/* In deprecated mode, re-add private channels */
	if (command_deprecated_in_ok(cmd, "include_private", "v24.02", "v24.08")) {
		connected = local_connected(opts, buf, result);
		mods = gossmods_from_listpeerchannels(tmpctx, &local_id,
						      buf, result, false,
						      gossmod_add_unknown_localchan,
						      gossmap);
		gossmap_apply_localmods(gossmap, mods);
	} else {
		connected = NULL;
		mods = NULL;
	}

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
	} else if (opts->destination) {
		struct gossmap_node *dst;

		dst = gossmap_find_node(gossmap, opts->destination);
		if (dst) {
			for (size_t i = 0; i < dst->num_chans; i++) {
				int dir;
				c = gossmap_nth_chan(gossmap, dst, i, &dir);
				json_add_halfchan(js, gossmap, connected,
						  c, 1 << !dir);
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

	if (mods)
		gossmap_remove_localmods(gossmap, mods);

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
		   p_opt("destination", param_node_id, &opts->destination),
		   NULL))
		return command_param_failed();

	if (!!opts->scid + !!opts->source + !!opts->destination > 1)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can only specify one of "
				    "`short_channel_id`, "
				    "`source` or `destination`");
	req = jsonrpc_request_start(cmd->plugin, cmd, "listpeerchannels",
				    listpeerchannels_done, forward_error, opts);
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
				   " for %s at %u: %s",
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
		if (!amount_msat_add(
			&capacity, capacity,
			amount_msat(fp16_to_u64(c->half[!dir].htlc_max))))
			continue;
	}
	return capacity;
}

static struct command_result *
listpeerchannels_listincoming_done(struct command *cmd,
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
	req = jsonrpc_request_start(cmd->plugin,
				    cmd, "listpeerchannels",
				    listpeerchannels_listincoming_done,
				    listpeerchannels_err, NULL);
	return send_outreq(cmd->plugin, req);
}

static void memleak_mark(struct plugin *p, struct htable *memtable)
{
	memleak_scan_obj(memtable, global_gossmap);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	size_t num_cupdates_rejected;

	plugin = p;
	rpc_scan(p, "getinfo",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_node_id, &local_id));

	global_gossmap = gossmap_load(NULL,
				      GOSSIP_STORE_FILENAME,
				      &num_cupdates_rejected);
	if (!global_gossmap)
		plugin_err(plugin, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));

	if (num_cupdates_rejected)
		plugin_log(plugin, LOG_DBG,
			   "gossmap ignored %zu channel updates",
			   num_cupdates_rejected);
 	plugin_set_memleak_handler(p, memleak_mark);
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
	plugin_main(argv, init, PLUGIN_STATIC, true, NULL, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0, NULL);
}
