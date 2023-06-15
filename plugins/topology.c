#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/tal/str/str.h>
#include <common/dijkstra.h>
#include <common/features.h>
#include <common/gossmap.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/route.h>
#include <common/type_to_string.h>
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
				    type_to_string(tmpctx, struct node_id, info->source));

	dst = gossmap_find_node(gossmap, info->destination);
	if (!dst)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s: unknown destination node_id (no public channels?)",
				    type_to_string(tmpctx, struct node_id, info->destination));

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

static struct gossmap_localmods *
gossmods_from_listpeerchannels(const tal_t *ctx,
			       struct plugin *plugin,
			       struct gossmap *gossmap,
			       const char *buf,
			       const jsmntok_t *toks)
{
	struct gossmap_localmods *mods = gossmap_localmods_new(ctx);
	const jsmntok_t *channels, *channel;
	size_t i;

	channels = json_get_member(buf, toks, "channels");
	json_for_each_arr(i, channel, channels) {
		struct short_channel_id scid;
		int dir;
		bool connected;
		struct node_id dst;
		struct amount_msat capacity;
		const char *state, *err;

		/* scid/direction may not exist. */
		scid.u64 = 0;
		capacity = AMOUNT_MSAT(0);
		err = json_scan(tmpctx, buf, channel,
				"{short_channel_id?:%,"
				"direction?:%,"
				"spendable_msat?:%,"
				"peer_connected:%,"
				"state:%,"
				"peer_id:%}",
				JSON_SCAN(json_to_short_channel_id, &scid),
				JSON_SCAN(json_to_int, &dir),
				JSON_SCAN(json_to_msat, &capacity),
				JSON_SCAN(json_to_bool, &connected),
				JSON_SCAN_TAL(tmpctx, json_strdup, &state),
				JSON_SCAN(json_to_node_id, &dst));
		if (err) {
			plugin_err(plugin,
				   "Bad listpeerchannels.channels %zu: %s",
				   i, err);
		}

		/* Unusable if no scid (yet) */
		if (scid.u64 == 0)
			continue;

		/* Disable if in bad state, or disconnected */
		if (!streq(state, "CHANNELD_NORMAL")
		    && !streq(state, "CHANNELD_AWAITING_SPLICE")) {
			goto disable;
		}

		if (!connected) {
			goto disable;
		}

		/* FIXME: features? */
		gossmap_local_addchan(mods, &local_id, &dst, &scid, NULL);
		gossmap_local_updatechan(mods, &scid,
					 AMOUNT_MSAT(0), capacity,
					 /* We don't charge ourselves fees */
					 0, 0, 0,
					 true,
					 dir);
		continue;

	disable:
		/* Only apply fake "disabled" if channel exists */
		if (gossmap_find_chan(gossmap, &scid)) {
			gossmap_local_updatechan(mods, &scid,
						 AMOUNT_MSAT(0), AMOUNT_MSAT(0),
						 0, 0, 0,
						 false,
						 dir);
		}
	}

	return mods;
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
	gossmap = get_gossmap();
	mods = gossmods_from_listpeerchannels(tmpctx, cmd->plugin,
					      gossmap, buf, result);

	/* Overlay local knowledge for dijkstra */
	gossmap_apply_localmods(gossmap, mods);
	res = try_route(cmd, gossmap, info);
	gossmap_remove_localmods(gossmap, mods);

	return res;
}

static struct command_result *listpeerchannels_err(struct command *cmd,
						   const char *buf,
						   const jsmntok_t *result,
						   struct getroute_info *info)
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
		   p_req("amount_msat|msatoshi", param_msat, &info->msat),
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

struct channel_routing_data {
	u32 fee_base;
	u32 fee_ppm;
	u16 delay;
	struct amount_msat htlc_minimum_msat;
	struct amount_msat htlc_maximum_msat;
	u32 channel_flags;
	u32 timestamp;
};

struct private_channel {
	struct short_channel_id scid;
	struct node_id node;
	struct channel_routing_data remote_data;
	struct channel_routing_data local_data;
};

/* pull private channel data for listchannels from listprivateinbound result */
static struct private_channel *populate_private_channel(const char *buf,
						 const jsmntok_t *channel,
						 struct private_channel *chan)
{
	const jsmntok_t *scid_tok, *cltv_tok;
	struct node_id id;
	u32 fee_base, fee_ppm;
	struct amount_msat htlc_min, htlc_max;
	u32 cltv_delta, channel_flags, timestamp;
	json_to_node_id(buf, json_get_member(buf, channel, "id"), &id);
	scid_tok = json_get_member(buf, channel, "short_channel_id");
	json_to_short_channel_id(buf, scid_tok, &chan->scid);

	const char *err;
	cltv_tok = json_get_member(buf, channel, "cltv_delta");
	if (cltv_tok) {
		err = json_scan(tmpctx, buf, channel,
				"{fee_base:%,fee_ppm:%,cltv_delta:%,"
				"htlc_minimum_msat:%,htlc_maximum_msat:%,"
				"channel_flags:%,timestamp:%}",
				JSON_SCAN(json_to_u32, &fee_base),
				JSON_SCAN(json_to_u32, &fee_ppm),
				JSON_SCAN(json_to_u32, &cltv_delta),
				JSON_SCAN(json_to_msat, &htlc_min),
				JSON_SCAN(json_to_msat, &htlc_max),
				JSON_SCAN(json_to_u32, &channel_flags),
				JSON_SCAN(json_to_u32, &timestamp));
		if (err)
			plugin_err(plugin,
				   "Bad listprivateinbound response (%s): %.*s",
				   err,
				   json_tok_full_len(channel),
				   json_tok_full(buf, channel));

		/* FIXME: populate node ids in correct position */
		chan->node = id;
		chan->remote_data.fee_base = fee_base;
		chan->remote_data.fee_ppm = fee_ppm;
		chan->remote_data.delay = cltv_delta;
		chan->remote_data.htlc_minimum_msat = htlc_min;
		chan->remote_data.htlc_maximum_msat = htlc_max;
		chan->remote_data.channel_flags = channel_flags;
		chan->remote_data.timestamp = timestamp;
	} else {
		/* Abused to indicate no update for this half chan */
		chan->remote_data.delay = 0;
	}
	cltv_tok = json_get_member(buf, channel, "local_update_cltv_delta");
	if (cltv_tok) {
		err = json_scan(tmpctx, buf, channel,
				"{local_update_cltv_delta:%,"
				"local_update_channel_flags:%,"
				"local_update_timestamp:%}",
				JSON_SCAN(json_to_u32, &cltv_delta),
				JSON_SCAN(json_to_u32, &channel_flags),
				JSON_SCAN(json_to_u32, &timestamp));
		if (err)
			plugin_err(plugin,
				   "Bad listprivateinbound response (%s): %.*s",
				   err,
				   json_tok_full_len(channel),
				   json_tok_full(buf, channel));

		/* FIXME: populate node ids in correct position */
		chan->node = id;
		chan->local_data.delay = cltv_delta;
		chan->local_data.channel_flags = channel_flags;
		chan->local_data.timestamp = timestamp;
	} else {
		chan->local_data.delay = 0;
	}

	return chan;
};

static inline const struct short_channel_id *priv_chan_scid(const struct private_channel *c)
{
	return &c->scid;
}

static inline size_t hash_scid(const struct short_channel_id *scid)
{
	/* scids cost money to generate, so simple hash works here */
	return (scid->u64 >> 32) ^ (scid->u64 >> 16) ^ scid->u64;
}

static inline bool chan_eq_scid(const struct private_channel *c,
				const struct short_channel_id *scid)
{
	return short_channel_id_eq(scid, &c->scid);
}

HTABLE_DEFINE_TYPE(struct private_channel, priv_chan_scid, hash_scid, chan_eq_scid,
		   private_channel_map);

HTABLE_DEFINE_TYPE(struct node_id, node_id_keyof, node_id_hash, node_id_eq,
		   node_map);

static const u8 *features_from_listpeerchannel(const char *buf,
					       const jsmntok_t *chan)
{
	const jsmntok_t *chan_type_tok, *bits_tok, *b;
	chan_type_tok = json_get_member(buf, chan, "channel_type");
	if (!chan_type_tok)
		return NULL;
	bits_tok = json_get_member(buf, chan_type_tok, "bits");
	if (!bits_tok)
		return NULL;
	u8* features = tal_arr(buf, u8, 0);
	size_t i;
	int feat;
	json_for_each_arr(i, b, bits_tok) {
		json_to_int(buf, b, &feat);
		set_feature_bit(&features, feat);
	}
	return features;
}

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

		if (c->private)
			continue;

		json_object_start(response, NULL);
		json_add_node_id(response, "source", &node_id[dir]);
		json_add_node_id(response, "destination", &node_id[!dir]);
		json_add_short_channel_id(response, "short_channel_id", &scid);
		json_add_num(response, "direction", dir);
		json_add_bool(response, "public", !c->private);

		gossmap_chan_get_update_details(gossmap, c, dir,
						&timestamp,
						&message_flags,
						&channel_flags,
						&fee_base_msat,
						&fee_proportional_millionths,
						&htlc_minimum_msat,
						&htlc_maximum_msat);

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

/* populate a listchannels half-channel */
static void json_add_halfchan_explicit(struct json_stream *js,
				       struct node_id *source_id,
				       struct node_id *destination_id,
				       struct short_channel_id *scid,
				       int direction,
				       struct amount_msat channel_total_msat,
				       u32 channel_flags,
				       bool active,
				       u32 timestamp,
				       u32 fee_base,
				       u32 fee_ppm,
				       u16 delay,
				       struct amount_msat htlc_minimum_msat,
				       struct amount_msat htlc_maximum_msat,
				       const u8 *features)
{
	json_object_start(js, NULL);
	json_add_node_id(js, "source", source_id);
	json_add_node_id(js, "destination", destination_id);
	json_add_short_channel_id(js, "short_channel_id", scid);
	json_add_num(js, "direction", direction);
	json_add_bool(js, "public", false);
	json_add_amount_msat(js, "amount_msat", channel_total_msat);
	json_add_num(js, "message_flags", 3);
	json_add_num(js, "channel_flags", channel_flags);
	bool disable = channel_flags & 2;
	json_add_bool(js, "active", active && !disable);
	json_add_u32(js, "last_update", timestamp);
	json_add_u32(js, "base_fee_millisatoshi", fee_base);
	json_add_u32(js, "fee_per_millionth", fee_ppm);
	json_add_u32(js, "delay", delay);
	json_add_amount_msat(js, "htlc_minimum_msat", htlc_minimum_msat);
	json_add_hex_talarr(js, "features", features);
	json_add_amount_msat(js, "htlc_maximum_msat", htlc_maximum_msat);
	json_object_end(js);
}

static const int LOCAL_CHAN = 1;
static const int REMOTE_CHAN = 2;

static void json_add_lpc_halfchan(const char *buf,
				  const jsmntok_t *chan,
				  struct private_channel_map *private_inbound,
				  u8 direction,
				  struct json_stream *js)
{
	struct short_channel_id scid;
	struct short_channel_id alias;
	struct private_channel *privchan;
	const jsmntok_t *scid_tok, *alias_tok, *amt_tok;
	const jsmntok_t *connected_tok, *chan_state_tok;
	struct node_id peer_id;
	bool active;
	struct amount_msat channel_total_msat;
	int local_dir;
	const u8 *features;

	scid_tok = json_get_member(buf, chan, "short_channel_id");
	alias_tok = json_get_member(buf, chan, "alias");
	if (alias_tok) {
		alias_tok = json_get_member(buf, alias_tok, "local");
		json_to_short_channel_id(buf, alias_tok, &alias);
	}
	if (!scid_tok) {
		if (!alias_tok) {
			plugin_err(plugin, "listpeerchannels returned channel "
				   "without scid or local alias");
			return;
		}
		scid_tok = alias_tok;
	}
	json_to_short_channel_id(buf, scid_tok, &scid);
	/* The listprivateinbound data for this channel */
	privchan = private_channel_map_get(private_inbound, &scid);
	if (!privchan && alias_tok) {
		privchan = private_channel_map_get(private_inbound,
						   &alias);
	}
	if (!privchan)
		return;
	json_to_node_id(buf, json_get_member(buf, chan, "peer_id"), &peer_id);
	json_to_int(buf, json_get_member(buf, chan, "direction"),
		    &local_dir);
	amt_tok = json_get_member(buf, chan, "total_msat");
	if (!amt_tok) {
		plugin_log(plugin, LOG_DBG, "no channel amt, skipping channel");
		return;
	}
	json_to_msat(buf, amt_tok, &channel_total_msat);
	connected_tok = json_get_member(buf, chan, "peer_connected");
	json_to_bool(buf, connected_tok, &active);
	chan_state_tok = json_get_member(buf, chan, "state");
	active &= (json_tok_streq(buf, chan_state_tok, "CHANNELD_NORMAL") ||
		   json_tok_streq(buf, chan_state_tok, "CHANNELD_AWAITING_SPLICE"));
	features = features_from_listpeerchannel(buf, chan);

	for (int d=LOCAL_CHAN; d<=REMOTE_CHAN; d*=2) {
		struct channel_routing_data *data;
		plugin_log(plugin, LOG_DBG, "dir: %i", d);
		if ((d & direction) == 0) {
			plugin_log(plugin, LOG_DBG, "skipping wrong dir: %i", d);
			continue;
		}

		if (d == LOCAL_CHAN) {
			data = &privchan->local_data;
			/* cltv_delta == 0 means this chan half has no data */
			if (!data->delay) {
				plugin_log(plugin, LOG_DBG, "no local cltv");
				continue;
			}
			struct amount_msat min_htlc_msat, max_htlc_msat;
			u32 fee_base, fee_ppm;
			const char *err;
			err = json_scan(tmpctx, buf, chan,
					"{fee_base_msat:%,fee_proportional_"
					"millionths:%,minimum_htlc_out_msat:%"
					",maximum_htlc_out_msat:%}",
					JSON_SCAN(json_to_u32, &fee_base),
					JSON_SCAN(json_to_u32, &fee_ppm),
					JSON_SCAN(json_to_msat, &min_htlc_msat),
					JSON_SCAN(json_to_msat, &max_htlc_msat));
			if (err) {
				plugin_log(plugin, LOG_DBG, "listchannels: "
					   "failed to parse listpeerchannels");
				continue;
			}
			json_add_halfchan_explicit(js,
						   &local_id,
						   &peer_id,
						   &scid,
						   local_dir,
						   channel_total_msat,
						   data->channel_flags,
						   active,
						   data->timestamp,
						   fee_base,
						   fee_ppm,
						   data->delay,
						   min_htlc_msat,
						   max_htlc_msat,
						   features);
		} else if (d == REMOTE_CHAN) {
			data = &privchan->remote_data;
			/* cltv_delta == 0 means this chan half has no data */
			if (!data->delay) {
				plugin_log(plugin, LOG_DBG, "no remote cltv");
				continue;
			}
			json_add_halfchan_explicit(js,
						   &peer_id,
						   &local_id,
						   &scid,
						   !local_dir,
						   channel_total_msat,
						   data->channel_flags,
						   active,
						   data->timestamp,
						   data->fee_base,
						   data->fee_ppm,
						   data->delay,
						   data->htlc_minimum_msat,
						   data->htlc_maximum_msat,
						   features);
		}
	}
	tal_free(features);
}

struct listchannels_opts {
	struct node_id *source;
	struct node_id *destination;
	struct short_channel_id *scid;
};

/* We record which local channels are valid; we could record which are
 * invalid, but our testsuite has some weirdness where it has local
 * channels in the store it knows nothing about. */
static void local_connected(const tal_t *ctx,
			    const char *buf,
			    const jsmntok_t *result,
			    struct node_map **connected)
{
	size_t i;
	const jsmntok_t *channel, *channels = json_get_member(buf, result, "channels");
	*connected = tal(ctx, struct node_map);

	node_map_init(*connected);
	tal_add_destructor(*connected, node_map_clear);

	json_for_each_arr(i, channel, channels) {
		struct node_id id;
		bool is_connected;
		const jsmntok_t *private_tok, *scid_tok;
		bool is_private;
		struct short_channel_id scid;
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
		private_tok = json_get_member(buf, channel, "private");
		json_to_bool(buf, private_tok, &is_private);
		scid_tok = json_get_member(buf, channel, "short_channel_id");
		if (scid_tok) {
			json_to_short_channel_id(buf, scid_tok, &scid);
		} else {
			scid_tok = json_get_member(buf, channel, "alias");
			if (!scid_tok)
				continue;
			scid_tok = json_get_member(buf, channel, "local");
			if (!scid_tok)
				continue;
			if (!json_to_short_channel_id(buf, scid_tok, &scid))
				continue;
		}

		/* Must also have a channel in CHANNELD_NORMAL/splice */
		if (streq(state, "CHANNELD_NORMAL")
		    || streq(state, "CHANNELD_AWAITING_SPLICE")) {
			node_map_add(*connected,
				     tal_dup(*connected, struct node_id, &id));
		}
	}

	return;
}

static bool peer_channel_with_peer(const char *buf, const jsmntok_t *chan,
				   struct node_id *peer_id)
{
	const jsmntok_t *peer_id_tok;
	peer_id_tok = json_get_member(buf, chan, "peer_id");
	if (!peer_id_tok)
		return false;
	struct node_id channel_peer;
	json_to_node_id(buf, peer_id_tok, &channel_peer);
	return node_id_eq(&channel_peer, peer_id);
}

static bool peer_channel_has_scid(const char *buf, const jsmntok_t *chan,
				   struct short_channel_id *scid)
{
	const jsmntok_t *scid_tok;
	struct short_channel_id channel_scid;
	scid_tok = json_get_member(buf, chan, "short_channel_id");
	/* FIXME: check for alias */
	if (scid_tok) {
		json_to_short_channel_id(buf, scid_tok, &channel_scid);
		if (short_channel_id_eq(scid, &channel_scid))
			return true;
	} else {
		scid_tok = json_get_member(buf, chan, "alias");
		if (scid_tok) {
			scid_tok = json_get_member(buf, chan, "local");
			if (!scid_tok)
				return false;
			json_to_short_channel_id(buf, scid_tok, &channel_scid);
			if (short_channel_id_eq(scid, &channel_scid))
				return true;
		}
	}
	return false;
}

struct opts_and_privinbound {
	struct listchannels_opts *opts;
	struct private_channel_map *private_inbound;
};

/* We want to combine local knowledge so we know which are actually inactive! */
/* We also want to use the local knowledge to populate local private channel
 * data in lieu of having the private gossip available. */
static struct command_result *listpeerchannels_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct opts_and_privinbound *opts_and_inbound)
{
	struct node_map *connected;
	struct gossmap_chan *c;
	struct json_stream *js;
	struct gossmap *gossmap = get_gossmap();
	struct listchannels_opts *opts = opts_and_inbound->opts;

	local_connected(opts, buf, result, &connected);

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

	/* Merge listpeerchannels data with listprivateinbound data to populate
	 * private channels */
	const jsmntok_t *chan, *channels;
	channels = json_get_member(buf, result, "channels");
	size_t i;
	struct private_channel_map *inbound;
	inbound = opts_and_inbound->private_inbound;
	json_for_each_arr(i, chan, channels) {
		if (opts->scid) {
			if (peer_channel_has_scid(buf, chan, opts->scid)) {
				json_add_lpc_halfchan(buf, chan, inbound,
						      LOCAL_CHAN | REMOTE_CHAN,
						      js);
			}
		} else if (opts->source) {
			if (node_id_eq(opts->source, &local_id)) {
				json_add_lpc_halfchan(buf, chan, inbound,
						      LOCAL_CHAN, js);
			} else if (peer_channel_with_peer(buf, chan, opts->source)) {
				json_add_lpc_halfchan(buf, chan, inbound,
						      REMOTE_CHAN, js);
			}
		} else if (opts->destination) {
			if (peer_channel_with_peer(buf, chan, opts->destination)) {
				json_add_lpc_halfchan(buf, chan, inbound,
						      LOCAL_CHAN, js);
			} else if (node_id_eq(opts->destination, &local_id)) {
				json_add_lpc_halfchan(buf, chan, inbound,
						      REMOTE_CHAN, js);
			}
		} else {
			json_add_lpc_halfchan(buf, chan, inbound,
					      LOCAL_CHAN | REMOTE_CHAN, js);
		}
	}
	json_array_end(js);
	return command_finished(cmd, js);
}

/* Private channel gossip data must be retrieved from lightningd. */
static struct command_result *listchannels_privateinbound_done(struct command *cmd,
							       const char *buffer,
							       const jsmntok_t *result,
							       struct listchannels_opts *opts)
{
	struct opts_and_privinbound *opts_and_inbound;
	struct out_req *req;
	opts_and_inbound = tal(cmd, struct opts_and_privinbound);
	opts_and_inbound->opts = opts;

	opts_and_inbound->private_inbound = tal(cmd, struct private_channel_map);
	private_channel_map_init(opts_and_inbound->private_inbound);
	tal_add_destructor(opts_and_inbound->private_inbound,
			   private_channel_map_clear);

	const jsmntok_t *channel, *channels, *scid_tok;
	channels = json_get_member(buffer, result, "private_channels");
	size_t i;
	json_for_each_arr(i, channel, channels) {
		scid_tok = json_get_member(buffer, channel, "short_channel_id");
		if (!scid_tok) {
			plugin_log(plugin, LOG_BROKEN,
				   "malformed listprivateinbound response.");
			continue;
		}
		struct short_channel_id scid;
		json_to_short_channel_id(buffer, scid_tok, &scid);

		struct private_channel *privchan;
		privchan = private_channel_map_get(opts_and_inbound->private_inbound, &scid);
		assert(!privchan);
		privchan = tal(opts_and_inbound, struct private_channel);
		assert(privchan);
		populate_private_channel(buffer, channel, privchan);
		private_channel_map_add(opts_and_inbound->private_inbound, privchan);
	}

	req = jsonrpc_request_start(cmd->plugin, cmd, "listpeerchannels",
				    listpeerchannels_done, forward_error,
				    opts_and_inbound);
	return send_outreq(cmd->plugin, req);
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
	req = jsonrpc_request_start(cmd->plugin, cmd, "listprivateinbound",
				    listchannels_privateinbound_done,
				    forward_error, opts);
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

	if (!peer)
		return capacity;
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

/* current data pulled from listpeerchannels */
struct chanliquidity {
	struct short_channel_id scid;
	struct amount_msat receivable;
	bool private;
};

static struct amount_msat max_receivable(struct short_channel_id *scid,
					 struct amount_msat *htlc_max,
					 bool *private,
					 struct chanliquidity *liquidity_data)
{
	for(size_t i = 0; i < tal_count(liquidity_data); i++) {
		if (short_channel_id_eq(&liquidity_data[i].scid, scid)) {
			if (private)
				*private = liquidity_data[i].private;
			if (amount_msat_less(liquidity_data[i].receivable, *htlc_max))
				return liquidity_data[i].receivable;
			return *htlc_max;
		}
	}
	if (private)
		*private = false;
	return *htlc_max;
}

/* Extract a private channel from listprivateinbound json and
 * reconstruct a json_listincoming entry */
static void add_private_channel(struct json_stream *js, const char *buf,
				const jsmntok_t *channel,
				struct chanliquidity *liquidity,
				struct short_channel_id *processed_channels,
				struct gossmap *gossmap,
				struct gossmap_node *me)
{
	const jsmntok_t *node_id_tok, *scid_tok, *fee_base_tok;
	const jsmntok_t *fee_ppm_tok, *cltv_tok;
	const jsmntok_t *min_tok, *max_tok, *features_tok;

	struct node_id id;
	struct short_channel_id scid, remote_alias;
	u32 fee_base, fee_ppm, cltv_delta;
	struct amount_msat htlc_min, htlc_max;
	u8 *features;
	bool private;

	scid_tok = json_get_member(buf, channel, "short_channel_id");
	if (!scid_tok)
		return;
	json_to_short_channel_id(buf, scid_tok, &scid);
	/* check if we've already used this from the gossmap
	 * public channels */
	for (size_t i = 0; i < tal_count(processed_channels); i++) {
		if (short_channel_id_eq(&scid, &processed_channels[i]))
			return;
	}

	/* listprivateinbound provides outbound cltv_delta, channel flags and
	 * timestamp. It's possible that only outbound routing fields were
	 * provided, in which case the entry should be ignored. */
	cltv_tok = json_get_member(buf, channel, "cltv_delta");
	if (!cltv_tok)
		return;

	json_object_start(js, NULL);

	node_id_tok = json_get_member(buf, channel, "id");
	assert(node_id_tok);
	json_to_node_id(buf, node_id_tok, &id);
	json_add_node_id(js, "id", &id);


	json_add_short_channel_id(js, "short_channel_id", &scid);

	scid_tok = json_get_member(buf, channel, "remote_alias");
	if (scid_tok) {
		json_to_short_channel_id(buf, scid_tok, &remote_alias);
		json_add_short_channel_id(js, "remote_alias", &remote_alias);
	}

	fee_base_tok = json_get_member(buf, channel, "fee_base");
	assert(fee_base_tok);
	json_to_u32(buf, fee_base_tok, &fee_base);
	json_add_u32(js, "fee_base_msat", fee_base);

	min_tok = json_get_member(buf, channel, "htlc_minimum_msat");
	assert(min_tok);
	json_to_msat(buf, min_tok, &htlc_min);
	json_add_amount_msat(js, "htlc_min_msat", htlc_min);

	max_tok = json_get_member(buf, channel, "htlc_maximum_msat");
	assert(max_tok);
	json_to_msat(buf, max_tok, &htlc_max);
	json_add_amount_msat(js, "htlc_max_msat", htlc_max);

	fee_ppm_tok = json_get_member(buf, channel, "fee_ppm");
	assert(fee_ppm_tok);
	json_to_u32(buf, fee_ppm_tok, &fee_ppm);
	json_add_u32(js, "fee_proportional_millionths", fee_ppm);

	cltv_tok = json_get_member(buf, channel, "cltv_delta");
	assert(cltv_tok);
	json_to_u32(buf, cltv_tok, &cltv_delta);
	json_add_u32(js, "cltv_expiry_delta", cltv_delta);

	struct amount_msat receivable;
	struct gossmap_node *peer;
	peer = gossmap_find_node(gossmap, &id);
	receivable = peer_capacity(gossmap, me, peer, NULL);
	if (amount_msat_greater(receivable, htlc_max))
		receivable = htlc_max;
	receivable = max_receivable(&scid, &receivable, &private, liquidity);
	json_add_amount_msat(js, "incoming_capacity_msat", receivable);

	json_add_bool(js, "public", !private);

	features_tok = json_get_member(buf, channel, "features");
	assert(features_tok);
	features = json_tok_bin_from_hex(tmpctx, buf, features_tok);
	json_add_hex_talarr(js, "peer_features", features);

	json_object_end(js);
}

static struct command_result *listprivateinbound_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct chanliquidity *liquidity)
{
	struct json_stream *js;
	struct gossmap_node *me;
	struct gossmap *gossmap;
	struct short_channel_id *processed_channels = tal_arr(cmd,
					struct short_channel_id, 0);
	js = jsonrpc_stream_success(cmd);

	json_array_start(js, "incoming");
	gossmap = get_gossmap();
	me = gossmap_find_node(gossmap, &local_id);
	if (!me)
		goto public_done;

	for (size_t i = 0; i < me->num_chans; i++) {
		struct node_id peer_id;
		int dir;
		struct gossmap_chan *ourchan;
		struct gossmap_node *peer;
		struct short_channel_id scid;
		const u8 *peer_features;
		struct amount_msat htlc_max;

		ourchan = gossmap_nth_chan(gossmap, me, i, &dir);
		/* FIXME: Rip out once private gossip removed. */
		if (ourchan->private)
			continue;
		/* Entirely missing?  Ignore. */
		if (ourchan->cupdate_off[!dir] == 0)
			continue;
		/* We used to ignore if the peer said it was disabled,
		 * but we have a report of LND telling us our unannounced
		 * channel is disabled, so we still use them. */
		peer = gossmap_nth_node(gossmap, ourchan, !dir);
		scid = gossmap_chan_scid(gossmap, ourchan);
		htlc_max = amount_msat(fp16_to_u64(ourchan->half[!dir]
						   .htlc_max));

		json_object_start(js, NULL);
		gossmap_node_get_id(gossmap, peer, &peer_id);
		json_add_node_id(js, "id", &peer_id);
		json_add_short_channel_id(js, "short_channel_id", &scid);
		json_add_amount_msat(js, "fee_base_msat",
				     amount_msat(ourchan->half[!dir].base_fee));
		json_add_amount_msat(js, "htlc_min_msat",
				     amount_msat(fp16_to_u64(ourchan->half[!dir]
							     .htlc_min)));
		json_add_amount_msat(js, "htlc_max_msat", htlc_max);
		json_add_u32(js, "fee_proportional_millionths",
			     ourchan->half[!dir].proportional_fee);
		json_add_u32(js, "cltv_expiry_delta", ourchan->half[!dir].delay);
		struct amount_msat max_inbound;
		max_inbound = peer_capacity(gossmap, me, peer, ourchan);
		/* limit by peer's total inbound */
		if (amount_msat_greater(max_inbound, htlc_max))
			max_inbound = htlc_max;
		json_add_amount_msat(js, "incoming_capacity_msat",
				     max_receivable(&scid, &max_inbound,
						    NULL, liquidity));
		json_add_bool(js, "public", !ourchan->private);
		peer_features = gossmap_node_get_features(tmpctx, gossmap, peer);
		if (peer_features)
			json_add_hex_talarr(js, "peer_features", peer_features);
		json_object_end(js);
		tal_arr_expand(&processed_channels, scid);
	}

public_done:

	{
		const jsmntok_t *channel, *channels;
		channels = json_get_member(buf, result, "private_channels");
		assert(channels);
		size_t i;

		json_for_each_arr(i, channel, channels) {
			add_private_channel(js, buf, channel, liquidity,
					    processed_channels, gossmap,
					    me);
		}

		json_array_end(js);
		tal_free(processed_channels);

		return command_finished(cmd, js);
	}

}

static struct command_result *findinboundliquidity(struct command *cmd,
						   const char *buf,
						   const jsmntok_t *result,
						   void *cb_arg UNUSED)
{
	/* Get current values for private inbound receiving capacity. */
	struct out_req *req;

	size_t i;
	const jsmntok_t *channel;
	const jsmntok_t *channels = json_get_member(buf, result, "channels");
	assert(channels);

	struct chanliquidity *inbound = tal_arr(cmd, struct chanliquidity, 0);

	json_for_each_arr(i, channel, channels) {
		const jsmntok_t *scid_tok, *receivable_tok, *private_tok;
		struct chanliquidity chanliquidity;
		scid_tok = json_get_member(buf, channel, "short_channel_id");
		if (!scid_tok) {
			const jsmntok_t *alias_tok;
			alias_tok = json_get_member(buf, channel, "alias");
			if (!alias_tok)
				continue;
			scid_tok = json_get_member(buf, alias_tok, "local");
			if (!scid_tok)
				continue;
		}
		json_to_short_channel_id(buf, scid_tok, &chanliquidity.scid);
		receivable_tok = json_get_member(buf, channel, "receivable_msat");
		assert(receivable_tok);
		json_to_msat(buf, receivable_tok, &chanliquidity.receivable);
		/* This differentiates unannounced public channels (zeroconf)
		 * from truly private channels */
		private_tok = json_get_member(buf, channel, "private");
		json_to_bool(buf, private_tok, &chanliquidity.private);
		tal_arr_expand(&inbound, chanliquidity);
	}

	req = jsonrpc_request_start(cmd->plugin, cmd, "listprivateinbound",
				    listprivateinbound_done, forward_error,
				    inbound);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *json_listincoming(struct command *cmd,
						const char *buffer,
						const jsmntok_t *params)
{
	struct out_req *req;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	req = jsonrpc_request_start(cmd->plugin, cmd, "listpeerchannels",
				    findinboundliquidity, forward_error, NULL);
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
		"channels",
		"Primitive route command",
		"Show route to {id} for {msatoshi}, using {riskfactor} and optional {cltv} (default 9). "
		"If specified search from {fromid} otherwise use this node as source. "
		"Randomize the route with up to {fuzzpercent} (ignored)). "
		"{exclude} an array of short-channel-id/direction (e.g. [ '564334x877x1/0', '564195x1292x0/1' ]) "
		"or node-id from consideration. "
		"Set the {maxhops} the route can take (default 20).",
		json_getroute,
	},
	{
		"listchannels",
		"channels",
		"List all known channels in the network",
		"Show channels for {short_channel_id}, {source} or {destination} "
		"(or all known channels, if not specified)",
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
	}
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_STATIC, true, NULL, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0, NULL);
}
