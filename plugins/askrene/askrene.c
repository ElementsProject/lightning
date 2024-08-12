/* All your payment questions answered!
 *
 * This powerful oracle combines data from the network, and then
 * determines optimal routes.
 *
 * When you feed it information, these are remembered as "layers", so you
 * can ask questions with (or without) certain layers.
 */
#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/gossmap.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/route.h>
#include <errno.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/flow.h>
#include <plugins/askrene/layer.h>
#include <plugins/askrene/mcf.h>
#include <plugins/askrene/reserve.h>
#include <plugins/libplugin.h>

static struct askrene *get_askrene(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct askrene);
}

static bool have_layer(const char **layers, const char *name)
{
	for (size_t i = 0; i < tal_count(layers); i++) {
		if (streq(layers[i], name))
			return true;
	}
	return false;
}

/* JSON helpers */
static struct command_result *param_string_array(struct command *cmd,
						 const char *name,
						 const char *buffer,
						 const jsmntok_t *tok,
						 const char ***arr)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY)
		return command_fail_badparam(cmd, name, buffer, tok, "should be an array");

	*arr = tal_arr(cmd, const char *, tok->size);
	json_for_each_arr(i, t, tok) {
		if (t->type != JSMN_STRING)
			return command_fail_badparam(cmd, name, buffer, t, "should be a string");
		(*arr)[i] = json_strdup(*arr, buffer, t);
	}
	return NULL;
}

static struct command_result *param_known_layer(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						struct layer **layer)
{
	const char *layername;
	struct command_result *ret = param_string(cmd, name, buffer, tok, &layername);
	if (ret)
		return ret;

	*layer = find_layer(get_askrene(cmd->plugin), layername);
	tal_free(layername);
	if (!*layer)
		return command_fail_badparam(cmd, name, buffer, tok, "Unknown layer");
	return NULL;
}

static bool json_to_zero_or_one(const char *buffer, const jsmntok_t *tok, int *num)
{
	u32 v32;
	if (!json_to_u32(buffer, tok, &v32))
		return false;
	if (v32 != 0 && v32 != 1)
		return false;
	*num = v32;
	return true;
}

static struct command_result *param_zero_or_one(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						int **num)
{
	*num = tal(cmd, int);
	if (json_to_zero_or_one(buffer, tok, *num))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be 0 or 1");
}

struct reserve_path {
	struct short_channel_id_dir *scidds;
	struct amount_msat *amounts;
};

static struct command_result *parse_reserve_path(struct command *cmd,
						 const char *name,
						 const char *buffer,
						 const jsmntok_t *tok,
						 struct short_channel_id_dir *scidd,
						 struct amount_msat *amount)
{
	const char *err;

	err = json_scan(tmpctx, buffer, tok, "{short_channel_id:%,direction:%,amount_msat:%}",
			JSON_SCAN(json_to_short_channel_id, &scidd->scid),
			JSON_SCAN(json_to_zero_or_one, &scidd->dir),
			JSON_SCAN(json_to_msat, amount));
	if (err)
		return command_fail_badparam(cmd, name, buffer, tok, err);
	return NULL;
}

static struct command_result *param_reserve_path(struct command *cmd,
						 const char *name,
						 const char *buffer,
						 const jsmntok_t *tok,
						 struct reserve_path **path)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY)
		return command_fail_badparam(cmd, name, buffer, tok, "should be an array");

	*path = tal(cmd, struct reserve_path);
	(*path)->scidds = tal_arr(cmd, struct short_channel_id_dir, tok->size);
	(*path)->amounts = tal_arr(cmd, struct amount_msat, tok->size);
	json_for_each_arr(i, t, tok) {
		struct command_result *ret;

		ret = parse_reserve_path(cmd, name, buffer, t,
					 &(*path)->scidds[i],
					 &(*path)->amounts[i]);
		if (ret)
			return ret;
	}
	return NULL;
}

static fp16_t *get_capacities(const tal_t *ctx,
			      struct plugin *plugin, struct gossmap *gossmap)
{
	fp16_t *caps;
	struct gossmap_chan *c;

	caps = tal_arrz(ctx, fp16_t, gossmap_max_chan_idx(gossmap));

	for (c = gossmap_first_chan(gossmap);
	     c;
	     c = gossmap_next_chan(gossmap, c)) {
		struct amount_sat cap;

		if (!gossmap_chan_get_capacity(gossmap, c, &cap)) {
			plugin_log(plugin, LOG_BROKEN,
				   "get_capacity failed for channel?");
			cap = AMOUNT_SAT(0);
		}
		caps[gossmap_chan_idx(gossmap, c)]
			= u64_to_fp16(cap.satoshis, true); /* Raw: fp16 */
	}
	return caps;
}

/* If we're the payer, we don't add delay or fee to our own outgoing
 * channels.  This wouldn't be right if we looped back through ourselves,
 * but we won't. */
/* FIXME: We could cache this until gossmap changes... */
static void add_free_source(struct plugin *plugin,
			    struct gossmap *gossmap,
			    struct gossmap_localmods *localmods,
			    const struct node_id *source)
{
	const struct gossmap_node *srcnode;

	/* If we're not in map, we complain later (unless we're purely
	 * using local channels) */
	srcnode = gossmap_find_node(gossmap, source);
	if (!srcnode)
		return;

	for (size_t i = 0; i < srcnode->num_chans; i++) {
		struct gossmap_chan *c;
		int dir;
		struct short_channel_id scid;

		c = gossmap_nth_chan(gossmap, srcnode, i, &dir);
		scid = gossmap_chan_scid(gossmap, c);
		if (!gossmap_local_updatechan(localmods,
					      scid,
					      /* Keep min and max */
					      gossmap_chan_htlc_min(c, dir),
					      gossmap_chan_htlc_max(c, dir),
					      0, 0, 0,
					      /* Keep enabled flag */
					      c->half[dir].enabled,
					      dir))
			plugin_err(plugin, "Could not zero fee on local %s",
				   fmt_short_channel_id(tmpctx, scid));
	}
}

/* Returns an error message, or sets *routes */
static const char *get_routes(const tal_t *ctx,
			      struct plugin *plugin,
			      const struct node_id *source,
			      const struct node_id *dest,
			      struct amount_msat amount,
			      struct amount_msat maxfee,
			      u32 finalcltv,
			      const char **layers,
			      struct gossmap_localmods *localmods,
			      const struct layer *local_layer,
			      struct route ***routes,
			      struct amount_msat **amounts,
			      double *probability)
{
	struct askrene *askrene = get_askrene(plugin);
	struct route_query *rq = tal(ctx, struct route_query);
	struct flow **flows;
	const struct gossmap_node *srcnode, *dstnode;
	double delay_feefactor;
	double base_fee_penalty;
	u32 prob_cost_factor, mu;
	const char *ret;
	bool zero_cost;

	if (gossmap_refresh(askrene->gossmap, NULL)) {
		/* FIXME: gossmap_refresh callbacks to we can update in place */
		tal_free(askrene->capacities);
		askrene->capacities = get_capacities(askrene, askrene->plugin, askrene->gossmap);
	}

	rq->plugin = plugin;
	rq->gossmap = askrene->gossmap;
	rq->reserved = askrene->reserved;
	rq->layers = tal_arr(rq, const struct layer *, 0);
	rq->capacities = tal_dup_talarr(rq, fp16_t, askrene->capacities);

	/* If we're told to zerocost local channels, then make sure that's done
	 * in local mods as well. */
	zero_cost = have_layer(layers, "auto.sourcefree")
		&& node_id_eq(source, &askrene->my_id);

	/* Layers don't have to exist: they might be empty! */
	for (size_t i = 0; i < tal_count(layers); i++) {
		const struct layer *l = find_layer(askrene, layers[i]);
		if (!l) {
			if (local_layer && streq(layers[i], "auto.localchans")) {
				plugin_log(plugin, LOG_DBG, "Adding auto.localchans");
				l = local_layer;
			} else
				continue;
		}

		tal_arr_expand(&rq->layers, l);
		/* FIXME: Implement localmods_merge, and cache this in layer? */
		layer_add_localmods(l, rq->gossmap, zero_cost, localmods);

		/* Clear any entries in capacities array if we
		 * override them (incl local channels) */
		layer_clear_overridden_capacities(l, askrene->gossmap, rq->capacities);
	}

	/* This does not see local mods!  If you add local channel in a layer, it won't
	 * have costs zeroed out here. */
	if (have_layer(layers, "auto.sourcefree"))
		add_free_source(plugin, askrene->gossmap, localmods, source);

	/* Clear scids with reservations, too, so we don't have to look up
	 * all the time! */
	reserves_clear_capacities(askrene->reserved, askrene->gossmap, rq->capacities);

	gossmap_apply_localmods(askrene->gossmap, localmods);

	srcnode = gossmap_find_node(askrene->gossmap, source);
	if (!srcnode) {
		ret = tal_fmt(ctx, "Unknown source node %s", fmt_node_id(tmpctx, source));
		goto out;
	}

	dstnode = gossmap_find_node(askrene->gossmap, dest);
	if (!dstnode) {
		ret = tal_fmt(ctx, "Unknown destination node %s", fmt_node_id(tmpctx, dest));
		goto out;
	}

	delay_feefactor = 1.0/1000000;
	base_fee_penalty = 10.0;

	/* From mcf.c: The input parameter `prob_cost_factor` in the function
	 * `minflow` is defined as the PPM from the delivery amount `T` we are
	 * *willing to pay* to increase the prob. of success by 0.1% */

	/* This value is somewhat implied by our fee budget: say we would pay
	 * the entire budget for 100% probability, that means prob_cost_factor
	 * is (fee / amount) / 1000, or in PPM: (fee / amount) * 1000 */
	if (amount_msat_zero(amount))
		prob_cost_factor = 0;
	else
		prob_cost_factor = amount_msat_ratio(maxfee, amount) * 1000;

	/* First up, don't care about fees.   */
	mu = 0;
	flows = minflow(rq, rq, srcnode, dstnode, amount,
			mu, delay_feefactor, base_fee_penalty, prob_cost_factor);
	if (!flows) {
		/* FIXME: disjktra here to see if there is any route, and
		 * diagnose problem (offline peers?  Not enough capacity at
		 * our end?  Not enough at theirs?) */
		ret = tal_fmt(ctx, "Could not find route");
		goto out;
	}

	/* Too much delay? */
	/* BOLT #4:
	 * ## `max_htlc_cltv` Selection
	 *
	 * This ... value is defined as 2016 blocks, based on historical value
	 * deployed by Lightning implementations.
	 */
	/* FIXME: Typo in spec for CLTV in descripton!  But it breaks our spelling check, so we omit it above */
	while (finalcltv + flows_worst_delay(flows) > 2016) {
		delay_feefactor *= 2;
		flows = minflow(rq, rq, srcnode, dstnode, amount,
				mu, delay_feefactor, base_fee_penalty, prob_cost_factor);
		if (!flows || delay_feefactor > 10) {
			ret = tal_fmt(ctx, "Could not find route without excessive delays");
			goto out;
		}
	}

	/* Too expensive? */
	while (amount_msat_greater(flowset_fee(plugin, flows), maxfee)) {
		mu += 10;
		flows = minflow(rq, rq, srcnode, dstnode, amount,
				mu, delay_feefactor, base_fee_penalty, prob_cost_factor);
		if (!flows || mu == 100) {
			ret = tal_fmt(ctx, "Could not find route without excessive cost");
			goto out;
		}
	}

	if (finalcltv + flows_worst_delay(flows) > 2016) {
		ret = tal_fmt(ctx, "Could not find route without excessive cost or delays");
		goto out;
	}

	/* Convert back into routes, with delay and other information fixed */
	*routes = tal_arr(ctx, struct route *, tal_count(flows));
	*amounts = tal_arr(ctx, struct amount_msat, tal_count(flows));
	for (size_t i = 0; i < tal_count(flows); i++) {
		struct route *r;
		struct amount_msat msat;
		u32 delay;

		(*routes)[i] = r = tal(*routes, struct route);
		/* FIXME: flow_probability doesn't take into account other flows! */
		r->success_prob = flows[i]->success_prob;
		r->hops = tal_arr(r, struct route_hop, tal_count(flows[i]->path));

		/* Fill in backwards to calc amount and delay */
		msat = flows[i]->amount;
		delay = finalcltv;

		for (int j = tal_count(flows[i]->path) - 1; j >= 0; j--) {
			struct route_hop *rh = &r->hops[j];
			struct gossmap_node *far_end;
			const struct half_chan *h = flow_edge(flows[i], j);

			if (!amount_msat_add_fee(&msat, h->base_fee, h->proportional_fee))
				plugin_err(plugin, "Adding fee to amount");
			delay += h->delay;

			rh->scid = gossmap_chan_scid(rq->gossmap, flows[i]->path[j]);
			rh->direction = flows[i]->dirs[j];
			far_end = gossmap_nth_node(rq->gossmap, flows[i]->path[j], !flows[i]->dirs[j]);
			gossmap_node_get_id(rq->gossmap, far_end, &rh->node_id);
			rh->amount = msat;
			rh->delay = delay;
		}
		(*amounts)[i] = flow_delivers(flows[i]);
	}

	*probability = flowset_probability(flows, rq);
	ret = NULL;

out:
	gossmap_remove_localmods(askrene->gossmap, localmods);
	return ret;
}

void get_constraints(const struct route_query *rq,
		     const struct gossmap_chan *chan,
		     int dir,
		     struct amount_msat *min,
		     struct amount_msat *max)
{
	struct short_channel_id_dir scidd;
	const struct reserve *reserve;
	size_t idx = gossmap_chan_idx(rq->gossmap, chan);

	*min = AMOUNT_MSAT(0);

	/* Fast path: no information known, no reserve. */
	if (idx < tal_count(rq->capacities) && rq->capacities[idx] != 0) {
		*max = amount_msat(fp16_to_u64(rq->capacities[idx]) * 1000);
		return;
	}

	/* Naive implementation! */
	scidd.scid = gossmap_chan_scid(rq->gossmap, chan);
	scidd.dir = dir;
	*max = AMOUNT_MSAT(-1ULL);

	/* Look through layers for any constraints */
	for (size_t i = 0; i < tal_count(rq->layers); i++) {
		const struct constraint *cmin, *cmax;
		cmin = layer_find_constraint(rq->layers[i], &scidd, CONSTRAINT_MIN);
		if (cmin && amount_msat_greater(cmin->limit, *min))
			*min = cmin->limit;
		cmax = layer_find_constraint(rq->layers[i], &scidd, CONSTRAINT_MAX);
		if (cmax && amount_msat_less(cmax->limit, *max))
			*max = cmax->limit;
	}

	/* Might be here because it's reserved, but capacity is normal. */
	if (amount_msat_eq(*max, AMOUNT_MSAT(-1ULL))) {
		struct amount_sat cap;
		if (gossmap_chan_get_capacity(rq->gossmap, chan, &cap)) {
			/* Shouldn't happen! */
			if (!amount_sat_to_msat(max, cap)) {
				plugin_log(rq->plugin, LOG_BROKEN,
					   "Local channel %s with capacity %s?",
					   fmt_short_channel_id(tmpctx, scidd.scid),
					   fmt_amount_sat(tmpctx, cap));
			}
		} else {
			/* Shouldn't happen: local channels have explicit constraints */
			plugin_log(rq->plugin, LOG_BROKEN,
				   "Channel %s without capacity?",
				   fmt_short_channel_id(tmpctx, scidd.scid));
		}
	}

	/* Finally, if any is in use, subtract that! */
	reserve = find_reserve(rq->reserved, &scidd);
	if (reserve) {
		/* They can definitely *try* to push too much through a channel! */
		if (!amount_msat_sub(min, *min, reserve->amount))
			*min = AMOUNT_MSAT(0);
		if (!amount_msat_sub(max, *max, reserve->amount))
			*max = AMOUNT_MSAT(0);
	}
}

struct getroutes_info {
	struct node_id *source, *dest;
	struct amount_msat *amount, *maxfee;
	u32 *finalcltv;
	const char **layers;
};

static struct command_result *do_getroutes(struct command *cmd,
					   struct gossmap_localmods *localmods,
					   const struct layer *local_layer,
					   const struct getroutes_info *info)
{
	const char *err;
	double probability;
	struct amount_msat *amounts;
	struct route **routes;
	struct json_stream *response;

	err = get_routes(cmd, cmd->plugin,
			 info->source, info->dest,
			 *info->amount, *info->maxfee, *info->finalcltv,
			 info->layers, localmods, local_layer,
			 &routes, &amounts, &probability);
	if (err)
		return command_fail(cmd, PAY_ROUTE_NOT_FOUND, "%s", err);

	response = jsonrpc_stream_success(cmd);
	json_add_u64(response, "probability_ppm", (u64)(probability * 1000000));
	json_array_start(response, "routes");
	for (size_t i = 0; i < tal_count(routes); i++) {
		json_object_start(response, NULL);
		json_add_u64(response, "probability_ppm", (u64)(routes[i]->success_prob * 1000000));
		json_add_amount_msat(response, "amount_msat", amounts[i]);
		json_array_start(response, "path");
		for (size_t j = 0; j < tal_count(routes[i]->hops); j++) {
			const struct route_hop *r = &routes[i]->hops[j];
			json_object_start(response, NULL);
			json_add_short_channel_id(response, "short_channel_id", r->scid);
			json_add_u32(response, "direction", r->direction);
			json_add_node_id(response, "next_node_id", &r->node_id);
			json_add_amount_msat(response, "amount_msat", r->amount);
			json_add_u32(response, "delay", r->delay);
			json_object_end(response);
		}
		json_array_end(response);
		json_object_end(response);
	}
	json_array_end(response);
	return command_finished(cmd, response);
}

static void add_localchan(struct gossmap_localmods *mods,
			  const struct node_id *self,
			  const struct node_id *peer,
			  const struct short_channel_id_dir *scidd,
			  struct amount_msat htlcmin,
			  struct amount_msat htlcmax,
			  struct amount_msat spendable,
			  struct amount_msat fee_base,
			  u32 fee_proportional,
			  u32 cltv_delta,
			  bool enabled,
			  const char *buf UNUSED,
			  const jsmntok_t *chantok UNUSED,
			  struct layer *local_layer)
{
	gossmod_add_localchan(mods, self, peer, scidd, htlcmin, htlcmax,
			      spendable, fee_base, fee_proportional, cltv_delta, enabled,
			      buf, chantok, local_layer);

	/* Known capacity on local channels (ts = max) */
	layer_update_constraint(local_layer, scidd, CONSTRAINT_MIN, UINT64_MAX, spendable);
	layer_update_constraint(local_layer, scidd, CONSTRAINT_MAX, UINT64_MAX, spendable);
}

static struct command_result *
listpeerchannels_done(struct command *cmd,
		      const char *buffer,
		      const jsmntok_t *toks,
		      struct getroutes_info *info)
{
	struct layer *local_layer = new_temp_layer(info, "auto.localchans");
	struct gossmap_localmods *localmods;
	bool zero_cost;

	/* If we're told to zerocost local channels, then make sure that's done
	 * in local mods as well. */
	zero_cost = have_layer(info->layers, "auto.sourcefree")
		&& node_id_eq(info->source, &get_askrene(cmd->plugin)->my_id);

	localmods = gossmods_from_listpeerchannels(cmd,
						   &get_askrene(cmd->plugin)->my_id,
						   buffer, toks,
						   zero_cost,
						   add_localchan,
						   local_layer);

	return do_getroutes(cmd, localmods, local_layer, info);
}

static struct command_result *json_getroutes(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *params)
{
	struct getroutes_info *info = tal(cmd, struct getroutes_info);

	if (!param(cmd, buffer, params,
		   p_req("source", param_node_id, &info->source),
		   p_req("destination", param_node_id, &info->dest),
		   p_req("amount_msat", param_msat, &info->amount),
		   p_req("layers", param_string_array, &info->layers),
		   p_req("maxfee_msat", param_msat, &info->maxfee),
		   p_req("finalcltv", param_u32, &info->finalcltv),
		   NULL))
		return command_param_failed();

	if (have_layer(info->layers, "auto.localchans")) {
		struct out_req *req;

		req = jsonrpc_request_start(cmd->plugin, cmd,
					    "listpeerchannels",
					    listpeerchannels_done,
					    forward_error, info);
		return send_outreq(cmd->plugin, req);
	}

	return do_getroutes(cmd, gossmap_localmods_new(cmd), NULL, info);
}

static struct command_result *json_askrene_reserve(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *params)
{
	struct reserve_path *path;
	struct json_stream *response;
	size_t num;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param(cmd, buffer, params,
		   p_req("path", param_reserve_path, &path),
		   NULL))
		return command_param_failed();

	num = reserves_add(askrene->reserved, path->scidds, path->amounts,
			   tal_count(path->scidds));
	if (num != tal_count(path->scidds)) {
		const struct reserve *r = find_reserve(askrene->reserved, &path->scidds[num]);
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Overflow reserving %zu: %s amount %s (%s reserved already)",
				    num,
				    fmt_short_channel_id_dir(tmpctx, &path->scidds[num]),
				    fmt_amount_msat(tmpctx, path->amounts[num]),
				    r ? fmt_amount_msat(tmpctx, r->amount) : "none");
	}

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_unreserve(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *params)
{
	struct reserve_path *path;
	struct json_stream *response;
	size_t num;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param(cmd, buffer, params,
		   p_req("path", param_reserve_path, &path),
		   NULL))
		return command_param_failed();

	num = reserves_remove(askrene->reserved, path->scidds, path->amounts,
			      tal_count(path->scidds));
	if (num != tal_count(path->scidds)) {
		const struct reserve *r = find_reserve(askrene->reserved, &path->scidds[num]);
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Underflow unreserving %zu: %s amount %s (%zu reserved, amount %s)",
				    num,
				    fmt_short_channel_id_dir(tmpctx, &path->scidds[num]),
				    fmt_amount_msat(tmpctx, path->amounts[num]),
				    r ? r->num_htlcs : 0,
				    r ? fmt_amount_msat(tmpctx, r->amount) : "none");
	}

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *param_layername(struct command *cmd,
					      const char *name,
					      const char *buffer,
					      const jsmntok_t *tok,
					      const char **str)
{
	*str = tal_strndup(cmd, buffer + tok->start,
			   tok->end - tok->start);
	if (strstarts(*str, "auto."))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "New layers cannot start with auto.");
	return NULL;
}

static struct command_result *json_askrene_create_channel(struct command *cmd,
							  const char *buffer,
							  const jsmntok_t *params)
{
	const char *layername;
	struct layer *layer;
	const struct local_channel *lc;
	struct node_id *src, *dst;
	struct short_channel_id *scid;
	struct amount_msat *capacity;
	struct json_stream *response;
	struct amount_msat *htlc_min, *htlc_max, *base_fee;
	u32 *proportional_fee;
	u16 *delay;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param_check(cmd, buffer, params,
			 p_req("layer", param_layername, &layername),
			 p_req("source", param_node_id, &src),
			 p_req("destination", param_node_id, &dst),
			 p_req("short_channel_id", param_short_channel_id, &scid),
			 p_req("capacity_msat", param_msat, &capacity),
			 p_req("htlc_minimum_msat", param_msat, &htlc_min),
			 p_req("htlc_maximum_msat", param_msat, &htlc_max),
			 p_req("fee_base_msat", param_msat, &base_fee),
			 p_req("fee_proportional_millionths", param_u32, &proportional_fee),
			 p_req("delay", param_u16, &delay),
			 NULL))
		return command_param_failed();

	/* If it exists, it must match */
	layer = find_layer(askrene, layername);
	if (layer) {
		lc = layer_find_local_channel(layer, *scid);
		if (lc && !layer_check_local_channel(lc, src, dst, *capacity)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "channel already exists with different values!");
		}
	} else
		lc = NULL;

	if (command_check_only(cmd))
		return command_check_done(cmd);

	if (!layer)
		layer = new_layer(askrene, layername);

	layer_update_local_channel(layer, src, dst, *scid, *capacity,
				   *base_fee, *proportional_fee, *delay,
				   *htlc_min, *htlc_max);

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_inform_channel(struct command *cmd,
							    const char *buffer,
							    const jsmntok_t *params)
{
	struct layer *layer;
	const char *layername;
	struct short_channel_id *scid;
	int *direction;
	struct json_stream *response;
	struct amount_msat *max, *min;
	const struct constraint *c;
	struct short_channel_id_dir scidd;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param_check(cmd, buffer, params,
			 p_req("layer", param_layername, &layername),
			 p_req("short_channel_id", param_short_channel_id, &scid),
			 p_req("direction", param_zero_or_one, &direction),
			 p_opt("minimum_msat", param_msat, &min),
			 p_opt("maximum_msat", param_msat, &max),
			 NULL))
		return command_param_failed();

	if ((!min && !max) || (min && max)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Must specify exactly one of maximum_msat/minimum_msat");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	layer = find_layer(askrene, layername);
	if (!layer)
		layer = new_layer(askrene, layername);

	/* Calls expect a convenient short_channel_id_dir struct */
	scidd.scid = *scid;
	scidd.dir = *direction;

	if (min) {
		c = layer_update_constraint(layer, &scidd, CONSTRAINT_MIN,
					    time_now().ts.tv_sec, *min);
	} else {
		c = layer_update_constraint(layer, &scidd, CONSTRAINT_MAX,
					    time_now().ts.tv_sec, *max);
	}
	response = jsonrpc_stream_success(cmd);
	json_add_constraint(response, "constraint", c, layer);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_disable_node(struct command *cmd,
							const char *buffer,
							const jsmntok_t *params)
{
	struct node_id *node;
	const char *layername;
	struct layer *layer;
	struct json_stream *response;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param(cmd, buffer, params,
		   p_req("layer", param_layername, &layername),
		   p_req("node", param_node_id, &node),
		   NULL))
		return command_param_failed();

	layer = find_layer(askrene, layername);
	if (!layer)
		layer = new_layer(askrene, layername);

	/* We save this in the layer, because they want us to disable all the channels
	 * to the node at *use* time (a new channel might be gossiped!). */
	layer_add_disabled_node(layer, node);

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_listlayers(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *params)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	const char *layername;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_opt("layer", param_string, &layername),
		   NULL))
		return command_param_failed();

	response = jsonrpc_stream_success(cmd);
	json_add_layers(response, askrene, "layers", layername);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_age(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *params)
{
	struct layer *layer;
	struct json_stream *response;
	u64 *cutoff;
	size_t num_removed;

	if (!param(cmd, buffer, params,
		   p_req("layer", param_known_layer, &layer),
		   p_req("cutoff", param_u64, &cutoff),
		   NULL))
		return command_param_failed();

	num_removed = layer_trim_constraints(layer, *cutoff);

	response = jsonrpc_stream_success(cmd);
	json_add_string(response, "layer", layer_name(layer));
	json_add_u64(response, "num_removed", num_removed);
	return command_finished(cmd, response);
}

static const struct plugin_command commands[] = {
	{
		"getroutes",
		json_getroutes,
	},
	{
		"askrene-reserve",
		json_askrene_reserve,
	},
	{
		"askrene-unreserve",
		json_askrene_unreserve,
	},
	{
		"askrene-disable-node",
		json_askrene_disable_node,
	},
	{
		"askrene-create-channel",
		json_askrene_create_channel,
	},
	{
		"askrene-inform-channel",
		json_askrene_inform_channel,
	},
	{
		"askrene-listlayers",
		json_askrene_listlayers,
	},
	{
		"askrene-age",
		json_askrene_age,
	},
};

static void askrene_markmem(struct plugin *plugin, struct htable *memtable)
{
	layer_memleak_mark(get_askrene(plugin), memtable);
}

static const char *init(struct plugin *plugin,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	struct askrene *askrene = tal(plugin, struct askrene);
	askrene->plugin = plugin;
	list_head_init(&askrene->layers);
	askrene->reserved = new_reserve_hash(askrene);
	askrene->gossmap = gossmap_load(askrene, GOSSIP_STORE_FILENAME, NULL);

	if (!askrene->gossmap)
		plugin_err(plugin, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));
	askrene->capacities = get_capacities(askrene, askrene->plugin, askrene->gossmap);
	rpc_scan(plugin, "getinfo", take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_node_id, &askrene->my_id));

	plugin_set_data(plugin, askrene);
	plugin_set_memleak_handler(plugin, askrene_markmem);
	return NULL;
}

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, NULL, PLUGIN_RESTARTABLE, true, NULL, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0, NULL);
}
