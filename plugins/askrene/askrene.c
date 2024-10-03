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
#include <plugins/askrene/refine.h>
#include <plugins/askrene/reserve.h>

/* "spendable" for a channel assumes a single HTLC: for additional HTLCs,
 * the need to pay for fees (if we're the owner) reduces it */
struct per_htlc_cost {
	struct short_channel_id_dir scidd;
	struct amount_msat per_htlc_cost;
};

static const struct short_channel_id_dir *
per_htlc_cost_key(const struct per_htlc_cost *phc)
{
	return &phc->scidd;
}

static size_t hash_scidd(const struct short_channel_id_dir *scidd)
{
	/* scids cost money to generate, so simple hash works here */
	return (scidd->scid.u64 >> 32) ^ (scidd->scid.u64 << 1) ^ scidd->dir;
}

static inline bool per_htlc_cost_eq_key(const struct per_htlc_cost *phc,
					const struct short_channel_id_dir *scidd)
{
	return short_channel_id_dir_eq(scidd, &phc->scidd);
}

HTABLE_DEFINE_TYPE(struct per_htlc_cost,
		   per_htlc_cost_key,
		   hash_scidd,
		   per_htlc_cost_eq_key,
		   additional_cost_htable);

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

	err = json_scan(tmpctx, buffer, tok, "{short_channel_id_dir:%,amount_msat:%}",
			JSON_SCAN(json_to_short_channel_id_dir, scidd),
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
		/* Pessimistic: round down! */
		caps[gossmap_chan_idx(gossmap, c)]
			= u64_to_fp16(cap.satoshis, false); /* Raw: fp16 */
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
	/* We apply existing localmods, save up mods we want, then append
	 * them: it's not safe to modify localmods while they are applied! */
	const struct gossmap_node *srcnode;
	struct mod {
		struct short_channel_id_dir scidd;
		fp16_t htlc_min, htlc_max;
		bool enabled;
	} *mods = tal_arr(tmpctx, struct mod, 0);

	gossmap_apply_localmods(gossmap, localmods);

	/* If we're not in map, we complain later */
	srcnode = gossmap_find_node(gossmap, source);

	for (size_t i = 0; srcnode && i < srcnode->num_chans; i++) {
		const struct gossmap_chan *c;
		const struct half_chan *h;
		struct mod mod;

		c = gossmap_nth_chan(gossmap, srcnode, i, &mod.scidd.dir);
		h = &c->half[mod.scidd.dir];

		mod.scidd.scid = gossmap_chan_scid(gossmap, c);
		mod.htlc_min = h->htlc_min;
		mod.htlc_max = h->htlc_max;
		mod.enabled = h->enabled;
		tal_arr_expand(&mods, mod);
	}
	gossmap_remove_localmods(gossmap, localmods);

	/* Now we can update localmods */
	for (size_t i = 0; i < tal_count(mods); i++) {
		if (!gossmap_local_updatechan(localmods,
					      mods[i].scidd.scid,
					      /* Keep min and max */
					      /* FIXME: lossy conversion! */
					      amount_msat(fp16_to_u64(mods[i].htlc_min)),
					      amount_msat(fp16_to_u64(mods[i].htlc_max)),
					      0, 0, 0,
					      /* Keep enabled flag */
					      mods[i].enabled,
					      mods[i].scidd.dir))
			plugin_err(plugin, "Could not zero fee on %s",
				   fmt_short_channel_id_dir(tmpctx, &mods[i].scidd));
	}
}

struct amount_msat get_additional_per_htlc_cost(const struct route_query *rq,
						const struct short_channel_id_dir *scidd)
{
	const struct per_htlc_cost *phc;
	phc = additional_cost_htable_get(rq->additional_costs, scidd);
	if (phc)
		return phc->per_htlc_cost;
	else
		return AMOUNT_MSAT(0);
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
			      const struct additional_cost_htable *additional_costs,
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
	rq->additional_costs = additional_costs;

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
		layer_add_localmods(l, rq->gossmap, false, localmods);

		/* Clear any entries in capacities array if we
		 * override them (incl local channels) */
		layer_clear_overridden_capacities(l, askrene->gossmap, rq->capacities);
	}

	/* This also looks into localmods, to zero them */
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
	if (amount_msat_is_zero(amount))
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

	/* The above did not take into account the extra funds to pay
	 * fees, so we try to adjust now.  We could re-run MCF if this
	 * fails, but failure basically never happens where payment is
	 * still possible */
	ret = refine_with_fees_and_limits(ctx, rq, amount, &flows);
	if (ret)
		goto out;

	/* Convert back into routes, with delay and other information fixed */
	*routes = tal_arr(ctx, struct route *, tal_count(flows));
	*amounts = tal_arr(ctx, struct amount_msat, tal_count(flows));
	for (size_t i = 0; i < tal_count(flows); i++) {
		struct route *r;
		struct amount_msat msat;
		u32 delay;

		(*routes)[i] = r = tal(*routes, struct route);
		r->success_prob = flow_probability(flows[i], rq);
		r->hops = tal_arr(r, struct route_hop, tal_count(flows[i]->path));

		/* Fill in backwards to calc amount and delay */
		msat = flows[i]->delivers;
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
		(*amounts)[i] = flows[i]->delivers;
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
	struct command *cmd;
	struct node_id *source, *dest;
	struct amount_msat *amount, *maxfee;
	u32 *finalcltv;
	const char **layers;
	struct additional_cost_htable *additional_costs;
	/* Non-NULL if we are told to use "auto.localchans" */
	struct layer *local_layer;
};

static struct command_result *do_getroutes(struct command *cmd,
					   struct gossmap_localmods *localmods,
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
			 info->layers, localmods, info->local_layer,
			 &routes, &amounts, info->additional_costs, &probability);
	if (err)
		return command_fail(cmd, PAY_ROUTE_NOT_FOUND, "%s", err);

	response = jsonrpc_stream_success(cmd);
	json_add_u64(response, "probability_ppm", (u64)(probability * 1000000));
	json_array_start(response, "routes");
	for (size_t i = 0; i < tal_count(routes); i++) {
		json_object_start(response, NULL);
		json_add_u64(response, "probability_ppm", (u64)(routes[i]->success_prob * 1000000));
		json_add_amount_msat(response, "amount_msat", amounts[i]);
		json_add_u32(response, "final_cltv", *info->finalcltv);
		json_array_start(response, "path");
		for (size_t j = 0; j < tal_count(routes[i]->hops); j++) {
			struct short_channel_id_dir scidd;
			const struct route_hop *r = &routes[i]->hops[j];
			json_object_start(response, NULL);
			scidd.scid = r->scid;
			scidd.dir = r->direction;
			json_add_short_channel_id_dir(response, "short_channel_id_dir", scidd);
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
			  const char *buf,
			  const jsmntok_t *chantok,
			  struct getroutes_info *info)
{
	u32 feerate;
	const char *opener;
	const char *err;

	gossmod_add_localchan(mods, self, peer, scidd, htlcmin, htlcmax,
			      spendable, fee_base, fee_proportional, cltv_delta, enabled,
			      buf, chantok, info->local_layer);

	/* We also need to know the feerate and opener, so we can calculate per-HTLC cost */
	feerate = 0; /* Can be unset on unconfirmed channels */
	err = json_scan(tmpctx, buf, chantok,
			"{feerate?:{perkw:%},opener:%}",
			JSON_SCAN(json_to_u32, &feerate),
			JSON_SCAN_TAL(tmpctx, json_strdup, &opener));
	if (err) {
		plugin_log(info->cmd->plugin, LOG_BROKEN,
			   "Cannot scan channel for feerate and owner (%s): %.*s",
			   err, json_tok_full_len(chantok), json_tok_full(buf, chantok));
		return;
	}

	if (feerate != 0 && streq(opener, "local")) {
		/* BOLT #3:
		 * The base fee for a commitment transaction:
		 *   - MUST be calculated to match:
		 *     1. Start with `weight` = 724 (1124 if `option_anchors` applies).
		 *     2. For each committed HTLC, if that output is not trimmed as specified in
		 *     [Trimmed Outputs](#trimmed-outputs), add 172 to `weight`.
		 *     3. Multiply `feerate_per_kw` by `weight`, divide by 1000 (rounding down).
		 */
		struct per_htlc_cost *phc
			= tal(info->additional_costs, struct per_htlc_cost);

		phc->scidd = *scidd;
		if (!amount_sat_to_msat(&phc->per_htlc_cost,
					amount_tx_fee(feerate, 172))) {
			/* Can't happen, since feerate is u32... */
			abort();
		}

		plugin_log(info->cmd->plugin, LOG_DBG, "Per-htlc cost for %s = %s (%u x 172)",
			   fmt_short_channel_id_dir(tmpctx, scidd),
			   fmt_amount_msat(tmpctx, phc->per_htlc_cost),
			   feerate);
		additional_cost_htable_add(info->additional_costs, phc);
	}

	/* Known capacity on local channels (ts = max) */
	layer_update_constraint(info->local_layer, scidd, CONSTRAINT_MIN, UINT64_MAX, spendable);
	layer_update_constraint(info->local_layer, scidd, CONSTRAINT_MAX, UINT64_MAX, spendable);
}

static struct command_result *
listpeerchannels_done(struct command *cmd,
		      const char *buffer,
		      const jsmntok_t *toks,
		      struct getroutes_info *info)
{
	struct gossmap_localmods *localmods;

	info->local_layer = new_temp_layer(info, "auto.localchans");
	localmods = gossmods_from_listpeerchannels(cmd,
						   &get_askrene(cmd->plugin)->my_id,
						   buffer, toks,
						   false,
						   add_localchan,
						   info);

	return do_getroutes(cmd, localmods, info);
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
		   p_req("final_cltv", param_u32, &info->finalcltv),
		   NULL))
		return command_param_failed();

	info->cmd = cmd;
	info->additional_costs = tal(info, struct additional_cost_htable);
	additional_cost_htable_init(info->additional_costs);

	if (have_layer(info->layers, "auto.localchans")) {
		struct out_req *req;

		req = jsonrpc_request_start(cmd->plugin, cmd,
					    "listpeerchannels",
					    listpeerchannels_done,
					    forward_error, info);
		return send_outreq(cmd->plugin, req);
	} else
		info->local_layer = NULL;

	return do_getroutes(cmd, gossmap_localmods_new(cmd), info);
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
	struct short_channel_id_dir *scidd;
	struct json_stream *response;
	struct amount_msat *max, *min;
	const struct constraint *c;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param_check(cmd, buffer, params,
			 p_req("layer", param_layername, &layername),
			 p_req("short_channel_id_dir", param_short_channel_id_dir, &scidd),
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

	if (min) {
		c = layer_update_constraint(layer, scidd, CONSTRAINT_MIN,
					    time_now().ts.tv_sec, *min);
	} else {
		c = layer_update_constraint(layer, scidd, CONSTRAINT_MAX,
					    time_now().ts.tv_sec, *max);
	}
	response = jsonrpc_stream_success(cmd);
	json_add_constraint(response, "constraint", c, layer);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_disable_channel(struct command *cmd,
							   const char *buffer,
							   const jsmntok_t *params)
{
	struct short_channel_id_dir *scidd;
	const char *layername;
	struct layer *layer;
	struct json_stream *response;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param(cmd, buffer, params,
		   p_req("layer", param_layername, &layername),
		   p_req("short_channel_id_dir", param_short_channel_id_dir, &scidd),
		   NULL))
		return command_param_failed();

	layer = find_layer(askrene, layername);
	if (!layer)
		layer = new_layer(askrene, layername);

	layer_add_disabled_channel(layer, scidd);

	response = jsonrpc_stream_success(cmd);
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
	{
		"askrene-disable-channel",
		json_askrene_disable_channel,
	},
};

static void askrene_markmem(struct plugin *plugin, struct htable *memtable)
{
	struct askrene *askrene = get_askrene(plugin);
	layer_memleak_mark(askrene, memtable);
	reserve_memleak_mark(askrene, memtable);
}

static const char *init(struct plugin *plugin,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	struct askrene *askrene = tal(plugin, struct askrene);
	askrene->plugin = plugin;
	list_head_init(&askrene->layers);
	askrene->reserved = new_reserve_htable(askrene);
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
