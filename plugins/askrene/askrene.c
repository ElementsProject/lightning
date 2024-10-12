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
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/route.h>
#include <errno.h>
#include <math.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/explain_failure.h>
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

/* Valid, known layers */
static struct command_result *param_layer_names(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						const char ***arr)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be an array");

	*arr = tal_arr(cmd, const char *, tok->size);
	json_for_each_arr(i, t, tok) {
		if (t->type != JSMN_STRING)
			return command_fail_badparam(cmd, name, buffer, t,
						     "should be a string");
		(*arr)[i] = json_strdup(*arr, buffer, t);

		/* Must be a known layer name */
		if (streq((*arr)[i], "auto.localchans")
		    || streq((*arr)[i], "auto.sourcefree"))
			continue;
		if (!find_layer(get_askrene(cmd->plugin), (*arr)[i])) {
			return command_fail_badparam(cmd, name, buffer, t,
						     "unknown layer");
		}
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

static struct command_result *parse_reserve_hop(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						struct reserve_hop *rhop)
{
	const char *err;

	err = json_scan(tmpctx, buffer, tok, "{short_channel_id_dir:%,amount_msat:%}",
			JSON_SCAN(json_to_short_channel_id_dir, &rhop->scidd),
			JSON_SCAN(json_to_msat, &rhop->amount));
	if (err)
		return command_fail_badparam(cmd, name, buffer, tok, err);
	return NULL;
}

static struct command_result *param_reserve_path(struct command *cmd,
						 const char *name,
						 const char *buffer,
						 const jsmntok_t *tok,
						 struct reserve_hop **path)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY)
		return command_fail_badparam(cmd, name, buffer, tok, "should be an array");

	*path = tal_arr(cmd, struct reserve_hop, tok->size);
	json_for_each_arr(i, t, tok) {
		struct command_result *ret;

		ret = parse_reserve_hop(cmd, name, buffer, t, &(*path)[i]);
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
		struct amount_msat cap;

		cap = gossmap_chan_get_capacity(gossmap, c);
		/* Pessimistic: round down! */
		caps[gossmap_chan_idx(gossmap, c)]
			= u64_to_fp16(cap.millisatoshis/1000, false); /* Raw: fp16 */
	}
	return caps;
}

/* If we're the payer, we don't add delay or fee to our own outgoing
 * channels.  This wouldn't be right if we looped back through ourselves,
 * but we won't. */
/* FIXME: We could cache this until gossmap/layer changes... */
static struct layer *source_free_layer(const tal_t *ctx,
				       struct gossmap *gossmap,
				       const struct node_id *source,
				       struct gossmap_localmods *localmods)
{
	/* We apply existing localmods so we see *all* channels */
	const struct gossmap_node *srcnode;
	const struct amount_msat zero_base_fee = AMOUNT_MSAT(0);
	const u16 zero_delay = 0;
	const u32 zero_prop_fee = 0;
	struct layer *layer = new_temp_layer(ctx, "auto.sourcefree");

	/* We apply this so we see any created channels */
	gossmap_apply_localmods(gossmap, localmods);

	/* If we're not in map, we complain later */
	srcnode = gossmap_find_node(gossmap, source);

	for (size_t i = 0; srcnode && i < srcnode->num_chans; i++) {
		struct short_channel_id_dir scidd;
		const struct gossmap_chan *c;

		c = gossmap_nth_chan(gossmap, srcnode, i, &scidd.dir);
		scidd.scid = gossmap_chan_scid(gossmap, c);
		layer_add_update_channel(layer, &scidd,
					 NULL, NULL, NULL,
					 &zero_base_fee, &zero_prop_fee,
					 &zero_delay);
	}
	gossmap_remove_localmods(gossmap, localmods);

	return layer;
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

const char *rq_log(const tal_t *ctx,
		   const struct route_query *rq,
		   enum log_level level,
		   const char *fmt,
		   ...)
{
	va_list args;
	const char *msg;

	va_start(args, fmt);
	msg = tal_vfmt(ctx, fmt, args);
	va_end(args);

	plugin_notify_message(rq->cmd, level, "%s", msg);

	/* Notifications already get logged at debug. Otherwise reduce
	 * severity. */
	if (level != LOG_DBG)
		plugin_log(rq->plugin,
			   level == LOG_BROKEN ? level : level - 1,
			   "%s: %s", rq->cmd->id, msg);
	return msg;
}

static const char *fmt_route(const tal_t *ctx,
			     const struct route *route,
			     struct amount_msat delivers,
			     u32 final_cltv)
{
	char *str = tal_strdup(ctx, "");

	for (size_t i = 0; i < tal_count(route->hops); i++) {
		struct short_channel_id_dir scidd;
		scidd.scid = route->hops[i].scid;
		scidd.dir = route->hops[i].direction;
		tal_append_fmt(&str, "%s/%u %s -> ",
			       fmt_amount_msat(tmpctx, route->hops[i].amount),
			       route->hops[i].delay,
			       fmt_short_channel_id_dir(tmpctx, &scidd));
	}
	tal_append_fmt(&str, "%s/%u",
		       fmt_amount_msat(tmpctx, delivers), final_cltv);
	return str;
}

static const char *fmt_flow_full(const tal_t *ctx,
				 const struct route_query *rq,
				 const struct flow *flow,
				 struct amount_msat total_delivered,
				 double delay_feefactor)
{
	struct amount_msat amt = flow->delivers;
	char *str = tal_fmt(ctx, "%s (linear cost %s)",
			    fmt_amount_msat(tmpctx, amt),
			    fmt_amount_msat(tmpctx, linear_flow_cost(flow,
								     total_delivered,
								     delay_feefactor)));

	for (int i = tal_count(flow->path) - 1; i >= 0; i--) {
		struct short_channel_id_dir scidd;
		struct amount_msat min, max;
		scidd.scid = gossmap_chan_scid(rq->gossmap, flow->path[i]);
		scidd.dir = flow->dirs[i];
		if (!amount_msat_add_fee(&amt,
					 flow->path[i]->half[scidd.dir].base_fee,
					 flow->path[i]->half[scidd.dir].proportional_fee))
			abort();
		get_constraints(rq, flow->path[i], scidd.dir, &min, &max);
		tal_append_fmt(&str, " <- %s %s (cap=%s,fee=%u+%u,delay=%u)",
			       fmt_amount_msat(tmpctx, amt),
			       fmt_short_channel_id_dir(tmpctx, &scidd),
			       fmt_amount_msat(tmpctx, max),
			       flow->path[i]->half[scidd.dir].base_fee,
			       flow->path[i]->half[scidd.dir].proportional_fee,
			       flow->path[i]->half[scidd.dir].delay);
	}
	return str;
}

static struct amount_msat linear_flows_cost(struct flow **flows,
					    struct amount_msat total_amount,
					    double delay_feefactor)
{
	struct amount_msat total = AMOUNT_MSAT(0);

	for (size_t i = 0; i < tal_count(flows); i++) {
		if (!amount_msat_accumulate(&total,
					    linear_flow_cost(flows[i],
							     total_amount,
							     delay_feefactor)))
			abort();
	}
	return total;
}

/* Returns an error message, or sets *routes */
static const char *get_routes(const tal_t *ctx,
			      struct command *cmd,
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
	struct askrene *askrene = get_askrene(cmd->plugin);
	struct route_query *rq = tal(ctx, struct route_query);
	struct flow **flows;
	const struct gossmap_node *srcnode, *dstnode;
	double delay_feefactor;
	u32 mu;
	const char *ret;
	double flowset_prob;

	if (gossmap_refresh(askrene->gossmap, NULL)) {
		/* FIXME: gossmap_refresh callbacks to we can update in place */
		tal_free(askrene->capacities);
		askrene->capacities = get_capacities(askrene, askrene->plugin, askrene->gossmap);
	}

	rq->cmd = cmd;
	rq->plugin = cmd->plugin;
	rq->gossmap = askrene->gossmap;
	rq->reserved = askrene->reserved;
	rq->layers = tal_arr(rq, const struct layer *, 0);
	rq->capacities = tal_dup_talarr(rq, fp16_t, askrene->capacities);
	rq->additional_costs = additional_costs;

	/* Layers must exist, but might be special ones! */
	for (size_t i = 0; i < tal_count(layers); i++) {
		const struct layer *l = find_layer(askrene, layers[i]);
		if (!l) {
			if (streq(layers[i], "auto.localchans")) {
				plugin_log(rq->plugin, LOG_DBG, "Adding auto.localchans");
				l = local_layer;
			} else {
				/* Handled below, after other layers */
				assert(streq(layers[i], "auto.sourcefree"));
				plugin_log(rq->plugin, LOG_DBG, "Adding auto.sourcefree");
				l = source_free_layer(layers, askrene->gossmap, source, localmods);
			}
		}

		tal_arr_expand(&rq->layers, l);
		/* FIXME: Implement localmods_merge, and cache this in layer? */
		layer_add_localmods(l, rq->gossmap, localmods);

		/* Clear any entries in capacities array if we
		 * override them (incl local channels) */
		layer_clear_overridden_capacities(l, askrene->gossmap, rq->capacities);
	}

	/* Clear scids with reservations, too, so we don't have to look up
	 * all the time! */
	reserves_clear_capacities(askrene->reserved, askrene->gossmap, rq->capacities);

	gossmap_apply_localmods(askrene->gossmap, localmods);

	srcnode = gossmap_find_node(askrene->gossmap, source);
	if (!srcnode) {
		ret = rq_log(ctx, rq, LOG_INFORM,
			     "Unknown source node %s",
			     fmt_node_id(tmpctx, source));
		goto fail;
	}

	dstnode = gossmap_find_node(askrene->gossmap, dest);
	if (!dstnode) {
		ret = rq_log(ctx, rq, LOG_INFORM,
			     "Unknown destination node %s",
			     fmt_node_id(tmpctx, dest));
		goto fail;
	}

	delay_feefactor = 1.0/1000000;

	/* First up, don't care about fees (well, just enough to tiebreak!) */
	mu = 1;
	flows = minflow(rq, rq, srcnode, dstnode, amount,
			mu, delay_feefactor);
	if (!flows) {
		ret = explain_failure(ctx, rq, srcnode, dstnode, amount);
		goto fail;
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
		rq_log(tmpctx, rq, LOG_UNUSUAL,
		       "The worst flow delay is %"PRIu64" (> %i), retrying with delay_feefactor %f...",
		       flows_worst_delay(flows), 2016 - finalcltv, delay_feefactor);
		flows = minflow(rq, rq, srcnode, dstnode, amount,
				mu, delay_feefactor);
		if (!flows || delay_feefactor > 10) {
			ret = rq_log(ctx, rq, LOG_UNUSUAL,
				     "Could not find route without excessive delays");
			goto fail;
		}
	}

	/* Too expensive? */
too_expensive:
	while (amount_msat_greater(flowset_fee(rq->plugin, flows), maxfee)) {
		struct flow **new_flows;

		if (mu == 1)
			mu = 10;
		else
			mu += 10;
		rq_log(tmpctx, rq, LOG_UNUSUAL,
		       "The flows had a fee of %s, greater than max of %s, retrying with mu of %u%%...",
		       fmt_amount_msat(tmpctx, flowset_fee(rq->plugin, flows)),
		       fmt_amount_msat(tmpctx, maxfee),
		       mu);
		new_flows = minflow(rq, rq, srcnode, dstnode, amount,
				    mu > 100 ? 100 : mu, delay_feefactor);
		if (!flows || mu >= 100) {
			ret = rq_log(ctx, rq, LOG_UNUSUAL,
				     "Could not find route without excessive cost");
			goto fail;
		}

		/* This is possible, because MCF's linear fees are not the same. */
		if (amount_msat_greater(flowset_fee(rq->plugin, new_flows),
					flowset_fee(rq->plugin, flows))) {
			struct amount_msat old_cost = linear_flows_cost(flows, amount, delay_feefactor);
			struct amount_msat new_cost = linear_flows_cost(new_flows, amount, delay_feefactor);
			if (amount_msat_greater_eq(new_cost, old_cost)) {
				rq_log(tmpctx, rq, LOG_BROKEN, "Old flows cost %s:",
				       fmt_amount_msat(tmpctx, old_cost));
				for (size_t i = 0; i < tal_count(flows); i++) {
					rq_log(tmpctx, rq, LOG_BROKEN,
					       "Flow %zu/%zu: %s", i, tal_count(flows),
					       fmt_flow_full(tmpctx, rq, flows[i], amount, delay_feefactor));
				}
				rq_log(tmpctx, rq, LOG_BROKEN, "Old flows cost %s:",
				       fmt_amount_msat(tmpctx, new_cost));
				for (size_t i = 0; i < tal_count(new_flows); i++) {
					rq_log(tmpctx, rq, LOG_BROKEN,
					       "Flow %zu/%zu: %s", i, tal_count(new_flows),
					       fmt_flow_full(tmpctx, rq, new_flows[i], amount, delay_feefactor));
				}
			}
		}
		tal_free(flows);
		flows = new_flows;
	}

	if (finalcltv + flows_worst_delay(flows) > 2016) {
		ret = rq_log(ctx, rq, LOG_UNUSUAL,
			     "Could not find route without excessive cost or delays");
		goto fail;
	}

	/* The above did not take into account the extra funds to pay
	 * fees, so we try to adjust now.  We could re-run MCF if this
	 * fails, but failure basically never happens where payment is
	 * still possible */
	ret = refine_with_fees_and_limits(ctx, rq, amount, &flows, &flowset_prob);
	if (ret)
		goto fail;

	/* Again, a tiny corner case: refine step can make us exceed maxfee */
	if (amount_msat_greater(flowset_fee(rq->plugin, flows), maxfee)) {
		rq_log(tmpctx, rq, LOG_UNUSUAL,
		       "After final refinement, fee was excessive: retrying");
		goto too_expensive;
	}

	rq_log(tmpctx, rq, LOG_DBG, "Final answer has %zu flows with mu=%u",
	       tal_count(flows), mu);

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
				plugin_err(rq->plugin, "Adding fee to amount");
			delay += h->delay;

			rh->scid = gossmap_chan_scid(rq->gossmap, flows[i]->path[j]);
			rh->direction = flows[i]->dirs[j];
			far_end = gossmap_nth_node(rq->gossmap, flows[i]->path[j], !flows[i]->dirs[j]);
			gossmap_node_get_id(rq->gossmap, far_end, &rh->node_id);
			rh->amount = msat;
			rh->delay = delay;
		}
		(*amounts)[i] = flows[i]->delivers;
		rq_log(tmpctx, rq, LOG_INFORM, "Flow %zu/%zu: %s",
		       i, tal_count(flows),
		       fmt_route(tmpctx, r, (*amounts)[i], finalcltv));
	}

	*probability = flowset_probability(flows, rq);
	if (fabs(*probability - flowset_prob) > 0.000001) {
		rq_log(tmpctx, rq, LOG_BROKEN, "Probability %f != expected %f",
		       *probability, flowset_prob);
	}
	gossmap_remove_localmods(askrene->gossmap, localmods);

	return NULL;

	/* Explicit failure path keeps the compiler (gcc version 12.3.0 -O3) from
	 * warning about uninitialized variables in the caller */
fail:
	assert(ret != NULL);
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

	/* Look through layers for any constraints (might be dummy
	 * ones, for created channels!) */
	for (size_t i = 0; i < tal_count(rq->layers); i++)
		layer_apply_constraints(rq->layers[i], &scidd, min, max);

	/* Might be here because it's reserved, but capacity is normal. */
	if (amount_msat_eq(*max, AMOUNT_MSAT(-1ULL)))
		*max = gossmap_chan_get_capacity(rq->gossmap, chan);

	/* Finally, if any is in use, subtract that! */
	reserve_sub(rq->reserved, &scidd, min);
	reserve_sub(rq->reserved, &scidd, max);
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

	err = get_routes(cmd, cmd,
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
			  struct amount_msat capacity_msat,
			  struct amount_msat htlcmin,
			  struct amount_msat htlcmax,
			  struct amount_msat spendable,
			  struct amount_msat fee_base,
			  u32 fee_proportional,
			  u16 cltv_delta,
			  bool enabled,
			  const char *buf,
			  const jsmntok_t *chantok,
			  struct getroutes_info *info)
{
	u32 feerate;
	const char *opener;
	const char *err;

	/* We get called twice, once in each direction: only create once. */
	if (!layer_find_local_channel(info->local_layer, scidd->scid))
		layer_add_local_channel(info->local_layer,
					self, peer, scidd->scid, capacity_msat);
	layer_add_update_channel(info->local_layer, scidd,
				 &enabled,
				 &htlcmin, &htlcmax,
				 &fee_base, &fee_proportional, &cltv_delta);

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
	layer_add_constraint(info->local_layer, scidd, UINT64_MAX, &spendable, &spendable);
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
		   p_req("layers", param_layer_names, &info->layers),
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
	struct reserve_hop *path;
	struct json_stream *response;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param(cmd, buffer, params,
		   p_req("path", param_reserve_path, &path),
		   NULL))
		return command_param_failed();

	for (size_t i = 0; i < tal_count(path); i++)
		reserve_add(askrene->reserved, &path[i], cmd->id);

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_unreserve(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *params)
{
	struct reserve_hop *path;
	struct json_stream *response;
	struct askrene *askrene = get_askrene(cmd->plugin);

	if (!param(cmd, buffer, params,
		   p_req("path", param_reserve_path, &path),
		   NULL))
		return command_param_failed();

	for (size_t i = 0; i < tal_count(path); i++) {
		if (!reserve_remove(askrene->reserved, &path[i])) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Unknown reservation for %s",
					    fmt_short_channel_id_dir(tmpctx,
								     &path[i].scidd));
		}
 	}

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_listreservations(struct command *cmd,
							    const char *buffer,
							    const jsmntok_t *params)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   NULL))
		return command_param_failed();

	response = jsonrpc_stream_success(cmd);
	json_add_reservations(response, askrene->reserved, "reservations");
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_create_channel(struct command *cmd,
							  const char *buffer,
							  const jsmntok_t *params)
{
	struct layer *layer;
	struct node_id *src, *dst;
	struct short_channel_id *scid;
	struct amount_msat *capacity;
	struct json_stream *response;

	if (!param_check(cmd, buffer, params,
			 p_req("layer", param_known_layer, &layer),
			 p_req("source", param_node_id, &src),
			 p_req("destination", param_node_id, &dst),
			 p_req("short_channel_id", param_short_channel_id, &scid),
			 p_req("capacity_msat", param_msat, &capacity),
			 NULL))
		return command_param_failed();

	if (layer_find_local_channel(layer, *scid)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "channel already exists");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	layer_add_local_channel(layer, src, dst, *scid, *capacity);

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_update_channel(struct command *cmd,
							  const char *buffer,
							  const jsmntok_t *params)
{
	struct layer *layer;
	struct short_channel_id_dir *scidd;
	bool *enabled;
	struct amount_msat *htlc_min, *htlc_max, *base_fee;
	u32 *proportional_fee;
	u16 *delay;
	struct json_stream *response;

 	if (!param(cmd, buffer, params,
		   p_req("layer", param_known_layer, &layer),
		   p_req("short_channel_id_dir", param_short_channel_id_dir, &scidd),
		   p_opt("enabled", param_bool, &enabled),
		   p_opt("htlc_minimum_msat", param_msat, &htlc_min),
		   p_opt("htlc_maximum_msat", param_msat, &htlc_max),
		   p_opt("fee_base_msat", param_msat, &base_fee),
		   p_opt("fee_proportional_millionths", param_u32, &proportional_fee),
		   p_opt("cltv_expiry_delta", param_u16, &delay),
		   NULL))
		return command_param_failed();

	layer_add_update_channel(layer, scidd,
				 enabled,
				 htlc_min, htlc_max,
				 base_fee, proportional_fee, delay);

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

enum inform {
	INFORM_CONSTRAINED,
	INFORM_UNCONSTRAINED,
	INFORM_SUCCEEDED,
};

static struct command_result *param_inform(struct command *cmd,
					   const char *name,
					   const char *buffer,
					   const jsmntok_t *tok,
					   enum inform **inform)
{
	*inform = tal(cmd, enum inform);
	if (json_tok_streq(buffer, tok, "constrained"))
		**inform = INFORM_CONSTRAINED;
	else if (json_tok_streq(buffer, tok, "unconstrained"))
		**inform = INFORM_UNCONSTRAINED;
	else if (json_tok_streq(buffer, tok, "succeeded"))
		**inform = INFORM_SUCCEEDED;
	else
		command_fail_badparam(cmd, name, buffer, tok,
				      "must be constrained/unconstrained/succeeded");
	return NULL;
}

static struct command_result *json_askrene_inform_channel(struct command *cmd,
							    const char *buffer,
							    const jsmntok_t *params)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	struct layer *layer;
	struct short_channel_id_dir *scidd;
	struct json_stream *response;
	struct amount_msat *amount;
	enum inform *inform;
	const struct constraint *c;

	if (!param_check(cmd, buffer, params,
			 p_req("layer", param_known_layer, &layer),
			 p_req("short_channel_id_dir", param_short_channel_id_dir, &scidd),
			 p_req("amount_msat", param_msat, &amount),
			 p_req("inform", param_inform, &inform),
			 NULL))
		return command_param_failed();

	switch (*inform) {
	case INFORM_CONSTRAINED:
		/* It didn't pass, so minimal assumption is that reserve was all used
		 * then there we were one msat short. */
		if (!amount_msat_sub(amount, *amount, AMOUNT_MSAT(1)))
			*amount = AMOUNT_MSAT(0);
		if (!reserve_accumulate(askrene->reserved, scidd, amount))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Amount overflow with reserves");
		if (command_check_only(cmd))
			return command_check_done(cmd);
		c = layer_add_constraint(layer, scidd, time_now().ts.tv_sec,
					 NULL, amount);
		goto output;
	case INFORM_UNCONSTRAINED:
		/* It passed, so the capacity is at least this much (minimal assumption is
		 * that no reserves were used) */
		if (command_check_only(cmd))
			return command_check_done(cmd);
		c = layer_add_constraint(layer, scidd, time_now().ts.tv_sec,
					 amount, NULL);
		goto output;
	case INFORM_SUCCEEDED:
		/* FIXME: We could do something useful here! */
		c = NULL;
		goto output;
	}
	abort();

output:
	response = jsonrpc_stream_success(cmd);
	json_array_start(response, "constraints");
	if (c)
		json_add_constraint(response, NULL, c, layer);
	json_array_end(response);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_disable_node(struct command *cmd,
							const char *buffer,
							const jsmntok_t *params)
{
	struct node_id *node;
	struct layer *layer;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_req("layer", param_known_layer, &layer),
		   p_req("node", param_node_id, &node),
		   NULL))
		return command_param_failed();

	/* We save this in the layer, because they want us to disable all the channels
	 * to the node at *use* time (a new channel might be gossiped!). */
	layer_add_disabled_node(layer, node);

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_create_layer(struct command *cmd,
							const char *buffer,
							const jsmntok_t *params)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	struct layer *layer;
	const char *layername;
	struct json_stream *response;

	if (!param_check(cmd, buffer, params,
			 p_req("layer", param_string, &layername),
			 NULL))
		return command_param_failed();

	if (find_layer(askrene, layername))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Layer already exists");

	if (strstarts(layername, "auto."))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Cannot create auto layer");

	if (command_check_only(cmd))
		return command_check_done(cmd);

	layer = new_layer(askrene, layername);

	response = jsonrpc_stream_success(cmd);
	json_add_layers(response, askrene, "layers", layer);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_remove_layer(struct command *cmd,
							const char *buffer,
							const jsmntok_t *params)
{
	struct layer *layer;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_req("layer", param_known_layer, &layer),
		   NULL))
		return command_param_failed();

	tal_free(layer);

	response = jsonrpc_stream_success(cmd);
	return command_finished(cmd, response);
}

static struct command_result *json_askrene_listlayers(struct command *cmd,
						      const char *buffer,
						      const jsmntok_t *params)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	struct layer *layer;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_opt("layer", param_known_layer, &layer),
		   NULL))
		return command_param_failed();

	response = jsonrpc_stream_success(cmd);
	json_add_layers(response, askrene, "layers", layer);
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
		"askrene-listreservations",
		json_askrene_listreservations,
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
		"askrene-update-channel",
		json_askrene_update_channel,
	},
	{
		"askrene-inform-channel",
		json_askrene_inform_channel,
	},
	{
		"askrene-create-layer",
		json_askrene_create_layer,
	},
	{
		"askrene-remove-layer",
		json_askrene_remove_layer,
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
