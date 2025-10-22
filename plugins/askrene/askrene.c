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
#include <ccan/time/time.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/route.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/flow.h>
#include <plugins/askrene/layer.h>
#include <plugins/askrene/mcf.h>
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

HTABLE_DEFINE_NODUPS_TYPE(struct per_htlc_cost,
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
		    || streq((*arr)[i], "auto.no_mpp_support")
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
				       struct askrene *askrene,
				       const struct node_id *source,
				       struct gossmap_localmods *localmods)
{
	/* We apply existing localmods so we see *all* channels */
	struct gossmap *gossmap = askrene->gossmap;
	const struct gossmap_node *srcnode;
	const struct amount_msat zero_base_fee = AMOUNT_MSAT(0);
	const u16 zero_delay = 0;
	const u32 zero_prop_fee = 0;
	struct layer *layer = new_temp_layer(ctx, askrene, "auto.sourcefree");

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

/* We're going to abuse MCF, and take the largest flow it gives and ram everything
 * through it.  This is more effective if there's at least a *chance* that can handle
 * the full amount.
 *
 * It's far from perfect, but I have very little sympathy: if you want
 * to receive amounts reliably, enable MPP.
 */
static struct layer *remove_small_channel_layer(const tal_t *ctx,
						struct askrene *askrene,
						struct amount_msat min_amount,
						struct gossmap_localmods *localmods)
{
	struct layer *layer = new_temp_layer(ctx, askrene, "auto.no_mpp_support");
	struct gossmap *gossmap = askrene->gossmap;
	struct gossmap_chan *c;

	/* We apply this so we see any created channels */
	gossmap_apply_localmods(gossmap, localmods);

	for (c = gossmap_first_chan(gossmap); c; c = gossmap_next_chan(gossmap, c)) {
		struct short_channel_id_dir scidd;
		if (amount_msat_greater_eq(gossmap_chan_get_capacity(gossmap, c),
					   min_amount))
			continue;

		scidd.scid = gossmap_chan_scid(gossmap, c);
		/* Layer will disable this in both directions */
		for (scidd.dir = 0; scidd.dir < 2; scidd.dir++) {
			const bool enabled = false;
			layer_add_update_channel(layer, &scidd, &enabled,
						 NULL, NULL, NULL, NULL, NULL);
		}
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

const char *fmt_flow_full(const tal_t *ctx,
			  const struct route_query *rq,
			  const struct flow *flow)
{
	struct amount_msat amt = flow->delivers;
	char *str = fmt_amount_msat(ctx, flow->delivers);

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

enum algorithm {
	/* Min. Cost Flow by successive shortests paths. */
	ALGO_DEFAULT,
	/* Algorithm that finds the optimal routing solution constrained to a
	 * single path. */
	ALGO_SINGLE_PATH,
};

static struct command_result *
param_algorithm(struct command *cmd, const char *name, const char *buffer,
		const jsmntok_t *tok, enum algorithm **algo)
{
	const char *algo_str = json_strdup(cmd, buffer, tok);
	*algo = tal(cmd, enum algorithm);
	if (streq(algo_str, "default"))
		**algo = ALGO_DEFAULT;
	else if (streq(algo_str, "single-path"))
		**algo = ALGO_SINGLE_PATH;
	else
		return command_fail_badparam(cmd, name, buffer, tok,
					     "unknown algorithm");
	return NULL;
}

struct getroutes_info {
	struct command *cmd;
	struct node_id source, dest;
	struct amount_msat amount, maxfee;
	u32 finalcltv, maxdelay;
	/* algorithm selection, only dev */
	enum algorithm dev_algo;
	const char **layers;
	struct additional_cost_htable *additional_costs;
	/* Non-NULL if we are told to use "auto.localchans" */
	struct layer *local_layer;
	u32 maxparts;
};

static void apply_layers(struct askrene *askrene, struct route_query *rq,
			 const struct node_id *source,
			 struct amount_msat amount,
			 struct gossmap_localmods *localmods,
			 const char **layers,
			 const struct layer *local_layer)
{
	/* Layers must exist, but might be special ones! */
	for (size_t i = 0; i < tal_count(layers); i++) {
		const struct layer *l = find_layer(askrene, layers[i]);
		if (!l) {
			if (streq(layers[i], "auto.localchans")) {
				plugin_log(rq->plugin, LOG_DBG, "Adding auto.localchans");
				l = local_layer;
			} else if (streq(layers[i], "auto.no_mpp_support")) {
				plugin_log(rq->plugin, LOG_DBG, "Adding auto.no_mpp_support, sorry");
				l = remove_small_channel_layer(layers, askrene, amount, localmods);
			} else {
				assert(streq(layers[i], "auto.sourcefree"));
				plugin_log(rq->plugin, LOG_DBG, "Adding auto.sourcefree");
				l = source_free_layer(layers, askrene, source, localmods);
			}
		}

		tal_arr_expand(&rq->layers, l);
		/* FIXME: Implement localmods_merge, and cache this in layer? */
		layer_add_localmods(l, rq->gossmap, localmods);

		/* Clear any entries in capacities array if we
		 * override them (incl local channels) */
		layer_clear_overridden_capacities(l, askrene->gossmap, rq->capacities);
	}
}

/* Convert back into routes, with delay and other information fixed */
static struct route **convert_flows_to_routes(const tal_t *ctx,
					      struct route_query *rq,
					      u32 finalcltv,
					      struct flow **flows,
					      struct amount_msat **amounts)
{
	struct route **routes;
	routes = tal_arr(ctx, struct route *, tal_count(flows));
	*amounts = tal_arr(ctx, struct amount_msat, tal_count(flows));

	for (size_t i = 0; i < tal_count(flows); i++) {
		struct route *r;
		struct amount_msat msat;
		u32 delay;

		routes[i] = r = tal(routes, struct route);
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

	return routes;
}

static void json_add_getroutes(struct json_stream *js,
			       struct route **routes,
			       const struct amount_msat *amounts,
			       double probability,
			       u32 final_cltv)
{
	json_add_u64(js, "probability_ppm", (u64)(probability * 1000000));
	json_array_start(js, "routes");
	for (size_t i = 0; i < tal_count(routes); i++) {
		json_object_start(js, NULL);
		json_add_u64(js, "probability_ppm",
			     (u64)(routes[i]->success_prob * 1000000));
		json_add_amount_msat(js, "amount_msat", amounts[i]);
		json_add_u32(js, "final_cltv", final_cltv);
		json_array_start(js, "path");
		for (size_t j = 0; j < tal_count(routes[i]->hops); j++) {
			struct short_channel_id_dir scidd;
			const struct route_hop *r = &routes[i]->hops[j];
			json_object_start(js, NULL);
			scidd.scid = r->scid;
			scidd.dir = r->direction;
			json_add_short_channel_id_dir(
			    js, "short_channel_id_dir", scidd);
			json_add_node_id(js, "next_node_id", &r->node_id);
			json_add_amount_msat(js, "amount_msat", r->amount);
			json_add_u32(js, "delay", r->delay);
			json_object_end(js);
		}
		json_array_end(js);
		json_object_end(js);
	}
	json_array_end(js);
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

static struct command_result *do_getroutes(struct command *cmd,
					   struct gossmap_localmods *localmods,
					   struct getroutes_info *info)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	struct route_query *rq = tal(cmd, struct route_query);
	const char *err;
	double probability;
	struct amount_msat *amounts;
	struct route **routes;
	struct flow **flows;
	struct json_stream *response;

	/* update the gossmap */
	if (gossmap_refresh(askrene->gossmap)) {
		/* FIXME: gossmap_refresh callbacks to we can update in place */
		tal_free(askrene->capacities);
		askrene->capacities =
		    get_capacities(askrene, askrene->plugin, askrene->gossmap);
	}

	/* build this request structure */
	rq->cmd = cmd;
	rq->plugin = cmd->plugin;
	rq->gossmap = askrene->gossmap;
	rq->reserved = askrene->reserved;
	rq->layers = tal_arr(rq, const struct layer *, 0);
	rq->capacities = tal_dup_talarr(rq, fp16_t, askrene->capacities);
	/* FIXME: we still need to do something useful with these */
	rq->additional_costs = info->additional_costs;
	rq->maxparts = info->maxparts;

	/* apply selected layers to the localmods */
	apply_layers(askrene, rq, &info->source, info->amount, localmods,
		     info->layers, info->local_layer);

	/* Clear scids with reservations, too, so we don't have to look up
	 * all the time! */
	reserves_clear_capacities(askrene->reserved, askrene->gossmap,
				  rq->capacities);

	/* we temporarily apply localmods */
	gossmap_apply_localmods(askrene->gossmap, localmods);

	/* I want to be able to disable channels while working on this query.
	 * Layers are for user interaction and cannot be used for this purpose.
	 */
	rq->disabled_chans =
	    tal_arrz(rq, bitmap,
		     2 * BITMAP_NWORDS(gossmap_max_chan_idx(askrene->gossmap)));

	/* localmods can add channels, so we need to allocate biases array
	 * *afterwards* */
	rq->biases =
	    tal_arrz(rq, s8, gossmap_max_chan_idx(askrene->gossmap) * 2);

	/* Note any channel biases */
	for (size_t i = 0; i < tal_count(rq->layers); i++)
		layer_apply_biases(rq->layers[i], askrene->gossmap, rq->biases);

	/* checkout the source */
	const struct gossmap_node *srcnode =
	    gossmap_find_node(askrene->gossmap, &info->source);
	if (!srcnode) {
		err = rq_log(tmpctx, rq, LOG_INFORM, "Unknown source node %s",
			     fmt_node_id(tmpctx, &info->source));
		goto fail;
	}

	/* checkout the destination */
	const struct gossmap_node *dstnode =
	    gossmap_find_node(askrene->gossmap, &info->dest);
	if (!dstnode) {
		err = rq_log(tmpctx, rq, LOG_INFORM,
			     "Unknown destination node %s",
			     fmt_node_id(tmpctx, &info->dest));
		goto fail;
	}

	/* auto.no_mpp_support layer overrides any choice of algorithm. */
	if (have_layer(info->layers, "auto.no_mpp_support") &&
	    info->dev_algo != ALGO_SINGLE_PATH) {
		info->dev_algo = ALGO_SINGLE_PATH;
		rq_log(tmpctx, rq, LOG_DBG,
		       "Layer no_mpp_support is active we switch to a "
		       "single path algorithm.");
	}

	/* Compute the routes. At this point we might select between multiple
	 * algorithms. Right now there is only one algorithm available. */
	struct timemono time_start = time_mono();
	if (info->dev_algo == ALGO_SINGLE_PATH) {
		err = single_path_routes(rq, rq, srcnode, dstnode, info->amount,
					 info->maxfee, info->finalcltv,
					 info->maxdelay, &flows, &probability);
	} else {
		assert(info->dev_algo == ALGO_DEFAULT);
		err = default_routes(rq, rq, srcnode, dstnode, info->amount,
				     info->maxfee, info->finalcltv,
				     info->maxdelay, &flows, &probability);
	}
	struct timerel time_delta = timemono_between(time_mono(), time_start);

	/* log the time of computation */
	rq_log(tmpctx, rq, LOG_DBG, "get_routes %s %" PRIu64 " ms",
	       err ? "failed after" : "completed in",
	       time_to_msec(time_delta));
	if (err)
		goto fail;

	/* otherwise we continue */
	assert(tal_count(flows) > 0);
	rq_log(tmpctx, rq, LOG_DBG, "Final answer has %zu flows",
	       tal_count(flows));

	/* convert flows to routes */
	routes = convert_flows_to_routes(rq, rq, info->finalcltv, flows,
					 &amounts);
	assert(tal_count(routes) == tal_count(flows));
	assert(tal_count(amounts) == tal_count(flows));

	/* At last we remove the localmods from the gossmap. */
	gossmap_remove_localmods(askrene->gossmap, localmods);

	/* output the results */
	response = jsonrpc_stream_success(cmd);
	json_add_getroutes(response, routes, amounts, probability,
			   info->finalcltv);
	return command_finished(cmd, response);

fail:
	assert(err);
	gossmap_remove_localmods(askrene->gossmap, localmods);
	return command_fail(cmd, PAY_ROUTE_NOT_FOUND, "%s", err);
 }

static void add_localchan(struct gossmap_localmods *mods,
			  const struct node_id *self,
			  const struct node_id *peer,
			  const struct short_channel_id_dir *scidd,
			  struct amount_msat capacity_msat,
			  struct amount_msat htlcmin,
			  struct amount_msat htlcmax,
			  struct amount_msat spendable,
			  struct amount_msat max_total_htlc,
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

	/* can't send more than expendable and no more than max_total_htlc */
	struct amount_msat max_msat = amount_msat_min(spendable, max_total_htlc);
	/* Known capacity on local channels (ts = max) */
	layer_add_constraint(info->local_layer, scidd, UINT64_MAX, &max_msat, &max_msat);
}

static struct command_result *
listpeerchannels_done(struct command *cmd,
		      const char *method UNUSED,
		      const char *buffer,
		      const jsmntok_t *toks,
		      struct getroutes_info *info)
{
	struct askrene *askrene = get_askrene(cmd->plugin);
	struct gossmap_localmods *localmods;

	info->local_layer = new_temp_layer(info, askrene, "auto.localchans");
	localmods = gossmods_from_listpeerchannels(cmd,
						   &askrene->my_id,
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
	/* BOLT #4:
	 * ## `max_htlc_cltv` Selection
	 *
	 * This ... value is defined as 2016 blocks, based on
	 * historical value deployed by Lightning implementations.
	 */
	/* FIXME: Typo in spec for CLTV in descripton! But it breaks our spelling check, so we omit it above */
	const u32 maxdelay_allowed = 2016;
	const u32 default_maxparts = 100;
	struct getroutes_info *info = tal(cmd, struct getroutes_info);
	/* param functions require pointers */
	struct node_id *source, *dest;
	struct amount_msat *amount, *maxfee;
	u32 *finalcltv, *maxdelay;
	enum algorithm *dev_algo;
	u32 *maxparts;

	if (!param_check(cmd, buffer, params,
			 p_req("source", param_node_id, &source),
			 p_req("destination", param_node_id, &dest),
			 p_req("amount_msat", param_msat, &amount),
			 p_req("layers", param_layer_names, &info->layers),
			 p_req("maxfee_msat", param_msat, &maxfee),
			 p_req("final_cltv", param_u32, &finalcltv),
			 p_opt_def("maxdelay", param_u32, &maxdelay,
				   maxdelay_allowed),
			 p_opt_def("maxparts", param_u32, &maxparts,
				   default_maxparts),
			 p_opt_dev("dev_algorithm", param_algorithm,
				   &dev_algo, ALGO_DEFAULT),
			 NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	if (amount_msat_is_zero(*amount)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "amount must be non-zero");
	}

	if (*maxdelay > maxdelay_allowed) {
		return command_fail(cmd, PAY_USER_ERROR,
				    "maximum delay allowed is %d",
				    maxdelay_allowed);
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	info->cmd = cmd;
	info->source = *source;
	info->dest = *dest;
	info->amount = *amount;
	info->maxfee = *maxfee;
	info->finalcltv = *finalcltv;
	info->maxdelay = *maxdelay;
	info->dev_algo = *dev_algo;
	info->additional_costs = tal(info, struct additional_cost_htable);
	additional_cost_htable_init(info->additional_costs);
	info->maxparts = *maxparts;

	if (have_layer(info->layers, "auto.localchans")) {
		struct out_req *req;

		req = jsonrpc_request_start(cmd,
					    "listpeerchannels",
					    listpeerchannels_done,
					    forward_error, info);
		return send_outreq(req);
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
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

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
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

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
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

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
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

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
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

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
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	switch (*inform) {
	case INFORM_CONSTRAINED:
		/* It didn't pass, so minimal assumption is that reserve was all used
		 * then there we were one msat short. */
		if (!reserve_accumulate(askrene->reserved, scidd, amount))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Amount overflow with reserves");
		if (!amount_msat_sub(amount, *amount, AMOUNT_MSAT(1)))
			*amount = AMOUNT_MSAT(0);
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

static struct command_result *param_s8_hundred(struct command *cmd,
					       const char *name,
					       const char *buffer,
					       const jsmntok_t *tok,
					       s8 **v)
{
	s64 s64val;

	if (!json_to_s64(buffer, tok, &s64val)
	    || s64val < -100
	    || s64val > 100)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be a number between -100 and 100");
	*v = tal(cmd, s8);
	**v = s64val;
	return NULL;
}

static struct command_result *json_askrene_bias_channel(struct command *cmd,
							const char *buffer,
							const jsmntok_t *params)
{
	struct layer *layer;
	struct short_channel_id_dir *scidd;
	struct json_stream *response;
	const char *description;
	s8 *bias;
	const struct bias *b;
	bool *relative;

	if (!param(cmd, buffer, params,
		   p_req("layer", param_known_layer, &layer),
		   p_req("short_channel_id_dir", param_short_channel_id_dir, &scidd),
		   p_req("bias", param_s8_hundred, &bias),
		   p_opt("description", param_string, &description),
		   p_opt_def("relative", param_bool, &relative, false),
		   NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	b = layer_set_bias(layer, scidd, description, *bias, *relative);
	response = jsonrpc_stream_success(cmd);
	json_array_start(response, "biases");
	if (b)
		json_add_bias(response, NULL, b, layer);
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
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

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
	bool *persistent;

	if (!param_check(cmd, buffer, params,
			 p_req("layer", param_string, &layername),
			 p_opt_def("persistent", param_bool, &persistent, false),
			 NULL))
		return command_param_failed();
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	if (strstarts(layername, "auto."))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Cannot create auto layer");

	/* If it's persistent, creation is a noop if it already exists */
	layer = find_layer(askrene, layername);
	if (layer && !*persistent) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Layer already exists");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	if (!layer)
		layer = new_layer(askrene, layername, *persistent);

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
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

	remove_layer(layer);

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
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

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
	plugin_log(cmd->plugin, LOG_TRACE, "%s called: %.*s", __func__,
		   json_tok_full_len(params), json_tok_full(buffer, params));

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
		"askrene-bias-channel",
		json_askrene_bias_channel,
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

static const char *init(struct command *init_cmd,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	struct plugin *plugin = init_cmd->plugin;
	struct askrene *askrene = tal(plugin, struct askrene);
	askrene->plugin = plugin;
	list_head_init(&askrene->layers);
	askrene->reserved = new_reserve_htable(askrene);
	askrene->gossmap = gossmap_load(askrene, GOSSIP_STORE_FILENAME,
					plugin_gossmap_logcb, plugin);

	if (!askrene->gossmap)
		plugin_err(plugin, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));
	askrene->capacities = get_capacities(askrene, askrene->plugin, askrene->gossmap);
	rpc_scan(init_cmd, "getinfo", take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_node_id, &askrene->my_id));

	plugin_set_data(plugin, askrene);

	load_layers(askrene, init_cmd);

	/* Layer needs its own command to write to the datastore */
	askrene->layer_cmd = aux_command(init_cmd);
	return NULL;
}

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, NULL, PLUGIN_RESTARTABLE, true, NULL, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0, NULL);
}
