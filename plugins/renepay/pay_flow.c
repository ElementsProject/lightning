/* Routines to get suitable pay_flow array from pay constraints */
#include "config.h"
#include <bitcoin/preimage.h>
#include <ccan/tal/str/str.h>
#include <common/gossmap.h>
#include <common/pseudorand.h>
#include <errno.h>
#include <plugins/libplugin.h>
#include <plugins/renepay/mcf.h>
#include <plugins/renepay/pay.h>
#include <plugins/renepay/pay_flow.h>

// FIXME These macros are used in more than one place of the code, they could be
// defined in a single header.
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

/* BOLT #7:
 *
 * If a route is computed by simply routing to the intended recipient and summing
 * the `cltv_expiry_delta`s, then it's possible for intermediate nodes to guess
 * their position in the route. Knowing the CLTV of the HTLC, the surrounding
 * network topology, and the `cltv_expiry_delta`s gives an attacker a way to guess
 * the intended recipient. Therefore, it's highly desirable to add a random offset
 * to the CLTV that the intended recipient will receive, which bumps all CLTVs
 * along the route.
 *
 * In order to create a plausible offset, the origin node MAY start a limited
 * random walk on the graph, starting from the intended recipient and summing the
 * `cltv_expiry_delta`s, and use the resulting sum as the offset.
 * This effectively creates a _shadow route extension_ to the actual route and
 * provides better protection against this attack vector than simply picking a
 * random offset would.
 */

/* There's little benefit in doing this per-flow, since you can
 * correlate flows so trivially, but it's good practice for when we
 * have PTLCs and that's not true. */

#define MAX_SHADOW_LEN 3

static void remove_htlc_payflow(
		struct chan_extra_map *chan_extra_map,
		struct pay_flow *pf)
{
	for (size_t i = 0; i < tal_count(pf->path_scidds); i++) {
		struct chan_extra_half *h = get_chan_extra_half_by_scid(
							       chan_extra_map,
							       &pf->path_scidds[i]);
		if(!h)
		{
			plugin_err(pay_plugin->plugin,
				   "%s could not resolve chan_extra_half",
				   __PRETTY_FUNCTION__);
		}
		if (!amount_msat_sub(&h->htlc_total, h->htlc_total, pf->amounts[i]))
		{
			plugin_err(pay_plugin->plugin,
				   "%s could not substract HTLC amounts, "
				   "half total htlc amount = %s, "
				   "pf->amounts[%lld] = %s.",
				   __PRETTY_FUNCTION__,
				   type_to_string(tmpctx, struct amount_msat, &h->htlc_total),
				   i,
				   type_to_string(tmpctx, struct amount_msat, &pf->amounts[i]));
		}
		if (h->num_htlcs == 0)
		{
			plugin_err(pay_plugin->plugin,
				   "%s could not decrease HTLC count.",
				   __PRETTY_FUNCTION__);
		}
		h->num_htlcs--;
	}
}

static void commit_htlc_payflow(
		struct chan_extra_map *chan_extra_map,
		const struct pay_flow *pf)
{
	for (size_t i = 0; i < tal_count(pf->path_scidds); i++) {
		struct chan_extra_half *h = get_chan_extra_half_by_scid(
							       chan_extra_map,
							       &pf->path_scidds[i]);
		if(!h)
		{
			plugin_err(pay_plugin->plugin,
				   "%s could not resolve chan_extra_half",
				   __PRETTY_FUNCTION__);
		}
		if (!amount_msat_add(&h->htlc_total, h->htlc_total, pf->amounts[i]))
		{
			plugin_err(pay_plugin->plugin,
				   "%s could not add HTLC amounts, "
				   "pf->amounts[%lld] = %s.",
				   __PRETTY_FUNCTION__,
				   i,
				   type_to_string(tmpctx, struct amount_msat, &pf->amounts[i]));
		}
		h->num_htlcs++;
	}
}

/* Returns CLTV, and fills in *shadow_fee, based on extending the path */
static u32 shadow_one_flow(const struct gossmap *gossmap,
			   const struct flow *f,
			   struct amount_msat *shadow_fee)
{
	size_t numpath = tal_count(f->amounts);
	struct amount_msat amount = f->amounts[numpath-1];
	struct gossmap_node *n;
	size_t hop;
	struct gossmap_chan *chans[MAX_SHADOW_LEN];
	int dirs[MAX_SHADOW_LEN];
	u32 shadow_delay = 0;

	/* Start at end of path */
	n = gossmap_nth_node(gossmap, f->path[numpath-1], !f->dirs[numpath-1]);

	/* We only create shadow for extra CLTV delays, *not* for
	 * amounts.  This is because with MPP our amounts are random
	 * looking already. */
	for (hop = 0; hop < MAX_SHADOW_LEN && pseudorand(2); hop++) {
		/* Try for a believable channel up to 10 times, then stop */
		for (size_t i = 0; i < 10; i++) {
			struct amount_sat cap;
			chans[hop] = gossmap_nth_chan(gossmap, n, pseudorand(n->num_chans),
						      &dirs[hop]);
			if (!gossmap_chan_set(chans[hop], dirs[hop])
			    || !gossmap_chan_get_capacity(gossmap, chans[hop], &cap)
			    /* This test is approximate, since amount would differ */
			    || amount_msat_greater_sat(amount, cap)) {
				chans[hop] = NULL;
				continue;
			}
		}
		if (!chans[hop])
			break;

		shadow_delay += chans[hop]->half[dirs[hop]].delay;
		n = gossmap_nth_node(gossmap, chans[hop], !dirs[hop]);
	}

	/* If we were actually trying to get amount to end of shadow,
	 * what would we be paying to the "intermediary" node (real dest) */
	for (int i = (int)hop - 1; i >= 0; i--)
		if (!amount_msat_add_fee(&amount,
					 chans[i]->half[dirs[i]].base_fee,
					 chans[i]->half[dirs[i]].proportional_fee))
			/* Ignore: treats impossible event as zero fee. */
			;

	/* Shouldn't happen either */
	if (!amount_msat_sub(shadow_fee, amount, f->amounts[numpath-1]))
		plugin_err(pay_plugin->plugin,
			   "Failed to calc shadow fee: %s - %s",
			   type_to_string(tmpctx, struct amount_msat, &amount),
			   type_to_string(tmpctx, struct amount_msat,
					  &f->amounts[numpath-1]));

	return shadow_delay;
}

static bool add_to_amounts(const struct gossmap *gossmap,
			   struct flow *f,
			   struct amount_msat maxspend,
			   struct amount_msat additional)
{
	struct amount_msat *amounts;
	size_t num = tal_count(f->amounts);

	/* Recalculate amounts backwards */
	amounts = tal_arr(tmpctx, struct amount_msat, num);
	if (!amount_msat_add(&amounts[num-1], f->amounts[num-1], additional))
		return false;

	for (int i = num-2; i >= 0; i--) {
		amounts[i] = amounts[i+1];
		if (!amount_msat_add_fee(&amounts[i],
					 flow_edge(f, i+1)->base_fee,
					 flow_edge(f, i+1)->proportional_fee))
			return false;
	}

	/* Do we now exceed budget? */
	if (amount_msat_greater(amounts[0], maxspend))
		return false;

	/* OK, replace amounts */
	tal_free(f->amounts);
	f->amounts = tal_steal(f, amounts);
	return true;
}

static u64 flow_delay(const struct flow *flow)
{
	u64 delay = 0;
	for (size_t i = 0; i < tal_count(flow->path); i++)
		delay += flow->path[i]->half[flow->dirs[i]].delay;
	return delay;
}

/* This enhances f->amounts, and returns per-flow cltvs */
static u32 *shadow_additions(const tal_t *ctx,
			     const struct gossmap *gossmap,
			     struct payment *p,
			     struct flow **flows,
			     bool is_entire_payment)
{
	u32 *final_cltvs;

	/* Set these up now in case we decide to do nothing */
	final_cltvs = tal_arr(ctx, u32, tal_count(flows));
	for (size_t i = 0; i < tal_count(flows); i++)
		final_cltvs[i] = p->final_cltv;

	/* --developer can disable this */
	if (!p->use_shadow)
		return final_cltvs;

	for (size_t i = 0; i < tal_count(flows); i++) {
		u32 shadow_delay;
		struct amount_msat shadow_fee;

		shadow_delay = shadow_one_flow(gossmap, flows[i],
					       &shadow_fee);
		if (flow_delay(flows[i]) + shadow_delay > p->maxdelay) {
			payment_note(p, LOG_UNUSUAL,
				     "No shadow for flow %zu/%zu:"
				     " delay would add %u to %"PRIu64", exceeding max delay.",
				     i, tal_count(flows),
				     shadow_delay,
				     flow_delay(flows[i]));
			continue;
		}

		/* We don't need to add fee amounts to obfuscate most payments
		 * when we're using MPP, since we randomly split amounts.  But
		 * if this really is the entire thing, we want to, since
		 * people use round numbers of msats in invoices. */
		if (is_entire_payment && tal_count(flows) == 1) {
			if (!add_to_amounts(gossmap, flows[i], p->maxspend,
					    shadow_fee)) {
				payment_note(p, LOG_UNUSUAL,
					     "No shadow fee for flow %zu/%zu:"
					" fee would add %s to %s, exceeding budget %s.",
					i, tal_count(flows),
					type_to_string(tmpctx, struct amount_msat,
						       &shadow_fee),
					type_to_string(tmpctx, struct amount_msat,
						       &flows[i]->amounts[0]),
					type_to_string(tmpctx, struct amount_msat,
						       &p->maxspend));
			} else {
				payment_note(p, LOG_DBG,
					"No MPP, so added %s shadow fee",
					type_to_string(tmpctx, struct amount_msat,
						       &shadow_fee));
			}
		}

		final_cltvs[i] += shadow_delay;
		payment_note(p, LOG_DBG, "Shadow route on flow %zu/%zu added %u block delay. now %u",
			i, tal_count(flows), shadow_delay, final_cltvs[i]);
	}

	return final_cltvs;
}

static void destroy_payment_flow(struct pay_flow *pf)
{
	list_del_from(&pf->payment->flows, &pf->list);
}

/* Print out flow, and any information we already know */
static const char *flow_path_annotated(const tal_t *ctx,
				       const struct pay_flow *flow)
{
	char *s = tal_strdup(ctx, "");
	for (size_t i = 0; i < tal_count(flow->path_scidds); i++) {
		tal_append_fmt(&s, "-%s%s->",
			       type_to_string(tmpctx,
					      struct short_channel_id_dir,
					      &flow->path_scidds[i]),
			       fmt_chan_extra_details(tmpctx,
						      pay_plugin->chan_extra_map,
						      &flow->path_scidds[i]));
	}
	return s;
}

/* Calculates delays and converts to scids, and links to the payment.
 * Frees flows. */
static void convert_and_attach_flows(struct payment *payment,
				     struct gossmap *gossmap,
				     struct flow **flows STEALS,
				     const u32 *final_cltvs,
				     u64 *next_partid)
{
	for (size_t i = 0; i < tal_count(flows); i++) {
		struct flow *f = flows[i];
		struct pay_flow *pf = tal(payment, struct pay_flow);
		size_t plen;

		plen = tal_count(f->path);

		pf->payment = payment;
		pf->state = PAY_FLOW_NOT_STARTED;
		pf->key.partid = (*next_partid)++;
		pf->key.groupid = payment->groupid;
		pf->key.payment_hash = payment->payment_hash;

		/* Convert gossmap_chan into scids and nodes */
		pf->path_scidds = tal_arr(pf, struct short_channel_id_dir, plen);
		pf->path_nodes = tal_arr(pf, struct node_id, plen);
		for (size_t j = 0; j < plen; j++) {
			struct gossmap_node *n;
			n = gossmap_nth_node(gossmap, f->path[j], !f->dirs[j]);
			gossmap_node_get_id(gossmap, n, &pf->path_nodes[j]);
			pf->path_scidds[j].scid
				= gossmap_chan_scid(gossmap, f->path[j]);
			pf->path_scidds[j].dir = f->dirs[j];
		}

		/* Calculate cumulative delays (backwards) */
		pf->cltv_delays = tal_arr(pf, u32, plen);
		pf->cltv_delays[plen-1] = final_cltvs[i];
		for (int j = (int)plen-2; j >= 0; j--) {
			pf->cltv_delays[j] = pf->cltv_delays[j+1]
				+ f->path[j+1]->half[f->dirs[j+1]].delay;
		}
		pf->amounts = tal_steal(pf, f->amounts);
		pf->success_prob = f->success_prob;

		/* Payment keeps a list of its flows. */
		list_add(&payment->flows, &pf->list);

		/* First time they see this: annotate important points */
		payflow_note(pf, LOG_INFORM,
			     "amount=%s prob=%.3lf fees=%s delay=%u path=%s",
			     fmt_amount_msat(tmpctx, payflow_delivered(pf)),
			     pf->success_prob,
			     fmt_amount_msat(tmpctx, payflow_fee(pf)),
			     pf->cltv_delays[0] - pf->cltv_delays[plen-1],
			     flow_path_annotated(tmpctx, pf));

		/* Increase totals for payment */
		if(!amount_msat_add(&payment->total_sent,
				    payment->total_sent,
				    pf->amounts[0]))
		{
			// TODO: fail this call and notifiy the plugin
			assert(0);
		}
		if(!amount_msat_add(&payment->total_delivering,
				    payment->total_delivering,
				    payflow_delivered(pf)))
		{
			// TODO: fail this call and notifiy the plugin
			assert(0);
		}

		/* We keep a global map to identify notifications
		 * about this flow. */
		payflow_map_add(pay_plugin->payflow_map, pf);

		/* record these HTLC along the flow path */
		commit_htlc_payflow(pay_plugin->chan_extra_map, pf);

		tal_add_destructor(pf, destroy_payment_flow);
	}
	tal_free(flows);
}

static bitmap *make_disabled_bitmap(const tal_t *ctx,
				    const struct gossmap *gossmap,
				    const struct short_channel_id *scids)
{
	bitmap *disabled
		= tal_arrz(ctx, bitmap,
			   BITMAP_NWORDS(gossmap_max_chan_idx(gossmap)));

	for (size_t i = 0; i < tal_count(scids); i++) {
		struct gossmap_chan *c = gossmap_find_chan(gossmap, &scids[i]);
		if (c)
			bitmap_set_bit(disabled, gossmap_chan_idx(gossmap, c));
	}
	return disabled;
}


static u64 flows_worst_delay(struct flow **flows)
{
	u64 maxdelay = 0;
	for (size_t i = 0; i < tal_count(flows); i++) {
		u64 delay = flow_delay(flows[i]);
		if (delay > maxdelay)
			maxdelay = delay;
	}
	return maxdelay;
}

/* FIXME: If only path has channels marked disabled, we should try... */
static bool disable_htlc_violations_oneflow(struct payment *p,
					    const struct flow *flow,
					    const struct gossmap *gossmap,
					    bitmap *disabled)
{
	bool disabled_some = false;

	for (size_t i = 0; i < tal_count(flow->path); i++) {
		const struct half_chan *h = &flow->path[i]->half[flow->dirs[i]];
		struct short_channel_id scid;
		const char *reason;

		if (!h->enabled)
			reason = "channel_update said it was disabled";
		else if (amount_msat_greater_fp16(flow->amounts[i], h->htlc_max))
			reason = "htlc above maximum";
		else if (amount_msat_less_fp16(flow->amounts[i], h->htlc_min))
			reason = "htlc below minimum";
		else
			continue;

		scid = gossmap_chan_scid(gossmap, flow->path[i]);
		payment_disable_chan(p, scid, LOG_INFORM, "%s", reason);
		/* Add to existing bitmap */
		bitmap_set_bit(disabled,
			       gossmap_chan_idx(gossmap, flow->path[i]));
		disabled_some = true;
	}
	return disabled_some;
}

/* If we can't use one of these flows because we hit limits, we disable that
 * channel for future searches and return false */
static bool disable_htlc_violations(struct payment *payment,
				    struct flow **flows,
				    const struct gossmap *gossmap,
				    bitmap *disabled)
{
	bool disabled_some = false;

	/* We continue through all of them, to disable many at once. */
	for (size_t i = 0; i < tal_count(flows); i++) {
		disabled_some |= disable_htlc_violations_oneflow(payment, flows[i],
								 gossmap,
								 disabled);
	}
	return disabled_some;
}

const char *add_payflows(const tal_t *ctx, struct payment *p,
			 struct amount_msat amount_to_deliver,
			 struct amount_msat feebudget, bool is_entire_payment,
			 enum jsonrpc_errcode *ecode)
{
	bitmap *disabled;
	const struct gossmap_node *src, *dst;
	char *errmsg, *fail = NULL;

	disabled = make_disabled_bitmap(tmpctx, pay_plugin->gossmap,
					p->disabled_scids);
	src = gossmap_find_node(pay_plugin->gossmap, &pay_plugin->my_id);
	if (!src) {
		*ecode = PAY_ROUTE_NOT_FOUND;
		return tal_fmt(ctx, "We don't have any channels.");
	}
	dst = gossmap_find_node(pay_plugin->gossmap, &p->destination);
	if (!dst) {
		*ecode = PAY_ROUTE_NOT_FOUND;
		return tal_fmt(ctx,
			       "Destination is unknown in the network gossip.");
	}

	/* probability "bugdet". We will prefer solutions whose probability of
	 * success is above this value. */
	double min_prob_success = p->min_prob_success;

	while (!amount_msat_zero(amount_to_deliver)) {
		struct flow **flows = minflow(
		    tmpctx, pay_plugin->gossmap, src, dst,
		    pay_plugin->chan_extra_map, disabled, amount_to_deliver,
		    feebudget, min_prob_success, p->delay_feefactor,
		    p->base_fee_penalty, p->prob_cost_factor, &errmsg);
		if (!flows) {
			*ecode = PAY_ROUTE_NOT_FOUND;

			/* We fail to allocate a portion of the payment, cleanup
			 * previous payflows. */
			// FIXME wouldn't it be better to put these payflows
			// into a tal ctx with a destructor?
			fail = tal_fmt(
			    ctx,
			    "minflow couldn't find a feasible flow for %s, %s",
			    type_to_string(tmpctx, struct amount_msat,
					   &amount_to_deliver),
			    errmsg);
			goto function_fail;
		}

		/* `delivering` could be smaller than `amount_to_deliver`
		 * because minflow does not count fees when constraining flows.
		 * Try to redistribute the missing amount among the optimal
		 * routes. */
		struct amount_msat delivering;

		if (!flows_fit_amount(tmpctx, &delivering, flows,
				      amount_to_deliver, pay_plugin->gossmap,
				      pay_plugin->chan_extra_map, &errmsg)) {
			fail = tal_fmt(ctx,
				       "(%s, line %d) flows_fit_amount failed "
				       "with error: %s",
				       __PRETTY_FUNCTION__, __LINE__, errmsg);
			goto function_fail;
		}

		/* Are we unhappy? */
		double prob =
		    flowset_probability(tmpctx, flows, pay_plugin->gossmap,
					pay_plugin->chan_extra_map, &errmsg);
		if (prob < 0) {
			plugin_err(pay_plugin->plugin,
				   "flow_set_probability failed: %s", errmsg);
		}
		struct amount_msat fee;
		if (!flowset_fee(&fee, flows)) {
			plugin_err(pay_plugin->plugin, "flowset_fee failed");
		}
		u64 delay = flows_worst_delay(flows) + p->final_cltv;

		payment_note(p, LOG_INFORM,
			     "we have computed a set of %ld flows with "
			     "probability %.3lf, fees %s and delay %ld",
			     tal_count(flows), prob,
			     type_to_string(tmpctx, struct amount_msat, &fee),
			     delay);

		if (amount_msat_greater(fee, feebudget)) {
			*ecode = PAY_ROUTE_TOO_EXPENSIVE;
			fail = tal_fmt(
			    ctx,
			    "Fee exceeds our fee budget, "
			    "fee = %s (maxfee = %s)",
			    type_to_string(tmpctx, struct amount_msat, &fee),
			    type_to_string(tmpctx, struct amount_msat,
					   &feebudget));
			goto function_fail;
		}
		if (delay > p->maxdelay) {
			/* FIXME: What is a sane limit? */
			if (p->delay_feefactor > 1000) {
				*ecode = PAY_ROUTE_TOO_EXPENSIVE;
				fail = tal_fmt(
				    ctx,
				    "CLTV delay exceeds our CLTV budget, "
				    "delay = %" PRIu64 " (maxdelay = %u)",
				    delay, p->maxdelay);
				goto function_fail;
			}

			p->delay_feefactor *= 2;
			payment_note(p, LOG_INFORM,
				     "delay %" PRIu64
				     " exceeds our max %u, so doubling "
				     "delay_feefactor to %f",
				     delay, p->maxdelay, p->delay_feefactor);

			continue; // retry
		}

		/* Now we check for min/max htlc violations, and
		 * excessive htlc counts.  It would be more efficient
		 * to do this inside minflow(), but the diagnostics here
		 * are far better, since we can report min/max which
		 * *actually* made us reconsider. */
		if (disable_htlc_violations(p, flows, pay_plugin->gossmap,
					    disabled)) {
			continue; // retry
		}

		/* This can adjust amounts and final cltv for each flow,
		 * to make it look like it's going elsewhere */
		// FIXME adding shadow fees after flows_fit_amount could mean
		// that we end up again with over-commitments
		const u32 *final_cltvs = shadow_additions(
		    tmpctx, pay_plugin->gossmap, p, flows, is_entire_payment);

		/* OK, we are happy with these flows: convert to
		 * pay_flows in the current payment, to outlive the
		 * current gossmap. */
		convert_and_attach_flows(p, pay_plugin->gossmap, flows,
					 final_cltvs, &p->next_partid);
		if (prob < 1e-10) {
			// this last flow probability is too small for division
			min_prob_success = 1.0;
		} else {
			/* prob here is a conditional probability, the next
			 * round of flows will have a conditional probability
			 * prob2 and we would like that
			 *	prob*prob2 >= min_prob_success
			 * hence min_prob_success/prob becomes the next
			 * iteration's target. */
			min_prob_success = MIN(1.0, min_prob_success / prob);
		}
		if (!amount_msat_sub(&feebudget, feebudget, fee)) {
			plugin_err(
			    pay_plugin->plugin,
			    "%s: cannot substract feebudget (%s) - fee(%s)",
			    __PRETTY_FUNCTION__,
			    fmt_amount_msat(tmpctx, feebudget),
			    fmt_amount_msat(tmpctx, fee));
		}
		if (!amount_msat_sub(&amount_to_deliver, amount_to_deliver,
				     delivering)) {
			// If we allow overpayment we might let some bugs
			// get through.
			plugin_err(pay_plugin->plugin,
				   "%s: minflow has produced an overpayment, "
				   "amount_to_deliver=%s delivering=%s",
				   __PRETTY_FUNCTION__,
				   fmt_amount_msat(tmpctx, amount_to_deliver),
				   fmt_amount_msat(tmpctx, delivering));
		}
	}
	return NULL;

function_fail:
	payment_remove_flows(p, PAY_FLOW_NOT_STARTED);
	return fail;
}

const char *flow_path_to_str(const tal_t *ctx, const struct pay_flow *flow)
{
	char *s = tal_strdup(ctx, "");
	for (size_t i = 0; i < tal_count(flow->path_scidds); i++) {
		tal_append_fmt(&s, "-%s->",
			       type_to_string(tmpctx, struct short_channel_id,
					      &flow->path_scidds[i].scid));
	}
	return s;
}

/* How much does this flow deliver to destination? */
struct amount_msat payflow_delivered(const struct pay_flow *flow)
{
	return flow->amounts[tal_count(flow->amounts)-1];
}

/* How much does this flow pay in fees? */
struct amount_msat payflow_fee(const struct pay_flow *pf)
{
	struct amount_msat fee;

	if (!amount_msat_sub(&fee, pf->amounts[0], payflow_delivered(pf)))
		abort();
	return fee;
}

static struct pf_result *pf_resolve(struct pay_flow *pf,
				    enum pay_flow_state oldstate,
				    enum pay_flow_state newstate,
				    bool reconsider)
{
	assert(pf->state == oldstate);
	pf->state = newstate;

	/* If it didn't deliver, remove from totals */
	if (pf->state != PAY_FLOW_SUCCESS) {
		if(!amount_msat_sub(&pf->payment->total_delivering,
				    pf->payment->total_delivering,
				    payflow_delivered(pf)))
		{
			// TODO: fail this call and notifiy the plugin
			assert(0);
		}
		if(!amount_msat_sub(&pf->payment->total_sent,
				    pf->payment->total_sent,
				    pf->amounts[0]))
		{
			// TODO: fail this call and notifiy the plugin
			assert(0);
		}
	}

	/* Subtract HTLC counters from the path */
	remove_htlc_payflow(pay_plugin->chan_extra_map, pf);
	/* And remove from the global map: no more notifications about this! */
	payflow_map_del(pay_plugin->payflow_map, pf);

	if (reconsider)
		payment_reconsider(pf->payment);
	return NULL;
}

/* We've been notified that a pay_flow has failed */
struct pf_result *pay_flow_failed(struct pay_flow *pf)
{
	return pf_resolve(pf, PAY_FLOW_IN_PROGRESS, PAY_FLOW_FAILED, true);
}

/* We've been notified that a pay_flow has failed, payment is done. */
struct pf_result *pay_flow_failed_final(struct pay_flow *pf,
					enum jsonrpc_errcode final_error,
					const char *final_msg TAKES)
{
	pf->final_error = final_error;
	pf->final_msg = tal_strdup(pf, final_msg);

	return pf_resolve(pf, PAY_FLOW_IN_PROGRESS, PAY_FLOW_FAILED_FINAL, true);
}

/* We've been notified that a pay_flow has failed, adding gossip. */
struct pf_result *pay_flow_failed_adding_gossip(struct pay_flow *pf)
{
	/* Don't bother reconsidering until addgossip done */
	return pf_resolve(pf, PAY_FLOW_IN_PROGRESS, PAY_FLOW_FAILED_GOSSIP_PENDING,
			  false);
}

/* We've finished adding gossip. */
struct pf_result *pay_flow_finished_adding_gossip(struct pay_flow *pf)
{
	assert(pf->state == PAY_FLOW_FAILED_GOSSIP_PENDING);
	pf->state = PAY_FLOW_FAILED;

	payment_reconsider(pf->payment);
	return NULL;
}

/* We've been notified that a pay_flow has succeeded. */
struct pf_result *pay_flow_succeeded(struct pay_flow *pf,
				     const struct preimage *preimage)
{
	pf->payment_preimage = tal_dup(pf, struct preimage, preimage);
	return pf_resolve(pf, PAY_FLOW_IN_PROGRESS, PAY_FLOW_SUCCESS, true);
}
