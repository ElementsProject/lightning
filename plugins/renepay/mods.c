#include "config.h"
#include <ccan/bitmap/bitmap.h>
#include <common/amount.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_stream.h>
#include <plugins/renepay/finish.h>
#include <plugins/renepay/mcf.h>
#include <plugins/renepay/mods.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/route.h>
#include <plugins/renepay/uncertainty_network.h>

#define INVALID_ID UINT32_MAX

#define OP_NULL ((u64)NULL)
#define OP_CALL 1
#define OP_IF 2
typedef const struct payment_modifier *modifier_ptr;
typedef bool (*)(struct payment *) condition_ptr;

static void *payment_virtual_program[];

/* Advance the payment virtual machine */
struct command_result *payment_continue(struct payment *payment)
{
	assert(payment->exec_state != INVALID_STATE);
	u64 op = (u64)payment_virtual_program[payment->exec_state++];

	if (op == OP_NULL) {
		plugin_err(pay_plugin->plugin,
			   "payment_continue reached the end of the virtual "
			   "machine execution.");
	} else if (op == OP_CALL) {
		modifier_ptr mod = (modifier_ptr)
		    payment_virtual_program[payment->exec_state++];

		if (mod == NULL)
			plugin_err(pay_plugin->plugin,
				   "payment_continue expected payment_modifier "
				   "but NULL found");

		plugin_log(pay_plugin->plugin, LOG_DBG, "Calling modifier %s",
			   mod->name);
		return mod->post_step_cb(payment);
	} else if (op == OP_IF) {
		condition_ptr cond = (condition_ptr)
		    payment_virtual_program[payment->exec_state++];

		if (cond == NULL)
			plugin_err(pay_plugin->plugin,
				   "payment_continue expected pointer to "
				   "condition but NULL found");

		const u64 position_iftrue =
		    (u64)payment_virtual_program[payment->exec_state++];

		if (cond(payment))
			payment->exec_state = position_iftrue;

		return payment_continue(payment);
	}
	plugin_err(pay_plugin->plugin, "payment_continue op code not defined");
	return NULL;
}

static void route_remove(struct route *route)
{
	remove_htlc_route(pay_plugin->unetwork, route);
	route_map_del(pay_plugin->route_map, route);
}

static void route_failed(struct route *route)
{
	assert(route);
	assert(route->payment);
	struct payment *payment = route->payment;
	if (!amount_msat_sub(&payment->total_delivering,
			     payment->total_delivering,
			     route_delivers(route)) ||
	    !amount_msat_sub(&payment->total_sent, payment->total_sent,
			     route_sends(route))) {
		plugin_err(pay_plugin, "%s: amount_msat substraction failed",
			   __PRETTY_FUNCTION__);
	}
	route_remove(route);
	// TODO: free? maybe not yet
}

static void route_pending(struct route *route)
{
	assert(route);
	assert(route->payment);
	struct payment *payment = route->payment;
	if (!amount_msat_sub(&payment->total_delivering,
			     payment->total_delivering,
			     route_delivers(route)) ||
	    !amount_msat_sub(&payment->total_sent, payment->total_sent,
			     route_sends(route))) {
		plugin_err(pay_plugin, "%s: amount_msat substraction failed",
			   __PRETTY_FUNCTION__);
	}
	commit_htlc_route(pay_plugin->unetwork, route);
	route_map_add(pay_plugin->route_map, route);
	// TODO: change ownership to pay_plugin? maybe not
}

/* Generic handler for RPC failures that should end up failing the payment. */
static struct command_result *payment_rpc_failure(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *toks,
						  struct payment *payment)
{
	const jsmntok_t *codetok = json_get_member(buffer, toks, "code");
	u32 errcode;
	if (codetok != NULL)
		json_to_u32(buffer, codetok, &errcode);
	else
		errcode = LIGHTNINGD;

	// TODO flag a payment as failed
	// payment_set_fail(
	//     payment, errcode,
	//     "Failing a partial payment due to a failed RPC call: %.*s",
	//     json_tok_full_len(toks), json_tok_full(buffer, toks));
	return payment_finish(payment);
}

/*****************************************************************************
 * previous_sendpays
 *
 * Obtain a list of previous sendpay requests and check if
 * the current payment hash has already being used in previous failed, pending
 * or completed attempts.
 */
// TODO: function test this previous_sendpays_pay_mod

static struct command_result *listsendpays_ok(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *result,
					      struct payment *payment)
{
	size_t i;
	const jsmntok_t *t, *arr;
	u32 max_group_id = 0;

	/* Data for pending payments, this will be the one
	 * who's result gets replayed if we end up suspending. */
	u32 pending_group_id = INVALID_ID;
	u32 max_pending_partid = 0;
	struct amount_msat pending_sent = AMOUNT_MSAT(0),
			   pending_msat = AMOUNT_MSAT(0);

	/* Data for a complete payment, if one exists. */
	u32 complete_parts = 0;
	struct preimage complete_preimage;
	u32 complete_created_at;
	u32 complete_groupid = INVALID_ID;
	struct amount_msat complete_sent = AMOUNT_MSAT(0),
			   complete_msat = AMOUNT_MSAT(0);

	arr = json_get_member(buf, result, "payments");
	if (!arr || arr->type != JSMN_ARRAY) {
		// TODO
		// payment_set_fail(
		//     payment, LIGHTNINGD,
		//     "Unexpected non-array result from listsendpays: %.*s",
		//     json_tok_full_len(result), json_tok_full(buf, result));
		return payment_finish(payment);
	}

	json_for_each_arr(i, t, arr)
	{
		u32 partid = 0, groupid;
		struct amount_msat this_msat, this_sent;
		const char *status;

		// TODO: we assume amount_msat is always present, but according
		// to the documentation this field is optional. How do I
		// interpret if amount_msat is missing?
		const char *err =
		    json_scan(tmpctx, buf, t,
			      "{status:%"
			      ",partid?:%"
			      ",groupid:%"
			      ",amount_msat:%"
			      ",amount_sent_msat:%}",
			      JSON_SCAN_TAL(tmpctx, json_strdup, &status),
			      JSON_SCAN(json_to_u32, &partid),
			      JSON_SCAN(json_to_u32, &groupid),
			      JSON_SCAN(json_to_msat, &this_msat),
			      JSON_SCAN(json_to_msat, &this_sent));

		if (err)
			plugin_err(pay_plugin->plugin,
				   "%s json_scan of listsendpay returns the "
				   "following error: %s",
				   __PRETTY_FUNCTION__, err);

		/* If we decide to create a new group, we base it on
		 * max_group_id */
		if (groupid > max_group_id)
			max_group_id = groupid;

		/* status could be completed, pending or failed */
		if (streq(status, "complete")) {
			if (complete_groupid != INVALID_ID &&
			    groupid != complete_groupid) {
				// TODO
				// payment_set_fail(payment, PAY_STATUS_UNEXPECTED,
				// 		 "Multiple complete groupids "
				// 		 "for this payment?");
				return payment_finish(payment);
			}
			complete_groupid = groupid;
			/* Now we know the payment completed. */
			if (!amount_msat_add(&complete_msat, complete_msat,
					     this_msat) ||
			    !amount_msat_add(&complete_sent, complete_sent,
					     this_sent))
				plugin_err(pay_plugin->plugin,
					   "%s (line %d) amount_msat overflow.",
					   __PRETTY_FUNCTION__, __LINE__);
			json_scan(
			    tmpctx, buf, t,
			    "{created_at:%"
			    ",payment_preimage:%}",
			    JSON_SCAN(json_to_u32, &complete_created_at),
			    JSON_SCAN(json_to_preimage, &complete_preimage));
			// FIXME there is json_add_timeabs, but there isn't
			// json_to_timeabs
			complete_parts++;
		} else if (streq(status, "pending")) {
			/* If we have more than one pending group, something
			 * went wrong! */
			if (pending_group_id != INVALID_ID &&
			    groupid != pending_group_id) {
				// TODO
				// payment_set_fail(payment, PAY_STATUS_UNEXPECTED,
				// 		 "Multiple pending groups for "
				// 		 "this payment?");
				return payment_finish(payment);
			}
			pending_group_id = groupid;
			if (partid > max_pending_partid)
				max_pending_partid = partid;

			if (!amount_msat_add(&pending_msat, pending_msat,
					     this_msat) ||
			    !amount_msat_add(&pending_sent, pending_sent,
					     this_sent))
				plugin_err(pay_plugin->plugin,
					   "%s (line %d) amount_msat overflow.",
					   __PRETTY_FUNCTION__, __LINE__);

		} else
			assert(streq(status, "failed"));
	}

	if (complete_groupid != INVALID_ID) {
		/* There are completed sendpays, we don't need to do anything
		 * but summarize the result. */
		payment->status = PAYMENT_SUCCESS;
		payment->start_time.ts.tv_sec = complete_created_at;
		payment->start_time.ts.tv_nsec = 0;

		payment->total_delivering = complete_msat;
		payment->total_sent = complete_sent;
		payment->next_partid = complete_parts + 1;
		payment->groupid = complete_groupid;
		payment->preimage =
		    tal_dup(payment, struct preimage, &complete_preimage);

		payment_note(payment, LOG_DBG,
			     "Payment completed by a previous sendpay.");
		return payment_finish(payment);
	} else if (pending_group_id != INVALID_ID) {
		/* Continue where we left off? */
		payment->groupid = pending_group_id;
		payment->next_partid = max_pending_partid + 1;
		payment->total_sent = pending_sent;
		payment->total_delivering = pending_msat;

		plugin_log(pay_plugin->plugin, LOG_DBG,
			   "There are pending sendpays to this invoice. "
			   "groupid = %" PRIu32 " "
			   "delivering = %s, "
			   "last_partid = %" PRIu32,
			   pending_group_id,
			   type_to_string(tmpctx, struct amount_msat,
					  &payment->total_delivering),
			   max_pending_partid);

		if (amount_msat_greater_eq(payment->total_delivering,
					   payment->amount)) {
			/* Pending payment already pays the full amount, we
			 * better stop. */
			// TODO
			// payment_set_fail(payment, PAY_IN_PROGRESS,
			// 		 "Payment is pending with full amount "
			// 		 "already commited");
			return payment_finish(payment);
		}
	} else {
		/* There are no pending nor completed sendpays, get me the last
		 * sendpay group. */
		payment->groupid = max_group_id + 1;
		payment->next_partid = 1;
	}

	return payment_continue(payment);
}

static struct command_result *previous_sendpays_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	assert(cmd);

	struct out_req *req = jsonrpc_request_start(
	    cmd->plugin, cmd, "listsendpays", listsendpays_ok,
	    payment_rpc_failure, payment);

	json_add_sha256(req->js, "payment_hash", &payment->payment_hash);
	return send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(previous_sendpays, previous_sendpays_cb);

/*****************************************************************************
 * initial_sanity_checks
 *
 * Some checks on a payment about to start.
 */
static struct command_result *initial_sanity_checks_cb(struct payment *payment)
{
	assert(amount_msat_zero(payment->total_sent));
	assert(amount_msat_zero(payment->total_delivering));
	assert(!payment->preimage);
	assert(tal_count(payment->cmd_array) == 1);

	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(initial_sanity_checks, initial_sanity_checks_cb);

/*****************************************************************************
 * selfpay
 *
 * Checks if the payment destination is the sender's node and perform a self
 * payment.
 */

static struct command_result *selfpay_success(struct command *cmd,
					      const char *buf,
					      const jsmntok_t *result,
					      struct payment *payment)
{
	struct preimage preimage;
	const char *err;
	err = json_scan(tmpctx, buf, result, "{payment_preimage:%}",
			JSON_SCAN(json_to_preimage, &preimage));
	if (err)
		plugin_err(
		    cmd->plugin, "selfpay didn't have payment_preimage? %.*s",
		    json_tok_full_len(result), json_tok_full(buf, result));

	payment->preimage = tal_dup(payment, struct preimage, &preimage);
	payment->status = PAYMENT_SUCCESS;
	payment_note(payment, LOG_DBG, "Paid with self-pay.");
	return payment_finish(payment);
}

static struct command_result *selfpay_cb(struct payment *payment)
{
	if (!node_id_eq(&pay_plugin->my_id, &payment->destination)) {
		payment_continue(payment);
		return;
	}

	struct command *cmd = payment_command(payment);
	if (!cmd)
		plugin_err(pay_plugin->plugin,
			   "Selfpay: cannot get a valid cmd.");
	struct out_req *req;
	req =
	    jsonrpc_request_start(cmd->plugin, cmd, "sendpay", selfpay_success,
				  payment_rpc_failure, payment);
	/* Empty route means "to-self" */
	json_array_start(req->js, "route");
	json_array_end(req->js);
	json_add_sha256(req->js, "payment_hash", &payment->payment_hash);
	if (payment->label)
		json_add_string(req->js, "label", payment->label);
	json_add_amount_msat(req->js, "amount_msat", payment->amount);
	json_add_string(req->js, "bolt11", payment->invstr);
	if (payment->payment_secret)
		json_add_secret(req->js, "payment_secret",
				payment->payment_secret);
	json_add_u32(req->js, "groupid", payment->groupid);
	if (payment->payment_metadata)
		json_add_hex_talarr(req->js, "payment_metadata",
				    payment->payment_metadata);
	if (payment->description)
		json_add_string(req->js, "description", payment->description);

	/* Pretend we have sent partid=1 with the total amount. */
	payment->next_partid = 2;
	payment->total_sent = payment->amount;
	return send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(selfpay, selfpay_cb);

/*****************************************************************************
 * getmychannels
 *
 * Calls listpeerchannels to get and updated state of the local channels.
 */

static void gossmod_cb(struct gossmap_localmods *mods,
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
		       bool is_local,
		       const char *buf,
		       const jsmntok_t *chantok,
		       struct payment *payment)
{
	struct amount_msat min, max;

	if (is_local) {
		/* local channels can send up to what's spendable */
		min = AMOUNT_MSAT(0);
		max = spendable;
	} else {
		/* remote channels can send up no more than spendable */
		min = htlcmin;
		max = amount_msat_min(spendable, htlcmax);
	}

	/* FIXME: features? */
	gossmap_local_addchan(mods, self, peer, scidd->scid, NULL);

	gossmap_local_updatechan(mods, scidd->scid, min, max,
				 fee_base.millisatoshis, /* Raw: gossmap */
				 fee_proportional,
				 cltv_delta,
				 enabled,
				 scidd->dir);

	/* Also update uncertainty map */
	uncertainty_network_update_from_listpeerchannels(payment, scidd, max, enabled,
							 buf, chantok,
							 pay_plugin->chan_extra_map);
}

static struct command_result *listpeerchannels_ok(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *result,
						  struct payment *payment)
{
	// FIXME: should local gossmods be global (ie. member of pay_plugin) or
	// local (ie. member of payment)?
	payment->local_gossmods = gossmods_from_listpeerchannels(
	    payment, &pay_plugin->my_id, buf, result, gossmod_cb, payment);

	return payment_continue(payment);
}

static struct command_result *getmychannels_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	if (!cmd)
		plugin_err(pay_plugin->plugin,
			   "getmychannels_pay_mod: cannot get a valid cmd.");

	struct out_req *req = jsonrpc_request_start(
	    cmd->plugin, cmd, "listpeerchannels", listpeerchannels_ok,
	    payment_rpc_failure, payment);
	return send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(getmychannels, getmychannels_cb);

/*****************************************************************************
 * refreshgossmap
 *
 * Update the gossmap.
 */
static struct command_result *refreshgossmap_cb(struct payment *payment)
{
	assert(pay_plugin->gossmap); // gossmap must be already initialized

	size_t num_channel_updates_rejected;
	bool gossmap_changed =
	    gossmap_refresh(pay_plugin->gossmap, &num_channel_updates_rejected);

	if (num_channel_updates_rejected)
		plugin_log(pay_plugin->plugin, LOG_DBG,
			   "gossmap ignored %zu channel updates",
			   num_channel_updates_rejected);

	// TODO: use unetwork here instead of chan_extra_map
	if (gossmap_changed)
		uncertainty_network_update(pay_plugin->gossmap,
					   pay_plugin->chan_extra_map);

	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(refreshgossmap, refreshgossmap_cb);

/*****************************************************************************
 * routehints
 *
 * Use route hints from the invoice to update the local gossmods and uncertainty
 * network.
 */
// TODO check how this is done in pay.c
static struct command_result *routehints_cb(struct payment *payment)
{
	// TODO(eduardo): are there route hints for B12?
	// TODO: use unetwork instead of chan_extra_map
	uncertainty_network_add_routehints(pay_plugin->chan_extra_map,
					   payment->routes, payment);
	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(routehints, routehints_cb);

/*****************************************************************************
 * compute_routes
 *
 * Compute the payment routes.
 */
static bitmap *make_disabled_bitmap(const tal_t *ctx,
				    const struct gossmap *gossmap,
				    const struct short_channel_id *scids)
{
	bitmap *disabled =
	    tal_arrz(ctx, bitmap, BITMAP_NWORDS(gossmap_max_chan_idx(gossmap)));

	for (size_t i = 0; i < tal_count(scids); i++) {
		struct gossmap_chan *c = gossmap_find_chan(gossmap, &scids[i]);
		if (c)
			bitmap_set_bit(disabled, gossmap_chan_idx(gossmap, c));
	}
	return disabled;
}

static bool disable_htlc_violations_oneflow(struct payment *p,
					    const struct flow *flow,
					    const struct gossmap *gossmap,
					    bitmap *disabled)
{
	bool disabled_some = false;
	struct amount_msat *amounts = tal_flow_amounts(tmpctx, flow);

	for (size_t i = 0; i < tal_count(flow->path); i++) {
		const struct half_chan *h = flow_edge(flow, i);
		struct short_channel_id scid;
		const char *reason;

		// FIXME: consider also the possibility of having an excessive
		// number of HTLCs in a single channel (both halves), that could
		// be also a reason for disabling it.
		if (!h->enabled)
			reason = "channel_update said it was disabled";
		else if (amount_msat_greater_fp16(amounts[i], h->htlc_max))
			reason = "htlc above maximum";
		else if (amount_msat_less_fp16(amounts[i], h->htlc_min))
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
		disabled_some |= disable_htlc_violations_oneflow(
		    payment, flows[i], gossmap, disabled);
	}
	return disabled_some;
}

/* Routes are computed and saved in the payment for later use. */
static const char *get_routes(struct payment *payment,
			      struct amount_msat amount_to_deliver,
			      struct amount_msat feebudget,
			      bool is_entire_payment,
			      enum jsonrpc_errcode *ecode)
{
	bitmap *disabled;
	const struct gossmap_node *src, *dst;
	char *fail = NULL;
	char *errmsg;

	disabled = make_disabled_bitmap(tmpctx, pay_plugin->gossmap,
					payment->disabled_scids);
	src = gossmap_find_node(pay_plugin->gossmap, &pay_plugin->my_id);
	if (!src) {
		*ecode = PAY_ROUTE_NOT_FOUND;
		return tal_fmt(tmpctx, "We don't have any channels.");
	}
	dst = gossmap_find_node(pay_plugin->gossmap, &payment->destination);
	if (!dst) {
		*ecode = PAY_ROUTE_NOT_FOUND;
		return tal_fmt(tmpctx,
			       "Destination is unknown in the network gossip.");
	}

	/* probability "bugdet". We will prefer solutions whose probability of
	 * success is above this value. */
	// FIXME: features factors here look like to many, see issue #6852
	double probability_budget = payment->min_prob_success;
	double delay_feefactor = payment->delay_feefactor;
	const double base_fee_penalty = payment->base_fee_penalty;
	const double prob_cost_factor = payment->prob_cost_factor;

	while (!amount_msat_zero(amount_to_deliver)) {

		// TODO: choose an algorithm, could be something like
		// payment->algorithm, that we set up based on command line
		// options and that can be changed according to some conditions
		// met during the payment process, eg. add "select_solver" pay
		// mod.
		struct flow **flows = minflow(
		    tmpctx, pay_plugin->gossmap, src, dst,
		    pay_plugin->chan_extra_map, disabled, amount_to_deliver,
		    feebudget, probability_budget, delay_feefactor,
		    base_fee_penalty, prob_cost_factor, &errmsg);

		if (!flows) {
			*ecode = PAY_ROUTE_NOT_FOUND;

			/* We fail to allocate a portion of the payment, cleanup
			 * previous payflows. */
			// FIXME wouldn't it be better to put these payflows
			// into a tal ctx with a destructor?

			fail = tal_fmt(
			    tmpctx,
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
			fail = tal_fmt(tmpctx,
				       "flows_fit_amount failed with error: %s",
				       errmsg);
			goto function_fail;
		}

		/* Check the fees */
		struct amount_msat fee;
		// TODO: flows should have a final_amount and not an amount
		// array
		if (!flowset_fee(&fee, flows)) {
			fail =
			    tal_fmt(tmpctx, "flowset_fee failed with error: %s",
				    errmsg);
			goto function_fail;
		}
		if (amount_msat_greater(fee, feebudget)) {
			*ecode = PAY_ROUTE_TOO_EXPENSIVE;
			fail = tal_fmt(
			    tmpctx,
			    "Fee exceeds our fee budget, fee = %s (feebudget = "
			    "%s)",
			    type_to_string(tmpctx, struct amount_msat, &fee),
			    type_to_string(tmpctx, struct amount_msat,
					   &feebudget));
			goto function_fail;
		}

		/* Check the CLTV delay */
		const u64 delay =
		    flows_worst_delay(flows) + payment->final_cltv;
		if (delay > payment->maxdelay) {
			/* FIXME: What is a sane limit? */
			if (delay_feefactor > 1000) {
				*ecode = PAY_ROUTE_TOO_EXPENSIVE;
				fail = tal_fmt(tmpctx,
					       "CLTV delay exceeds our CLTV "
					       "budget, delay = %" PRIu64
					       " (maxdelay = %u)",
					       delay, payment->maxdelay);
				goto function_fail;
			}

			delay_feefactor *= 2;
			payment_note(payment, LOG_INFORM,
				     "delay %" PRIu64
				     " exceeds our max %u, so doubling "
				     "delay_feefactor to %f",
				     delay, payment->maxdelay, delay_feefactor);

			continue; // retry
		}

		/* Compute the flows probability */
		double prob =
		    flowset_probability(tmpctx, flows, pay_plugin->gossmap,
					pay_plugin->chan_extra_map, &errmsg);
		if (prob < 0) {
			fail = tal_fmt(
			    tmpctx, "flowset_probability failed with error: %s",
			    errmsg);
			goto function_fail;
		}

		/* Now we check for min/max htlc violations, and
		 * excessive htlc counts.  It would be more efficient
		 * to do this inside minflow(), but the diagnostics here
		 * are far better, since we can report min/max which
		 * *actually* made us reconsider. */
		if (disable_htlc_violations(payment, flows, pay_plugin->gossmap,
					    disabled)) {
			continue; // retry
		}

		/* This can adjust amounts and final cltv for each flow,
		 * to make it look like it's going elsewhere */
		// TODO: add shadow additions, but be aware that they change the
		// flows. One idea could be to have them by default, and after
		// we have a good flow we decide whether to keep them or not
		// const u32 *final_cltvs = shadow_additions(
		//    tmpctx, pay_plugin->gossmap, p, flows, is_entire_payment);
		// convert_and_attach_flows(payment, pay_plugin->gossmap, flows,
		//			 final_cltvs, &payment->next_partid);

		/* OK, we are happy with these flows: convert to
		 * routes in the current payment. */

		// TODO review the payment_note
		payment_note(payment, LOG_INFORM,
			     "we have computed a set of %ld flows with "
			     "probability %.3lf, fees %s and delay %ld",
			     tal_count(flows), prob,
			     type_to_string(tmpctx, struct amount_msat, &fee),
			     delay);

		u64 groupid = payment->groupid, partid = payment->next_partid;

		struct route **routes = flows_to_routes(
		    payment, payment, groupid, partid, payment->payment_hash,
		    payment->final_cltv, pay_plugin->gossmap, flows);

		payment_append_routes(routes);

		payment->next_partid += tal_count(routes);

		attach_routes(payment, routes);

		/* For the next iteration get me the amount_to_deliver */
		if (!amount_msat_sub(&amount_to_deliver, amount_to_deliver,
				     delivering)) {
			/* In the next iteration we search routes that allocate
			 *	amount_to_deliver - delivering
			 * If we have
			 *	delivering > amount_to_deliver
			 * it means we have made a mistake somewhere. */
			plugin_err(pay_plugin->plugin,
				   "amount_to_deliver = %s smaller than "
				   "delivering = %s",
				   fmt_amount_msat(tmpctx, amount_to_deliver),
				   fmt_amount_msat(tmpctx, delivering));
		}

		/* For the next iteration get me the feebudget */
		if (!amount_msat_sub(&feebudget, feebudget, fee)) {
			plugin_err(
			    pay_plugin->plugin,
			    "amount_msat substraction feebudget-fee failed");
		}

		/* For the next iteration get me the probability_budget */
		if (prob < 1e-10) {
			// this last flow probability is too small for division
			probability_budget = 1.0;
		} else {
			/* prob here is a conditional probability, the next
			 * round of flows will have a conditional probability
			 * prob2 and we would like that
			 *	prob*prob2 >= probability_budget
			 * hence probability_budget/prob becomes the next
			 * iteration's target. */
			probability_budget =
			    MIN(1.0, probability_budget / prob);
		}
	}
	return NULL;

function_fail:
	//	payment_remove_flows(p, PAY_FLOW_NOT_STARTED);

	return fail;
}

static void compute_routes_cb(struct payment *payment)
{
	assert(payment->status == PAYMENT_PENDING);

	struct amount_msat feebudget, fees_spent, remaining;

	/* Total feebudget  */
	if (!amount_msat_sub(&feebudget, payment->maxspend, payment->amount))
		plugin_err(pay_plugin->plugin, "%s: fee budget is negative?",
			   __PRETTY_FUNCTION__);

	/* Fees spent so far */
	if (!amount_msat_sub(&fees_spent, payment->total_sent,
			     payment->total_delivering))
		plugin_err(pay_plugin->plugin,
			   "%s: total_delivering is greater than total_sent?",
			   __PRETTY_FUNCTION__);

	/* Remaining fee budget. */
	if (!amount_msat_sub(&feebudget, feebudget, fees_spent))
		plugin_err(pay_plugin->plugin,
			   "%s: fees_speng is greater than feebudget?",
			   __PRETTY_FUNCTION__);

	/* How much are we still trying to send? */
	if (!amount_msat_sub(&remaining, payment->amount,
			     payment->total_delivering))
		plugin_err(pay_plugin->plugin,
			   "%s: total_delivering is greater than amount?",
			   __PRETTY_FUNCTION__);

	/* We let this return an unlikely path, as it's better to try once
	 * than simply refuse.  Plus, models are not truth! */
	gossmap_apply_localmods(pay_plugin->gossmap, payment->local_gossmods);
	// TODO: add an algorithm selector here
	// TODO: review add_payflows
	enum jsonrpc_errcode errcode;
	const char *err_msg =
	    get_routes(payment, remaining, feebudget,
		       /* is entire payment? */
		       amount_msat_zero(payment->total_delivering), &errcode);
	gossmap_remove_localmods(pay_plugin->gossmap, payment->local_gossmods);

	/* Couldn't feasible route, we stop. */
	if (err_msg) {
		// TODO
		// payment_set_fail(payment, errcode, "%s", err_msg);
		payment_finish(payment);
	}

	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(compute_routes, compute_routes_cb);

/*****************************************************************************
 * send_routes
 *
 * This payment modifier takes the payment routes and starts the payment request
 * calling sendpay.
 */

static struct command_result *sendpay_done(struct command *cmd, const char *buf,
					   const jsmntok_t *result,
					   struct route *route)
{
	// TODO: put here the user interface messages
	return command_still_pending(cmd);
}

/* sendpay really only fails immediately in two ways:
 * 1. We screwed up and misused the API.
 * 2. The first peer is disconnected.
 */
static struct command_result *sendpay_failed(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *err,
					     struct route *route)
{
	// TODO check how pay.c handles this
	struct payment *payment = route->payment;
	enum jsonrpc_errcode errcode;
	const char *msg;

	assert(payment);

	if (json_scan(tmpctx, buf, err, "{code:%,message:%}",
		      JSON_SCAN(json_to_jsonrpc_errcode, &errcode),
		      JSON_SCAN_TAL(tmpctx, json_strdup, &msg)))
		plugin_err(pay_plugin->plugin,
			   "Unable to parse sendpay error: %.*s",
			   json_tok_full_len(err), json_tok_full(buf, err));

	if (errcode != PAY_TRY_OTHER_ROUTE)
		plugin_err(pay_plugin->plugin,
			   "Strange error from sendpay: %.*s",
			   json_tok_full_len(err), json_tok_full(buf, err));

	/* There is no new knowledge from this kind of failure.
	 * We just disable this scid. */
	// TODO: review this
	payflow_disable_chan(pf, pf->path_scidds[0].scid, LOG_INFORM,
			     "sendpay didn't like first hop: %s", msg);

	// TODO: review this
	route_failed(route);
	return command_still_pending(cmd);
}

static struct command_result *send_routes_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	assert(cmd);

	for (size_t i = 0; i < tal_count(payment->routes); i++) {
		struct route *route = payment->routes[i];

		struct out_req *req =
		    jsonrpc_request_start(pay_plugin->plugin, cmd, "sendpay",
					  sendpay_done, sendpay_failed, route);

		json_array_start(req->js, "route");
		const size_t pathlen = tal_count(route->hops);

		for (size_t j = 0; j < pathlen; j++) {
			const route_hop *hop = &route->hops[j];

			json_object_start(req->js, NULL);
			json_add_node_id(req->js, "id", &hop->node_id);
			json_add_short_channel_id(req->js, "channel",
						  &hop->scid);
			json_add_amount_msat(req->js, "amount_msat",
					     hop->amount);
			json_add_num(req->js, "direction", hop->direction);
			json_add_u32(req->js, "delay", hop->delay);
			json_add_string(req->js, "style", "tlv");
			json_object_end(req->js);
		}
		json_array_end(req->js);

		json_add_sha256(req->js, "payment_hash",
				&payment->payment_hash);
		json_add_secret(req->js, "payment_secret",
				payment->payment_secret);

		/* FIXME: sendpay has a check that we don't total more than
		 * the exact amount, if we're setting partid (i.e. MPP).
		 * However, we always set partid, and we add a shadow amount *if
		 * we've only have one part*, so we have to use that amount
		 * here.
		 *
		 * The spec was loosened so you are actually allowed
		 * to overpay, so this check is now overzealous. */
		if (amount_msat_greater(route_delivers(route),
					payment->amount)) {
			json_add_amount_msat(req->js, "amount_msat",
					     route_delivers(route));
		} else {
			json_add_amount_msat(req->js, "amount_msat",
					     payment->amount);
		}

		json_add_u64(req->js, "partid", route->key.partid);

		json_add_u64(req->js, "groupid", route->key.groupid);

		/* FIXME: some of these fields might not be required for all
		 * payment parts. */
		json_add_string(req->js, "bolt11", payment->invstr);

		if (payment->payment_metadata)
			json_add_hex_talarr(req->js, "payment_metadata",
					    payment->payment_metadata);
		if (payment->label)
			json_add_string(req->js, "label", payment->label);
		if (payment->description)
			json_add_string(req->js, "description",
					payment->description);

		send_outreq(pay_plugin->plugin, req);

		route_pending(route);
	}

	payment->routes = tal_free(payment->routes);

	/* Safety check. */
	payment_assert_delivering_all(payment);

	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(send_routes, send_routes_cb);

/*****************************************************************************
 * waitblockheight
 *
 * FIXME: We use this mod to clear the real stack of function calls so that we
 * don't get a stackoverflow. I am not sure if there is a more elegant way to
 * achieve it with this model.
 */

static struct command_result *waitblockheight_ok(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *result,
						 struct payment *payment)
{
	return payment_continue(payment);
}

static struct command_result *waitblockheight_cb(struct payment *payment)
{
	struct command *cmd = payment_command(payment);
	assert(cmd);

	struct out_req *req = jsonrpc_request_start(
	    cmd->plugin, cmd, "waitblockheight", waitblockheight_ok,
	    payment_rpc_failure, payment);

	json_add_num(req->js, "blockheight", 0);
	return send_outreq(cmd->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(waitblockheight, waitblockheight_cb);

/*****************************************************************************
 * check_timeout
 */
static struct command_result *check_timeout_cb(struct payment *payment)
{
	if (time_after(time_now(), payment->stop_time)) {
		payment_fail(payment, PAY_STOPPED_RETRYING, "Timed out");
		return payment_finish(payment);
	}
	return payment_continue(payment);
}

REGISTER_PAYMENT_MODIFIER(check_timeout, check_timeout_cb);

/*****************************************************************************
 * end
 *
 * A dummy modifier used to end the payment, just for testing.
 */
static struct command_result *end_cb(struct payment *payment)
{
	payment_fail(payment, LIGHTNINGD,
		     "Failing the payment on purpose (call to end_pay_mod)");
	return payment_finish(payment);
}

REGISTER_PAYMENT_MODIFIER(end, end_cb);

// TODO
static void *payment_virtual_program[] = {
	OP_CALL, previous_sendpays_mod, // 0
	OP_CALL, selfpay_pay_mod,       // 2
	OP_CALL, refreshgossmap_pay_mod,// 4
	OP_CALL, getmychannels_pay_mod, // 6
	OP_CALL, routehints_pay_mod,    // 8

	OP_CALL, compute_routes_pay_mod,// 10
	OP_CALL, send_routes_pay_mod,   // 12
	OP_CALL, collect_results_pay_mod,// 14
	OP_IF, payment_ifretry, (void*)10,// 16
	OP_IF, payment_iftrue, (void*)14 ,//19
	NULL // 22
};
