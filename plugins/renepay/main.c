#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/htable/htable_type.h>
#include <ccan/tal/str/str.h>
#include <common/bolt11.h>
#include <common/bolt12_merkle.h>
#include <common/gossmap.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <errno.h>
#include <plugins/renepay/failure.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/success.h>
#include <plugins/renepay/uncertainty_network.h>
#include <stdio.h>

// TODO(eduardo): maybe there are too many debug_err and plugin_err and
// plugin_log(...,LOG_BROKEN,...) that could be resolved with a command_fail

// TODO(eduardo): notice that pending attempts performed with another
// pay plugin are not considered by the uncertainty network in renepay,
// it would be nice if listsendpay would give us the route of pending
// sendpays.

#define INVALID_ID UINT64_MAX

struct pay_plugin *pay_plugin;

static void memleak_mark(struct plugin *p, struct htable *memtable)
{
	memleak_scan_obj(memtable, pay_plugin);
	memleak_scan_htable(memtable, &pay_plugin->chan_extra_map->raw);
	memleak_scan_htable(memtable, &pay_plugin->payment_map->raw);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	size_t num_channel_updates_rejected;

	tal_steal(p, pay_plugin);
	pay_plugin->plugin = p;
	pay_plugin->last_time = 0;

	rpc_scan(p, "getinfo", take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_node_id, &pay_plugin->my_id));

	rpc_scan(p, "listconfigs",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{configs:"
		 "{max-locktime-blocks:{value_int:%},"
		 "experimental-offers:{set:%}}}",
		 JSON_SCAN(json_to_number, &pay_plugin->maxdelay_default),
		 JSON_SCAN(json_to_bool, &pay_plugin->exp_offers)
		 );

	list_head_init(&pay_plugin->payments);

	pay_plugin->payment_map = tal(pay_plugin, struct payment_map);
	payment_map_init(pay_plugin->payment_map);

	pay_plugin->chan_extra_map = tal(pay_plugin,struct chan_extra_map);
	chan_extra_map_init(pay_plugin->chan_extra_map);

	pay_plugin->payflow_map = tal(pay_plugin,struct payflow_map);
	payflow_map_init(pay_plugin->payflow_map);

	pay_plugin->route_map = tal(pay_plugin,struct route_map);
	route_map_init(pay_plugin->route_map);

	pay_plugin->unetwork = unetwork_new(pay_plugin);

	pay_plugin->gossmap = gossmap_load(pay_plugin,
					   GOSSIP_STORE_FILENAME,
					   &num_channel_updates_rejected);

	if (!pay_plugin->gossmap)
		plugin_err(p, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));
	if (num_channel_updates_rejected)
		plugin_log(p, LOG_DBG,
			   "gossmap ignored %zu channel updates",
			   num_channel_updates_rejected);

	uncertainty_network_update(pay_plugin->gossmap,
				   pay_plugin->chan_extra_map);
	plugin_set_memleak_handler(p, memleak_mark);
	return NULL;
}

/* Sometimes we don't know exactly who to blame... */
static struct pf_result *handle_unhandleable_error(struct pay_flow *pf,
						   const char *what)
{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);
	size_t n = tal_count(pf);

	/* We got a mangled reply.  We don't know who to penalize! */
	payflow_note(pf, LOG_UNUSUAL, "%s on route %s",
		     what, flow_path_to_str(tmpctx, pf));

	if (n == 1)
	{
		/* This is a terminal error. */
		return pay_flow_failed_final(pf, PAY_UNPARSEABLE_ONION, what);
	}
	/* FIXME: check chan_extra_map, since we might have succeeded though
	 * this node before? */

	/* Prefer a node not directly connected to either end. */
	if (n > 3) {
		/* us ->0-> ourpeer ->1-> rando ->2-> theirpeer ->3-> dest */
		n = 1 + pseudorand(n - 2);
	} else
		/* Assume it's not the destination */
		n = pseudorand(n-1);

	payflow_disable_chan(pf, pf->path_scidds[n].scid,
			     LOG_INFORM, "randomly chosen");

	return pay_flow_failed(pf);
}

/* We hold onto the flow (and delete the timer) while we're waiting for
 * gossipd to receive the channel_update we got from the error. */
struct addgossip {
	struct short_channel_id scid;
	struct pay_flow *pf;
};

static struct command_result *addgossip_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *err,
					     struct addgossip *adg)
{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);

	/* This may free adg (pf is the parent), or otherwise it'll
	 * happen later. */
	pay_flow_finished_adding_gossip(adg->pf);

	bool gossmap_changed = gossmap_refresh(pay_plugin->gossmap, NULL);

	if (pay_plugin->gossmap == NULL)
		plugin_err(pay_plugin->plugin, "Failed to refresh gossmap: %s",
			   strerror(errno));

	if (gossmap_changed)
		uncertainty_network_update(pay_plugin->gossmap,
					   pay_plugin->chan_extra_map);

	return command_still_pending(cmd);
}

static struct command_result *addgossip_failure(struct command *cmd,
						const char *buf,
						const jsmntok_t *err,
						struct addgossip *adg)

{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);

	payflow_disable_chan(adg->pf, adg->scid,
			     LOG_INFORM, "addgossip failed (%.*s)",
			     err->end - err->start, buf + err->start);

	return addgossip_done(cmd, buf, err, adg);
}

static struct pf_result *submit_update(struct pay_flow *pf,
				       const u8 *update,
				       struct short_channel_id errscid)
{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);
	struct out_req *req;
	struct addgossip *adg = tal(pf, struct addgossip);

	/* We need to stash scid in case this fails, and we need to hold flow so
	 * we don't get a rexmit before this is complete. */
	adg->scid = errscid;
	adg->pf = pf;

	payflow_note(pf, LOG_DBG, "... extracted channel_update %s, telling gossipd", tal_hex(tmpctx, update));

	req = jsonrpc_request_start(pay_plugin->plugin, NULL, "addgossip",
				    addgossip_done,
				    addgossip_failure,
				    adg);
	json_add_hex_talarr(req->js, "message", update);
	send_outreq(pay_plugin->plugin, req);

	/* Don't retry until we call pay_flow_finished_adding_gossip! */
	return pay_flow_failed_adding_gossip(pf);
}

/* Fix up the channel_update to include the type if it doesn't currently have
 * one. See ElementsProject/lightning#1730 and lightningnetwork/lnd#1599 for the
 * in-depth discussion on why we break message parsing here... */
static u8 *patch_channel_update(const tal_t *ctx, u8 *channel_update TAKES)
{
	u8 *fixed;
	if (channel_update != NULL &&
	    fromwire_peektype(channel_update) != WIRE_CHANNEL_UPDATE) {
		/* This should be a channel_update, prefix with the
		 * WIRE_CHANNEL_UPDATE type, but isn't. Let's prefix it. */
		fixed = tal_arr(ctx, u8, 0);
		towire_u16(&fixed, WIRE_CHANNEL_UPDATE);
		towire(&fixed, channel_update, tal_bytelen(channel_update));
		if (taken(channel_update))
			tal_free(channel_update);
		return fixed;
	} else {
		return tal_dup_talarr(ctx, u8, channel_update);
	}
}


/* Return NULL if the wrapped onion error message has no channel_update field,
 * or return the embedded channel_update message otherwise. */
static u8 *channel_update_from_onion_error(const tal_t *ctx,
					   const u8 *onion_message)
{
	u8 *channel_update = NULL;
	struct amount_msat unused_msat;
	u32 unused32;

	/* Identify failcodes that have some channel_update.
	 *
	 * TODO > BOLT 1.0: Add new failcodes when updating to a
	 * new BOLT version. */
	if (!fromwire_temporary_channel_failure(ctx,
						onion_message,
						&channel_update) &&
	    !fromwire_amount_below_minimum(ctx,
					   onion_message, &unused_msat,
					   &channel_update) &&
	    !fromwire_fee_insufficient(ctx,
		    		       onion_message, &unused_msat,
				       &channel_update) &&
	    !fromwire_incorrect_cltv_expiry(ctx,
		    			    onion_message, &unused32,
					    &channel_update) &&
	    !fromwire_expiry_too_soon(ctx,
		    		      onion_message,
				      &channel_update))
		/* No channel update. */
		return NULL;

	return patch_channel_update(ctx, take(channel_update));
}

static void destroy_payment(struct payment *p)
{
	list_del_from(&pay_plugin->payments, &p->list);
	payment_map_del(pay_plugin->payment_map, p);
}

static struct command_result *json_paystatus(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *params)
{
	const char *invstring;
	struct json_stream *ret;
	struct payment *p;

	if (!param(cmd, buf, params,
		   p_opt("invstring", param_invstring, &invstring),
		   NULL))
		return command_param_failed();

	ret = jsonrpc_stream_success(cmd);
	json_array_start(ret, "paystatus");

	// FIXME search payments by payment_hash, use the map
	// use bolt11_decode
	list_for_each(&pay_plugin->payments, p, list) {
		if (invstring && !streq(invstring, p->invstr))
			continue;

		json_object_start(ret, NULL);
		if (p->label != NULL)
			json_add_string(ret, "label", p->label);

		if (p->invstr)
			json_add_invstring(ret,p->invstr);

		json_add_amount_msat(ret, "amount_msat", p->amount);
		json_add_sha256(ret, "payment_hash", &p->payment_hash);
		json_add_node_id(ret, "destination", &p->destination);

		if (p->description)
			json_add_string(ret, "description", p->description);

		json_add_timeabs(ret,"created_at",p->start_time);
		json_add_u64(ret,"groupid",p->groupid);

		switch(p->status)
		{
			case PAYMENT_SUCCESS:
				json_add_string(ret,"status","complete");
				assert(p->preimage);
				json_add_preimage(ret,"payment_preimage",p->preimage);
				json_add_amount_msat(ret, "amount_sent_msat", p->total_sent);

			break;
			case PAYMENT_FAIL:
				json_add_string(ret,"status","failed");
			break;
			default:
				json_add_string(ret,"status","pending");
		}

		json_array_start(ret, "notes");
		for (size_t i = 0; i < tal_count(p->paynotes); i++)
			json_add_string(ret, NULL, p->paynotes[i]);
		json_array_end(ret);
		json_object_end(ret);

		// TODO(eduardo): maybe we should add also:
		// - payment_secret?
		// - payment_metadata?
		// - number of parts?
	}
	json_array_end(ret);

	return command_finished(cmd, ret);
}

static struct command_result *renepay_command_finish(struct payment *payment,
						     struct command *cmd)
{
	struct json_stream *result = payment_result(payment, cmd);
	return command_finished(cmd, result);
}

static struct command_result *renepay_finish(struct payment *p)
{
	assert(!payment_commands_empty(p));
	struct command *cmd = p->cmd_array[0];
	for (size_t i = 1; i < tal_count(p->cmd_array); ++i) {
		renepay_command_finish(p, p->cmd_array[i]);
	}
	tal_resize(&p->cmd_array, 0);
	return renepay_command_finish(p, cmd);
}

struct command_result *renepay_success(struct payment *p);
struct command_result *renepay_success(struct payment *p)
{
	p->status = PAYMENT_SUCCESS;
	return renepay_finish(p);
}

static struct command_result *renepay_fail(struct payment *p)
{
	p->status = PAYMENT_FAIL;
	return renepay_finish(p);
}

void payment_retry(struct payment *p);
void payment_retry(struct payment *p)
{
	// TODO
}

static struct command_result * payment_start(struct payment *p)
{
	p->status = PAYMENT_PENDING;
	plugin_log(pay_plugin->plugin, LOG_DBG, "Starting renepay");
	struct command *cmd = payment_command(p);
	assert(p);

	// TODO: can we make a list of payment modifiers instead?
	/* We have a stack of payment modifiers, they will be executed in
	 * last-in-first-out order. */
	payment_clear_modifiers(p);
	payment_push_modifier(p, &wait_or_retry_pay_mod);
	payment_push_modifier(p, &send_routes_pay_mod);
	payment_push_modifier(p, &compute_routes_pay_mod);
	// add shadow route
	payment_push_modifier(p, &routehints_pay_mod);
	payment_push_modifier(p, &getmychannels_pay_mod);
	payment_push_modifier(p, &refreshgossmap_pay_mod);
	// add knowledge decay
	payment_push_modifier(p, &selfpay_pay_mod);
	// add check pre-approved invoice
	payment_push_modifier(p, &previous_sendpays_pay_mod);
	payment_push_modifier(p, &initial_sanity_checks_pay_mod);
	payment_continue(p);

	return command_still_pending(cmd);

	// /* FIXME: We use a linear function to decide how to decay the
	//  * channel information. Other shapes could be used.
	//  * Also the choice of the proportional parameter TIMER_FORGET_SEC is
	//  * arbitrary.
	//  * Another idea is to measure time in blockheight. */
	// const u64 now_sec = time_now().ts.tv_sec;
	// const double fraction =
	//     (now_sec - pay_plugin->last_time) * 1.0 / TIMER_FORGET_SEC;
	// uncertainty_network_relax_fraction(pay_plugin->chan_extra_map,
	// 				   fraction);
	// pay_plugin->last_time = now_sec;

	// if (!uncertainty_network_check_invariants(pay_plugin->chan_extra_map))
	// 	plugin_err(pay_plugin->plugin,
	// 		   "uncertainty network invariants are violated");
}

static struct command_result *json_pay(struct command *cmd, const char *buf,
				       const jsmntok_t *params)
{
	/* === Parse command line arguments === */

	const char *invstr;
	struct amount_msat *msat;
	struct amount_msat *maxfee;
	u32 *maxdelay;
	u32 *retryfor;
	const char *description;
	const char *label;

	// dev options
	bool *use_shadow;

	// MCF options
	u64 *base_fee_penalty_millionths; // base fee to proportional fee
	u64 *prob_cost_factor_millionths; // prob. cost to proportional fee
	u64 *riskfactor_millionths; // delay to proportional proportional fee
	u64 *min_prob_success_millionths; // target probability

	if (!param(cmd, buf, params,
		   p_req("invstring", param_invstring, &invstr),
		   p_opt("amount_msat", param_msat, &msat),
		   p_opt("maxfee", param_msat, &maxfee),

		   p_opt_def("maxdelay", param_number, &maxdelay,
			     /* maxdelay has a configuration default value named
			      * "max-locktime-blocks", this is retrieved at
			      * init. */
			     pay_plugin->maxdelay_default),

		   p_opt_def("retry_for", param_number, &retryfor,
			     60), // 60 seconds
		   p_opt("description", param_string, &description),
		   p_opt("label", param_string, &label),

		   // FIXME add support for offers
		   // p_opt("localofferid", param_sha256, &local_offer_id),

		   p_opt_dev("dev_use_shadow", param_bool, &use_shadow, true),

		   // MCF options
		   p_opt_dev("dev_base_fee_penalty", param_millionths,
			     &base_fee_penalty_millionths,
			     10000000), // default is 10.0
		   p_opt_dev("dev_prob_cost_factor", param_millionths,
			     &prob_cost_factor_millionths,
			     10000000), // default is 10.0
		   p_opt_dev("dev_riskfactor", param_millionths,
			     &riskfactor_millionths, 1), // default is 1e-6
		   p_opt_dev("dev_min_prob_success", param_millionths,
			     &min_prob_success_millionths,
			     900000), // default is 0.9
		   NULL))
		return command_param_failed();

	/* === Parse invoice === */

	// FIXME: add support for bol12 invoices
	if (bolt12_has_prefix(invstr))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "BOLT12 invoices are not yet supported.");

	char *fail;
	struct bolt11 *b11 =
	    bolt11_decode(tmpctx, invstr, plugin_feature_set(cmd->plugin),
			  description, chainparams, &fail);
	if (b11 == NULL)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Invalid bolt11: %s", fail);

	/* Sanity check */
	if (feature_offered(b11->features, OPT_VAR_ONION) &&
	    !b11->payment_secret)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Invalid bolt11:"
				    " sets feature var_onion with no secret");
	/* BOLT #11:
	 * A reader:
	 *...
	 * - MUST check that the SHA2 256-bit hash in the `h` field
	 *   exactly matches the hashed description.
	 */
	if (!b11->description) {
		if (!b11->description_hash)
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "Invalid bolt11: missing description");

		if (!description)
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "bolt11 uses description_hash, but you did "
			    "not provide description parameter");
	}

	if (b11->msat) {
		// amount is written in the invoice
		if (msat)
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "amount_msat parameter unnecessary");
		msat = b11->msat;
	} else {
		// amount is not written in the invoice
		if (!msat)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "amount_msat parameter required");
	}

	// Default max fee is 5 sats, or 0.5%, whichever is *higher*
	if (!maxfee) {
		struct amount_msat fee = amount_msat_div(*msat, 200);
		if (amount_msat_less(fee, AMOUNT_MSAT(5000)))
			fee = AMOUNT_MSAT(5000);
		maxfee = tal_dup(tmpctx, struct amount_msat, &fee);
	}

	const u64 now_sec = time_now().ts.tv_sec;
	if (now_sec > (b11->timestamp + b11->expiry))
		return command_fail(cmd, PAY_INVOICE_EXPIRED,
				    "Invoice expired");

	/* === Get payment === */

	// one payment_hash one payment is not assumed, it is enforced
	struct payment *payment =
	    payment_map_get(pay_plugin->payment_map, b11->payment_hash);

	if(!payment)
	{
		payment = payment_new(
			tmpctx,
			&b11->payment_hash,
			take(invstr),
			take(label),
			take(description),
			b11->payment_secret,
			b11->metadata,
			cast_const2(const struct route_info**, b11->routes),
			&b11->receiver_id,
			*msat,
			*maxfee,
			*maxdelay,
			*retryfor,
			b11->min_final_cltv_expiry,
			*base_fee_penalty_millionths,
			*prob_cost_factor_millionths,
			*riskfactor_millionths,
			*min_prob_success_millionths,
			use_shadow);

		if (!payment)
			return command_fail(cmd, PLUGIN_ERROR,
					    "failed to create a new payment");
		if (!payment_register_command(payment, cmd))
			return command_fail(cmd, PLUGIN_ERROR,
					    "failed to register command");

		// good to go
		payment = tal_steal(pay_plugin, payment);

		// FIXME do we really need a list here?
		list_add_tail(&pay_plugin->payments, &payment->list);
		payment_map_add(pay_plugin->payment_map, payment);

		tal_add_destructor(payment, destroy_payment);

		return payment_start(payment);
	}

	/* === Start or continue payment === */
	if (payment->status == PAYMENT_SUCCESS) {
		// this payment is already a success, we show the result
		assert(payment_commands_empty(payment));
		struct json_stream *result = payment_result(payment, cmd);
		return command_finished(cmd, result);
	}

	if (payment->status == PAYMENT_FAIL) {
		// this payment already failed, we try again
		assert(payment_commands_empty(payment));
		if (!payment_register_command(payment, cmd))
			return command_fail(cmd, PLUGIN_ERROR,
					    "failed to register command");

		/* Last time we tried the payment failed, this time we try again
		but we update the parameters. All parameters except the payment
		hash are updated, hence we are silently allowing two invoices to
		have the same payment_hash as long as the first failed. */
		if (!payment_update(payment,
				    take(invstr),
				    take(label),
				    take(description),
				    b11->payment_secret,
				    b11->metadata,
				    cast_const2(const struct route_info**, b11->routes),
				    &b11->receiver_id,
				    *msat,
				    *maxfee,
				    *maxdelay,
				    *retryfor,
				    b11->min_final_cltv_expiry,
				    *base_fee_penalty_millionths,
				    *prob_cost_factor_millionths,
				    *riskfactor_millionths,
				    *min_prob_success_millionths,
				    use_shadow))
			return command_fail(
			    cmd, PLUGIN_ERROR,
			    "failed to update the payment parameters");

		return payment_start(payment);
	}

	// else: this payment is pending we continue its execution, we merge all
	// calling cmds into a single payment request
	if (!payment_register_command(payment, cmd))
		return command_fail(cmd, PLUGIN_ERROR,
				    "failed to register command");
	return command_still_pending(cmd);
}

/* Terminates flow */
static struct pf_result *handle_sendpay_failure_payment(struct pay_flow *pf STEALS,
							const char *message,
							u32 erridx,
							enum onion_wire onionerr,
							const u8 *raw)
{
	struct short_channel_id errscid;
	const u8 *update;

	assert(pf);

	/* Final node is usually a hard failure */
	if (erridx == tal_count(pf->path_scidds)) {
		if (onionerr == WIRE_MPP_TIMEOUT) {
			return pay_flow_failed(pf);
		}

		payflow_note(pf, LOG_INFORM,
			     "final destination permanent failure");
		return pay_flow_failed_final(pf, PAY_DESTINATION_PERM_FAIL, message);
	}

	errscid = pf->path_scidds[erridx].scid;
	switch (onionerr) {
	/* These definitely mean eliminate channel */
	case WIRE_PERMANENT_CHANNEL_FAILURE:
	case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
	/* FIXME: lnd returns this for disconnected peer, so don't disable perm! */
	case WIRE_UNKNOWN_NEXT_PEER:
	case WIRE_CHANNEL_DISABLED:
	/* These mean node is weird, but we eliminate channel here too */
	case WIRE_INVALID_REALM:
	case WIRE_TEMPORARY_NODE_FAILURE:
	case WIRE_PERMANENT_NODE_FAILURE:
	case WIRE_REQUIRED_NODE_FEATURE_MISSING:
	/* These shouldn't happen, but eliminate channel */
	case WIRE_INVALID_ONION_VERSION:
	case WIRE_INVALID_ONION_HMAC:
	case WIRE_INVALID_ONION_KEY:
	case WIRE_INVALID_ONION_PAYLOAD:
	case WIRE_INVALID_ONION_BLINDING:
	case WIRE_EXPIRY_TOO_FAR:
		payflow_disable_chan(pf, errscid, LOG_UNUSUAL,
				     "%s",
				     onion_wire_name(onionerr));
		return pay_flow_failed(pf);

	/* These can be fixed (maybe) by applying the included channel_update */
	case WIRE_AMOUNT_BELOW_MINIMUM:
	case WIRE_FEE_INSUFFICIENT:
	case WIRE_INCORRECT_CLTV_EXPIRY:
	case WIRE_EXPIRY_TOO_SOON:
		plugin_log(pay_plugin->plugin,LOG_DBG,"sendpay_failure, apply channel_update");
		/* FIXME: Check scid! */
		// TODO(eduardo): check
		update = channel_update_from_onion_error(tmpctx, raw);
		if (update)
			return submit_update(pf, update, errscid);

		payflow_disable_chan(pf, errscid,
				     LOG_UNUSUAL, "missing channel_update");
		return pay_flow_failed(pf);

	case WIRE_TEMPORARY_CHANNEL_FAILURE:
		/* These also contain a channel_update, but in this case it's simply
		 * advisory, not necessary. */
		update = channel_update_from_onion_error(tmpctx, raw);
		if (update)
			return submit_update(pf, update, errscid);

		return pay_flow_failed(pf);

	/* These should only come from the final distination. */
	case WIRE_MPP_TIMEOUT:
	case WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
		break;
	}

	payflow_disable_chan(pf, errscid,
			     LOG_UNUSUAL, "unexpected error code %u",
			     onionerr);
	return pay_flow_failed(pf);
}

static void handle_sendpay_failure_flow(struct pay_flow *pf,
					const char *msg,
					u32 erridx,
					u32 onionerr)
{
	assert(pf);

	/* we know that all channels before erridx where able to commit to this payment */
	uncertainty_network_channel_can_send(
			pay_plugin->chan_extra_map,
			pf,
			erridx);

	/* Insufficient funds (not from final, that's weird!) */
	if((enum onion_wire)onionerr == WIRE_TEMPORARY_CHANNEL_FAILURE
	   && erridx < tal_count(pf->path_scidds))
	{
		const char *old_state =
		    fmt_chan_extra_details(tmpctx, pay_plugin->chan_extra_map,
					   &pf->path_scidds[erridx]);

		char *fail;
		if (!chan_extra_cannot_send(tmpctx, pay_plugin->chan_extra_map,
					    &pf->path_scidds[erridx],
					    &fail)) {
			plugin_err(pay_plugin->plugin,
				   "chan_extra_cannot_send failed: %s", fail);
		}

		payflow_note(pf, LOG_INFORM,
			     "Failure to forward amount %s in channel %s, "
			     "state change %s -> %s",
			     fmt_amount_msat(tmpctx, pf->amounts[erridx]),
			     fmt_short_channel_id_dir(tmpctx,
						      &pf->path_scidds[erridx]),
			     old_state,
			     fmt_chan_extra_details(tmpctx,
						    pay_plugin->chan_extra_map,
						    &pf->path_scidds[erridx]));
	}
}

struct pf_result *sendpay_failure(struct pay_flow *pf,
				  enum jsonrpc_errcode errcode, const char *buf,
				  const jsmntok_t *sub);
/* Dummy return ensures all paths call pay_flow_* to close flow! */
struct pf_result *sendpay_failure(struct pay_flow *pf,
				  enum jsonrpc_errcode errcode, const char *buf,
				  const jsmntok_t *sub)
{
	const char *msg, *err;
	u32 erridx, onionerr;
	const u8 *raw;

	/* Only one code is really actionable */
	switch (errcode) {
	case PAY_UNPARSEABLE_ONION:
		return handle_unhandleable_error(pf, "Unparsable onion reply");

	case PAY_TRY_OTHER_ROUTE:
		break;
	case PAY_DESTINATION_PERM_FAIL:
		break;
	default:
		return pay_flow_failed_final(pf,
					     errcode,
					     "Unexpected errorcode from sendpay_failure");
	}

	/* Extract remaining fields for feedback */
	raw = NULL;
 	err = json_scan(tmpctx, buf, sub,
			"{message:%"
			",data:{erring_index:%"
			",failcode:%"
			",raw_message?:%}}",
			JSON_SCAN_TAL(tmpctx, json_strdup, &msg),
			JSON_SCAN(json_to_u32, &erridx),
			JSON_SCAN(json_to_u32, &onionerr),
			JSON_SCAN_TAL(tmpctx, json_tok_bin_from_hex, &raw));
	if (err)
		return handle_unhandleable_error(pf, err);

	/* Answer must be sane: but note, erridx can be final node! */
	if (erridx > tal_count(pf->path_scidds)) {
		plugin_err(pay_plugin->plugin,
			   "Erring channel %u/%zu in path %s",
			   erridx, tal_count(pf->path_scidds),
			   flow_path_to_str(tmpctx, pf));
	}

	payflow_note(pf, LOG_INFORM, "Failed at node #%u (%s): %s",
		     erridx, onion_wire_name(onionerr), msg);
	handle_sendpay_failure_flow(pf, msg, erridx, onionerr);

	return handle_sendpay_failure_payment(pf, msg, erridx, onionerr, raw);
}

static const struct plugin_command commands[] = {
	{
		"renepaystatus",
		"payment",
		"Detail status of attempts to pay {bolt11}, or all",
		"Covers both old payments and current ones.",
		json_paystatus
	},
	{
		"renepay",
		"payment",
		"Send payment specified by {invstring}",
		"Attempt to pay an invoice.",
		json_pay
	},
};

static const struct plugin_notification notifications[] = {
	{
		"sendpay_success",
		notification_sendpay_success,
	},
	{
		"sendpay_failure",
		notification_sendpay_failure,
	}
};

int main(int argc, char *argv[])
{
	setup_locale();

	/* Most gets initialized in init(), but set debug options here. */
	pay_plugin = tal(NULL, struct pay_plugin);
	pay_plugin->debug_mcf = pay_plugin->debug_payflow = false;

	plugin_main(
		argv,
		init,
		PLUGIN_RESTARTABLE,
		/* init_rpc */ true,
		/* features */ NULL,
		commands, ARRAY_SIZE(commands),
		notifications, ARRAY_SIZE(notifications),
		/* hooks */ NULL, 0,
		/* notification topics */ NULL, 0,
		plugin_option("renepay-debug-mcf", "flag",
			"Enable renepay MCF debug info.",
			flag_option, &pay_plugin->debug_mcf),
		plugin_option("renepay-debug-payflow", "flag",
			"Enable renepay payment flows debug info.",
			flag_option, &pay_plugin->debug_payflow),
		NULL);

	return 0;
}
