#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/htable/htable_type.h>
#include <ccan/tal/str/str.h>
#include <common/bolt11.h>
#include <common/bolt12_merkle.h>
#include <common/gossmap.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/type_to_string.h>
#include <errno.h>
#include <plugins/renepay/debug.h>
#include <plugins/renepay/pay.h>
#include <plugins/renepay/pay_flow.h>
#include <plugins/renepay/uncertainty_network.h>

// TODO(eduardo): maybe there are too many debug_err and plugin_err and
// plugin_log(...,LOG_BROKEN,...) that could be resolved with a command_fail

// TODO(eduardo): notice that pending attempts performed with another
// pay plugin are not considered by the uncertainty network in renepay,
// it would be nice if listsendpay would give us the route of pending
// sendpays.

#define INVALID_ID UINT64_MAX
#define MAX(a,b) ((a)>(b)? (a) : (b))
#define MIN(a,b) ((a)<(b)? (a) : (b))

struct pay_plugin *pay_plugin;

static void timer_kick(struct payment *payment);
static struct command_result *try_paying(struct command *cmd,
					 struct payment *payment);

void amount_msat_accumulate_(struct amount_msat *dst,
			     struct amount_msat src,
			     const char *dstname,
			     const char *srcname)
{
	if (amount_msat_add(dst, *dst, src))
		return;
	debug_err("Overflow adding %s (%s) into %s (%s)",
		   srcname, type_to_string(tmpctx, struct amount_msat, &src),
		   dstname, type_to_string(tmpctx, struct amount_msat, dst));
}

void amount_msat_reduce_(struct amount_msat *dst,
			 struct amount_msat src,
			 const char *dstname,
			 const char *srcname)
{
	if (amount_msat_sub(dst, *dst, src))
		return;
	debug_err("Underflow subtracting %s (%s) from %s (%s)",
		   srcname, type_to_string(tmpctx, struct amount_msat, &src),
		   dstname, type_to_string(tmpctx, struct amount_msat, dst));
}


#if DEVELOPER
static void memleak_mark(struct plugin *p, struct htable *memtable)
{
	memleak_scan_obj(memtable, pay_plugin);
	memleak_scan_htable(memtable, &pay_plugin->chan_extra_map->raw);
}
#endif

static void destroy_payflow(struct pay_flow *flow)
{
	remove_htlc_payflow(pay_plugin->chan_extra_map,flow);
	payflow_map_del(pay_plugin->payflow_map, flow);
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

	pay_plugin->chan_extra_map = tal(pay_plugin,struct chan_extra_map);
	chan_extra_map_init(pay_plugin->chan_extra_map);

	pay_plugin->payflow_map = tal(pay_plugin,struct payflow_map);
	payflow_map_init(pay_plugin->payflow_map);

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
#if DEVELOPER
	plugin_set_memleak_handler(p, memleak_mark);
#endif
	return NULL;
}


static void payment_settimer(struct payment *payment)
{
	payment->rexmit_timer = tal_free(payment->rexmit_timer);
	payment->rexmit_timer = plugin_timer(
			pay_plugin->plugin,
			time_from_msec(TIMER_COLLECT_FAILURES_MSEC),
			timer_kick, payment);
}

/* Happens when timer goes off, but also works to arm timer if nothing to do */
static void timer_kick(struct payment *payment)
{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);

	switch (payment->status)
	{
		/* Some flows succeeded, we finish the payment. */
		case PAYMENT_SUCCESS:
			plugin_log(pay_plugin->plugin,LOG_DBG,"status is PAYMENT_SUCCESS");
			payment_success(payment);
		break;

		/* Some flows failed, we retry. */
		case PAYMENT_FAIL:
			plugin_log(pay_plugin->plugin,LOG_DBG,"status is PAYMENT_FAIL");
			payment_assert_delivering_incomplete(payment);
			try_paying(payment->cmd, payment);
		break;

		/* Nothing has returned yet, we have to wait. */
		case PAYMENT_PENDING:
			plugin_log(pay_plugin->plugin,LOG_DBG,"status is PAYMENT_PENDING");
			payment_assert_delivering_all(payment);
			payment_settimer(payment);
		break;
	}
}

/* Sometimes we don't know exactly who to blame... */
static void handle_unhandleable_error(struct pay_flow *flow,
				      const char *what)
{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);
	size_t n = tal_count(flow);

	/* We got a mangled reply.  We don't know who to penalize! */
	debug_paynote(flow->payment, "%s on route %s", what, flow_path_to_str(tmpctx, flow));

	// TODO(eduardo): does LOG_BROKEN finish the plugin execution?
	plugin_log(pay_plugin->plugin, LOG_BROKEN,
		   "%s on route %s",
		   what, flow_path_to_str(tmpctx, flow));

	if (n == 1)
	{
		payflow_fail(flow);
		payment_fail(flow->payment, PAY_UNPARSEABLE_ONION,
			     "Got %s from the destination", what);
		return;
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

	tal_arr_expand(&flow->payment->disabled, flow->path_scids[n]);
	debug_paynote(flow->payment, "... eliminated %s",
		type_to_string(tmpctx, struct short_channel_id,
			       &flow->path_scids[n]));
}

/* We hold onto the flow (and delete the timer) while we're waiting for
 * gossipd to receive the channel_update we got from the error. */
struct addgossip {
	struct short_channel_id scid;
	struct pay_flow *flow;
};

static struct command_result *addgossip_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *err,
					     struct addgossip *adg)
{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);
	struct payment * payment = adg->flow->payment;

	/* Release this: if it's the last flow we'll retry immediately */

	payflow_fail(adg->flow);
	tal_free(adg);
	payment_settimer(payment);

	return command_still_pending(cmd);
}

static struct command_result *addgossip_failure(struct command *cmd,
						const char *buf,
						const jsmntok_t *err,
						struct addgossip *adg)

{
	struct payment * payment = adg->flow->payment;
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);

	debug_paynote(payment, "addgossip failed, removing channel %s (%.*s)",
		type_to_string(tmpctx, struct short_channel_id, &adg->scid),
		err->end - err->start, buf + err->start);
	tal_arr_expand(&payment->disabled, adg->scid);

	return addgossip_done(cmd, buf, err, adg);
}

static struct command_result *submit_update(struct pay_flow *flow,
					    const u8 *update,
					    struct short_channel_id errscid)
{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);
	struct payment *payment = flow->payment;
	struct out_req *req;
	struct addgossip *adg = tal(flow, struct addgossip);

	/* We need to stash scid in case this fails, and we need to hold flow so
	 * we don't get a rexmit before this is complete. */
	adg->scid = errscid;
	adg->flow = flow;
	/* Disable re-xmit until this returns */
	payment->rexmit_timer = tal_free(payment->rexmit_timer);

	debug_paynote(payment, "... extracted channel_update, telling gossipd");
	plugin_log(pay_plugin->plugin, LOG_DBG, "(update = %s)", tal_hex(tmpctx, update));

	req = jsonrpc_request_start(pay_plugin->plugin, NULL, "addgossip",
				    addgossip_done,
				    addgossip_failure,
				    adg);
	json_add_hex_talarr(req->js, "message", update);
	return send_outreq(pay_plugin->plugin, req);
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

/* Once we've sent it, we immediate wait for reply. */
static struct command_result *flow_sent(struct command *cmd,
					const char *buf,
					const jsmntok_t *result,
					struct pay_flow *flow)
{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);
	return command_still_pending(cmd);
}

/* sendpay really only fails immediately in two ways:
 * 1. We screwed up and misused the API.
 * 2. The first peer is disconnected.
 */
static struct command_result *flow_sendpay_failed(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *err,
						  struct pay_flow *flow)
{
	struct payment *payment = flow->payment;
	enum jsonrpc_errcode errcode;
	const char *msg;

	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);

	debug_assert(payment);

	/* This is a fail. */
	if (payment->status != PAYMENT_SUCCESS)
		payment->status=PAYMENT_FAIL;

	if (json_scan(tmpctx, buf, err,
		      "{code:%,message:%}",
		      JSON_SCAN(json_to_jsonrpc_errcode, &errcode),
		      JSON_SCAN_TAL(tmpctx, json_strdup, &msg))) {
		plugin_err(cmd->plugin, "Bad fail from sendpay: %.*s",
			   json_tok_full_len(err), json_tok_full(buf, err));
	}
	if (errcode != PAY_TRY_OTHER_ROUTE)
		plugin_err(cmd->plugin, "Strange error from sendpay: %.*s",
			   json_tok_full_len(err), json_tok_full(buf, err));

	debug_paynote(payment,
		      "sendpay didn't like first hop, eliminated: %s", msg)

	/* There is no new knowledge from this kind of failure.
	 * We just disable this scid. */
	tal_arr_expand(&payment->disabled, flow->path_scids[0]);

	payflow_fail(flow);
	return command_still_pending(cmd);
}


static struct command_result *
sendpay_flows(struct command *cmd,
	      struct payment *p,
	      struct pay_flow **flows STEALS)
{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);
	debug_paynote(p, "Sending out batch of %zu payments", tal_count(flows));

	for (size_t i = 0; i < tal_count(flows); i++) {
		const size_t path_lengh = tal_count(flows[i]->amounts);
		debug_paynote(p, "sendpay flow groupid=%ld, partid=%ld, delivering=%s, probability=%.3lf",
			      flows[i]->key.groupid,
			      flows[i]->key.partid,
			      type_to_string(tmpctx,struct amount_msat,
				&flows[i]->amounts[path_lengh-1]),
			      flows[i]->success_prob);
		struct out_req *req;
		req = jsonrpc_request_start(cmd->plugin, cmd, "sendpay",
					    flow_sent, flow_sendpay_failed,
					    flows[i]);

		json_array_start(req->js, "route");
		for (size_t j = 0; j < tal_count(flows[i]->path_nodes); j++) {
			json_object_start(req->js, NULL);
			json_add_node_id(req->js, "id",
					 &flows[i]->path_nodes[j]);
			json_add_short_channel_id(req->js, "channel",
						  &flows[i]->path_scids[j]);
			json_add_amount_msat(req->js, "amount_msat",
						  flows[i]->amounts[j]);
			json_add_num(req->js, "direction",
						  flows[i]->path_dirs[j]);
			json_add_u32(req->js, "delay",
				     flows[i]->cltv_delays[j]);
			json_add_string(req->js,"style","tlv");
			json_object_end(req->js);
		}
		json_array_end(req->js);

		json_add_sha256(req->js, "payment_hash", &p->payment_hash);
		json_add_secret(req->js, "payment_secret", p->payment_secret);

		json_add_amount_msat(req->js, "amount_msat", p->amount);

		json_add_u64(req->js, "partid", flows[i]->key.partid);

		json_add_u64(req->js, "groupid", p->groupid);
		if (p->payment_metadata)
			json_add_hex_talarr(req->js, "payment_metadata",
					    p->payment_metadata);

		/* FIXME: We don't need these three for all payments! */
		if (p->label)
			json_add_string(req->js, "label", p->label);
		json_add_string(req->js, "bolt11", p->invstr);
		if (p->description)
			json_add_string(req->js, "description", p->description);

		amount_msat_accumulate(&p->total_sent, flows[i]->amounts[0]);
		amount_msat_accumulate(&p->total_delivering,
				       payflow_delivered(flows[i]));

		/* Flow now owned by all_flows instead of req., in this way we
		 * can control the destruction occurs before we remove temporary
		 * channels from chan_extra_map. */
		tal_steal(pay_plugin,flows[i]);

		/* Let's keep record of this flow. */
		payflow_map_add(pay_plugin->payflow_map,flows[i]);

		/* record these HTLC along the flow path */
		commit_htlc_payflow(pay_plugin->chan_extra_map,flows[i]);

		/* Remove the HTLC from the chan_extra_map after finish. */
		tal_add_destructor(flows[i], destroy_payflow);

		send_outreq(cmd->plugin, req);
	}

	/* Safety check. */
	payment_assert_delivering_all(p);

	tal_free(flows);

	/* Get ready to process replies */
	payment_settimer(p);

	return command_still_pending(cmd);
}

static struct command_result *try_paying(struct command *cmd,
					 struct payment *payment)
{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);

	struct amount_msat feebudget, fees_spent, remaining;

	payment->status = PAYMENT_PENDING;
	if (time_after(time_now(), payment->stop_time))
		return payment_fail(payment, PAY_STOPPED_RETRYING, "Timed out");

	/* Total feebudget  */
	if (!amount_msat_sub(&feebudget, payment->maxspend, payment->amount))
	{
		plugin_err(pay_plugin->plugin,
			   "%s (line %d) could not substract maxspend=%s and amount=%s.",
			   __PRETTY_FUNCTION__,
			   __LINE__,
			   type_to_string(tmpctx, struct amount_msat, &payment->maxspend),
			   type_to_string(tmpctx, struct amount_msat, &payment->amount));
	}

	/* Fees spent so far */
	if (!amount_msat_sub(&fees_spent, payment->total_sent, payment->total_delivering))
	{
		plugin_err(pay_plugin->plugin,
			   "%s (line %d) could not substract total_sent=%s and total_delivering=%s.",
			   __PRETTY_FUNCTION__,
			   __LINE__,
			   type_to_string(tmpctx, struct amount_msat, &payment->total_sent),
			   type_to_string(tmpctx, struct amount_msat, &payment->total_delivering));
	}

	/* Remaining fee budget. */
	if (!amount_msat_sub(&feebudget, feebudget, fees_spent))
	{
		plugin_err(pay_plugin->plugin,
			   "%s (line %d) could not substract feebudget=%s and fees_spent=%s.",
			   __PRETTY_FUNCTION__,
			   __LINE__,
			   type_to_string(tmpctx, struct amount_msat, &feebudget),
			   type_to_string(tmpctx, struct amount_msat, &fees_spent));
	}

	/* How much are we still trying to send? */
	if (!amount_msat_sub(&remaining, payment->amount, payment->total_delivering))
	{
		plugin_err(pay_plugin->plugin,
			   "%s (line %d) could not substract amount=%s and total_delivering=%s.",
			   __PRETTY_FUNCTION__,
			   __LINE__,
			   type_to_string(tmpctx, struct amount_msat, &payment->amount),
			   type_to_string(tmpctx, struct amount_msat, &payment->total_delivering));
	}

	// plugin_log(pay_plugin->plugin,LOG_DBG,fmt_chan_extra_map(tmpctx,pay_plugin->chan_extra_map));

	const char *err_msg;

	/* We let this return an unlikely path, as it's better to try once
	 * than simply refuse.  Plus, models are not truth! */
	gossmap_apply_localmods(pay_plugin->gossmap, payment->local_gossmods);
	struct pay_flow **pay_flows = get_payflows(
						payment,
						remaining, feebudget,
				 		/* is entire payment? */
						amount_msat_eq(payment->total_delivering, AMOUNT_MSAT(0)),

						&err_msg);
	gossmap_remove_localmods(pay_plugin->gossmap, payment->local_gossmods);

	// plugin_log(pay_plugin->plugin,LOG_DBG,"get_payflows produced %s",fmt_payflows(tmpctx,pay_flows));

	/* MCF cannot find a feasible route, we stop. */
	if (!pay_flows)
	{
		return payment_fail(payment, PAY_ROUTE_NOT_FOUND,
				    "Failed to find a route, %s",
				    err_msg);
	}
	/* Now begin making payments */

	return sendpay_flows(cmd, payment, pay_flows);
}

static void destroy_cmd_payment_ptr(struct command *cmd,
				    struct payment *payment)
{
	assert(payment->cmd == cmd);
	payment->cmd = NULL;
}

static struct command_result *listpeerchannels_done(
		struct command *cmd,
		const char *buf,
		const jsmntok_t *result,
		struct payment *payment)
{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);
	if (!uncertainty_network_update_from_listpeerchannels(
			pay_plugin->chan_extra_map,
			pay_plugin->my_id,
			payment,
			buf,
			result))
		return command_fail(cmd, LIGHTNINGD,
				    "listpeerchannels malformed: %.*s",
				    json_tok_full_len(result),
				    json_tok_full(buf, result));
	// TODO(eduardo): check that there won't be a prob. cost associated with
	// any gossmap local chan. The same way there aren't fees to pay for my
	// local channels.

	/* From now on, we keep a record of the payment, so persist it beyond this cmd. */
	tal_steal(pay_plugin->plugin, payment);
	/* When we terminate cmd for any reason, clear it from payment so we don't do it again. */
	tal_add_destructor2(cmd, destroy_cmd_payment_ptr, payment);

	return try_paying(cmd, payment);
}


static void destroy_payment(struct payment *p)
{
	list_del_from(&pay_plugin->payments, &p->list);
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
				debug_assert(p->preimage);
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


/* Taken from ./plugins/pay.c
 *
 * We are interested in any prior attempts to pay this payment_hash /
 * invoice so we can set the `groupid` correctly and ensure we don't
 * already have a pending payment running. We also collect the summary
 * about an eventual previous complete payment so we can return that
 * as a no-op. */
static struct command_result *
payment_listsendpays_previous(
		struct command *cmd,
		const char *buf,
		const jsmntok_t *result,
		struct payment * payment)
{
	debug_info("calling %s",__PRETTY_FUNCTION__);

	size_t i;
	const jsmntok_t *t, *arr;

	/* Group ID of the pending payment, this will be the one
	 * who's result gets replayed if we end up suspending. */
	u64 pending_group_id = INVALID_ID;
	u64 max_pending_partid=0;
	u64 max_group_id = 0;
	struct amount_msat pending_sent = AMOUNT_MSAT(0),
			   pending_msat = AMOUNT_MSAT(0);

	/* Metadata for a complete payment, if one exists. */
	u32 complete_parts = 0;
	struct preimage complete_preimage;
	struct amount_msat complete_sent = AMOUNT_MSAT(0),
			   complete_msat = AMOUNT_MSAT(0);
	u32 complete_created_at;

	arr = json_get_member(buf, result, "payments");
	if (!arr || arr->type != JSMN_ARRAY)
		return command_fail(
		    cmd, LIGHTNINGD,
		    "Unexpected non-array result from listsendpays: %.*s",
		    json_tok_full_len(result),
		    json_tok_full(buf, result));

	json_for_each_arr(i, t, arr)
	{
		u64 partid, groupid;
		struct amount_msat this_msat, this_sent;
		const char *status;

		// TODO(eduardo): assuming amount_msat is always known.
		json_scan(tmpctx,buf,t,
			  "{status:%"
			  ",partid:%"
			  ",groupid:%"
			  ",amount_msat:%"
			  ",amount_sent_msat:%}",
			  JSON_SCAN_TAL(tmpctx, json_strdup, &status),
			  JSON_SCAN(json_to_u64,&partid),
			  JSON_SCAN(json_to_u64,&groupid),
			  JSON_SCAN(json_to_msat,&this_msat),
			  JSON_SCAN(json_to_msat,&this_sent));

		/* If we decide to create a new group, we base it on max_group_id */
		if (groupid > max_group_id)
			max_group_id = 1;

		/* status could be completed, pending or failed */
		if (streq(status, "complete")) {
			/* Now we know the payment completed. */
			if(!amount_msat_add(&complete_msat,complete_msat,this_msat))
				debug_err("%s (line %d) msat overflow.",
					__PRETTY_FUNCTION__,__LINE__);
			if(!amount_msat_add(&complete_sent,complete_sent,this_sent))
				debug_err("%s (line %d) msat overflow.",
					__PRETTY_FUNCTION__,__LINE__);
			json_scan(tmpctx, buf, t,
				  "{created_at:%"
				  ",payment_preimage:%}",
				  JSON_SCAN(json_to_u32, &complete_created_at),
				  JSON_SCAN(json_to_preimage, &complete_preimage));
			complete_parts++;
		} else if (streq(status, "pending")) {
			/* If we have more than one pending group, something went wrong! */
			if (pending_group_id != INVALID_ID
			    && groupid != pending_group_id)
				return command_fail(cmd, PAY_STATUS_UNEXPECTED,
						    "Multiple pending groups for this payment?");
			pending_group_id = groupid;
			if (partid > max_pending_partid)
				max_pending_partid = partid;
		} else
			assert(streq(status, "failed"));
	}

	if (complete_parts != 0) {
		/* There are completed sendpays, we don't need to do anything
		 * but summarize the result. */
		struct json_stream *ret = jsonrpc_stream_success(cmd);
		json_add_preimage(ret, "payment_preimage", &complete_preimage);
		json_add_string(ret, "status", "complete");
		json_add_amount_msat(ret, "amount_msat", complete_msat);
		json_add_amount_msat(ret, "amount_sent_msat",complete_sent);
		json_add_node_id(ret, "destination", &payment->destination);
		json_add_sha256(ret, "payment_hash", &payment->payment_hash);
		json_add_u32(ret, "created_at", complete_created_at);
		json_add_num(ret, "parts", complete_parts);

		/* This payment was already completed, we don't keep record of
		 * it twice: payment will be freed with cmd */
		return command_finished(cmd, ret);
	} else if (pending_group_id != INVALID_ID) {
		/* Continue where we left off? */
		payment->groupid = pending_group_id;
		payment->next_partid = max_pending_partid+1;

		payment->total_sent = pending_sent;
		payment->total_delivering = pending_msat;

		plugin_log(pay_plugin->plugin,LOG_DBG,
			   "There are pending sendpays to this invoice. "
			   "groupid = %"PRIu64" "
			   "delivering = %s, "
			   "last_partid = %"PRIu64,
			   pending_group_id,
			   type_to_string(tmpctx,struct amount_msat,&payment->total_delivering),
			   max_pending_partid);

		if(amount_msat_greater_eq(payment->total_delivering,payment->amount))
		{
			/* Pending payment already pays the full amount, we
			 * better stop. */
			return command_fail(cmd, PAY_IN_PROGRESS,
					    "Payment is pending with full amount already commited");
		}
	}else
	{
		/* There are no pending nor completed sendpays, get me the last
		 * sendpay group. */
		/* FIXME: use groupid 0 to have sendpay assign an unused groupid,
		 * as this is theoretically racy against other plugins paying the
		 * same thing!
		 * *BUT* that means we have to create one flow first, so we
		 * can match the others. */
		payment->groupid = max_group_id + 1;
		payment->next_partid=1;
	}


	struct out_req *req;
	/* Get local capacities... */
	req = jsonrpc_request_start(cmd->plugin, cmd, "listpeerchannels",
				    listpeerchannels_done,
				    listpeerchannels_done, payment);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *json_pay(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *params)
{
	const char *invstr;
	const char *label;
	const char *description;
	struct sha256 * local_offer_id;
 	u64 invexpiry;
 	struct amount_msat *msat, *invmsat;
	struct amount_msat *maxfee;
	struct sha256 payment_hash;
	struct secret *payment_secret;
	const u8 *payment_metadata;
	struct node_id destination;
	u32 *maxdelay;
	u32 *retryfor;
	u64 *base_fee_penalty;
	u64 *prob_cost_factor;
	u64 *riskfactor_millionths;
	u64 *min_prob_success_millionths;
	bool *use_shadow;
	u16 final_cltv;
	const struct route_info **routes = NULL;

	if (!param(cmd, buf, params,
		   p_req("invstring", param_invstring, &invstr),
 		   p_opt("amount_msat", param_msat, &msat),
 		   p_opt("maxfee", param_msat, &maxfee),

		   p_opt_def("maxdelay", param_number, &maxdelay,
			     /* We're initially called to probe usage, before init! */
			     pay_plugin ? pay_plugin->maxdelay_default : 0),


 		   p_opt_def("retry_for", param_number, &retryfor, 60), // 60 seconds
 		   p_opt("localofferid", param_sha256, &local_offer_id),
 		   p_opt("description", param_string, &description),
 		   p_opt("label", param_string, &label),
#if DEVELOPER
		   // MCF parameters
		   // TODO(eduardo): are these parameters read correctly?
		   p_opt_def("base_fee_penalty", param_millionths, &base_fee_penalty,10),
 		   p_opt_def("prob_cost_factor", param_millionths, &prob_cost_factor,10),
		   p_opt_def("riskfactor", param_millionths,&riskfactor_millionths,1),
		   p_opt_def("min_prob_success", param_millionths,
		   	&min_prob_success_millionths,900000),// default is 90%
		   p_opt_def("use_shadow", param_bool, &use_shadow, true),
#endif
		   NULL))
		return command_param_failed();

	/* We might need to parse invstring to get amount */
	if (!bolt12_has_prefix(invstr)) {
		struct bolt11 *b11;
		char *fail;

		b11 =
		    bolt11_decode(tmpctx, invstr, plugin_feature_set(cmd->plugin),
				  description, chainparams, &fail);
		if (b11 == NULL)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Invalid bolt11: %s", fail);

		invmsat = b11->msat;
		invexpiry = b11->timestamp + b11->expiry;

		destination = b11->receiver_id;
		payment_hash = b11->payment_hash;
		payment_secret =
			tal_dup_or_null(cmd, struct secret, b11->payment_secret);
		if (b11->metadata)
			payment_metadata = tal_dup_talarr(cmd, u8, b11->metadata);
		else
			payment_metadata = NULL;


		final_cltv = b11->min_final_cltv_expiry;
		/* Sanity check */
		if (feature_offered(b11->features, OPT_VAR_ONION) &&
		    !b11->payment_secret)
			return command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "Invalid bolt11:"
			    " sets feature var_onion with no secret");
		/* BOLT #11:
		 * A reader:
		 *...
		 * - MUST check that the SHA2 256-bit hash in the `h` field
		 *   exactly matches the hashed description.
		 */
		if (!b11->description) {
			if (!b11->description_hash) {
				return command_fail(cmd,
						    JSONRPC2_INVALID_PARAMS,
						    "Invalid bolt11: missing description");
			}
			if (!description)
				return command_fail(cmd,
						    JSONRPC2_INVALID_PARAMS,
						    "bolt11 uses description_hash, but you did not provide description parameter");
		}

		routes = cast_const2(const struct route_info **,
				     b11->routes);
	} else {
		// TODO(eduardo): check this, compare with `pay`
		const struct tlv_invoice *b12;
		char *fail;
		b12 = invoice_decode(tmpctx, invstr, strlen(invstr),
				     plugin_feature_set(cmd->plugin),
				     chainparams, &fail);
		if (b12 == NULL)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Invalid bolt12: %s", fail);
		if (!pay_plugin->exp_offers)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "experimental-offers disabled");

		if (!b12->offer_node_id)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "invoice missing offer_node_id");
		if (!b12->invoice_payment_hash)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "invoice missing payment_hash");
		if (!b12->invoice_created_at)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "invoice missing created_at");
		if (b12->invoice_amount) {
			invmsat = tal(cmd, struct amount_msat);
			*invmsat = amount_msat(*b12->invoice_amount);
		} else
			invmsat = NULL;

		node_id_from_pubkey(&destination, b12->offer_node_id);
		payment_hash = *b12->invoice_payment_hash;
		if (b12->invreq_recurrence_counter && !label)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "recurring invoice requires a label");
		/* FIXME payment_secret should be signature! */
		{
			struct sha256 merkle;

			payment_secret = tal(cmd, struct secret);
			merkle_tlv(b12->fields, &merkle);
			memcpy(payment_secret, &merkle, sizeof(merkle));
			BUILD_ASSERT(sizeof(*payment_secret) ==
				     sizeof(merkle));
		}
		payment_metadata = NULL;
		/* FIXME: blinded paths! */
		final_cltv = 18;
		/* BOLT-offers #12:
		 * - if `relative_expiry` is present:
		 *   - MUST reject the invoice if the current time since
		 *     1970-01-01 UTC is greater than `created_at` plus
		 *     `seconds_from_creation`.
		 * - otherwise:
		 *   - MUST reject the invoice if the current time since
		 *     1970-01-01 UTC is greater than `created_at` plus
		 * 7200.
		 */
		if (b12->invoice_relative_expiry)
			invexpiry = *b12->invoice_created_at + *b12->invoice_relative_expiry;
		else
			invexpiry = *b12->invoice_created_at + BOLT12_DEFAULT_REL_EXPIRY;
	}

	if (node_id_eq(&pay_plugin->my_id, &destination))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "This payment is destined for ourselves. "
				    "Self-payments are not supported");

	// set the payment amount
	if (invmsat) {
		// amount is written in the invoice
		if (msat) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "amount_msat parameter unnecessary");
		}
		msat = invmsat;
	} else {
		// amount is not written in the invoice
		if (!msat) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "amount_msat parameter required");
		}
	}

	/* Default max fee is 5 sats, or 0.5%, whichever is *higher* */
	if (!maxfee) {
		struct amount_msat fee = amount_msat_div(*msat, 200);
		if (amount_msat_less(fee, AMOUNT_MSAT(5000)))
			fee = AMOUNT_MSAT(5000);
		maxfee = tal_dup(tmpctx, struct amount_msat, &fee);
	}

	const u64 now_sec = time_now().ts.tv_sec;
	if (now_sec > invexpiry)
		return command_fail(cmd, PAY_INVOICE_EXPIRED, "Invoice expired");

#if !DEVELOPER
	/* Please renepay try to give me a reliable payment 90% chances of
	 * success, once you do, then minimize as much as possible those fees. */
	base_fee_penalty = tal(tmpctx, u64);
	*base_fee_penalty = 10;
	prob_cost_factor = tal(tmpctx, u64);
	*prob_cost_factor = 10;
	riskfactor_millionths = tal(tmpctx, u64);
	*riskfactor_millionths = 1;
	min_prob_success_millionths = tal(tmpctx, u64);
	*min_prob_success_millionths = 90;
	use_shadow = tal(tmpctx, bool);
	*use_shadow = 1;
#endif

	/* Payment is allocated off cmd to start, in case we fail cmd
	 * (e.g. already in progress, already succeeded).  Once it's
	 * actually started, it persists beyond the command, so we
	 * tal_steal. */
	struct payment *payment = payment_new(cmd,
					       cmd,
					       take(invstr),
					       take(label),
					       take(description),
					       take(local_offer_id),
					       take(payment_secret),
					       take(payment_metadata),
					       &destination,
					       &payment_hash,
					       *msat,
					       *maxfee,
					       *maxdelay,
					       *retryfor,
					       final_cltv,
					       *base_fee_penalty,
					       *prob_cost_factor,
					       *riskfactor_millionths,
					       *min_prob_success_millionths,
					       use_shadow);

	/* We immediately add this payment to the payment list. */
	list_add_tail(&pay_plugin->payments, &payment->list);
	tal_add_destructor(payment, destroy_payment);

	plugin_log(pay_plugin->plugin,LOG_DBG,"Starting renepay");
	bool gossmap_changed = gossmap_refresh(pay_plugin->gossmap, NULL);

	if (pay_plugin->gossmap == NULL)
		plugin_err(pay_plugin->plugin, "Failed to refresh gossmap: %s",
			   strerror(errno));

	/* Free parameters which would be considered "leaks" by our fussy memleak code */
	tal_free(msat);
	tal_free(maxfee);
	tal_free(maxdelay);
	tal_free(retryfor);

	/* To construct the uncertainty network we need to perform the following
	 * steps:
	 * 1. check that there is a 1-to-1 map between channels in gossmap
	 * and the uncertainty network. We call `uncertainty_network_update`
	 *
	 * 2. add my local channels that could be private.
	 * We call `update_uncertainty_network_from_listpeerchannels`.
	 *
	 * 3. add hidden/private channels listed in the routehints.
	 * We call `uncertainty_network_add_routehints`.
	 *
	 * 4. check the uncertainty network invariants.
	 * */
	if(gossmap_changed)
		uncertainty_network_update(pay_plugin->gossmap,
					   pay_plugin->chan_extra_map);


	/* TODO(eduardo): We use a linear function to decide how to decay the
	 * channel information. Other shapes could be used.
	 * Also the choice of the proportional parameter TIMER_FORGET_SEC is
	 * arbitrary.
	 * Another idea is to measure time in blockheight. */
	const double fraction = (now_sec - pay_plugin->last_time)*1.0/TIMER_FORGET_SEC;
	uncertainty_network_relax_fraction(pay_plugin->chan_extra_map,
					   fraction);
	pay_plugin->last_time = now_sec;

	// TODO(eduardo): are there route hints for B12?
	// Add any extra hidden channel revealed by the routehints to the uncertainty network.
	uncertainty_network_add_routehints(pay_plugin->chan_extra_map, routes, payment);

	if(!uncertainty_network_check_invariants(pay_plugin->chan_extra_map))
		plugin_log(pay_plugin->plugin,
			   LOG_BROKEN,
			   "uncertainty network invariants are violated");

	/* Next, request listsendpays for previous payments that use the same
	 * hash. */
	struct out_req *req
		= jsonrpc_request_start(cmd->plugin, cmd, "listsendpays",
			payment_listsendpays_previous,
			payment_listsendpays_previous, payment);

	json_add_sha256(req->js, "payment_hash", &payment->payment_hash);
	return send_outreq(cmd->plugin, req);
}

static void handle_sendpay_failure_payment(struct pay_flow *flow,
					   const char *message,
					   u32 erridx,
					   enum onion_wire onionerr,
					   const u8 *raw)
{
	struct short_channel_id errscid;
	struct payment *p = flow->payment;

	debug_assert(flow);
	debug_assert(p);

	/* Final node is usually a hard failure, but lightningd said
	 * TRY_OTHER_ROUTE? */
	if (erridx == tal_count(flow->path_scids)) {
		debug_paynote(p,
			      "onion error %s from final node #%u: %s",
			      onion_wire_name(onionerr),
			      erridx,
			      message);

		if (onionerr == WIRE_MPP_TIMEOUT)
			return;

		debug_paynote(p,"final destination failure");
		payment_fail(p, PAY_DESTINATION_PERM_FAIL,
				    "Destination said %s: %s",
				    onion_wire_name(onionerr),
				    message);
		return;
	}

	errscid = flow->path_scids[erridx];
	debug_paynote(p,
		"onion error %s from node #%u %s: %s",
		onion_wire_name(onionerr),
		erridx,
		type_to_string(tmpctx, struct short_channel_id, &errscid),
		message);

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
		debug_paynote(p, "we're removing scid %s",
			      type_to_string(tmpctx,struct short_channel_id,&errscid));
		tal_arr_expand(&p->disabled, errscid);
		return;

	/* These can be fixed (maybe) by applying the included channel_update */
	case WIRE_AMOUNT_BELOW_MINIMUM:
	case WIRE_FEE_INSUFFICIENT:
	case WIRE_INCORRECT_CLTV_EXPIRY:
	case WIRE_EXPIRY_TOO_SOON:
		plugin_log(pay_plugin->plugin,LOG_DBG,"sendpay_failure, apply channel_update");
		/* FIXME: Check scid! */
		// TODO(eduardo): check
		const u8 *update = channel_update_from_onion_error(tmpctx, raw);
		if (update)
		{
			submit_update(flow, update, errscid);
			return;
		}

		debug_paynote(p, "missing an update, so we're removing scid %s",
			      type_to_string(tmpctx,struct short_channel_id,&errscid));
		tal_arr_expand(&p->disabled, errscid);
		return;

	case WIRE_TEMPORARY_CHANNEL_FAILURE:
		return;

	/* These should only come from the final distination. */
	case WIRE_MPP_TIMEOUT:
	case WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
		break;
	}

	debug_paynote(p,"unkown onion error code %u, removing scid %s",
		      onionerr,
		      type_to_string(tmpctx,struct short_channel_id,&errscid));
	tal_arr_expand(&p->disabled, errscid);
	return;
}

static void handle_sendpay_failure_flow(struct pay_flow *flow,
					const char *msg,
					u32 erridx,
					u32 onionerr)
{
	debug_assert(flow);

	struct payment * const p = flow->payment;
	if (p->status != PAYMENT_SUCCESS)
		p->status=PAYMENT_FAIL;

	plugin_log(pay_plugin->plugin, LOG_UNUSUAL,
		"onion error %s from node #%u %s: "
		"%s",
		onion_wire_name(onionerr),
		erridx,
		erridx == tal_count(flow->path_scids)
		? "final"
		: type_to_string(tmpctx, struct short_channel_id, &flow->path_scids[erridx]),
		msg);

	/* we know that all channels before erridx where able to commit to this payment */
	uncertainty_network_channel_can_send(
			pay_plugin->chan_extra_map,
			flow,
			erridx);

	/* Insufficient funds (not from final, that's weird!) */
	if((enum onion_wire)onionerr == WIRE_TEMPORARY_CHANNEL_FAILURE
	   && erridx < tal_count(flow->path_scids))
	{
		plugin_log(pay_plugin->plugin,LOG_DBG,
			   "sendpay_failure says insufficient funds!");

		chan_extra_cannot_send(p,pay_plugin->chan_extra_map,
				       flow->path_scids[erridx],
				       flow->path_dirs[erridx],
				    /* This channel can't send all that was
				     * commited in HTLCs.
				     * Had we removed the commited amount then
				     * we would have to put here flow->amounts[erridx]. */
				       AMOUNT_MSAT(0));
	}
}

/* See if this notification is about one of our flows. */
static struct pay_flow *pay_flow_from_notification(const char *buf,
						   const jsmntok_t *obj)
{
	struct payflow_key key;
	const char *err;

	/* Single part payment?  No partid */
	key.partid = 0;
	err = json_scan(tmpctx, buf, obj, "{partid?:%,groupid:%,payment_hash:%}",
			JSON_SCAN(json_to_u64, &key.partid),
			JSON_SCAN(json_to_u64, &key.groupid),
			JSON_SCAN(json_to_sha256, &key.payment_hash));
	if (err) {
		plugin_err(pay_plugin->plugin,
			   "Missing fields (%s) in notification: %.*s",
			   err,
			   json_tok_full_len(obj),
			   json_tok_full(buf, obj));
	}

	return payflow_map_get(pay_plugin->payflow_map, &key);
}

// TODO(eduardo): if I subscribe to a shutdown notification, the plugin takes
// forever to close and eventually it gets killed by force.
// static struct command_result *notification_shutdown(struct command *cmd,
// 					         const char *buf,
// 					         const jsmntok_t *params)
// {
// 	/* TODO(eduardo):
// 	 * 1. at shutdown the `struct plugin *p` is not freed,
// 	 * 2. `memleak_check` is called before we have the chance to get this
// 	 * notification. */
// 	// plugin_log(pay_plugin->plugin,LOG_DBG,"received shutdown notification, freeing data.");
// 	pay_plugin->ctx = tal_free(pay_plugin->ctx);
// 	return notification_handled(cmd);
// }
static struct command_result *notification_sendpay_success(
		struct command *cmd,
		const char *buf,
		const jsmntok_t *params)
{
	struct pay_flow *flow;
	struct preimage preimage;
	const char *err;
	const jsmntok_t *sub = json_get_member(buf, params, "sendpay_success");

	flow = pay_flow_from_notification(buf, sub);
	if (!flow)
		return notification_handled(cmd);

	err = json_scan(tmpctx, buf, sub, "{payment_preimage:%}",
			JSON_SCAN(json_to_preimage, &preimage));
	if (err) {
		plugin_err(pay_plugin->plugin,
			   "Bad payment_preimage (%s) in sendpay_success: %.*s",
			   err,
			   json_tok_full_len(params),
			   json_tok_full(buf, params));
	}

	// 3. mark as success
	struct payment * const p = flow->payment;
	debug_assert(p);
	p->status = PAYMENT_SUCCESS;

	/* We could have preimage from previous part */
	tal_free(p->preimage);
	p->preimage = tal_dup(p,struct preimage, &preimage);

	// 4. update information and release pending HTLCs
	uncertainty_network_flow_success(pay_plugin->chan_extra_map,flow);
	tal_free(flow);

	return notification_handled(cmd);
}

static struct command_result *notification_sendpay_failure(
		struct command *cmd,
		const char *buf,
		const jsmntok_t *params)
{
	struct pay_flow *flow;
	const char *err;
	enum jsonrpc_errcode errcode;
	const jsmntok_t *sub = json_get_member(buf, params, "sendpay_failure");

	flow = pay_flow_from_notification(buf, json_get_member(buf, sub, "data"));
	if (!flow)
		return notification_handled(cmd);

	err = json_scan(tmpctx, buf, sub, "{code:%}",
			JSON_SCAN(json_to_jsonrpc_errcode, &errcode));
	if (err) {
		plugin_err(pay_plugin->plugin,
			   "Bad code (%s) in sendpay_failure: %.*s",
			   err,
			   json_tok_full_len(params),
			   json_tok_full(buf, params));
	}

	/* Only one code is really actionable */
	switch (errcode) {
	case PAY_UNPARSEABLE_ONION:
		debug_paynote(flow->payment, "Unparsable onion reply on route %s",
			      flow_path_to_str(tmpctx, flow));
		err = "Unparsable onion reply";
		goto unhandleable;
	case PAY_TRY_OTHER_ROUTE:
		break;
	case PAY_DESTINATION_PERM_FAIL:
		break;
	default:
		payment_fail(flow->payment, errcode,
			     "Unexpected errocode from sendpay_failure: %.*s",
			     json_tok_full_len(params),
			     json_tok_full(buf, params));
		goto done;
	}

	/* Extract remaining fields forto feedback */
	const char *msg;
	u32 erridx, onionerr;
	const u8 *raw;

 	err = json_scan(tmpctx, buf, sub,
			"{message:%"
			",data:{erring_index:%"
			",failcode:%"
			",raw_message:%}}",
			JSON_SCAN_TAL(tmpctx, json_strdup, &msg),
			JSON_SCAN(json_to_u32, &erridx),
			JSON_SCAN(json_to_u32, &onionerr),
			JSON_SCAN_TAL(tmpctx, json_tok_bin_from_hex, &raw));
	if (err)
		goto unhandleable;

	/* Answer must be sane: but note, erridx can be final node! */
	if (erridx > tal_count(flow->path_scids)) {
		plugin_err(pay_plugin->plugin,
			   "Erring channel %u/%zu in path %s",
			   erridx, tal_count(flow->path_scids),
			   flow_path_to_str(tmpctx, flow));
	}

	handle_sendpay_failure_flow(flow, msg, erridx, onionerr);
	handle_sendpay_failure_payment(flow, msg, erridx, onionerr, raw);

done:
	if(flow) payflow_fail(flow);
	return notification_handled(cmd);

unhandleable:
	handle_unhandleable_error(flow, err);
	goto done;
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
	// {
	// 	"shutdown",
	// 	notification_shutdown,
	// },
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
