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

#define INVALID_ID UINT64_MAX
#define MAX(a,b) ((a)>(b)? (a) : (b))

static struct pay_plugin the_pay_plugin;
struct pay_plugin * const pay_plugin = &the_pay_plugin;

static void timer_kick(struct renepay * renepay);
static struct command_result *try_paying(struct command *cmd,
					 struct renepay * renepay,
					 bool first_time);

// TODO(eduardo): maybe we don't need these
static void background_timer_kick(void*p UNUSED);
static void background_settimer(void);

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
	/* TODO(eduardo): understand the purpose of memleak_scan_obj, why use it
	 * instead of tal_free?
	 * 1st problem: this is executed before the plugin can process the
	 * shutdown notification,
	 * 2nd problem: memleak_scan_obj does not propagate to children.
	 * For the moment let's just (incorrectly) do tal_free here
	 * */
	pay_plugin->ctx = tal_free(pay_plugin->ctx);

	// memleak_scan_obj(memtable, pay_plugin->ctx);
	// memleak_scan_obj(memtable, pay_plugin->gossmap);
	// memleak_scan_obj(memtable, pay_plugin->chan_extra_map);
	// memleak_scan_htable(memtable, &pay_plugin->chan_extra_map->raw);
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

	pay_plugin->ctx = notleak_with_children(tal(p,tal_t));
	pay_plugin->plugin = p;
	pay_plugin->rexmit_timer=NULL;

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

	pay_plugin->chan_extra_map = tal(pay_plugin->ctx,struct chan_extra_map);
	chan_extra_map_init(pay_plugin->chan_extra_map);

	pay_plugin->payflow_map = tal(pay_plugin->ctx,struct payflow_map);
	payflow_map_init(pay_plugin->payflow_map);

	pay_plugin->gossmap = gossmap_load(pay_plugin->ctx,
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

	background_settimer();
	return NULL;
}


// /* TODO(eduardo): an example of an RPC call that is not bound to any command. */
//static
//struct command_result* getinfo_done(struct command *cmd UNUSED,
//			 const char *buf,
//			 const jsmntok_t *result,
//			 void* pp  UNUSED)
//{
//	struct node_id id;
//	const jsmntok_t *id_tok = json_get_member(buf,result,"id");
//	json_to_node_id(buf,id_tok,&id);
//
//	plugin_log(pay_plugin->plugin,LOG_DBG,
//		"calling %s, nodeid = %s",
//		__PRETTY_FUNCTION__,
//		type_to_string(tmpctx,struct node_id,&id));
//
//	return command_still_pending(NULL);
//}

static void background_settimer(void)
{
	pay_plugin->rexmit_timer
		= tal_free(pay_plugin->rexmit_timer);
	pay_plugin->rexmit_timer
		= plugin_timer(
			pay_plugin->plugin,
			time_from_msec(2000),
			background_timer_kick, NULL);
}

static void background_timer_kick(void * p UNUSED)
{
	// plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);
	background_settimer();

	// /* TODO(eduardo): an example of an RPC call that is not bound to any command. */
	// struct out_req * req = jsonrpc_request_start(pay_plugin->plugin,
	// 				NULL,
	// 				"getinfo",
	// 			    	getinfo_done,
	// 			    	getinfo_done,
	// 			    	NULL);
	// send_outreq(pay_plugin->plugin, req);
}

static void renepay_settimer(struct renepay * renepay)
{
	renepay->rexmit_timer = tal_free(renepay->rexmit_timer);
	renepay->rexmit_timer = plugin_timer(
			pay_plugin->plugin,
			time_from_msec(TIMER_COLLECT_FAILURES_MSEC),
			timer_kick, renepay);
}

/* Happens when timer goes off, but also works to arm timer if nothing to do */
static void timer_kick(struct renepay * renepay)
{
	struct payment * const p = renepay->payment;
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);

	switch(p->status)
	{
		/* Some flows succeeded, we finish the payment. */
		case PAYMENT_SUCCESS:
			renepay_success(renepay);
		break;

		/* Some flows failed, we retry. */
		case PAYMENT_FAIL:
			payment_assert_delivering_incomplete(p);
			try_paying(renepay->cmd,renepay,false);
		break;

		/* Nothing has returned yet, we have to wait. */
		case PAYMENT_PENDING:
			payment_assert_delivering_all(p);
			renepay_settimer(renepay);
		break;
	}
}

/* Sometimes we don't know exactly who to blame... */
static struct command_result *handle_unhandleable_error(struct renepay * renepay,
							struct pay_flow *flow,
							const char *what)
{
	struct payment * const p = renepay->payment;
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);
	size_t n = tal_count(flow);

	/* We got a mangled reply.  We don't know who to penalize! */
	debug_paynote(p, "%s on route %s", what, flow_path_to_str(tmpctx, flow));

	// TODO(eduardo): does LOG_BROKEN finish the plugin execution?
	plugin_log(pay_plugin->plugin, LOG_BROKEN,
		   "%s on route %s",
		   what, flow_path_to_str(tmpctx, flow));

	if (n == 1)
	{
		payflow_fail(flow);
		return renepay_fail(renepay, PAY_UNPARSEABLE_ONION,
				    "Got %s from the destination", what);
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

	tal_arr_expand(&renepay->disabled, flow->path_scids[n]);
	debug_paynote(p, "... eliminated %s",
		type_to_string(tmpctx, struct short_channel_id,
			       &flow->path_scids[n]));
	return NULL;
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
	struct renepay * renepay = adg->flow->payment->renepay;

	/* Release this: if it's the last flow we'll retry immediately */

	payflow_fail(adg->flow);
	tal_free(adg);
	renepay_settimer(renepay);

	return command_still_pending(cmd);
}

static struct command_result *addgossip_failure(struct command *cmd,
						const char *buf,
						const jsmntok_t *err,
						struct addgossip *adg)

{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);
	struct payment * p = adg->flow->payment;
	struct renepay * renepay = p->renepay;

	debug_paynote(p, "addgossip failed, removing channel %s (%.*s)",
		type_to_string(tmpctx, struct short_channel_id, &adg->scid),
		err->end - err->start, buf + err->start);
	tal_arr_expand(&renepay->disabled, adg->scid);

	return addgossip_done(cmd, buf, err, adg);
}

static struct command_result *submit_update(struct command *cmd,
					    struct pay_flow *flow,
					    const u8 *update,
					    struct short_channel_id errscid)
{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);
	struct payment * p = flow->payment;
	struct renepay * renepay = p->renepay;
	struct out_req *req;
	struct addgossip *adg = tal(cmd, struct addgossip);

	/* We need to stash scid in case this fails, and we need to hold flow so
	 * we don't get a rexmit before this is complete. */
	adg->scid = errscid;
	adg->flow = flow;
	/* Disable re-xmit until this returns */
	renepay->rexmit_timer
		= tal_free(renepay->rexmit_timer);

	debug_paynote(p, "... extracted channel_update, telling gossipd");
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
					   const char *buf,
					   const jsmntok_t *onionmsgtok)
{
	u8 *channel_update = NULL;
	struct amount_msat unused_msat;
	u32 unused32;
	u8 *onion_message = json_tok_bin_from_hex(tmpctx, buf, onionmsgtok);

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
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);

	struct payment *p = flow->payment;
	debug_assert(p);
	struct renepay * renepay = p->renepay;
	debug_assert(renepay);

	/* This is a fail. */
	payment_fail(p);

	u64 errcode;
	const jsmntok_t *msg = json_get_member(buf, err, "message");

	if (!json_to_u64(buf, json_get_member(buf, err, "code"), &errcode))
		plugin_err(cmd->plugin, "Bad errcode from sendpay: %.*s",
			   json_tok_full_len(err), json_tok_full(buf, err));

	if (errcode != PAY_TRY_OTHER_ROUTE)
		plugin_err(cmd->plugin, "Strange error from sendpay: %.*s",
			   json_tok_full_len(err), json_tok_full(buf, err));

	debug_paynote(p,
		"sendpay didn't like first hop, eliminated: %.*s",
		msg->end - msg->start, buf + msg->start);

	/* There is no new knowledge from this kind of failure.
	 * We just disable this scid. */
	tal_arr_expand(&renepay->disabled, flow->path_scids[0]);

	payflow_fail(flow);
	return command_still_pending(cmd);
}


static struct command_result *
sendpay_flows(struct command *cmd,
	      struct renepay * renepay,
	      struct pay_flow **flows STEALS)
{
	struct payment * const p = renepay->payment;

	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);
	debug_paynote(p, "Sending out batch of %zu payments", tal_count(flows));

	for (size_t i = 0; i < tal_count(flows); i++) {
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
		tal_steal(pay_plugin->ctx,flows[i]);

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
	renepay_settimer(renepay);

	return command_still_pending(cmd);
}

static struct command_result *try_paying(struct command *cmd,
					 struct renepay *renepay,
					 bool first_time)
{
	struct payment * const p = renepay->payment;
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);

	// TODO(eduardo): does it make sense to have this limit on attempts?
	/* I am classifying the flows in attempt cycles. */
	renepay_new_attempt(renepay);
	/* We try only MAX_NUM_ATTEMPTS, then we give up. */
	if ( renepay_attempt_count(renepay) > MAX_NUM_ATTEMPTS)
	{
		return renepay_fail(renepay, PAY_STOPPED_RETRYING,
				    "Reached maximum number of attempts (%d)",
				    MAX_NUM_ATTEMPTS);
	}

	struct amount_msat feebudget, fees_spent, remaining;

	if (time_after(time_now(), p->stop_time))
		return renepay_fail(renepay, PAY_STOPPED_RETRYING, "Timed out");

	/* Total feebudget  */
	if (!amount_msat_sub(&feebudget, p->maxspend, p->amount))
	{
		plugin_err(pay_plugin->plugin,
			   "%s (line %d) could not substract maxspend=%s and amount=%s.",
			   __PRETTY_FUNCTION__,
			   __LINE__,
			   type_to_string(tmpctx, struct amount_msat, &p->maxspend),
			   type_to_string(tmpctx, struct amount_msat, &p->amount));
	}

	/* Fees spent so far */
	if (!amount_msat_sub(&fees_spent, p->total_sent, p->total_delivering))
	{
		plugin_err(pay_plugin->plugin,
			   "%s (line %d) could not substract total_sent=%s and total_delivering=%s.",
			   __PRETTY_FUNCTION__,
			   __LINE__,
			   type_to_string(tmpctx, struct amount_msat, &p->total_sent),
			   type_to_string(tmpctx, struct amount_msat, &p->total_delivering));
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
	if (!amount_msat_sub(&remaining, p->amount, p->total_delivering))
	{
		plugin_err(pay_plugin->plugin,
			   "%s (line %d) could not substract amount=%s and total_delivering=%s.",
			   __PRETTY_FUNCTION__,
			   __LINE__,
			   type_to_string(tmpctx, struct amount_msat, &p->amount),
			   type_to_string(tmpctx, struct amount_msat, &p->total_delivering));
	}

	// plugin_log(pay_plugin->plugin,LOG_DBG,fmt_chan_extra_map(tmpctx,pay_plugin->chan_extra_map));

	char const * err_msg;

	/* We let this return an unlikely path, as it's better to try once
	 * than simply refuse.  Plus, models are not truth! */
	struct pay_flow **pay_flows = get_payflows(
						renepay,
						remaining, feebudget,

						/* would you accept unlikely
						 * payments? */
						first_time,

				 		/* is entire payment? */
						amount_msat_eq(p->total_delivering, AMOUNT_MSAT(0)),

						&err_msg);

	// plugin_log(pay_plugin->plugin,LOG_DBG,"get_payflows produced %s",fmt_payflows(tmpctx,pay_flows));

	/* MCF cannot find a feasible route, we stop. */
	// TODO(eduardo): alternatively we can fallback to `pay`.
	if (!pay_flows)
	{
		return renepay_fail(renepay, PAY_ROUTE_NOT_FOUND,
				    "Failed to find a route, %s",
				    err_msg);
	}
	/* Now begin making payments */

	return sendpay_flows(cmd, renepay, pay_flows);
}

static struct command_result *listpeerchannels_done(
		struct command *cmd,
		const char *buf,
		const jsmntok_t *result,
		struct renepay *renepay)
{
	plugin_log(pay_plugin->plugin,LOG_DBG,"calling %s",__PRETTY_FUNCTION__);
	if (!uncertainty_network_update_from_listpeerchannels(
			pay_plugin->chan_extra_map,
			pay_plugin->my_id,
			renepay,
			buf,
			result))
		return renepay_fail(renepay,LIGHTNINGD,
				    "listpeerchannels malformed: %.*s",
				    json_tok_full_len(result),
				    json_tok_full(buf, result));
	// So we have all localmods data, now we apply it. Only once per
	// payment.
	// TODO(eduardo): check that there won't be a prob. cost associated with
	// any gossmap local chan. The same way there aren't fees to pay for my
	// local channels.
	gossmap_apply_localmods(pay_plugin->gossmap,renepay->local_gossmods);
	renepay->localmods_applied=true;
	return try_paying(cmd, renepay, true);
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
		   p_opt("invstring", param_string, &invstring),
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
		struct renepay * renepay)
{
	debug_info("calling %s",__PRETTY_FUNCTION__);
	struct payment * p = renepay->payment;

	size_t i;
	const jsmntok_t *t, *arr, *err;

	/* Do we have pending sendpays for the previous attempt? */
	bool pending = false;
	/* Group ID of the first pending payment, this will be the one
	 * who's result gets replayed if we end up suspending. */
	u64 first_pending_group_id = INVALID_ID;
	u64 last_pending_group_id = INVALID_ID;
	u64 last_pending_partid=0;
	struct amount_msat pending_sent = AMOUNT_MSAT(0),
			   pending_msat = AMOUNT_MSAT(0);

	/* Did a prior attempt succeed? */
	bool completed = false;
	/* Metadata for a complete payment, if one exists. */
	u32 complete_parts = 0;
	struct preimage complete_preimage;
	struct amount_msat complete_sent = AMOUNT_MSAT(0),
			   complete_msat = AMOUNT_MSAT(0);
	u32 complete_created_at;

	u64 last_group=INVALID_ID;

	err = json_get_member(buf, result, "error");
	if (err)
		return command_fail(
			   cmd, LIGHTNINGD,
			   "Error retrieving previous pay attempts: %s",
			   json_strdup(tmpctx, buf, err));

	arr = json_get_member(buf, result, "payments");
	if (!arr || arr->type != JSMN_ARRAY)
		return command_fail(
		    cmd, LIGHTNINGD,
		    "Unexpected non-array result from listsendpays");

	/* We iterate through all prior sendpays, looking for the
	 * latest group and remembering what its state is. */
	json_for_each_arr(i, t, arr)
	{
		u64 partid, groupid;
		struct amount_msat this_msat, this_sent;

		const jsmntok_t *status;

		// TODO(eduardo): assuming amount_msat is always known.
		json_scan(tmpctx,buf,t,
			  "{partid:%"
			  ",groupid:%"
			  ",amount_msat:%"
			  ",amount_sent_msat:%}",
			  JSON_SCAN(json_to_u64,&partid),
			  JSON_SCAN(json_to_u64,&groupid),
			  JSON_SCAN(json_to_msat,&this_msat),
			  JSON_SCAN(json_to_msat,&this_sent));

		/* status could be completed, pending or failed */


		status = json_get_member(buf, t, "status");

		if(json_tok_streq(buf,status,"failed"))
			continue;

		if(json_tok_streq(buf,status,"complete"))
		{
			/* Now we know the payment completed. */
			completed = true;
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
			complete_parts ++;
		}

		if(json_tok_streq(buf,status,"pending"))
		{
			pending = true; // there are parts pending

			if(first_pending_group_id==INVALID_ID ||
			   last_pending_group_id==INVALID_ID)
				first_pending_group_id = last_pending_group_id = groupid;

			if(groupid > last_pending_group_id)
			{
				last_pending_group_id = groupid;
				last_pending_partid = partid;
				pending_msat = AMOUNT_MSAT(0);
				pending_sent = AMOUNT_MSAT(0);
			}
			if(groupid < first_pending_group_id)
			{
				first_pending_group_id = groupid;
			}
			if(groupid == last_pending_group_id)
			{
				amount_msat_accumulate(&pending_sent,this_sent);
				amount_msat_accumulate(&pending_msat,this_msat);

				last_pending_partid = MAX(last_pending_partid,partid);
				plugin_log(pay_plugin->plugin,LOG_DBG,
					"pending deliver increased by %s",
					type_to_string(tmpctx,struct amount_msat,&this_msat));
			}

		}
	}

	if (completed) {
		struct json_stream *ret = jsonrpc_stream_success(cmd);
		json_add_preimage(ret, "payment_preimage", &complete_preimage);
		json_add_string(ret, "status", "complete");
		json_add_amount_msat(ret, "amount_msat", complete_msat);
		json_add_amount_msat(ret, "amount_sent_msat",complete_sent);
		json_add_node_id(ret, "destination", &p->destination);
		json_add_sha256(ret, "payment_hash", &p->payment_hash);
		json_add_u32(ret, "created_at", complete_created_at);
		json_add_num(ret, "parts", complete_parts);

		/* This payment was already completed, we don't keep record of
		 * it twice. */
		renepay->payment = tal_free(renepay->payment);

		return command_finished(cmd, ret);
	} else if (pending) {
		p->groupid = last_pending_group_id;
		renepay->next_partid = last_pending_partid+1;

		p->total_sent = pending_sent;
		p->total_delivering = pending_msat;

		plugin_log(pay_plugin->plugin,LOG_DBG,
			   "There are pending sendpays to this invoice. "
			   "groupid = %ld, "
			   "delivering = %s, "
			   "last_partid = %ld",
			   last_pending_group_id,
			   type_to_string(tmpctx,struct amount_msat,&p->total_delivering),
			   last_pending_partid);

		if( first_pending_group_id != last_pending_group_id)
		{
			/* At least two pending groups for the same invoice,
			 * this is weird, we better stop. */
			renepay->payment = tal_free(renepay->payment);
			return renepay_fail(renepay, PAY_IN_PROGRESS,
					    "Payment is pending by some other request.");
		}
		if(amount_msat_greater_eq(p->total_delivering,p->amount))
		{
			/* Pending payment already pays the full amount, we
			 * better stop. */
			renepay->payment = tal_free(renepay->payment);
			return renepay_fail(renepay, PAY_IN_PROGRESS,
					    "Payment is pending with full amount already commited");
		}
	}else
	{
		p->groupid = (last_group==INVALID_ID  ? 1 : (last_group+1)) ;
		renepay->next_partid=1;
	}


	struct out_req *req;
	/* Get local capacities... */
	req = jsonrpc_request_start(cmd->plugin, cmd, "listpeerchannels",
				    listpeerchannels_done,
				    listpeerchannels_done, renepay);
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
	u64 *riskfactor_millionths;
	u32 *maxdelay;
	u64 *base_fee_penalty;
	u64 *prob_cost_factor;
	u64 *min_prob_success_millionths;
	u32 *retryfor;

#if DEVELOPER
	bool *use_shadow;
#endif

	if (!param(cmd, buf, params,
		   p_req("invstring", param_string, &invstr),
 		   p_opt("amount_msat", param_msat, &msat),
 		   p_opt("maxfee", param_msat, &maxfee),

		   // MCF parameters
		   // TODO(eduardo): are these parameters read correctly?
		   p_opt_def("base_fee_penalty", param_millionths, &base_fee_penalty,10),
 		   p_opt_def("prob_cost_factor", param_millionths, &prob_cost_factor,10),
		   p_opt_def("min_prob_success", param_millionths,
		   	&min_prob_success_millionths,100000),// default is 10%

		   p_opt_def("riskfactor", param_millionths,&riskfactor_millionths,1),

		   p_opt_def("maxdelay", param_number, &maxdelay,
			     /* We're initially called to probe usage, before init! */
			     pay_plugin ? pay_plugin->maxdelay_default : 0),


 		   p_opt_def("retry_for", param_number, &retryfor, 60), // 60 seconds
 		   p_opt("localofferid", param_sha256, &local_offer_id),
 		   p_opt("description", param_string, &description),
 		   p_opt("label", param_string, &label),
#if DEVELOPER
		   p_opt_def("use_shadow", param_bool, &use_shadow, true),
#endif
		   NULL))
		return command_param_failed();

	/* renepay is bound to the command, if the command finishes renepay is
	 * freed. */
	struct renepay * renepay = renepay_new(cmd);
	tal_add_destructor2(renepay,
			    renepay_cleanup,
			    pay_plugin->gossmap);
 	struct payment * p = renepay->payment;

	p->invstr = tal_steal(p,invstr);
	p->description = tal_steal(p,description);
	p->label = tal_steal(p,label);
	p->local_offer_id = tal_steal(p,local_offer_id);

	p->base_fee_penalty = *base_fee_penalty;
	base_fee_penalty = tal_free(base_fee_penalty);

	p->prob_cost_factor = *prob_cost_factor;
	prob_cost_factor = tal_free(prob_cost_factor);

	p->min_prob_success = *min_prob_success_millionths/1e6;
	min_prob_success_millionths = tal_free(min_prob_success_millionths);

	p->delay_feefactor = *riskfactor_millionths/1e6;
	riskfactor_millionths = tal_free(riskfactor_millionths);

	p->maxdelay = *maxdelay;
	maxdelay = tal_free(maxdelay);

	/* We inmediately add this payment to the payment list. */
	tal_steal(pay_plugin->ctx,p);
	list_add_tail(&pay_plugin->payments, &p->list);
	tal_add_destructor(p, destroy_payment);

	plugin_log(pay_plugin->plugin,LOG_DBG,"Starting renepay");
	bool gossmap_changed = gossmap_refresh(pay_plugin->gossmap, NULL);

	if (pay_plugin->gossmap == NULL)
		plugin_err(pay_plugin->plugin, "Failed to refresh gossmap: %s",
			   strerror(errno));

	p->start_time = time_now();
	p->stop_time = timeabs_add(p->start_time, time_from_sec(*retryfor));
	tal_free(retryfor);

	bool invstr_is_b11=false;
	if (!bolt12_has_prefix(p->invstr)) {
		struct bolt11 *b11;
		char *fail;

		b11 =
		    bolt11_decode(tmpctx, p->invstr, plugin_feature_set(cmd->plugin),
				  p->description, chainparams, &fail);
		if (b11 == NULL)
			return renepay_fail(renepay, JSONRPC2_INVALID_PARAMS,
					    "Invalid bolt11: %s", fail);
		invstr_is_b11=true;

		invmsat = b11->msat;
		invexpiry = b11->timestamp + b11->expiry;

		p->destination = b11->receiver_id;
		p->payment_hash = b11->payment_hash;
		p->payment_secret =
			tal_dup_or_null(p, struct secret, b11->payment_secret);
		if (b11->metadata)
			p->payment_metadata = tal_dup_talarr(p, u8, b11->metadata);
		else
			p->payment_metadata = NULL;


		p->final_cltv = b11->min_final_cltv_expiry;
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
				return renepay_fail(renepay,
						    JSONRPC2_INVALID_PARAMS,
						    "Invalid bolt11: missing description");
			}
			if (!p->description)
				return renepay_fail(renepay,
						    JSONRPC2_INVALID_PARAMS,
						    "bolt11 uses description_hash, but you did not provide description parameter");
		}
	} else {
		// TODO(eduardo): check this, compare with `pay`
		const struct tlv_invoice *b12;
		char *fail;
		b12 = invoice_decode(tmpctx, p->invstr, strlen(p->invstr),
				     plugin_feature_set(cmd->plugin),
				     chainparams, &fail);
		if (b12 == NULL)
			return renepay_fail(renepay, JSONRPC2_INVALID_PARAMS,
					    "Invalid bolt12: %s", fail);
		if (!pay_plugin->exp_offers)
			return renepay_fail(renepay, JSONRPC2_INVALID_PARAMS,
					    "experimental-offers disabled");

		if (!b12->offer_node_id)
			return renepay_fail(renepay, JSONRPC2_INVALID_PARAMS,
					    "invoice missing offer_node_id");
		if (!b12->invoice_payment_hash)
			return renepay_fail(renepay, JSONRPC2_INVALID_PARAMS,
					    "invoice missing payment_hash");
		if (!b12->invoice_created_at)
			return renepay_fail(renepay, JSONRPC2_INVALID_PARAMS,
					    "invoice missing created_at");
		if (b12->invoice_amount) {
			invmsat = tal(cmd, struct amount_msat);
			*invmsat = amount_msat(*b12->invoice_amount);
		} else
			invmsat = NULL;

		node_id_from_pubkey(&p->destination, b12->offer_node_id);
		p->payment_hash = *b12->invoice_payment_hash;
		if (b12->invreq_recurrence_counter && !p->label)
			return renepay_fail(
			    renepay, JSONRPC2_INVALID_PARAMS,
			    "recurring invoice requires a label");
		/* FIXME payment_secret should be signature! */
		{
			struct sha256 merkle;

			p->payment_secret = tal(p, struct secret);
			merkle_tlv(b12->fields, &merkle);
			memcpy(p->payment_secret, &merkle, sizeof(merkle));
			BUILD_ASSERT(sizeof(*p->payment_secret) ==
				     sizeof(merkle));
		}
		p->payment_metadata = NULL;
		/* FIXME: blinded paths! */
		p->final_cltv = 18;
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

	if (node_id_eq(&pay_plugin->my_id, &p->destination))
		return renepay_fail(renepay, JSONRPC2_INVALID_PARAMS,
				    "This payment is destined for ourselves. "
				    "Self-payments are not supported");


	// set the payment amount
	if (invmsat) {
		// amount is written in the invoice
		if (msat) {
			return renepay_fail(renepay, JSONRPC2_INVALID_PARAMS,
					    "amount_msat parameter unnecessary");
		}
		p->amount = *invmsat;
		tal_free(invmsat);
	} else {
		// amount is not written in the invoice
		if (!msat) {
			return renepay_fail(renepay, JSONRPC2_INVALID_PARAMS,
					    "amount_msat parameter required");
		}
		p->amount = *msat;
		tal_free(msat);
	}

	/* Default max fee is 5 sats, or 0.5%, whichever is *higher* */
	if (!maxfee) {
		struct amount_msat fee = amount_msat_div(p->amount, 200);
		if (amount_msat_less(fee, AMOUNT_MSAT(5000)))
			fee = AMOUNT_MSAT(5000);
		maxfee = tal_dup(tmpctx, struct amount_msat, &fee);
	}

	if (!amount_msat_add(&p->maxspend, p->amount, *maxfee)) {
		return renepay_fail(
			renepay, JSONRPC2_INVALID_PARAMS,
			"Overflow when computing fee budget, fee far too high.");
	}
	tal_free(maxfee);

	if (time_now().ts.tv_sec > invexpiry)
		return renepay_fail(renepay, PAY_INVOICE_EXPIRED, "Invoice expired");


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


	// TODO(eduardo): are there route hints for B12?
	// Add any extra hidden channel revealed by the routehints to the uncertainty network.
	if(invstr_is_b11)
		uncertainty_network_add_routehints(pay_plugin->chan_extra_map,renepay);

	if(!uncertainty_network_check_invariants(pay_plugin->chan_extra_map))
		plugin_log(pay_plugin->plugin,
			   LOG_BROKEN,
			   "uncertainty network invariants are violated");

	/* Next, request listsendpays for previous payments that use the same
	 * hash. */
	struct out_req *req
		= jsonrpc_request_start(cmd->plugin, cmd, "listsendpays",
			payment_listsendpays_previous,
			payment_listsendpays_previous, renepay);

	json_add_sha256(req->js, "payment_hash", &p->payment_hash);
	return send_outreq(cmd->plugin, req);

	// TODO(eduardo):
	// - get time since last payment,
	// - forget a portion of the bounds
	// - note that if sufficient time has passed, then we would forget
	// everything use TIMER_FORGET_SEC.
}

static void handle_sendpay_failure_renepay(
		struct command *cmd,
		const char *buf,
		const jsmntok_t *result,
		struct renepay *renepay,
		struct pay_flow *flow)
{
	debug_assert(renepay);
	debug_assert(flow);
	struct payment *p = renepay->payment;
	debug_assert(p);

	u64 errcode;
	if (!json_to_u64(buf, json_get_member(buf, result, "code"), &errcode))
	{
		plugin_log(pay_plugin->plugin,LOG_BROKEN,
			  "Failed to get code from sendpay_failure notification"
			  ", received json: %.*s",
			  json_tok_full_len(result),
			  json_tok_full(buf,result));
		return;
	}
	const jsmntok_t *msgtok = json_get_member(buf, result, "message");
	const char *message;
	if(msgtok)
		message = tal_fmt(tmpctx,"%.*s",
				  msgtok->end - msgtok->start,
				  buf + msgtok->start);
	else
		message = "[message missing from sendpay_failure notification]";

	switch(errcode)
	{
		case PAY_UNPARSEABLE_ONION:
			debug_paynote(p, "Unparsable onion reply on route %s",
				      flow_path_to_str(tmpctx, flow));
			goto unhandleable;
		case PAY_TRY_OTHER_ROUTE:
			break;
		case PAY_DESTINATION_PERM_FAIL:
			renepay_fail(renepay,errcode,
				     "Got a final failure from destination");
			return;
		default:
			renepay_fail(renepay,errcode,
				     "Unexpected errocode from sendpay_failure: %.*s",
				     json_tok_full_len(result),
				     json_tok_full(buf,result));
			return;
	}

	const jsmntok_t* datatok = json_get_member(buf, result, "data");

	if(!datatok)
	{
		plugin_err(pay_plugin->plugin,
			  "Failed to get data from sendpay_failure notification"
			  ", received json: %.*s",
			  json_tok_full_len(result),
			  json_tok_full(buf,result));
	}


	/* OK, we expect an onion error reply. */
	u32 erridx;
	const jsmntok_t * erridxtok = json_get_member(buf, datatok, "erring_index");
	if (!erridxtok || !json_to_u32(buf, erridxtok, &erridx))
	{
		debug_paynote(p, "Missing erring_index reply on route %s",
			      flow_path_to_str(tmpctx, flow));
		plugin_log(pay_plugin->plugin,LOG_DBG,
			   "%s (line %d) missing erring_index "
			   "on request %.*s",
			   __PRETTY_FUNCTION__,__LINE__,
			   json_tok_full_len(result),
			   json_tok_full(buf,result));
		goto unhandleable;
	}

	struct short_channel_id errscid;
	const jsmntok_t *errchantok = json_get_member(buf, datatok, "erring_channel");
	if(!errchantok || !json_to_short_channel_id(buf, errchantok, &errscid))
	{
		debug_paynote(p, "Missing erring_channel reply on route %s",
			      flow_path_to_str(tmpctx, flow));
		goto unhandleable;
	}

	if (erridx<tal_count(flow->path_scids)
	    && !short_channel_id_eq(&errscid, &flow->path_scids[erridx]))
	{
		debug_paynote(p,
			      "erring_index (%d) does not correspond"
			      "to erring_channel (%s) on route %s",
			      erridx,
			      type_to_string(tmpctx,struct short_channel_id,&errscid),
			      flow_path_to_str(tmpctx,flow));
		goto unhandleable;
	}

	u32 onionerr;
	const jsmntok_t *failcodetok = json_get_member(buf, datatok, "failcode");
	if(!failcodetok || !json_to_u32(buf, failcodetok, &onionerr))
	{
		// TODO(eduardo): I wonder which error code should I show the
		// user in this case?
		renepay_fail(renepay,LIGHTNINGD,
			  "Failed to get failcode from sendpay_failure notification"
			  ", received json: %.*s",
			  json_tok_full_len(result),
			  json_tok_full(buf,result));
		return;
	}

	debug_paynote(p,
		"onion error %s from node #%u %s: %s",
		onion_wire_name(onionerr),
		erridx,
		type_to_string(tmpctx, struct short_channel_id, &errscid),
		message);

	const jsmntok_t *rawoniontok = json_get_member(buf, datatok, "raw_message");
	if(!rawoniontok)
		goto unhandleable;

	switch ((enum onion_wire)onionerr) {
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
		tal_arr_expand(&renepay->disabled, errscid);
		return;

	/* These can be fixed (maybe) by applying the included channel_update */
	case WIRE_AMOUNT_BELOW_MINIMUM:
	case WIRE_FEE_INSUFFICIENT:
	case WIRE_INCORRECT_CLTV_EXPIRY:
	case WIRE_EXPIRY_TOO_SOON:
		plugin_log(pay_plugin->plugin,LOG_DBG,"sendpay_failure, apply channel_update");
		/* FIXME: Check scid! */
		// TODO(eduardo): check
		const u8 *update = channel_update_from_onion_error(tmpctx, buf, rawoniontok);
		if (update)
		{
			submit_update(cmd, flow, update, errscid);
			return;
		}

		debug_paynote(p, "missing an update, so we're removing scid %s",
			      type_to_string(tmpctx,struct short_channel_id,&errscid));
		tal_arr_expand(&renepay->disabled, errscid);
		return;

	case WIRE_TEMPORARY_CHANNEL_FAILURE:
	case WIRE_MPP_TIMEOUT:
		return;

	/* These are from the final distination: fail */
	case WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
		debug_paynote(p,"final destination failure");
		renepay_fail(renepay,errcode,
				    "Destination said %s: %s",
				    onion_wire_name(onionerr),
				    message);
		return;
	}

	debug_assert(erridx<=tal_count(flow->path_nodes));

	if(erridx == tal_count(flow->path_nodes))
	{
		debug_paynote(p,"unkown onion error code %u, fatal",
			      onionerr);
		renepay_fail(renepay,errcode,
			     "Destination gave unknown error code %u: %s",
			     onionerr,message);
		return;
	}else
	{
		debug_paynote(p,"unkown onion error code %u, removing scid %s",
			      onionerr,
			      type_to_string(tmpctx,struct short_channel_id,&errscid));
		tal_arr_expand(&renepay->disabled, errscid);
		return;
	}
	unhandleable:
	// TODO(eduardo): check
	handle_unhandleable_error(renepay, flow, "");
}

static void handle_sendpay_failure_flow(
		struct command *cmd,
		const char *buf,
		const jsmntok_t *result,
		struct pay_flow *flow)
{
	// TODO(eduardo): review with Rusty the level of severity of the
	// different cases of error below.
	debug_assert(flow);

	struct payment * const p = flow->payment;
	payment_fail(p);

	u64 errcode;
	if (!json_to_u64(buf, json_get_member(buf, result, "code"), &errcode))
	{
		plugin_log(pay_plugin->plugin,LOG_BROKEN,
			  "Failed to get code from sendpay_failure notification"
			  ", received json: %.*s",
			  json_tok_full_len(result),
			  json_tok_full(buf,result));
		return;
	}
	const jsmntok_t *msgtok = json_get_member(buf, result, "message");
	const char *message;
	if(msgtok)
		message = tal_fmt(tmpctx,"%.*s",
				  msgtok->end - msgtok->start,
				  buf + msgtok->start);
	else
		message = "[message missing from sendpay_failure notification]";

	if(errcode!=PAY_TRY_OTHER_ROUTE)
		return;

	const jsmntok_t* datatok = json_get_member(buf, result, "data");
	if(!datatok)
	{
		plugin_err(pay_plugin->plugin,
			  "Failed to get data from sendpay_failure notification"
			  ", received json: %.*s",
			  json_tok_full_len(result),
			  json_tok_full(buf,result));
	}

	/* OK, we expect an onion error reply. */
	u32 erridx;
	const jsmntok_t * erridxtok = json_get_member(buf, datatok, "erring_index");
	if (!erridxtok || !json_to_u32(buf, erridxtok, &erridx))
	{
		plugin_log(pay_plugin->plugin,LOG_BROKEN,
			  "Failed to get erring_index from sendpay_failure notification"
			  ", received json: %.*s",
			  json_tok_full_len(result),
			  json_tok_full(buf,result));
		return;
	}

	struct short_channel_id errscid;
	const jsmntok_t *errchantok = json_get_member(buf, datatok, "erring_channel");
	if(!errchantok || !json_to_short_channel_id(buf, errchantok, &errscid))
	{
		plugin_log(pay_plugin->plugin,LOG_BROKEN,
			  "Failed to get erring_channel from sendpay_failure notification"
			  ", received json: %.*s",
			  json_tok_full_len(result),
			  json_tok_full(buf,result));
		return;
	}

	if (erridx<tal_count(flow->path_scids)
	    && !short_channel_id_eq(&errscid, &flow->path_scids[erridx]))
	{
		plugin_err(pay_plugin->plugin,
			   "Erring channel %u/%zu was %s not %s (path %s)",
			   erridx, tal_count(flow->path_scids),
			   type_to_string(tmpctx,
			   		  struct short_channel_id,
					  &errscid),
			   type_to_string(tmpctx,
			   		  struct short_channel_id,
			   		  &flow->path_scids[erridx]),
			   flow_path_to_str(tmpctx, flow));
		return;
	}


	u32 onionerr;
	const jsmntok_t *failcodetok = json_get_member(buf, datatok, "failcode");
	if(!failcodetok || !json_to_u32(buf, failcodetok, &onionerr))
	{
		plugin_log(pay_plugin->plugin,LOG_BROKEN,
			  "Failed to get failcode from sendpay_failure notification"
			  ", received json: %.*s",
			  json_tok_full_len(result),
			  json_tok_full(buf,result));
		return;

	}

	plugin_log(pay_plugin->plugin,LOG_UNUSUAL,
		"onion error %s from node #%u %s: "
		"%s",
		onion_wire_name(onionerr),
		erridx,
		type_to_string(tmpctx, struct short_channel_id, &errscid),
		message);

	/* we know that all channels before erridx where able to commit to this payment */
	uncertainty_network_channel_can_send(
			pay_plugin->chan_extra_map,
			flow,
			erridx);

	/* Insufficient funds! */
	if((enum onion_wire)onionerr == WIRE_TEMPORARY_CHANNEL_FAILURE)
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
	struct pay_flow *flow = NULL;
	const jsmntok_t *resulttok = json_get_member(buf,params,"sendpay_success");
	if(!resulttok)
		debug_err("Failed to get result from sendpay_success notification"
			  ", received json: %.*s",
			  json_tok_full_len(params),
			  json_tok_full(buf,params));

	// 1. generate the key of this payflow
	struct payflow_key key;
	key.payment_hash = tal(tmpctx,struct sha256);

	const jsmntok_t *parttok = json_get_member(buf,resulttok,"partid");
	if(!parttok || !json_to_u64(buf,parttok,&key.partid))
	{
		// No partid, is this a single-path payment?
		key.partid = 0;
		// debug_err("Failed to get partid from sendpay_success notification"
		// 	  ", received json: %.*s",
		// 	  json_tok_full_len(params),
		// 	  json_tok_full(buf,params));
	}
	const jsmntok_t *grouptok = json_get_member(buf,resulttok,"groupid");
	if(!grouptok || !json_to_u64(buf,grouptok,&key.groupid))
		debug_err("Failed to get groupid from sendpay_success notification"
			  ", received json: %.*s",
			  json_tok_full_len(params),
			  json_tok_full(buf,params));

	const jsmntok_t *hashtok = json_get_member(buf,resulttok,"payment_hash");
	if(!hashtok || !json_to_sha256(buf,hashtok,key.payment_hash))
		debug_err("Failed to get payment_hash from sendpay_success notification"
			  ", received json: %.*s",
			  json_tok_full_len(params),
			  json_tok_full(buf,params));

	plugin_log(pay_plugin->plugin,LOG_DBG,
		"I received a sendpay_success with key %s",
		fmt_payflow_key(tmpctx,&key));

	// 2. is this payflow recorded in renepay?
	flow = payflow_map_get(pay_plugin->payflow_map,key);
	if(!flow)
	{
		plugin_log(pay_plugin->plugin,LOG_DBG,
			"sendpay_success does not correspond to a renepay attempt, %s",
			fmt_payflow_key(tmpctx,&key));
		goto done;
	}

	// 3. mark as success
	struct payment * const p = flow->payment;
	debug_assert(p);

	payment_success(p);

	const jsmntok_t *preimagetok
		= json_get_member(buf, resulttok, "payment_preimage");
	struct preimage preimage;

	if (!preimagetok || !json_to_preimage(buf, preimagetok,&preimage))
		debug_err("Failed to get payment_preimage from sendpay_success notification"
			  ", received json: %.*s",
			  json_tok_full_len(params),
			  json_tok_full(buf,params));

	p->preimage = tal_dup_or_null(p,struct preimage,&preimage);

	// 4. update information and release pending HTLCs
	uncertainty_network_flow_success(pay_plugin->chan_extra_map,flow);

	done:
	tal_free(flow);
	return notification_handled(cmd);
}
static struct command_result *notification_sendpay_failure(
		struct command *cmd,
		const char *buf,
		const jsmntok_t *params)
{
	struct pay_flow *flow = NULL;

	const jsmntok_t *resulttok = json_get_member(buf,params,"sendpay_failure");
	if(!resulttok)
		debug_err("Failed to get result from sendpay_failure notification"
			  ", received json: %.*s",
			  json_tok_full_len(params),
			  json_tok_full(buf,params));

	const jsmntok_t *datatok = json_get_member(buf,resulttok,"data");
	if(!datatok)
		debug_err("Failed to get data from sendpay_failure notification"
			  ", received json: %.*s",
			  json_tok_full_len(params),
			  json_tok_full(buf,params));


	// 1. generate the key of this payflow
	struct payflow_key key;
	key.payment_hash = tal(tmpctx,struct sha256);

	const jsmntok_t *parttok = json_get_member(buf,datatok,"partid");
	if(!parttok || !json_to_u64(buf,parttok,&key.partid))
	{
		// No partid, is this a single-path payment?
		key.partid = 0;
	}
	const jsmntok_t *grouptok = json_get_member(buf,datatok,"groupid");
	if(!grouptok || !json_to_u64(buf,grouptok,&key.groupid))
		debug_err("Failed to get groupid from sendpay_failure notification"
			  ", received json: %.*s",
			  json_tok_full_len(params),
			  json_tok_full(buf,params));

	const jsmntok_t *hashtok = json_get_member(buf,datatok,"payment_hash");
	if(!hashtok || !json_to_sha256(buf,hashtok,key.payment_hash))
		debug_err("Failed to get payment_hash from sendpay_failure notification"
			  ", received json: %.*s",
			  json_tok_full_len(params),
			  json_tok_full(buf,params));

	plugin_log(pay_plugin->plugin,LOG_DBG,
		"I received a sendpay_failure with key %s",
		fmt_payflow_key(tmpctx,&key));

	// 2. is this payflow recorded in renepay?
	flow = payflow_map_get(pay_plugin->payflow_map,key);
	if(!flow)
	{
		plugin_log(pay_plugin->plugin,LOG_DBG,
			"sendpay_failure does not correspond to a renepay attempt, %s",
			fmt_payflow_key(tmpctx,&key));
		goto done;
	}

	// 3. process failure
	handle_sendpay_failure_flow(cmd,buf,resulttok,flow);

	// there is possibly a pending renepay command for this flow
	struct renepay * const renepay = flow->payment->renepay;

	if(renepay)
		handle_sendpay_failure_renepay(cmd,buf,resulttok,renepay,flow);

	done:
	if(flow) payflow_fail(flow);
	return notification_handled(cmd);
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

	// TODO(eduardo): I think this is actually never executed
	tal_free(pay_plugin->ctx);
	return 0;
}
