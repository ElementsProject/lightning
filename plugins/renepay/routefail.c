#include "config.h"
#include <common/json_stream.h>
#include <common/jsonrpc_errors.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/routefail.h>
#include <plugins/renepay/routetracker.h>
#include <wire/peer_wiregen.h>

struct routefail {
	u64 exec_state;
	struct command *cmd;
	struct route *route;
};

struct routefail_modifier {
	const char *name;
	struct command_result *(*step_cb)(struct routefail *r);
};

#define REGISTER_ROUTEFAIL_MODIFIER(name, step_cb)                             \
	struct routefail_modifier name##_routefail_mod = {                     \
	    stringify(name),                                                   \
	    typesafe_cb_cast(struct command_result * (*)(struct routefail *),  \
			     struct command_result * (*)(struct routefail *),  \
			     step_cb),                                         \
	};

static struct command_result *routefail_continue(struct routefail *r);

struct command_result *routefail_start(const tal_t *ctx, struct route *route,
				       struct command *cmd)
{
	struct routefail *r = tal(ctx, struct routefail);
	r->exec_state = 0;
	r->route = route;
	r->cmd = cmd;
	assert(route->result);
	return routefail_continue(r);
}

void *routefail_virtual_program[];
static struct command_result *routefail_continue(struct routefail *r)
{

	assert(r->exec_state != INVALID_STATE);
	const struct routefail_modifier *mod =
	    (const struct routefail_modifier *)
		routefail_virtual_program[r->exec_state++];

	if (mod == NULL)
		plugin_err(pay_plugin->plugin,
			   "%s expected routefail_modifier "
			   "but NULL found",
			   __PRETTY_FUNCTION__);

	plugin_log(pay_plugin->plugin, LOG_DBG, "Calling routefail_modifier %s",
		   mod->name);
	return mod->step_cb(r);
}

/* Generic handler for RPC failures. */
static struct command_result *routefail_rpc_failure(struct command *cmd,
						    const char *buffer,
						    const jsmntok_t *toks,
						    struct routefail *r)
{
	const jsmntok_t *codetok = json_get_member(buffer, toks, "code");
	u32 errcode;
	if (codetok != NULL)
		json_to_u32(buffer, codetok, &errcode);
	else
		errcode = LIGHTNINGD;

	plugin_err(r->cmd->plugin,
		   "routefail state machine has stopped due to a failed RPC "
		   "call: %.*s",
		   json_tok_full_len(toks), json_tok_full(buffer, toks));
	return notification_handled(r->cmd);
}

/*****************************************************************************
 * end
 *
 * The default ending of routefail.
 */
static struct command_result *end_done(struct command *cmd,
				       const char *buf UNUSED,
				       const jsmntok_t *result UNUSED,
				       struct routefail *r)
{
	/* Notify the tracker that route has failed and routefail have completed
	 * handling all possible errors cases. */
	route_failure_register(r->route);
	tal_free(r);
	return notification_handled(cmd);
}
static struct command_result *end_cb(struct routefail *r)
{
	struct out_req *req =
	    jsonrpc_request_start(r->cmd->plugin, r->cmd, "waitblockheight",
				  end_done, routefail_rpc_failure, r);
	json_add_num(req->js, "blockheight", 0);
	return send_outreq(r->cmd->plugin, req);
}

REGISTER_ROUTEFAIL_MODIFIER(end, end_cb);

/*****************************************************************************
 * update_gossip
 *
 * Update gossip from waitsendpay error message.
 */

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
	if (!fromwire_temporary_channel_failure(ctx, onion_message,
						&channel_update) &&
	    !fromwire_amount_below_minimum(ctx, onion_message, &unused_msat,
					   &channel_update) &&
	    !fromwire_fee_insufficient(ctx, onion_message, &unused_msat,
				       &channel_update) &&
	    !fromwire_incorrect_cltv_expiry(ctx, onion_message, &unused32,
					    &channel_update) &&
	    !fromwire_expiry_too_soon(ctx, onion_message, &channel_update))
		/* No channel update. */
		return NULL;

	return patch_channel_update(ctx, take(channel_update));
}

static struct command_result *update_gossip_done(struct command *cmd UNUSED,
						 const char *buf UNUSED,
						 const jsmntok_t *result UNUSED,
						 struct routefail *r)
{
	return routefail_continue(r);
}

static struct command_result *update_gossip_failure(struct command *cmd UNUSED,
						    const char *buf,
						    const jsmntok_t *result,
						    struct routefail *r)
{
	/* FIXME it might be too strong assumption that erring_channel should
	 * always be present here, but at least the documentation for
	 * waitsendpay says it is present in the case of error. */
	assert(r->route->result->erring_channel);

	payment_disable_chan(
	    r->route->payment, *r->route->result->erring_channel, LOG_INFORM,
	    "addgossip failed (%.*s)", json_tok_full_len(result),
	    json_tok_full(buf, result));
	return routefail_continue(r);
}

static struct command_result *update_gossip_cb(struct routefail *r)
{
	/* if there is no raw_message we continue */
	if (!r->route->result->raw_message)
		goto skip_update_gossip;

	const u8 *update = channel_update_from_onion_error(
	    tmpctx, r->route->result->raw_message);

	if (!update)
		goto skip_update_gossip;

	struct out_req *req =
	    jsonrpc_request_start(r->cmd->plugin, r->cmd, "addgossip",
				  update_gossip_done, update_gossip_failure, r);
	json_add_hex_talarr(req->js, "message", update);
	return send_outreq(r->cmd->plugin, req);

skip_update_gossip:
	return routefail_continue(r);
}

REGISTER_ROUTEFAIL_MODIFIER(update_gossip, update_gossip_cb);

/*****************************************************************************
 * update_knowledge
 *
 * Update the uncertainty network from waitsendpay error message.
 */

static struct command_result *update_knowledge_cb(struct routefail *r)
{
	const struct route *route = r->route;
	const struct payment_result *result = route->result;

	/* FIXME: If we don't know the hops there isn't much we can infer, but
	 * a little bit we could. */
	if (!route->hops || !result->erring_index)
		goto skip_update_network;

	uncertainty_channel_can_send(pay_plugin->uncertainty, route,
				  *result->erring_index);

	if (result->failcode == WIRE_TEMPORARY_CHANNEL_FAILURE &&
	    *result->erring_index < tal_count(route->hops)) {
		uncertainty_channel_cannot_send(
		    pay_plugin->uncertainty,
		    route->hops[*result->erring_index].scid,
		    route->hops[*result->erring_index].direction);
	}

	uncertainty_remove_htlcs(pay_plugin->uncertainty, route);

skip_update_network:
	return routefail_continue(r);
}

REGISTER_ROUTEFAIL_MODIFIER(update_knowledge, update_knowledge_cb);

/*****************************************************************************
 * handle_cases
 *
 * Process the kind of error, we might decide that this payment cannot continue
 * or is it worth continue trying.
 */

/* Mark this as a final error. When read this route result will inmediately end
 * the payment. */
static void route_final_error(struct route *route, enum jsonrpc_errcode error,
			      const char *what)
{
	route->final_error = error;
	route->final_msg = tal_strdup(route, what);
}

static void handle_unhandleable_error(struct route *route, const char *fmt, ...)
{
	if (!route->hops)
		return;
	size_t n = tal_count(route->hops);
	if (n == 0)
		return;

	va_list ap;
	const char *what;

	va_start(ap, fmt);
	what = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	if (n == 1) {
		/* This is a terminal error. */
		return route_final_error(route, PAY_UNPARSEABLE_ONION, what);
	}

	/* Prefer a node not directly connected to either end. */
	if (n > 3) {
		/* us ->0-> ourpeer ->1-> rando ->2-> theirpeer ->3-> dest */
		n = 1 + pseudorand(n - 2);
	} else
		/* Assume it's not the destination */
		n = pseudorand(n - 1);

	payment_disable_chan(route->payment, route->hops[n].scid, LOG_INFORM,
			     "randomly chosen");
}

static struct command_result *handle_cases_cb(struct routefail *r)
{
	struct route *route = r->route;
	const struct payment_result *result = route->result;

	// TODO: i am not sure these are compulsory
	assert(result->erring_index);
	assert(result->erring_node);

	switch (result->code) {
	case PAY_UNPARSEABLE_ONION:
		handle_unhandleable_error(
		    route, "received PAY_UNPARSEABLE_ONION error");
		goto finish;
		break;
	case PAY_TRY_OTHER_ROUTE:
		break;
	case PAY_DESTINATION_PERM_FAIL:
	default:
		route_final_error(route, result->code, result->message);
		goto finish;
	}

	/* Final node is usually a hard failure */
	if (node_id_eq(result->erring_node, &route->payment->destination) &&
	    result->failcode != WIRE_MPP_TIMEOUT) {
		route_final_error(route, PAY_DESTINATION_PERM_FAIL,
				  "final destination permanent failure");
		goto finish;
	}

	switch (result->failcode) {
	/* These definitely mean eliminate channel */
	case WIRE_PERMANENT_CHANNEL_FAILURE:
	case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
	/* FIXME: lnd returns this for disconnected peer, so don't disable perm!
	 */
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
		if (result->erring_channel)
			payment_disable_chan(route->payment,
					     *result->erring_channel,
					     LOG_UNUSUAL, "%s",
					     onion_wire_name(result->failcode));
		else
			handle_unhandleable_error(
			    route,
			    "received %s error, but don't have an "
			    "erring_channel",
			    onion_wire_name(result->failcode));
		break;

	/* These can be fixed (maybe) by applying the included channel_update */
	case WIRE_AMOUNT_BELOW_MINIMUM:
	case WIRE_FEE_INSUFFICIENT:
	case WIRE_INCORRECT_CLTV_EXPIRY:
	case WIRE_EXPIRY_TOO_SOON:
	case WIRE_TEMPORARY_CHANNEL_FAILURE:
		break;

	/* These should only come from the final distination. */
	case WIRE_MPP_TIMEOUT:
	case WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
		break;

	default:
		if (result->erring_channel)
			payment_disable_chan(
			    route->payment, *result->erring_channel,
			    LOG_UNUSUAL, "Unexpected error code %u",
			    result->failcode);
		else
			handle_unhandleable_error(
			    route,
			    "received %s error, but don't have an "
			    "erring_channel",
			    onion_wire_name(result->failcode));
	}

finish:
	return routefail_continue(r);
}

REGISTER_ROUTEFAIL_MODIFIER(handle_cases, handle_cases_cb);

/*****************************************************************************
 * Virtual machine */
// TODO: maybe I should make a single virtual machine interpreter (with
// templates and typesafety?) that is able to run on different static programs
// and types. One instance will execute the payment program and another instance
// will run the routefail program.

void *routefail_virtual_program[] = {
    &update_gossip_routefail_mod,
    &update_knowledge_routefail_mod,
    &handle_cases_routefail_mod,
    &end_routefail_mod,
    NULL};
