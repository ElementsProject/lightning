#include "config.h"
#include <common/json_stream.h>
#include <common/jsonrpc_errors.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/routefail.h>
#include <wire/peer_wiregen.h>

enum node_type {
	FINAL_NODE,
	INTERMEDIATE_NODE,
	ORIGIN_NODE,
	UNKNOWN_NODE
};

static struct command_result *
routefail_update_gossip(struct route_notification *r);
static struct command_result *
routefail_handle_cases(struct route_notification *r);
static struct command_result *
routefail_update_knowledge(struct route_notification *r);

struct command_result *routefail_start(struct route_notification *r)
{
	return routefail_update_gossip(r);
}

static struct command_result *routefail_end(struct route_notification *r)
{
	return route_unreserve(r);
}

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
						 struct route_notification *r)
{
	return routefail_handle_cases(r);
}

static struct command_result *update_gossip_failure(struct command *cmd UNUSED,
						    const char *buf,
						    const jsmntok_t *result,
						    struct route_notification *r)
{
	assert(r);
	assert(r->payment);

	/* FIXME it might be too strong assumption that erring_channel should
	 * always be present here, but at least the documentation for
	 * waitsendpay says it is present in the case of error. */
	assert(r->route->result->erring_channel);
	struct short_channel_id_dir scidd = {
	    .scid = *r->route->result->erring_channel,
	    .dir = *r->route->result->erring_direction};
	payment_disable_chan(
	    r->payment, scidd, LOG_INFORM,
	    "addgossip failed (%.*s)", json_tok_full_len(result),
	    json_tok_full(buf, result));
	return update_gossip_done(cmd, buf, result, r);
}

static struct command_result *
routefail_update_gossip(struct route_notification *r)
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
	return routefail_handle_cases(r);
}

/*****************************************************************************
 * handle_cases
 *
 * Process the kind of error, we might decide that this payment cannot continue
 * or is it worth continue trying.
 */

/* Mark this as a final error. When read this route result will inmediately end
 * the payment. */
static void route_final_error(struct route *route, enum jsonrpc_errcode error,
			      const char *fmt, ...)
{
	assert(route);

	va_list ap;
	const char *what;

	va_start(ap, fmt);
	what = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	route->final_error = error;
	route->final_msg = tal_strdup(route, what);
}

static struct command_result *
routefail_handle_cases(struct route_notification *r)
{
	/* BOLT #4:
	 *
	 * A _forwarding node_ MAY, but a _final node_ MUST NOT:
	 *...
	 *     - return an `invalid_onion_version` error.
	 *...
	 *     - return an `invalid_onion_hmac` error.
	 *...
	 *     - return an `invalid_onion_key` error.
	 *...
	 *     - return a `temporary_channel_failure` error.
	 *...
	 *     - return a `permanent_channel_failure` error.
	 *...
	 *     - return a `required_channel_feature_missing` error.
	 *...
	 *     - return an `unknown_next_peer` error.
	 *...
	 *     - return an `amount_below_minimum` error.
	 *...
	 *     - return a `fee_insufficient` error.
	 *...
	 *     - return an `incorrect_cltv_expiry` error.
	 *...
	 *     - return an `expiry_too_soon` error.
	 *...
	 *     - return an `expiry_too_far` error.
	 *...
	 *     - return a `channel_disabled` error.
	 */
	/* BOLT #4:
	 *
	 * An _intermediate hop_ MUST NOT, but the _final node_:
	 *...
	 *     - MUST return an `incorrect_or_unknown_payment_details` error.
	 *...
	 *     - MUST return `final_incorrect_cltv_expiry` error.
	 *...
	 *     - MUST return a `final_incorrect_htlc_amount` error.
	 */
	assert(r);
	struct route *route = r->route;
	assert(route);
	struct payment_result *result = route->result;
	assert(result);
	struct payment *payment = r->payment;
	assert(payment);

	int path_len = 0;
	if (route->hops)
		path_len = tal_count(route->hops);

	assert(result->erring_index);

	enum node_type node_type = UNKNOWN_NODE;
	if (route->hops) {
		if (*result->erring_index == path_len)
			node_type = FINAL_NODE;
		else if (*result->erring_index == 0)
			node_type = ORIGIN_NODE;
		else
			node_type = INTERMEDIATE_NODE;
	}

	assert(result->erring_node);

	switch (result->failcode) {
	// intermediate only
	case WIRE_INVALID_ONION_VERSION:
	case WIRE_INVALID_ONION_HMAC:
	case WIRE_INVALID_ONION_KEY:
		if (node_type == FINAL_NODE)
			payment_note(payment, LOG_UNUSUAL,
				     "Final node %s reported strange "
				     "error code %04x (%s)",
				     fmt_node_id(tmpctx, result->erring_node),
				     result->failcode,
				     onion_wire_name(result->failcode));

	case WIRE_INVALID_ONION_BLINDING:
		if (node_type == FINAL_NODE) {
			/* these errors from a final node mean a permanent
			 * failure */
			route_final_error(
			    route, PAY_DESTINATION_PERM_FAIL,
			    "Received error code %04x (%s) at final node.",
			    result->failcode,
			    onion_wire_name(result->failcode));
		} else if (node_type == INTERMEDIATE_NODE ||
			   node_type == ORIGIN_NODE) {
			/* we disable the next node in the hop */
			assert(*result->erring_index < path_len);
			payment_disable_node(
			    payment,
			    route->hops[*result->erring_index].node_id, LOG_DBG,
			    "received %s from previous hop",
			    onion_wire_name(result->failcode));
		}
		break;

	// final only
	case WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
		if (node_type == INTERMEDIATE_NODE)
			payment_note(payment, LOG_UNUSUAL,
				     "Intermediate node %s reported strange "
				     "error code %04x (%s)",
				     fmt_node_id(tmpctx, result->erring_node),
				     result->failcode,
				     onion_wire_name(result->failcode));

	case WIRE_PERMANENT_NODE_FAILURE:
	case WIRE_REQUIRED_NODE_FEATURE_MISSING:
	case WIRE_TEMPORARY_NODE_FAILURE:
	case WIRE_INVALID_REALM:
	case WIRE_INVALID_ONION_PAYLOAD:

		if (node_type == FINAL_NODE) {
			route_final_error(
			    route, PAY_DESTINATION_PERM_FAIL,
			    "Received error code %04x (%s) at final node.",
			    result->failcode,
			    onion_wire_name(result->failcode));
		} else if (node_type == ORIGIN_NODE) {
			route_final_error(
			    route, PAY_UNSPECIFIED_ERROR,
			    "Error code %04x (%s) reported at the origin.",
			    result->failcode,
			    onion_wire_name(result->failcode));
		} else {
			payment_disable_node(payment,
					     *result->erring_node, LOG_INFORM,
					     "received error %s",
					     onion_wire_name(result->failcode));
		}
		break;

	// intermediate only
	case WIRE_PERMANENT_CHANNEL_FAILURE:
	case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
	case WIRE_UNKNOWN_NEXT_PEER:
	case WIRE_EXPIRY_TOO_FAR:
	case WIRE_CHANNEL_DISABLED:
		if (node_type == FINAL_NODE) {
			payment_note(payment, LOG_UNUSUAL,
				     "Final node %s reported strange "
				     "error code %04x (%s)",
				     fmt_node_id(tmpctx, result->erring_node),
				     result->failcode,
				     onion_wire_name(result->failcode));

			route_final_error(
			    route, PAY_DESTINATION_PERM_FAIL,
			    "Received error code %04x (%s) at final node.",
			    result->failcode,
			    onion_wire_name(result->failcode));

		} else {
			assert(result->erring_channel);
			struct short_channel_id_dir scidd = {
			    .scid = *result->erring_channel,
			    .dir = *result->erring_direction};
			payment_disable_chan(
			    payment, scidd, LOG_INFORM,
			    "%s", onion_wire_name(result->failcode));
		}
		break;
	// final only
	case WIRE_MPP_TIMEOUT:

		if (node_type == INTERMEDIATE_NODE) {
			/* Normally WIRE_MPP_TIMEOUT is raised by the final
			 * node. If this is not the final node, then something
			 * wrong is going on. We report it and disable that
			 * node. */
			payment_note(payment, LOG_UNUSUAL,
				     "Intermediate node %s reported strange "
				     "error code %04x (%s)",
				     fmt_node_id(tmpctx, result->erring_node),
				     result->failcode,
				     onion_wire_name(result->failcode));

			payment_disable_node(payment,
					     *result->erring_node, LOG_INFORM,
					     "received error %s",
					     onion_wire_name(result->failcode));
		}
		break;

	// intermediate only
	case WIRE_EXPIRY_TOO_SOON:
	case WIRE_INCORRECT_CLTV_EXPIRY:
	case WIRE_FEE_INSUFFICIENT:
	case WIRE_AMOUNT_BELOW_MINIMUM:

		if (node_type == FINAL_NODE) {
			payment_note(payment, LOG_UNUSUAL,
				     "Final node %s reported strange "
				     "error code %04x (%s)",
				     fmt_node_id(tmpctx, result->erring_node),
				     result->failcode,
				     onion_wire_name(result->failcode));

			route_final_error(
			    route, PAY_DESTINATION_PERM_FAIL,
			    "Received error code %04x (%s) at final node.",
			    result->failcode,
			    onion_wire_name(result->failcode));

		} else {
			/* Usually this means we need to update the channel
			 * information and try again. To avoid hitting this
			 * error again with the same channel we flag it. */
			assert(result->erring_channel);
			struct short_channel_id_dir scidd = {
			    .scid = *result->erring_channel,
			    .dir = *result->erring_direction};
			payment_warn_chan(payment,
					  scidd, LOG_INFORM,
					  "received error %s",
					  onion_wire_name(result->failcode));
		}

		break;
	// intermediate only
	case WIRE_TEMPORARY_CHANNEL_FAILURE:

		if (node_type == FINAL_NODE) {
			/* WIRE_TEMPORARY_CHANNEL_FAILURE could mean that the
			 * next channel has not enough outbound liquidity or
			 * cannot add another HTLC. A final node cannot raise
			 * this error. */
			payment_note(payment, LOG_UNUSUAL,
				     "Final node %s reported strange "
				     "error code %04x (%s)",
				     fmt_node_id(tmpctx, result->erring_node),
				     result->failcode,
				     onion_wire_name(result->failcode));

			route_final_error(
			    route, PAY_DESTINATION_PERM_FAIL,
			    "Received error code %04x (%s) at final node.",
			    result->failcode,
			    onion_wire_name(result->failcode));
		}

		break;
	}
	return routefail_update_knowledge(r);
}

/*****************************************************************************
 * update_knowledge
 *
 * Make RPC calls to askrene to pass information about the liquidity constraint
 * we have learned from the errors.
 */

static struct command_result *
askrene_inform_done(struct command *cmd UNUSED, const char *buf UNUSED,
		    const jsmntok_t *result UNUSED,
		    struct route_notification *r)
{
	return routefail_end(r);
}

static struct command_result *
askrene_inform_fail(struct command *cmd UNUSED, const char *buf UNUSED,
		    const jsmntok_t *result UNUSED,
		    struct route_notification *r)
{
	plugin_log(
	    cmd->plugin, LOG_UNUSUAL,
	    "%s: failed RPC call to askrene-inform-channel, returned: %.*s",
	    __func__, json_tok_full_len(result), json_tok_full(buf, result));
	return askrene_inform_done(cmd, buf, result, r);
}

static struct command_result *
routefail_update_knowledge(struct route_notification *r)
{
	/* If we don't have the hops we can't learn anything. */
	if (!r->route->hops || !r->route->result
		|| !r->route->result->erring_index) {
		plugin_log(r->cmd->plugin, LOG_DBG,
			   "Cannot update knowledge from route %s, missing "
			   "hops or result.",
			   fmt_routekey(tmpctx, &r->route->key));
		goto skip_update_knowledge;
	}

	const int path_len = tal_count(r->route->hops);
	const int last_good_channel = *r->route->result->erring_index - 1;

	if (last_good_channel >= path_len)
		plugin_err(r->cmd->plugin,
			   "%s: last_good_channel (%d) >= path_len (%d)",
			   __func__, last_good_channel, path_len);

	if(r->route->result->failcode!=WIRE_TEMPORARY_CHANNEL_FAILURE ||
		(last_good_channel + 1)>=path_len)
		goto skip_update_knowledge;

	/* A WIRE_TEMPORARY_CHANNEL_FAILURE could mean not enough liquidity to
	 * forward the payment or cannot add one more HTLC. */
	const struct short_channel_id scid =
	    r->route->hops[last_good_channel + 1].scid;
	const int direction = r->route->hops[last_good_channel + 1].direction;
	const struct amount_msat this_amt =
	    r->route->hops[last_good_channel + 1].amount;

	// FIXME: call askrene-query-reserve
	// if this route was reseved then
	//	call askrene-inform-channel for amt
	// else
	//	call askrene-inform-channel for amt+this_amnt

	struct out_req *req = jsonrpc_request_start(
	    r->cmd->plugin, r->cmd, "askrene-inform-channel",
	    askrene_inform_done, askrene_inform_fail, r);

	json_add_string(req->js, "layer", RENEPAY_LAYER);
	json_add_short_channel_id(req->js, "short_channel_id", scid);
	json_add_num(req->js, "direction", direction);
	json_add_amount_msat(req->js, "maximum_msat", this_amt);

	return send_outreq(r->cmd->plugin, req);

skip_update_knowledge:
	return routefail_end(r);
}
