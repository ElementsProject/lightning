#include "config.h"
#include <common/json_stream.h>
#include <common/jsonrpc_errors.h>
#include <plugins/renepay/payplugin.h>
#include <plugins/renepay/routefail.h>
#include <plugins/renepay/routetracker.h>
#include <wire/peer_wiregen.h>

enum node_type {
	FINAL_NODE,
	INTERMEDIATE_NODE,
	ORIGIN_NODE,
	UNKNOWN_NODE
};

struct routefail {
	struct command *cmd;
	struct payment *payment;
	struct route *route;
};

static struct command_result *update_gossip(struct routefail *r);
static struct command_result *handle_failure(struct routefail *r);

struct command_result *routefail_start(const tal_t *ctx, struct route *route,
				       struct command *cmd)
{
	assert(route);
	struct routefail *r = tal(ctx, struct routefail);
	struct payment *payment =
		    payment_map_get(pay_plugin->payment_map, route->key.payment_hash);

	if (payment == NULL)
		plugin_err(pay_plugin->plugin,
			   "%s: payment with hash %s not found.",
			   __func__,
			   fmt_sha256(tmpctx, &route->key.payment_hash));

	r->payment = payment;
	r->route = route;
	r->cmd = cmd;
	assert(route->result);
	return update_gossip(r);
}

static struct command_result *routefail_end(struct routefail *r TAKES)
{
	/* Notify the tracker that route has failed and routefail have completed
	 * handling all possible errors cases. */
	struct command *cmd = r->cmd;
	route_failure_register(r->payment->routetracker, r->route);
	if (taken(r))
		r = tal_steal(tmpctx, r);
	return notification_handled(cmd);
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
						 struct routefail *r)
{
	return handle_failure(r);
}

static struct command_result *update_gossip_failure(struct command *cmd UNUSED,
						    const char *buf,
						    const jsmntok_t *result,
						    struct routefail *r)
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

static struct command_result *update_gossip(struct routefail *r)
{
	/* if there is no raw_message we continue */
	if (!r->route->result->raw_message)
		goto skip_update_gossip;

	const u8 *update = channel_update_from_onion_error(
	    tmpctx, r->route->result->raw_message);

	if (!update)
		goto skip_update_gossip;

	struct out_req *req =
	    jsonrpc_request_start(r->cmd, "addgossip",
				  update_gossip_done, update_gossip_failure, r);
	json_add_hex_talarr(req->js, "message", update);
	return send_outreq(req);

skip_update_gossip:
	return handle_failure(r);
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

static struct command_result *handle_failure(struct routefail *r)
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
	return routefail_end(take(r));
}
