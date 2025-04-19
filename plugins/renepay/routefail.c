#include "config.h"
#include <common/json_stream.h>
#include <common/jsonrpc_errors.h>
#include <plugins/renepay/renepay.h>
#include <plugins/renepay/renepayconfig.h>
#include <plugins/renepay/routefail.h>
#include <plugins/renepay/routetracker.h>
#include <plugins/renepay/utils.h>
#include <wire/peer_wiregen.h>

#define MIN(x, y) ((x) < (y) ? (x) : (y))

enum node_type {
	FINAL_NODE,
	INTERMEDIATE_NODE,
	ORIGIN_NODE,
	UNKNOWN_NODE
};

struct routefail {
	struct rpcbatch *batch;
	struct payment *payment;
	struct route *route;
};

static bool get_erring_scidd(struct route *route,
			     struct short_channel_id_dir *scidd)
{
	assert(scidd);
	if (!route->result->erring_direction || !route->result->erring_channel)
		return false;
	scidd->dir = *route->result->erring_direction;
	scidd->scid = *route->result->erring_channel;
	return true;
}

static void update_gossip(struct routefail *r);

static void handle_failure(struct routefail *r);

static struct command_result *log_routefail_err(struct command *cmd,
						const char *method,
						const char *buf,
						const jsmntok_t *tok,
						struct routefail *r)
{
	plugin_log(cmd->plugin, LOG_UNUSUAL,
		   "routefail batch failed: %s failed: '%.*s'", method,
		   json_tok_full_len(tok), json_tok_full(buf, tok));
	return command_still_pending(cmd);
}

static struct command_result *routefail_done(struct command *cmd,
					    struct routefail *r)
{
	/* Notify the tracker that route has failed and routefail have completed
	 * handling all possible errors cases. */
	routetracker_add_to_final(r->payment, r->payment->routetracker, r->route);
	tal_free(r);
	return notification_handled(cmd);
}

struct command_result *routesuccess_start(struct command *cmd,
					  struct route *route)
{
	// FIXME: call askrene-inform-channel with inform=succeeded for this
	// route
	struct renepay *renepay = get_renepay(cmd->plugin);
	struct payment *payment = route_get_payment_verify(renepay, route);
	routetracker_add_to_final(payment, payment->routetracker, route);
	return notification_handled(cmd);
}

struct command_result *routefail_start(struct command *cmd, struct route *route)
{
	struct renepay *renepay = get_renepay(cmd->plugin);
	struct routefail *r = tal(cmd, struct routefail);
	r->batch = rpcbatch_new(cmd, routefail_done, r);
	r->route = route;
	r->payment = route_get_payment_verify(renepay, route);
	update_gossip(r);
	handle_failure(r);
	return rpcbatch_done(r->batch);
}

static void disable_node(struct routefail *r, struct node_id *node)
{
	struct out_req *req = add_to_rpcbatch(r->batch, "askrene-disable-node",
					      NULL, log_routefail_err, r);
	json_add_string(req->js, "layer", r->payment->payment_layer);
	json_add_node_id(req->js, "node", node);
	send_outreq(req);
}

static void disable_channel(struct routefail *r,
			    struct short_channel_id_dir scidd)
{
	struct out_req *req = add_to_rpcbatch(
	    r->batch, "askrene-udpate-channel", NULL, log_routefail_err, r);
	json_add_string(req->js, "layer", r->payment->payment_layer);
	json_add_short_channel_id_dir(req->js, "short_channel_id_dir", scidd);
	json_add_bool(req->js, "enabled", false);
	send_outreq(req);
}

static void bias_channel(struct routefail *r, struct short_channel_id_dir scidd,
			 int bias)
{
	// FIXME: we want to increment the bias, not set it
	struct out_req *req = add_to_rpcbatch(r->batch, "askrene-bias-channel",
					      NULL, log_routefail_err, r);
	json_add_string(req->js, "layer", r->payment->payment_layer);
	json_add_short_channel_id_dir(req->js, "short_channel_id_dir", scidd);
	json_add_num(req->js, "bias", bias);
	send_outreq(req);
}

static void channel_can_send(struct routefail *r,
			     struct short_channel_id_dir scidd,
			     struct amount_msat amount)
{
	struct out_req *req = add_to_rpcbatch(
	    r->batch, "askrene-inform-channel", NULL, log_routefail_err, r);
	json_add_string(req->js, "layer", RENEPAY_LAYER);
	json_add_short_channel_id_dir(req->js, "short_channel_id_dir", scidd);
	json_add_amount_msat(req->js, "amount_msat", amount);
	json_add_string(req->js, "inform", "unconstrained");
	send_outreq(req);
}

static void channel_cannot_send(struct routefail *r,
				struct short_channel_id_dir scidd,
				struct amount_msat amount)
{
	struct out_req *req = add_to_rpcbatch(
	    r->batch, "askrene-inform-channel", NULL, log_routefail_err, r);
	json_add_string(req->js, "layer", RENEPAY_LAYER);
	json_add_short_channel_id_dir(req->js, "short_channel_id_dir", scidd);
	json_add_amount_msat(req->js, "amount_msat", amount);
	json_add_string(req->js, "inform", "constrained");
	send_outreq(req);
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

static struct command_result *
addgossip_fail(struct command *cmd, const char *method, const char *buf,
	       const jsmntok_t *result, struct routefail *r)
{
	struct short_channel_id_dir scidd;
	if (get_erring_scidd(r->route, &scidd)) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "failed to update gossip of erring channel %s",
			   fmt_short_channel_id_dir(tmpctx, &scidd));
		disable_channel(r, scidd);
	} else {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "failed to update gossip of UNKNOWN erring channel");
	}
	return command_still_pending(cmd);
}

static void update_gossip(struct routefail *r)
{
	/* if there is no raw_message we continue */
	if (!r->route->result->raw_message)
		goto skip_update_gossip;

	const u8 *update = channel_update_from_onion_error(
	    tmpctx, r->route->result->raw_message);

	if (!update)
		goto skip_update_gossip;

	struct out_req *req = add_to_rpcbatch(
	    r->batch, "addgossip", NULL, addgossip_fail, r);
	json_add_hex_talarr(req->js, "message", update);
	send_outreq(req);

skip_update_gossip:
	return;
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

/* FIXME: do proper error handling for BOLT12 */
static void handle_failure(struct routefail *r)
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
	struct short_channel_id_dir scidd;

	int path_len = 0;
	if (route->hops)
		path_len = tal_count(route->hops);

	enum onion_wire failcode;
	if(result->failcode)
		failcode = *result->failcode;
	else{
		payment_note(
		    payment, LOG_UNUSUAL,
		    "The failcode is unknown we skip error handling");
		goto finish;
	}

	if (!result->erring_index) {
		payment_note(
		    payment, LOG_UNUSUAL,
		    "The erring_index is unknown we skip error handling");
		goto finish;
	}

	enum node_type node_type = UNKNOWN_NODE;
	if (route->hops) {
		if (*result->erring_index == path_len)
			node_type = FINAL_NODE;
		else if (*result->erring_index == 0)
			node_type = ORIGIN_NODE;
		else
			node_type = INTERMEDIATE_NODE;

		/* All channels before the hop that failed have supposedly the
		 * ability to forward the payment. This is information. */
		const int last_good_channel =
		    MIN(*result->erring_index, path_len) - 1;
		for (int i = 0; i <= last_good_channel; i++) {
			scidd.scid = route->hops[i].scid;
			scidd.dir = route->hops[i].direction;
			channel_can_send(r, scidd, route->hops[i].amount);
		}
		if (failcode == WIRE_TEMPORARY_CHANNEL_FAILURE &&
		    (last_good_channel + 1) < path_len) {
			scidd.scid = route->hops[last_good_channel + 1].scid;
			scidd.dir =
			    route->hops[last_good_channel + 1].direction;
			channel_cannot_send(
			    r, scidd,
			    route->hops[last_good_channel + 1].amount);
		}
	}

	switch (failcode) {
	// intermediate only
	case WIRE_INVALID_ONION_VERSION:
	case WIRE_INVALID_ONION_HMAC:
	case WIRE_INVALID_ONION_KEY:
		switch (node_type) {
		case FINAL_NODE:
			payment_note(payment, LOG_UNUSUAL,
				     "Final node reported strange "
				     "error code %04x (%s)",
				     failcode,
				     onion_wire_name(failcode));
			break;
		case ORIGIN_NODE:
		case INTERMEDIATE_NODE:
		case UNKNOWN_NODE:
			break;
		}

	case WIRE_INVALID_ONION_BLINDING:
		switch (node_type) {
		case FINAL_NODE:
			/* these errors from a final node mean a permanent
			 * failure */
			route_final_error(
			    route, PAY_DESTINATION_PERM_FAIL,
			    "Received error code %04x (%s) at final node.",
			    failcode,
			    onion_wire_name(failcode));

			break;
		case INTERMEDIATE_NODE:
		case ORIGIN_NODE:
			if (!route->hops)
				break;

			/* we disable the next node in the hop */
			assert(*result->erring_index < path_len);
			payment_disable_node(
			    payment, route->hops[*result->erring_index].node_id,
			    LOG_DBG, "received %s from previous hop",
			    onion_wire_name(failcode));
			disable_node(
			    r, &route->hops[*result->erring_index].node_id);
			break;
		case UNKNOWN_NODE:
			break;
		}
		break;

	// final only
	case WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
		switch (node_type) {
		case FINAL_NODE:
			route_final_error(route, PAY_DESTINATION_PERM_FAIL,
					  "Unknown invoice or wrong payment "
					  "details at destination.");
			break;
		case ORIGIN_NODE:
			route_final_error(
			    route, PAY_UNSPECIFIED_ERROR,
			    "Error code %04x (%s) reported at the origin.",
			    failcode,
			    onion_wire_name(failcode));
			break;
		case INTERMEDIATE_NODE:
			if (!route->hops)
				break;
			payment_disable_node(
			    payment,
			    route->hops[*result->erring_index - 1].node_id,
			    LOG_INFORM, "received error %s",
			    onion_wire_name(failcode));
			disable_node(
			    r, &route->hops[*result->erring_index - 1].node_id);
			break;
		case UNKNOWN_NODE:
			break;
		}
		break;
	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
		switch (node_type) {
		case INTERMEDIATE_NODE:
			payment_note(payment, LOG_UNUSUAL,
				     "Intermediate node reported strange "
				     "error code %04x (%s)",
				     failcode,
				     onion_wire_name(failcode));
			break;
		case ORIGIN_NODE:
		case FINAL_NODE:
		case UNKNOWN_NODE:
			break;
		}

	case WIRE_PERMANENT_NODE_FAILURE:
	case WIRE_REQUIRED_NODE_FEATURE_MISSING:
	case WIRE_TEMPORARY_NODE_FAILURE:
	case WIRE_INVALID_ONION_PAYLOAD:
		switch (node_type) {
		case FINAL_NODE:
			route_final_error(
			    route, PAY_DESTINATION_PERM_FAIL,
			    "Received error code %04x (%s) at final node.",
			    failcode,
			    onion_wire_name(failcode));
			break;
		case ORIGIN_NODE:
			route_final_error(
			    route, PAY_UNSPECIFIED_ERROR,
			    "Error code %04x (%s) reported at the origin.",
			    failcode,
			    onion_wire_name(failcode));
			break;
		case INTERMEDIATE_NODE:
			if (!route->hops)
				break;
			payment_disable_node(
			    payment,
			    route->hops[*result->erring_index - 1].node_id,
			    LOG_INFORM, "received error %s",
			    onion_wire_name(failcode));
			disable_node(
			    r, &route->hops[*result->erring_index - 1].node_id);
			break;
		case UNKNOWN_NODE:
			break;
		}
		break;

	// intermediate only
	case WIRE_PERMANENT_CHANNEL_FAILURE:
	case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
	case WIRE_UNKNOWN_NEXT_PEER:
	case WIRE_EXPIRY_TOO_FAR:
	case WIRE_CHANNEL_DISABLED:
		switch (node_type) {
		case FINAL_NODE:
			payment_note(payment, LOG_UNUSUAL,
				     "Final node reported strange "
				     "error code %04x (%s)",
				     failcode,
				     onion_wire_name(failcode));

			route_final_error(
			    route, PAY_DESTINATION_PERM_FAIL,
			    "Received error code %04x (%s) at final node.",
			    failcode,
			    onion_wire_name(failcode));

			break;
		case ORIGIN_NODE:
			payment_note(payment, LOG_UNUSUAL,
				     "First node reported strange "
				     "error code %04x (%s)",
				     failcode,
				     onion_wire_name(failcode));

			break;
		case INTERMEDIATE_NODE:
			if (!route->hops)
				break;
			payment_disable_chan(payment, scidd, LOG_INFORM, "%s",
					     onion_wire_name(failcode));
			if (get_erring_scidd(r->route, &scidd))
				disable_channel(r, scidd);
			break;
		case UNKNOWN_NODE:
			break;
		}
		break;
	// final only
	case WIRE_MPP_TIMEOUT:
		switch (node_type) {
		case INTERMEDIATE_NODE:
			/* Normally WIRE_MPP_TIMEOUT is raised by the final
			 * node. If this is not the final node, then something
			 * wrong is going on. We report it and disable that
			 * node. */
			payment_note(payment, LOG_UNUSUAL,
				     "Intermediate node reported strange "
				     "error code %04x (%s)",
				     failcode,
				     onion_wire_name(failcode));

			if (!route->hops)
				break;
			payment_disable_node(
			    payment,
			    route->hops[*result->erring_index - 1].node_id,
			    LOG_INFORM, "received error %s",
			    onion_wire_name(failcode));
			disable_node(
			    r, &route->hops[*result->erring_index - 1].node_id);
			break;
		case ORIGIN_NODE:
		case FINAL_NODE:
		case UNKNOWN_NODE:
			break;
		}
		break;

	// intermediate only
	case WIRE_EXPIRY_TOO_SOON:
	case WIRE_INCORRECT_CLTV_EXPIRY:
	case WIRE_FEE_INSUFFICIENT:
	case WIRE_AMOUNT_BELOW_MINIMUM:
		switch (node_type) {
		case FINAL_NODE:
			payment_note(payment, LOG_UNUSUAL,
				     "Final node reported strange "
				     "error code %04x (%s)",
				     failcode,
				     onion_wire_name(failcode));

			route_final_error(
			    route, PAY_DESTINATION_PERM_FAIL,
			    "Received error code %04x (%s) at final node.",
			    failcode,
			    onion_wire_name(failcode));

			break;
		case ORIGIN_NODE:
			payment_note(payment, LOG_UNUSUAL,
				     "First node reported strange "
				     "error code %04x (%s)",
				     failcode,
				     onion_wire_name(failcode));

			break;
		case INTERMEDIATE_NODE:
			if (!route->hops)
				break;
			/* Usually this means we need to update the channel
			 * information and try again. To avoid hitting this
			 * error again with the same channel we flag it. */
			payment_warn_chan(payment, scidd, LOG_INFORM,
					  "received error %s",
					  onion_wire_name(failcode));
			if (get_erring_scidd(r->route, &scidd))
				bias_channel(r, scidd, -1);
			break;
		case UNKNOWN_NODE:
			break;
		}
		break;
	// intermediate only
	case WIRE_TEMPORARY_CHANNEL_FAILURE:
		switch (node_type) {
		case FINAL_NODE:
			/* WIRE_TEMPORARY_CHANNEL_FAILURE could mean that the
			 * next channel has not enough outbound liquidity or
			 * cannot add another HTLC. A final node cannot raise
			 * this error. */
			payment_note(payment, LOG_UNUSUAL,
				     "Final node reported strange "
				     "error code %04x (%s)",
				     failcode,
				     onion_wire_name(failcode));

			route_final_error(
			    route, PAY_DESTINATION_PERM_FAIL,
			    "Received error code %04x (%s) at final node.",
			    failcode,
			    onion_wire_name(failcode));

			break;
		case INTERMEDIATE_NODE:
		case ORIGIN_NODE:
		case UNKNOWN_NODE:
			break;
		}
		break;
	}

finish:
	return;
}
