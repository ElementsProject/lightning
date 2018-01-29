#include "pay.h"
#include <bitcoin/preimage.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <channeld/gen_channel_wire.h>
#include <common/bolt11.h>
#include <gossipd/gen_gossip_wire.h>
#include <gossipd/routing.h>
#include <inttypes.h>
#include <lightningd/chaintopology.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/subd.h>
#include <sodium/randombytes.h>

static void json_pay_success(struct command *cmd, const struct preimage *rval)
{
	struct json_result *response;

	/* Can be NULL if JSON RPC goes away. */
	if (!cmd)
		return;

	response = new_json_result(cmd);
	json_object_start(response, NULL);
	json_add_hex(response, "preimage", rval, sizeof(*rval));
	json_object_end(response);
	command_success(cmd, response);
}

static void json_pay_failed(struct command *cmd,
			    enum onion_type failure_code,
			    const char *details)
{
	/* Can be NULL if JSON RPC goes away. */
	if (cmd) {
		command_fail(cmd, "failed: %s (%s)",
			     onion_type_name(failure_code), details);
	}
}

void payment_succeeded(struct lightningd *ld, struct htlc_out *hout,
		       const struct preimage *rval)
{
	wallet_payment_set_status(ld->wallet, &hout->payment_hash,
				  PAYMENT_COMPLETE, rval);
	/* Can be NULL if JSON RPC goes away. */
	if (hout->cmd)
		json_pay_success(hout->cmd, rval);
	hout->cmd = NULL;
}

/* Return NULL if the wrapped onion error message has no
 * channel_update field, or return the embedded
 * channel_update message otherwise. */
static u8 *channel_update_from_onion_error(const tal_t *ctx,
					   const u8 *onion_message)
{
	u8 *channel_update = NULL;
	u64 unused64;
	u32 unused32;

	/* Identify failcodes that have some channel_update.
	 *
	 * TODO > BOLT 1.0: Add new failcodes when updating to a
	 * new BOLT version. */
	if (!fromwire_temporary_channel_failure(ctx,
						onion_message, NULL,
						&channel_update) &&
	    !fromwire_amount_below_minimum(ctx,
					   onion_message, NULL, &unused64,
					   &channel_update) &&
	    !fromwire_fee_insufficient(ctx,
		    		       onion_message, NULL, &unused64,
				       &channel_update) &&
	    !fromwire_incorrect_cltv_expiry(ctx,
		    			    onion_message, NULL, &unused32,
					    &channel_update) &&
	    !fromwire_expiry_too_soon(ctx,
		    		      onion_message, NULL,
				      &channel_update))
		/* No channel update. */
		channel_update = NULL;

	return channel_update;
}

struct routing_failure {
	enum onion_type failcode;
	struct pubkey erring_node;
	struct short_channel_id erring_channel;
	u8 *channel_update;
};

/* Return a struct routing_failure for a local failure allocated
 * from the given context. */
static struct routing_failure*
local_routing_failure(const tal_t *ctx,
		      const struct lightningd *ld,
		      const struct htlc_out *hout,
		      const struct wallet_payment *payment)
{
	struct routing_failure *routing_failure;

	assert(hout->failcode);

	routing_failure = tal(ctx, struct routing_failure);
	routing_failure->failcode = hout->failcode;
	routing_failure->erring_node = ld->id;
	routing_failure->erring_channel = payment->route_channels[0];
	routing_failure->channel_update = NULL;

	return routing_failure;
}

/* Return false if permanent failure at the destination, true if
 * retrying is plausible. Fill *routing_failure with NULL if
 * we cannot report the remote failure, or with the routing
 * failure to report (allocated from ctx) otherwise. */
static bool remote_routing_failure(const tal_t *ctx,
				   struct routing_failure **routing_failure,
				   const struct wallet_payment *payment,
				   const struct onionreply *failure)
{
	enum onion_type failcode = fromwire_peektype(failure->msg);
	u8 *channel_update;
	const struct pubkey *route_nodes;
	const struct pubkey *erring_node;
	const struct short_channel_id *route_channels;
	const struct short_channel_id *erring_channel;
	static const struct short_channel_id dummy_channel = { 0, 0, 0 };
	int origin_index;
	bool retry_plausible;
	bool report_to_gossipd;

	*routing_failure = tal(ctx, struct routing_failure);
	route_nodes = payment->route_nodes;
	route_channels = payment->route_channels;
	origin_index = failure->origin_index;
	channel_update
		= channel_update_from_onion_error(*routing_failure,
						  failure->msg);
	retry_plausible = true;
	report_to_gossipd = true;

	assert(origin_index < tal_count(route_nodes));

	/* Check if at destination. */
	if (origin_index == tal_count(route_nodes) - 1) {
		/* BOLT #4:
		 *
		 * - if the _final node_ is returning the error:
		 *   - if the PERM bit is set:
		 *     - SHOULD fail the payment.
		 * */
		if (failcode & PERM)
			retry_plausible = false;
		else
			retry_plausible = true;
		/* Only send message to gossipd if NODE error;
		 * there is no "next" channel to report as
		 * failing if this is the last node. */
		if (failcode & NODE) {
			erring_channel = &dummy_channel;
			report_to_gossipd = true;
		} else
			report_to_gossipd = false;
	} else
		/* Report the *next* channel as failing. */
		erring_channel = &route_channels[origin_index + 1];

	erring_node = &route_nodes[origin_index];

	if (report_to_gossipd) {
		(*routing_failure)->failcode = failcode;
		(*routing_failure)->erring_node = *erring_node;
		(*routing_failure)->erring_channel = *erring_channel;
		(*routing_failure)->channel_update = channel_update;
	} else
		*routing_failure = tal_free(*routing_failure);

	return retry_plausible;
}

static void report_routing_failure(struct subd *gossip,
				   struct routing_failure *fail)
{
	u8 *gossip_msg
		= towire_gossip_routing_failure(gossip,
						&fail->erring_node,
						&fail->erring_channel,
						(u16) fail->failcode,
						fail->channel_update);
	subd_send_msg(gossip, gossip_msg);

	tal_free(gossip_msg);
}

void payment_failed(struct lightningd *ld, const struct htlc_out *hout,
		    const char *localfail)
{
	struct onionreply *reply;
	enum onion_type failcode;
	struct secret *path_secrets;
	struct wallet_payment *payment;
	const tal_t *tmpctx = tal_tmpctx(ld);
	struct routing_failure* fail = NULL;
	const char *failmsg;
	bool retry_plausible;

	payment = wallet_payment_by_hash(tmpctx, ld->wallet,
					 &hout->payment_hash);

	/* This gives more details than a generic failure message */
	if (localfail) {
		fail = local_routing_failure(tmpctx, ld, hout, payment);
		failcode = fail->failcode;
		failmsg = localfail;
		retry_plausible = true;
	} else {
		/* Must be remote fail. */
		assert(!hout->failcode);
		failmsg = "reply from remote";
		/* Try to parse reply. */
		path_secrets = payment->path_secrets;
		reply = unwrap_onionreply(tmpctx, path_secrets,
					  tal_count(path_secrets),
					  hout->failuremsg);
		if (!reply) {
			log_info(hout->key.peer->log,
				 "htlc %"PRIu64" failed with bad reply (%s)",
				 hout->key.id,
				 tal_hex(ltmp, hout->failuremsg));
			/* Cannot report failure. */
			fail = NULL;
			failcode = WIRE_PERMANENT_NODE_FAILURE;
			/* Not safe to retry, not know what failed. */
			/* FIXME: some mitigation for this branch. */
			retry_plausible = false;
		} else {
			failcode = fromwire_peektype(reply->msg);
			log_info(hout->key.peer->log,
				 "htlc %"PRIu64" "
				 "failed from %ith node "
				 "with code 0x%04x (%s)",
				 hout->key.id,
				 reply->origin_index,
				 failcode, onion_type_name(failcode));
			retry_plausible
				= remote_routing_failure(tmpctx, &fail,
							 payment, reply);
		}
	}

	/* This may invalidated the payment structure returned, so
	 * access to payment object should not be done after the
	 * below call.  */
	wallet_payment_set_status(ld->wallet, &hout->payment_hash,
				  PAYMENT_FAILED, NULL);

	/* Report to gossipd if there is something we can report. */
	if (fail) {
		log_debug(ld->log,
			  "Reporting route failure to gossipd: 0x%04x (%s) "
			  "node %s channel %s update %s",
			  fail->failcode, onion_type_name(fail->failcode),
			  type_to_string(tmpctx, struct pubkey,
					 &fail->erring_node),
			  type_to_string(tmpctx, struct short_channel_id,
				  	 &fail->erring_channel),
			  tal_hex(tmpctx, fail->channel_update));
		report_routing_failure(ld->gossip, fail);
	}

	/* FIXME(ZmnSCPxj): if retrying is plausible, and we are
	 * using pay command rather than sendpay, retry routing
	 * and payment again. */
	(void) retry_plausible;

	json_pay_failed(hout->cmd, failcode, failmsg);
	tal_free(tmpctx);
}

/* When JSON RPC goes away, cmd is freed: detach from the hout */
static void remove_cmd_from_hout(struct command *cmd, struct htlc_out *hout)
{
	assert(hout->cmd == cmd);
	hout->cmd = NULL;
}

/* Returns true if it's still pending. */
static bool send_payment(struct command *cmd,
			 const struct sha256 *rhash,
			 const struct route_hop *route)
{
	struct peer *peer;
	const u8 *onion;
	u8 sessionkey[32];
	unsigned int base_expiry;
	struct onionpacket *packet;
	struct secret *path_secrets;
	enum onion_type failcode;
	/* Freed automatically on cmd completion: only manually at end. */
	const tal_t *tmpctx = tal_tmpctx(cmd);
	size_t i, n_hops = tal_count(route);
	struct hop_data *hop_data = tal_arr(tmpctx, struct hop_data, n_hops);
	struct pubkey *ids = tal_arr(tmpctx, struct pubkey, n_hops);
	struct wallet_payment *payment = NULL;
	struct htlc_out *hout;
	struct short_channel_id *channels;

	/* Expiry for HTLCs is absolute.  And add one to give some margin. */
	base_expiry = get_block_height(cmd->ld->topology) + 1;

	/* Extract IDs for each hop: create_onionpacket wants array. */
	for (i = 0; i < n_hops; i++)
		ids[i] = route[i].nodeid;

	/* Copy hop_data[n] from route[n+1] (ie. where it goes next) */
	for (i = 0; i < n_hops - 1; i++) {
		hop_data[i].realm = 0;
		hop_data[i].channel_id = route[i+1].channel_id;
		hop_data[i].amt_forward = route[i+1].amount;
		hop_data[i].outgoing_cltv = base_expiry + route[i+1].delay;
	}

	/* And finally set the final hop to the special values in
	 * BOLT04 */
	hop_data[i].realm = 0;
	hop_data[i].outgoing_cltv = base_expiry + route[i].delay;
	memset(&hop_data[i].channel_id, 0, sizeof(struct short_channel_id));
	hop_data[i].amt_forward = route[i].amount;

	/* Now, do we already have a payment? */
	payment = wallet_payment_by_hash(tmpctx, cmd->ld->wallet, rhash);
	if (payment) {
		/* FIXME: We should really do something smarter here! */
		log_debug(cmd->ld->log, "json_sendpay: found previous");
		if (payment->status == PAYMENT_PENDING) {
			log_add(cmd->ld->log, "... still in progress");
			command_fail(cmd, "still in progress");
			return false;
		}
		if (payment->status == PAYMENT_COMPLETE) {
			log_add(cmd->ld->log, "... succeeded");
			/* Must match successful payment parameters. */
			if (payment->msatoshi != hop_data[n_hops-1].amt_forward) {
				command_fail(cmd,
					     "already succeeded with amount %"
					     PRIu64, payment->msatoshi);
				return false;
			}
			if (!structeq(&payment->destination, &ids[n_hops-1])) {
				command_fail(cmd,
					     "already succeeded to %s",
					     type_to_string(cmd, struct pubkey,
							    &payment->destination));
				return false;
			}
			json_pay_success(cmd, payment->payment_preimage);
			return false;
		}
		wallet_payment_delete(cmd->ld->wallet, rhash);
		log_add(cmd->ld->log, "... retrying");
	}

	peer = peer_by_id(cmd->ld, &ids[0]);
	if (!peer) {
		command_fail(cmd, "no connection to first peer found");
		return false;
	}

	randombytes_buf(&sessionkey, sizeof(sessionkey));

	/* Onion will carry us from first peer onwards. */
	packet = create_onionpacket(cmd, ids, hop_data, sessionkey, rhash->u.u8,
				    sizeof(struct sha256), &path_secrets);
	onion = serialize_onionpacket(cmd, packet);

	log_info(cmd->ld->log, "Sending %u over %zu hops to deliver %u",
		 route[0].amount, n_hops, route[n_hops-1].amount);

	failcode = send_htlc_out(peer, route[0].amount,
				 base_expiry + route[0].delay,
				 rhash, onion, NULL, cmd,
				 &hout);
	if (failcode) {
		command_fail(cmd, "first peer not ready: %s",
			     onion_type_name(failcode));
		return false;
	}

	/* Copy channels used along the route. */
	channels = tal_arr(tmpctx, struct short_channel_id, n_hops);
	for (i = 0; i < n_hops; ++i)
		channels[i] = route[i].channel_id;

	/* If hout fails, payment should be freed too. */
	payment = tal(hout, struct wallet_payment);
	payment->id = 0;
	payment->payment_hash = *rhash;
	payment->destination = ids[n_hops - 1];
	payment->status = PAYMENT_PENDING;
	payment->msatoshi = route[n_hops-1].amount;
	payment->timestamp = time_now().ts.tv_sec;
	payment->payment_preimage = NULL;
	payment->path_secrets = tal_steal(payment, path_secrets);
	payment->route_nodes = tal_steal(payment, ids);
	payment->route_channels = tal_steal(payment, channels);

	/* We write this into db when HTLC is actually sent. */
	wallet_payment_setup(cmd->ld->wallet, payment);

	/* If we fail, remove cmd ptr from htlc_out. */
	tal_add_destructor2(cmd, remove_cmd_from_hout, hout);

	tal_free(tmpctx);
	return true;
}

static void json_sendpay(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *routetok, *rhashtok;
	const jsmntok_t *t, *end;
	size_t n_hops;
	struct sha256 rhash;
	struct route_hop *route;

	if (!json_get_params(buffer, params,
			     "route", &routetok,
			     "rhash", &rhashtok,
			     NULL)) {
		command_fail(cmd, "Need route and rhash");
		return;
	}

	if (!hex_decode(buffer + rhashtok->start,
			rhashtok->end - rhashtok->start,
			&rhash, sizeof(rhash))) {
		command_fail(cmd, "'%.*s' is not a valid sha256 hash",
			     (int)(rhashtok->end - rhashtok->start),
			     buffer + rhashtok->start);
		return;
	}

	if (routetok->type != JSMN_ARRAY) {
		command_fail(cmd, "'%.*s' is not an array",
			     (int)(routetok->end - routetok->start),
			     buffer + routetok->start);
		return;
	}

	end = json_next(routetok);
	n_hops = 0;
	route = tal_arr(cmd, struct route_hop, n_hops);

	for (t = routetok + 1; t < end; t = json_next(t)) {
		const jsmntok_t *amttok, *idtok, *delaytok, *chantok;

		if (t->type != JSMN_OBJECT) {
			command_fail(cmd, "route %zu '%.*s' is not an object",
				     n_hops,
				     (int)(t->end - t->start),
				     buffer + t->start);
			return;
		}
		amttok = json_get_member(buffer, t, "msatoshi");
		idtok = json_get_member(buffer, t, "id");
		delaytok = json_get_member(buffer, t, "delay");
		chantok = json_get_member(buffer, t, "channel");
		if (!amttok || !idtok || !delaytok || !chantok) {
			command_fail(cmd, "route %zu needs msatoshi/id/channel/delay",
				     n_hops);
			return;
		}

		tal_resize(&route, n_hops + 1);

		/* What that hop will forward */
		if (!json_tok_number(buffer, amttok, &route[n_hops].amount)) {
			command_fail(cmd, "route %zu invalid msatoshi",
				     n_hops);
			return;
		}

		if (!json_tok_short_channel_id(buffer, chantok,
					       &route[n_hops].channel_id)) {
			command_fail(cmd, "route %zu invalid channel_id", n_hops);
			return;
		}
		if (!json_tok_pubkey(buffer, idtok, &route[n_hops].nodeid)) {
			command_fail(cmd, "route %zu invalid id", n_hops);
			return;
		}
		if (!json_tok_number(buffer, delaytok, &route[n_hops].delay)) {
			command_fail(cmd, "route %zu invalid delay", n_hops);
			return;
		}
		n_hops++;
	}

	if (n_hops == 0) {
		command_fail(cmd, "Empty route");
		return;
	}

	if (send_payment(cmd, &rhash, route))
		command_still_pending(cmd);
}

static const struct json_command sendpay_command = {
	"sendpay",
	json_sendpay,
	"Send along {route} in return for preimage of {rhash}"
};
AUTODATA(json_command, &sendpay_command);

struct pay {
	struct sha256 payment_hash;
	struct command *cmd;
};

static void json_pay_getroute_reply(struct subd *gossip,
				    const u8 *reply, const int *fds,
				    struct pay *pay)
{
	struct route_hop *route;

	fromwire_gossip_getroute_reply(reply, reply, NULL, &route);

	if (tal_count(route) == 0) {
		command_fail(pay->cmd, "Could not find a route");
		return;
	}

	send_payment(pay->cmd, &pay->payment_hash, route);
}

static void json_pay(struct command *cmd,
		     const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *bolt11tok, *msatoshitok, *desctok, *riskfactortok;
	double riskfactor = 1.0;
	u64 msatoshi;
	struct pay *pay = tal(cmd, struct pay);
	struct bolt11 *b11;
	char *fail, *b11str, *desc;
	u8 *req;

	if (!json_get_params(buffer, params,
			     "bolt11", &bolt11tok,
			     "?msatoshi", &msatoshitok,
			     "?description", &desctok,
			     "?riskfactor", &riskfactortok,
			     NULL)) {
		command_fail(cmd, "Need bolt11 string");
		return;
	}

	b11str = tal_strndup(cmd, buffer + bolt11tok->start,
			     bolt11tok->end - bolt11tok->start);
	if (desctok)
		desc = tal_strndup(cmd, buffer + desctok->start,
				   desctok->end - desctok->start);
	else
		desc = NULL;

	b11 = bolt11_decode(pay, b11str, desc, &fail);
	if (!b11) {
		command_fail(cmd, "Invalid bolt11: %s", fail);
		return;
	}

	pay->cmd = cmd;
	pay->payment_hash = b11->payment_hash;

	if (b11->msatoshi) {
		msatoshi = *b11->msatoshi;
		if (msatoshitok) {
			command_fail(cmd, "msatoshi parameter unnecessary");
			return;
		}
	} else {
		if (!msatoshitok) {
			command_fail(cmd, "msatoshi parameter required");
			return;
		}
		if (!json_tok_u64(buffer, msatoshitok, &msatoshi)) {
			command_fail(cmd,
				     "msatoshi '%.*s' is not a valid number",
				     (int)(msatoshitok->end-msatoshitok->start),
				     buffer + msatoshitok->start);
			return;
		}
	}

	if (riskfactortok
	    && !json_tok_double(buffer, riskfactortok, &riskfactor)) {
		command_fail(cmd, "'%.*s' is not a valid double",
			     (int)(riskfactortok->end - riskfactortok->start),
			     buffer + riskfactortok->start);
		return;
	}

	/* FIXME: use b11->routes */
	req = towire_gossip_getroute_request(cmd, &cmd->ld->id,
					     &b11->receiver_id,
					     msatoshi, riskfactor*1000,
					     b11->min_final_cltv_expiry);
	subd_req(pay, cmd->ld->gossip, req, -1, 0, json_pay_getroute_reply, pay);
	command_still_pending(cmd);
}

static const struct json_command pay_command = {
	"pay",
	json_pay,
	"Send payment specified by {bolt11} with optional {msatoshi} (if and only if {bolt11} does not have amount), {description} (required if {bolt11} uses description hash) and {riskfactor} (default 1.0)"
};
AUTODATA(json_command, &pay_command);

static void json_listpayments(struct command *cmd, const char *buffer,
			       const jsmntok_t *params)
{
	const struct wallet_payment **payments;
	struct json_result *response = new_json_result(cmd);
	jsmntok_t *bolt11tok, *rhashtok;
	struct sha256 *rhash = NULL;

	if (!json_get_params(buffer, params,
			     "?bolt11", &bolt11tok,
			     "?payment_hash", &rhashtok,
			     NULL)) {
		command_fail(cmd, "Invalid parameters");
		return;
	}

	if (bolt11tok) {
		struct bolt11 *b11;
		char *b11str, *fail;

		if (rhashtok) {
			command_fail(cmd, "Can only specify one of"
				     " {bolt11} or {payment_hash}");
			return;
		}

		b11str = tal_strndup(cmd, buffer + bolt11tok->start,
				     bolt11tok->end - bolt11tok->start);

		b11 = bolt11_decode(cmd, b11str, NULL, &fail);
		if (!b11) {
			command_fail(cmd, "Invalid bolt11: %s", fail);
			return;
		}
		rhash = &b11->payment_hash;
	} else if (rhashtok) {
		rhash = tal(cmd, struct sha256);
		if (!hex_decode(buffer + rhashtok->start,
				rhashtok->end - rhashtok->start,
				rhash, sizeof(*rhash))) {
			command_fail(cmd, "'%.*s' is not a valid sha256 hash",
				     (int)(rhashtok->end - rhashtok->start),
				     buffer + rhashtok->start);
			return;
		}
	}

	payments = wallet_payment_list(cmd, cmd->ld->wallet, rhash);

	json_object_start(response, NULL);
	json_array_start(response, "payments");
	for (int i=0; i<tal_count(payments); i++) {
		const struct wallet_payment *t = payments[i];
		json_object_start(response, NULL);
		json_add_u64(response, "id", t->id);
		json_add_hex(response, "payment_hash", &t->payment_hash, sizeof(t->payment_hash));
		json_add_pubkey(response, "destination", &t->destination);
		json_add_u64(response, "msatoshi", t->msatoshi);
		if (deprecated_apis)
			json_add_u64(response, "timestamp", t->timestamp);
		json_add_u64(response, "created_at", t->timestamp);

		switch (t->status) {
		case PAYMENT_PENDING:
			json_add_string(response, "status", "pending");
			break;
		case PAYMENT_COMPLETE:
			json_add_string(response, "status", "complete");
			break;
		case PAYMENT_FAILED:
			json_add_string(response, "status", "failed");
			break;
		}
		if (t->payment_preimage)
			json_add_hex(response, "payment_preimage",
				     t->payment_preimage,
				     sizeof(*t->payment_preimage));

		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command listpayments_command = {
	"listpayments",
	json_listpayments,
	"Show outgoing payments"
};
AUTODATA(json_command, &listpayments_command);
