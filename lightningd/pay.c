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
			    const struct pubkey *sender,
			    enum onion_type failure_code,
			    const char *details)
{
	/* Can be NULL if JSON RPC goes away. */
	if (cmd) {
		/* FIXME: Report sender! */
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

void payment_failed(struct lightningd *ld, const struct htlc_out *hout,
		    const char *localfail)
{
	struct onionreply *reply;
	enum onion_type failcode;
	struct secret *path_secrets;
	const tal_t *tmpctx = tal_tmpctx(ld);

	wallet_payment_set_status(ld->wallet, &hout->payment_hash,
				  PAYMENT_FAILED, NULL);

	/* This gives more details than a generic failure message */
	if (localfail) {
		json_pay_failed(hout->cmd, NULL, hout->failcode, localfail);
		tal_free(tmpctx);
		return;
	}

	/* Must be remote fail. */
	assert(!hout->failcode);
	path_secrets = wallet_payment_get_secrets(tmpctx, ld->wallet,
						  &hout->payment_hash);
	reply = unwrap_onionreply(tmpctx, path_secrets, tal_count(path_secrets),
				  hout->failuremsg);
	if (!reply) {
		log_info(hout->key.peer->log,
			 "htlc %"PRIu64" failed with bad reply (%s)",
			 hout->key.id,
			 tal_hex(ltmp, hout->failuremsg));
		failcode = WIRE_PERMANENT_NODE_FAILURE;
	} else {
		failcode = fromwire_peektype(reply->msg);
		log_info(hout->key.peer->log,
			 "htlc %"PRIu64" failed from %ith node with code 0x%04x (%s)",
			 hout->key.id,
			 reply->origin_index,
			 failcode, onion_type_name(failcode));
	}

	/* FIXME: save ids we can turn reply->origin_index into sender. */

	/* FIXME: check for routing failure / perm fail. */
	/* check_for_routing_failure(i, sender, failure_code); */

	json_pay_failed(hout->cmd, NULL, failcode, "reply from remote");
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
	"Send along {route} in return for preimage of {rhash}",
	"Returns the {preimage} on success"
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
	"Send payment specified by {bolt11} with optional {msatoshi} (iff {bolt11} does not have amount), {description} (required if {bolt11} uses description hash) and {riskfactor} (default 1.0)",
	"Returns the {preimage} on success"
};
AUTODATA(json_command, &pay_command);

static void json_listpayments(struct command *cmd, const char *buffer,
			       const jsmntok_t *params)
{
	const struct wallet_payment **payments;
	struct json_result *response = new_json_result(cmd);

	payments = wallet_payment_list(cmd, cmd->ld->wallet);

	json_array_start(response, NULL);
	for (int i=0; i<tal_count(payments); i++) {
		const struct wallet_payment *t = payments[i];
		json_object_start(response, NULL);
		json_add_u64(response, "id", t->id);
		json_add_hex(response, "payment_hash", &t->payment_hash, sizeof(t->payment_hash));
		json_add_pubkey(response, "destination", &t->destination);
		json_add_u64(response, "msatoshi", t->msatoshi);
		json_add_u64(response, "timestamp", t->timestamp);

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
	command_success(cmd, response);
}

static const struct json_command listpayments_command = {
	"listpayments",
	json_listpayments,
	"Get a list of incoming and outgoing payments",
	"Returns a list of payments with {payment_hash}, {destination}, {msatoshi}, {timestamp} and {status}"
};
AUTODATA(json_command, &listpayments_command);
