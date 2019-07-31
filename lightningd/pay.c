#include "pay.h"
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bolt11.h>
#include <common/json_command.h>
#include <common/jsonrpc_errors.h>
#include <common/param.h>
#include <common/timeout.h>
#include <gossipd/gen_gossip_wire.h>
#include <lightningd/chaintopology.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/subd.h>
#include <sodium/randombytes.h>

/* Routing failure object */
struct routing_failure {
	unsigned int erring_index;
	enum onion_type failcode;
	struct node_id erring_node;
	struct short_channel_id erring_channel;
	int channel_dir;
};

/* sendpay command */
struct sendpay_command {
	struct list_node list;

	struct sha256 payment_hash;
	struct command *cmd;
};

static void destroy_sendpay_command(struct sendpay_command *pc)
{
	list_del(&pc->list);
}

/* Owned by cmd, if cmd is deleted, then sendpay_success/sendpay_fail will
 * no longer be called. */
static void
add_sendpay_waiter(struct lightningd *ld,
		   struct command *cmd,
		   const struct sha256 *payment_hash)
{
	struct sendpay_command *pc = tal(cmd, struct sendpay_command);

	pc->payment_hash = *payment_hash;
	pc->cmd = cmd;
	list_add(&ld->sendpay_commands, &pc->list);
	tal_add_destructor(pc, destroy_sendpay_command);
}

/* Owned by cmd, if cmd is deleted, then sendpay_success/sendpay_fail will
 * no longer be called. */
static void
add_waitsendpay_waiter(struct lightningd *ld,
		       struct command *cmd,
		       const struct sha256 *payment_hash)
{
	struct sendpay_command *pc = tal(cmd, struct sendpay_command);

	pc->payment_hash = *payment_hash;
	pc->cmd = cmd;
	list_add(&ld->waitsendpay_commands, &pc->list);
	tal_add_destructor(pc, destroy_sendpay_command);
}

/* Outputs fields, not a separate object*/
static void
json_add_payment_fields(struct json_stream *response,
			const struct wallet_payment *t)
{
	json_add_u64(response, "id", t->id);
	json_add_hex(response, "payment_hash", &t->payment_hash, sizeof(t->payment_hash));
	json_add_node_id(response, "destination", &t->destination);
	json_add_amount_msat_compat(response, t->msatoshi,
				    "msatoshi", "amount_msat");
	json_add_amount_msat_compat(response, t->msatoshi_sent,
				    "msatoshi_sent", "amount_sent_msat");
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
	if (t->label) {
		if (deprecated_apis)
			json_add_string(response, "description", t->label);
		json_add_string(response, "label", t->label);
	}
	if (t->bolt11)
		json_add_string(response, "bolt11", t->bolt11);
}

static struct command_result *sendpay_success(struct command *cmd,
					      const struct wallet_payment *payment)
{
	struct json_stream *response;

	assert(payment->status == PAYMENT_COMPLETE);

	response = json_stream_success(cmd);
	json_add_payment_fields(response, payment);
	return command_success(cmd, response);
}

static void
json_add_routefail_info(struct json_stream *js,
			unsigned int erring_index,
			enum onion_type failcode,
			const struct node_id *erring_node,
			const struct short_channel_id *erring_channel,
			int channel_dir)
{
	const char *failcodename = onion_type_name(failcode);

	json_add_num(js, "erring_index", erring_index);
	json_add_num(js, "failcode", failcode);
	/* FIXME: Better way to detect this? */
	if (!strstarts(failcodename, "INVALID "))
		json_add_string(js, "failcodename", failcodename);
	json_add_node_id(js, "erring_node", erring_node);
	json_add_short_channel_id(js, "erring_channel", erring_channel);
	json_add_num(js, "erring_direction", channel_dir);
}

/* onionreply used if pay_errcode == PAY_UNPARSEABLE_ONION */
static struct command_result *
sendpay_fail(struct command *cmd,
	     int pay_errcode,
	     const u8 *onionreply,
	     const struct routing_failure *fail,
	     const char *details)
{
	struct json_stream *data;

	if (pay_errcode == PAY_UNPARSEABLE_ONION) {
		data = json_stream_fail(cmd, PAY_UNPARSEABLE_ONION,
					"Malformed error reply");
		json_add_hex_talarr(data, "onionreply", onionreply);
		json_object_end(data);
		return command_failed(cmd, data);
	}

	assert(fail);
	data = json_stream_fail(cmd, pay_errcode,
				tal_fmt(tmpctx, "failed: %s (%s)",
					onion_type_name(fail->failcode),
					details));
	json_add_routefail_info(data,
				fail->erring_index,
				fail->failcode,
				&fail->erring_node,
				&fail->erring_channel,
				fail->channel_dir);
	json_object_end(data);
	return command_failed(cmd, data);
}

/* We defer sendpay "success" until we know it's pending; consumes cmd */
static struct command_result *
json_sendpay_in_progress(struct command *cmd,
			 const struct wallet_payment *payment)
{
	struct json_stream *response = json_stream_success(cmd);
	json_add_string(response, "message",
			"Monitor status with listpayments or waitsendpay");
	json_add_payment_fields(response, payment);
	return command_success(cmd, response);
}

static void tell_waiters_failed(struct lightningd *ld,
				const struct sha256 *payment_hash,
				int pay_errcode,
				const u8 *onionreply,
				const struct routing_failure *fail,
				const char *details)
{
	struct sendpay_command *pc;
	struct sendpay_command *next;

	/* Careful: sendpay_fail deletes cmd */
	list_for_each_safe(&ld->waitsendpay_commands, pc, next, list) {
		if (!sha256_eq(payment_hash, &pc->payment_hash))
			continue;

		sendpay_fail(pc->cmd, pay_errcode, onionreply, fail, details);
	}
}

static void tell_waiters_success(struct lightningd *ld,
				 const struct sha256 *payment_hash,
				 struct wallet_payment *payment)
{
	struct sendpay_command *pc;
	struct sendpay_command *next;

	/* Careful: sendpay_success deletes cmd */
	list_for_each_safe(&ld->waitsendpay_commands, pc, next, list) {
		if (!sha256_eq(payment_hash, &pc->payment_hash))
			continue;

		sendpay_success(pc->cmd, payment);
	}
}

void payment_succeeded(struct lightningd *ld, struct htlc_out *hout,
		       const struct preimage *rval)
{
	struct wallet_payment *payment;

	wallet_payment_set_status(ld->wallet, &hout->payment_hash,
				  PAYMENT_COMPLETE, rval);
	payment = wallet_payment_by_hash(tmpctx, ld->wallet,
					 &hout->payment_hash);
	assert(payment);

	tell_waiters_success(ld, &hout->payment_hash, payment);
}

/* Return a struct routing_failure for an immediate failure
 * (returned directly from send_htlc_out). The returned
 * failure is allocated from the given context. */
static struct routing_failure*
immediate_routing_failure(const tal_t *ctx,
			  const struct lightningd *ld,
			  enum onion_type failcode,
			  const struct short_channel_id *channel0,
			  const struct node_id *dstid)
{
	struct routing_failure *routing_failure;

	assert(failcode);

	routing_failure = tal(ctx, struct routing_failure);
	routing_failure->erring_index = 0;
	routing_failure->failcode = failcode;
	routing_failure->erring_node = ld->id;
	routing_failure->erring_channel = *channel0;
	routing_failure->channel_dir = node_id_idx(&ld->id, dstid);

	return routing_failure;
}

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
	routing_failure->erring_index = 0;
	routing_failure->failcode = hout->failcode;
	routing_failure->erring_node = ld->id;
	routing_failure->erring_channel = payment->route_channels[0];
	routing_failure->channel_dir = node_id_idx(&ld->id,
						   &payment->route_nodes[0]);

	log_debug(hout->key.channel->log, "local_routing_failure: %u (%s)",
		  hout->failcode, onion_type_name(hout->failcode));
	return routing_failure;
}

/* Fills in *pay_errcode with PAY_TRY_OTHER_ROUTE or PAY_DESTINATION_PERM_FAIL */
static struct routing_failure*
remote_routing_failure(const tal_t *ctx,
		       struct lightningd *ld,
		       const struct wallet_payment *payment,
		       const struct onionreply *failure,
		       struct log *log,
		       int *pay_errcode)
{
	enum onion_type failcode = fromwire_peektype(failure->msg);
	struct routing_failure *routing_failure;
	const struct node_id *route_nodes;
	const struct node_id *erring_node;
	const struct short_channel_id *route_channels;
	const struct short_channel_id *erring_channel;
	int origin_index;
	int dir;

	routing_failure = tal(ctx, struct routing_failure);
	route_nodes = payment->route_nodes;
	route_channels = payment->route_channels;
	origin_index = failure->origin_index;

	assert(origin_index < tal_count(route_nodes));

	/* Check if at destination. */
	if (origin_index == tal_count(route_nodes) - 1) {
		/* If any channel is to blame, it's the last one. */
		erring_channel = &route_channels[origin_index];
		/* Single hop? */
		if (origin_index == 0)
			dir = node_id_idx(&ld->id,
					  &route_nodes[origin_index]);
		else
			dir = node_id_idx(&route_nodes[origin_index - 1],
					  &route_nodes[origin_index]);

		/* BOLT #4:
		 *
		 * - if the _final node_ is returning the error:
		 *   - if the PERM bit is set:
		 *     - SHOULD fail the payment.
		 * */
		if (failcode & PERM)
			*pay_errcode = PAY_DESTINATION_PERM_FAIL;
		else
			/* FIXME: not right for WIRE_FINAL_EXPIRY_TOO_SOON */
			*pay_errcode = PAY_TRY_OTHER_ROUTE;
		erring_node = &route_nodes[origin_index];
	} else {
		u8 *gossip_msg;

		*pay_errcode = PAY_TRY_OTHER_ROUTE;

		/* Report the *next* channel as failing. */
		erring_channel = &route_channels[origin_index + 1];

		dir = node_id_idx(&route_nodes[origin_index],
				  &route_nodes[origin_index+1]);

		/* If the error is a BADONION, then it's on behalf of the
		 * following node. */
		if (failcode & BADONION) {
			log_debug(log, "failcode %u from onionreply %s",
				  failcode, tal_hex(tmpctx, failure->msg));
			erring_node = &route_nodes[origin_index + 1];
		} else
			erring_node = &route_nodes[origin_index];

		/* Tell gossipd: it may want to remove channels or even nodes
		 * in response to this, and there may be a channel_update
		 * embedded too */
		gossip_msg = towire_gossip_payment_failure(NULL,
							   erring_node,
							   erring_channel,
							   dir,
							   failure->msg);
		subd_send_msg(ld->gossip, take(gossip_msg));
	}

	routing_failure->erring_index = (unsigned int) (origin_index + 1);
	routing_failure->failcode = failcode;
	routing_failure->erring_node = *erring_node;
	routing_failure->erring_channel = *erring_channel;
	routing_failure->channel_dir = dir;

	return routing_failure;
}

void payment_store(struct lightningd *ld, const struct sha256 *payment_hash)
{
	struct sendpay_command *pc;
	struct sendpay_command *next;
	const struct wallet_payment *payment;

	wallet_payment_store(ld->wallet, payment_hash);
	payment = wallet_payment_by_hash(tmpctx, ld->wallet, payment_hash);
	assert(payment);

	/* Trigger any sendpay commands waiting for the store to occur. */
	list_for_each_safe(&ld->sendpay_commands, pc, next, list) {
		if (!sha256_eq(payment_hash, &pc->payment_hash))
			continue;

		/* Deletes from list, frees pc */
		json_sendpay_in_progress(pc->cmd, payment);
	}
}

void payment_failed(struct lightningd *ld, const struct htlc_out *hout,
		    const char *localfail)
{
	struct wallet_payment *payment;
	struct routing_failure* fail = NULL;
	const char *failmsg;
	int pay_errcode;

	payment = wallet_payment_by_hash(tmpctx, ld->wallet,
					 &hout->payment_hash);

#ifdef COMPAT_V052
	/* Prior to "pay: delete HTLC when we delete payment." we would
	 * delete a payment on retry, but leave the HTLC. */
	if (!payment) {
		log_unusual(hout->key.channel->log,
			    "No payment for %s:"
			    " was this an old database?",
			    type_to_string(tmpctx, struct sha256,
					   &hout->payment_hash));
		return;
	}

	/* FIXME: Prior to 299b280f7, we didn't put route_nodes and
	 * route_channels in db.  If this happens, it's an old payment,
	 * so we can simply mark it failed in db and return. */
	if (!payment->route_channels) {
		log_unusual(hout->key.channel->log,
			    "No route_channels for htlc %s:"
			    " was this an old database?",
			    type_to_string(tmpctx, struct sha256,
					   &hout->payment_hash));
		wallet_payment_set_status(ld->wallet, &hout->payment_hash,
					  PAYMENT_FAILED, NULL);
		return;
	}
#else
	assert(payment);
	assert(payment->route_channels);
#endif

	/* This gives more details than a generic failure message */
	if (localfail) {
		fail = local_routing_failure(tmpctx, ld, hout, payment);
		failmsg = localfail;
		pay_errcode = PAY_TRY_OTHER_ROUTE;
	} else {
		/* Must be remote fail. */
		assert(!hout->failcode);
		failmsg = "reply from remote";
		/* Try to parse reply. */
		struct secret *path_secrets = payment->path_secrets;
		struct onionreply *reply;

		reply = unwrap_onionreply(tmpctx, path_secrets,
					  tal_count(path_secrets),
					  hout->failuremsg);
		if (!reply) {
			log_info(hout->key.channel->log,
				 "htlc %"PRIu64" failed with bad reply (%s)",
				 hout->key.id,
				 tal_hex(tmpctx, hout->failuremsg));
			/* Cannot record failure. */
			fail = NULL;
			pay_errcode = PAY_UNPARSEABLE_ONION;
		} else {
			enum onion_type failcode = fromwire_peektype(reply->msg);
			log_info(hout->key.channel->log,
				 "htlc %"PRIu64" "
				 "failed from %ith node "
				 "with code 0x%04x (%s)",
				 hout->key.id,
				 reply->origin_index,
				 failcode, onion_type_name(failcode));
			fail = remote_routing_failure(tmpctx, ld,
						      payment, reply,
						      hout->key.channel->log,
						      &pay_errcode);
		}
	}

	/* Save to DB */
	payment_store(ld, &hout->payment_hash);
	wallet_payment_set_status(ld->wallet, &hout->payment_hash,
				  PAYMENT_FAILED, NULL);
	wallet_payment_set_failinfo(ld->wallet,
				    &hout->payment_hash,
				    fail ? NULL : hout->failuremsg,
				    pay_errcode == PAY_DESTINATION_PERM_FAIL,
				    fail ? fail->erring_index : -1,
				    fail ? fail->failcode : 0,
				    fail ? &fail->erring_node : NULL,
				    fail ? &fail->erring_channel : NULL,
				    NULL,
				    failmsg,
				    fail ? fail->channel_dir : 0);

	tell_waiters_failed(ld, &hout->payment_hash, pay_errcode,
			    hout->failuremsg, fail, failmsg);
}

/* Wait for a payment. If cmd is deleted, then json_waitsendpay_on_resolve
 * no longer be called.
 * Return callback if we called already, otherwise NULL. */
static struct command_result *wait_payment(struct lightningd *ld,
					   struct command *cmd,
					   const struct sha256 *payment_hash)
{
	struct wallet_payment *payment;
	u8 *failonionreply;
	bool faildestperm;
	int failindex;
	enum onion_type failcode;
	struct node_id *failnode;
	struct short_channel_id *failchannel;
	u8 *failupdate;
	char *faildetail;
	struct routing_failure *fail;
	int faildirection;

	payment = wallet_payment_by_hash(tmpctx, ld->wallet, payment_hash);
	if (!payment) {
		return command_fail(cmd, PAY_NO_SUCH_PAYMENT,
				    "Never attempted payment for '%s'",
				    type_to_string(tmpctx, struct sha256,
						   payment_hash));
	}

	switch (payment->status) {
	case PAYMENT_PENDING:
		add_waitsendpay_waiter(ld, cmd, payment_hash);
		return NULL;

	case PAYMENT_COMPLETE:
		return sendpay_success(cmd, payment);

	case PAYMENT_FAILED:
		/* Get error from DB */
		wallet_payment_get_failinfo(tmpctx, ld->wallet, payment_hash,
					    &failonionreply,
					    &faildestperm,
					    &failindex,
					    &failcode,
					    &failnode,
					    &failchannel,
					    &failupdate,
					    &faildetail,
					    &faildirection);
		/* Old DB might not save failure information */
		if (!failonionreply && !failnode) {
			return command_fail(cmd, PAY_UNSPECIFIED_ERROR,
					    "Payment failure reason unknown");
		} else if (failonionreply) {
			/* failed to parse returned onion error */
			return sendpay_fail(cmd, PAY_UNPARSEABLE_ONION,
					    failonionreply,
					    NULL, faildetail);
		} else {
			/* Parsed onion error, get its details */
			assert(failnode);
			assert(failchannel);
			fail = tal(tmpctx, struct routing_failure);
			fail->erring_index = failindex;
			fail->failcode = failcode;
			fail->erring_node = *failnode;
			fail->erring_channel = *failchannel;
			fail->channel_dir = faildirection;
			return sendpay_fail(cmd,
					    faildestperm
					    ? PAY_DESTINATION_PERM_FAIL
					    : PAY_TRY_OTHER_ROUTE,
					    NULL,
					    fail, faildetail);
		}
	}

	/* Impossible. */
	abort();
}

/* Returns command_result if cmd was resolved, NULL if not yet called. */
static struct command_result *
send_payment(struct lightningd *ld,
	     struct command *cmd,
	     const struct sha256 *rhash,
	     const struct route_hop *route,
	     struct amount_msat msat,
	     const char *label TAKES,
	     const char *b11str TAKES)
{
	const u8 *onion;
	u8 sessionkey[32];
	unsigned int base_expiry;
	struct onionpacket *packet;
	struct secret *path_secrets;
	enum onion_type failcode;
	size_t i, n_hops = tal_count(route);
	struct hop_data *hop_data = tal_arr(tmpctx, struct hop_data, n_hops);
	struct node_id *ids = tal_arr(tmpctx, struct node_id, n_hops);
	struct wallet_payment *payment = NULL;
	struct htlc_out *hout;
	struct short_channel_id *channels;
	struct routing_failure *fail;
	struct channel *channel;
	struct sphinx_path *path;
	struct short_channel_id finalscid;
	struct pubkey pubkey;
	bool ret;

	/* Expiry for HTLCs is absolute.  And add one to give some margin. */
	base_expiry = get_block_height(ld->topology) + 1;
	memset(&finalscid, 0, sizeof(struct short_channel_id));

	path = sphinx_path_new(tmpctx, rhash->u.u8);
	/* Extract IDs for each hop: create_onionpacket wants array. */
	for (i = 0; i < n_hops; i++)
		ids[i] = route[i].nodeid;

	/* Copy hop_data[n] from route[n+1] (ie. where it goes next) */
	for (i = 0; i < n_hops - 1; i++) {
		ret = pubkey_from_node_id(&pubkey, &ids[i]);
		assert(ret);
		hop_data[i].realm = 0;
		hop_data[i].channel_id = route[i+1].channel_id;
		hop_data[i].amt_forward = route[i+1].amount;
		hop_data[i].outgoing_cltv = base_expiry + route[i+1].delay;
		sphinx_add_v0_hop(path, &pubkey, &route[i + 1].channel_id,
				  route[i + 1].amount,
				  base_expiry + route[i + 1].delay);
	}

	/* And finally set the final hop to the special values in
	 * BOLT04 */
	memset(&finalscid, 0, sizeof(struct short_channel_id));
	ret = pubkey_from_node_id(&pubkey, &ids[i]);
	assert(ret);
	sphinx_add_v0_hop(path, &pubkey, &finalscid,
			  route[i].amount,
			  base_expiry + route[i].delay);

	/* Now, do we already have a payment? */
	payment = wallet_payment_by_hash(tmpctx, ld->wallet, rhash);
	if (payment) {
		/* FIXME: We should really do something smarter here! */
		log_debug(ld->log, "send_payment: found previous");
		if (payment->status == PAYMENT_PENDING) {
			log_add(ld->log, "Payment is still in progress");
			return json_sendpay_in_progress(cmd, payment);
		}
		if (payment->status == PAYMENT_COMPLETE) {
			log_add(ld->log, "... succeeded");
			/* Must match successful payment parameters. */
			if (!amount_msat_eq(payment->msatoshi, msat)) {
				return command_fail(cmd, PAY_RHASH_ALREADY_USED,
						    "Already succeeded "
						    "with amount %s",
						    type_to_string(tmpctx,
								   struct amount_msat,
								   &payment->msatoshi));
			}
			if (!node_id_eq(&payment->destination, &ids[n_hops-1])) {
				return command_fail(cmd, PAY_RHASH_ALREADY_USED,
						    "Already succeeded to %s",
						    type_to_string(tmpctx,
								   struct node_id,
								   &payment->destination));
			}
			return sendpay_success(cmd, payment);
		}
		log_add(ld->log, "... retrying");
	}

	channel = active_channel_by_id(ld, &ids[0], NULL);
	if (!channel) {
		struct json_stream *data
			= json_stream_fail(cmd, PAY_TRY_OTHER_ROUTE,
					   "No connection to first "
					   "peer found");

		json_add_routefail_info(data, 0, WIRE_UNKNOWN_NEXT_PEER,
					&ld->id, &route[0].channel_id,
					node_id_idx(&ld->id, &route[0].nodeid));
		json_object_end(data);
		return command_failed(cmd, data);
	}

	randombytes_buf(&sessionkey, sizeof(sessionkey));

	/* Onion will carry us from first peer onwards. */
	packet = create_onionpacket(tmpctx, path, &path_secrets);
	onion = serialize_onionpacket(tmpctx, packet);

	log_info(ld->log, "Sending %s over %zu hops to deliver %s",
		 type_to_string(tmpctx, struct amount_msat, &route[0].amount),
		 n_hops, type_to_string(tmpctx, struct amount_msat, &msat));

	failcode = send_htlc_out(channel, route[0].amount,
				 base_expiry + route[0].delay,
				 rhash, onion, NULL, &hout);
	if (failcode) {
		fail = immediate_routing_failure(cmd, ld,
						 failcode,
						 &route[0].channel_id,
						 &channel->peer->id);

		return sendpay_fail(cmd, PAY_TRY_OTHER_ROUTE, NULL,
				    fail, "First peer not ready");
	}

	/* Copy channels used along the route. */
	channels = tal_arr(tmpctx, struct short_channel_id, n_hops);
	for (i = 0; i < n_hops; ++i)
		channels[i] = route[i].channel_id;

	/* If we're retrying, delete all trace of previous one.  We delete
	 * outgoing HTLC, too, otherwise it gets reported to onchaind as
	 * a possibility, and we end up in handle_missing_htlc_output->
	 * onchain_failed_our_htlc->payment_failed with no payment.
	 */
	if (payment) {
		wallet_payment_delete(ld->wallet, rhash);
		wallet_local_htlc_out_delete(ld->wallet, channel, rhash);
	}

	/* If hout fails, payment should be freed too. */
	payment = tal(hout, struct wallet_payment);
	payment->id = 0;
	payment->payment_hash = *rhash;
	payment->destination = ids[n_hops - 1];
	payment->status = PAYMENT_PENDING;
	payment->msatoshi = msat;
	payment->msatoshi_sent = route[0].amount;
	payment->timestamp = time_now().ts.tv_sec;
	payment->payment_preimage = NULL;
	payment->path_secrets = tal_steal(payment, path_secrets);
	payment->route_nodes = tal_steal(payment, ids);
	payment->route_channels = tal_steal(payment, channels);
	if (label != NULL)
		payment->label = tal_strdup(payment, label);
	else
		payment->label = NULL;
	if (b11str != NULL)
		payment->bolt11 = tal_strdup(payment, b11str);
	else
		payment->bolt11 = NULL;

	/* We write this into db when HTLC is actually sent. */
	wallet_payment_setup(ld->wallet, payment);

	add_sendpay_waiter(ld, cmd, rhash);
	return NULL;
}

/*-----------------------------------------------------------------------------
JSON-RPC sendpay interface
-----------------------------------------------------------------------------*/

static struct command_result *json_sendpay(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	struct sha256 *rhash;
	struct route_hop *route;
	size_t routelen;
	struct amount_msat *msat;
	const char *b11str, *label;
	struct command_result *res;

	/* If by array, or 'check' command, use 'label' as param name */
	if (!params || params->type == JSMN_ARRAY) {
		if (!param(cmd, buffer, params,
			   p_req("route", param_route, &route),
			   p_req("payment_hash", param_sha256, &rhash),
			   p_opt("label", param_escaped_string, &label),
			   p_opt("msatoshi", param_msat, &msat),
			   p_opt("bolt11", param_string, &b11str),
			   NULL))
			return command_param_failed();
	} else {
		const char *description_deprecated;

		/* If by keyword, treat description and label as
		 * separate parameters. */
		if (!param(cmd, buffer, params,
			   p_req("route", param_route, &route),
			   p_req("payment_hash", param_sha256, &rhash),
			   p_opt("label", param_escaped_string, &label),
			   p_opt("description", param_escaped_string,
				 &description_deprecated),
			   p_opt("msatoshi", param_msat, &msat),
			   p_opt("bolt11", param_string, &b11str),
			   NULL))
			return command_param_failed();

		if (description_deprecated) {
			if (!deprecated_apis)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "Deprecated parameter description, use label");
			if (label)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "Cannot specify both description and label");
			label = description_deprecated;
		}
	}

	routelen = tal_count(route);

	/* The given msatoshi is the actual payment that the payee is
	 * requesting. The final hop amount is what we actually give, which can
	 * be from the msatoshi to twice msatoshi. */

	/* if not: msatoshi <= finalhop.amount <= 2 * msatoshi, fail. */
	if (msat) {
		struct amount_msat limit = route[routelen-1].amount;

		if (amount_msat_less(*msat, limit))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi %s less than final %s",
					    type_to_string(tmpctx,
							   struct amount_msat,
							   msat),
					    type_to_string(tmpctx,
							   struct amount_msat,
							   &route[routelen-1].amount));
		limit.millisatoshis *= 2; /* Raw: sanity check */
		if (amount_msat_greater(*msat, limit))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi %s more than twice final %s",
					    type_to_string(tmpctx,
							   struct amount_msat,
							   msat),
					    type_to_string(tmpctx,
							   struct amount_msat,
							   &route[routelen-1].amount));
	}

	res = send_payment(cmd->ld, cmd, rhash, route,
			   msat ? *msat : route[routelen-1].amount,
			   label, b11str);
	if (res)
		return res;
	return command_still_pending(cmd);
}

static const struct json_command sendpay_command = {
	"sendpay",
	"payment",
	json_sendpay,
	"Send along {route} in return for preimage of {payment_hash}"
};
AUTODATA(json_command, &sendpay_command);

static void waitsendpay_timeout(struct command *cmd)
{
	was_pending(command_fail(cmd, PAY_IN_PROGRESS,
				 "Timed out while waiting"));
}

static struct command_result *json_waitsendpay(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	struct sha256 *rhash;
	unsigned int *timeout;
	struct command_result *res;

	if (!param(cmd, buffer, params,
		   p_req("payment_hash", param_sha256, &rhash),
		   p_opt("timeout", param_number, &timeout),
		   NULL))
		return command_param_failed();

	res = wait_payment(cmd->ld, cmd, rhash);
	if (res)
		return res;

	if (timeout)
		new_reltimer(cmd->ld->timers, cmd, time_from_sec(*timeout),
			     &waitsendpay_timeout, cmd);
	return command_still_pending(cmd);
}

static const struct json_command waitsendpay_command = {
	"waitsendpay",
	"payment",
	json_waitsendpay,
	"Wait for payment attempt on {payment_hash} to succeed or fail, "
	"but only up to {timeout} seconds."
};
AUTODATA(json_command, &waitsendpay_command);

static struct command_result *json_listsendpays(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	const struct wallet_payment **payments;
	struct json_stream *response;
	struct sha256 *rhash;
	const char *b11str;

	if (!param(cmd, buffer, params,
		   p_opt("bolt11", param_string, &b11str),
		   p_opt("payment_hash", param_sha256, &rhash),
		   NULL))
		return command_param_failed();

	if (rhash && b11str) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can only specify one of"
				    " {bolt11} or {payment_hash}");
	}

	if (b11str) {
		struct bolt11 *b11;
		char *fail;

		b11 = bolt11_decode(cmd, b11str, NULL, &fail);
		if (!b11) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Invalid bolt11: %s", fail);
		}
		rhash = &b11->payment_hash;
	}

	payments = wallet_payment_list(cmd, cmd->ld->wallet, rhash);

	response = json_stream_success(cmd);

	json_array_start(response, "payments");
	for (size_t i = 0; i < tal_count(payments); i++) {
		json_object_start(response, NULL);
		json_add_payment_fields(response, payments[i]);
		json_object_end(response);
	}
	json_array_end(response);

	return command_success(cmd, response);
}

static const struct json_command listpayments_command = {
	"listpayments",
	"payment",
	json_listsendpays,
	"Show outgoing payments",
	true /* deprecated, use new name */
};
AUTODATA(json_command, &listpayments_command);

static const struct json_command listsendpays_command = {
	"listsendpays",
	"payment",
	json_listsendpays,
	"Show sendpay, old and current, optionally limiting to {bolt11} or {payment_hash}."
};
AUTODATA(json_command, &listsendpays_command);
