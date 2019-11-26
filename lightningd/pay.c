#include "pay.h"
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bolt11.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/param.h>
#include <common/timeout.h>
#include <gossipd/gen_gossip_wire.h>
#include <lightningd/chaintopology.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/notification.h>
#include <lightningd/options.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/subd.h>
#include <sodium/randombytes.h>

/* Routing failure object */
struct routing_failure {
	unsigned int erring_index;
	enum onion_type failcode;
	const struct node_id *erring_node;
	const struct short_channel_id *erring_channel;
	int channel_dir;
	/* If remote sent us a message, this is it. */
	const u8 *msg;
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
void json_add_payment_fields(struct json_stream *response,
			     const struct wallet_payment *t)
{
	json_add_u64(response, "id", t->id);
	json_add_sha256(response, "payment_hash", &t->payment_hash);
	if (t->destination != NULL)
		json_add_node_id(response, "destination", t->destination);

	/* If we have a 0 amount delivered at the remote end we simply don't
	 * know since the onion was generated externally. */
	if (amount_msat_greater(t->msatoshi, AMOUNT_MSAT(0)))
		json_add_amount_msat_compat(response, t->msatoshi, "msatoshi",
					    "amount_msat");
	else
		json_add_null(response, "amount_msat");


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
		json_add_preimage(response, "payment_preimage",
                    t->payment_preimage);
	if (t->label)
		json_add_string(response, "label", t->label);
	if (t->bolt11)
		json_add_string(response, "bolt11", t->bolt11);

	if (t->failonion)
		json_add_hex(response, "erroronion", t->failonion,
			     tal_count(t->failonion));
}

static struct command_result *sendpay_success(struct command *cmd,
					      const struct wallet_payment *payment)
{
	struct json_stream *response;

	assert(payment->status == PAYMENT_COMPLETE);

	notify_sendpay_success(cmd->ld, payment);
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
			int channel_dir,
			const u8 *msg)
{
	const char *failcodename = onion_type_name(failcode);

	json_add_num(js, "erring_index", erring_index);
	json_add_num(js, "failcode", failcode);
	/* FIXME: Better way to detect this? */
	if (!strstarts(failcodename, "INVALID "))
		json_add_string(js, "failcodename", failcodename);

	if (erring_node != NULL)
		json_add_node_id(js, "erring_node", erring_node);

	if (erring_channel != NULL) {
		json_add_short_channel_id(js, "erring_channel", erring_channel);
		json_add_num(js, "erring_direction", channel_dir);
	}

	if (msg)
		json_add_hex_talarr(js, "raw_message", msg);
}

void json_sendpay_fail_fields(struct json_stream *js,
			      const struct wallet_payment *payment,
			      int pay_errcode,
			      const u8 *onionreply,
			      const struct routing_failure *fail)
{
	/* "immediate_routing_failure" is before payment creation. */
	if (payment)
		json_add_payment_fields(js, payment);
	if (pay_errcode == PAY_UNPARSEABLE_ONION)
		json_add_hex_talarr(js, "onionreply", onionreply);
	else
		json_add_routefail_info(js,
					fail->erring_index,
					fail->failcode,
					fail->erring_node,
					fail->erring_channel,
					fail->channel_dir,
					fail->msg);
}

/* onionreply used if pay_errcode == PAY_UNPARSEABLE_ONION */
static struct command_result *
sendpay_fail(struct command *cmd,
	     const struct wallet_payment *payment,
	     int pay_errcode,
	     const u8 *onionreply,
	     const struct routing_failure *fail,
	     const char *details)
{
	struct json_stream *data;
	char *errmsg;

	if (pay_errcode == PAY_UNPARSEABLE_ONION)
		errmsg = "Malformed error reply";
	else {
		assert(fail);
		errmsg = tal_fmt(tmpctx, "failed: %s (%s)",
				 onion_type_name(fail->failcode),
				 details);
	}

	notify_sendpay_failure(cmd->ld,
			       payment,
			       pay_errcode,
			       onionreply,
			       fail,
			       errmsg);

	data = json_stream_fail(cmd, pay_errcode,
				errmsg);
	json_sendpay_fail_fields(data,
				 payment,
				 pay_errcode,
				 onionreply,
				 fail);
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
				const struct wallet_payment *payment,
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

		sendpay_fail(pc->cmd, payment,
			     pay_errcode, onionreply, fail, details);
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
	routing_failure->erring_node =
	    tal_dup(routing_failure, struct node_id, &ld->id);
	routing_failure->erring_channel =
	    tal_dup(routing_failure, struct short_channel_id, channel0);
	routing_failure->channel_dir = node_id_idx(&ld->id, dstid);
	routing_failure->msg = NULL;

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
	routing_failure->erring_node =
	    tal_dup(routing_failure, struct node_id, &ld->id);

	if (payment->route_nodes != NULL && payment->route_channels != NULL) {
		routing_failure->erring_channel =
		    tal_dup(routing_failure, struct short_channel_id,
			    &payment->route_channels[0]);
		routing_failure->channel_dir =
		    node_id_idx(&ld->id, &payment->route_nodes[0]);
	} else {
		routing_failure->erring_channel = NULL;
	}

	routing_failure->msg = NULL;

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

	assert(route_nodes == NULL || origin_index < tal_count(route_nodes));

	/* Either we have both channels and nodes, or neither */
	assert((route_nodes == NULL) == (route_channels == NULL));

	if (route_nodes == NULL) {
		/* This means we have the `shared_secrets`, but cannot infer
		 * the erring channel and node since we don't have them. This
		 * can happen if the payment was initialized using `sendonion`
		 * and the `shared_secrets` where specified. */
		dir = 0;
		erring_channel = NULL;
		erring_node = NULL;

		/* We don't know if there's another route, that'd depend on
		 * where the failure occured and whether it was a node
		 * failure. Let's assume it wasn't a terminal one, and have
		 * the sendonion caller deal with the actual decision. */
		*pay_errcode = PAY_TRY_OTHER_ROUTE;
	} else if (origin_index == tal_count(route_nodes) - 1) {
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
	routing_failure->msg = tal_dup_arr(routing_failure, u8, failure->msg,
					   tal_count(failure->msg), 0);

	if (erring_node != NULL)
		routing_failure->erring_node =
		    tal_dup(routing_failure, struct node_id, erring_node);
	else
		routing_failure->erring_node = NULL;

	if (erring_channel != NULL) {
		routing_failure->erring_channel = tal_dup(
		    routing_failure, struct short_channel_id, erring_channel);
		routing_failure->channel_dir = dir;
	} else {
		routing_failure->erring_channel = NULL;
		routing_failure->channel_dir = 0;
	}

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
#else
	assert(payment);
#endif
	assert((payment->route_channels == NULL) == (payment->route_nodes == NULL));

	/* This gives more details than a generic failure message */
	if (localfail) {
		fail = local_routing_failure(tmpctx, ld, hout, payment);
		failmsg = localfail;
		pay_errcode = PAY_TRY_OTHER_ROUTE;
	} else if (payment->path_secrets == NULL) {
		/* This was a payment initiated with `sendonion`, we therefore
		 * don't have the path secrets and cannot decode the error
		 * onion. Let's store it and hope whatever called `sendonion`
		 * knows how to deal with these. */

		pay_errcode = PAY_UNPARSEABLE_ONION;
		fail = NULL;
		failmsg = NULL;
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
			log_debug(hout->key.channel->log, "failmsg: %s",
				  tal_hex(tmpctx, reply->msg));
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
				    fail ? fail->erring_node : NULL,
				    fail ? fail->erring_channel : NULL,
				    NULL,
				    failmsg,
				    fail ? fail->channel_dir : 0);

	tell_waiters_failed(ld, &hout->payment_hash, payment,
			    pay_errcode, hout->failuremsg, fail, failmsg);
}

/* Wait for a payment. If cmd is deleted, then wait_payment()
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
			return sendpay_fail(cmd,
					    payment,
					    PAY_UNPARSEABLE_ONION,
					    failonionreply,
					    NULL, faildetail);
		} else {
			/* Parsed onion error, get its details */
			assert(failnode);
			assert(failchannel);
			fail = tal(tmpctx, struct routing_failure);
			fail->erring_index = failindex;
			fail->failcode = failcode;
			fail->erring_node =
			    tal_dup(fail, struct node_id, failnode);
			fail->erring_channel =
			    tal_dup(fail, struct short_channel_id, failchannel);
			fail->channel_dir = faildirection;
			/* FIXME: We don't store this! */
			fail->msg = NULL;
			return sendpay_fail(cmd,
					    payment,
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

static bool should_use_tlv(enum route_hop_style style)
{
	switch (style) {
	case ROUTE_HOP_TLV:
#if EXPERIMENTAL_FEATURES
		return true;
#endif
		/* Otherwise fall thru */
	case ROUTE_HOP_LEGACY:
		return false;
	}
	abort();
}

static enum onion_type send_onion(struct lightningd *ld,
				   const struct onionpacket *packet,
				   const struct route_hop *first_hop,
				   const struct sha256 *payment_hash,
				   struct channel *channel,
				   struct htlc_out **hout)
{
	const u8 *onion;
	unsigned int base_expiry;
	base_expiry = get_block_height(ld->topology) + 1;
	onion = serialize_onionpacket(tmpctx, packet);
	return send_htlc_out(channel, first_hop->amount,
				  base_expiry + first_hop->delay,
				  payment_hash, onion, NULL, hout);
}

/* Returns command_result if cmd was resolved, NULL if not yet called. */
static struct command_result *
send_payment(struct lightningd *ld,
	     struct command *cmd,
	     const struct sha256 *rhash,
	     const struct route_hop *route,
	     struct amount_msat msat,
	     const char *label TAKES,
	     const char *b11str TAKES,
	     const struct secret *payment_secret)
{
	unsigned int base_expiry;
	struct onionpacket *packet;
	struct secret *path_secrets;
	enum onion_type failcode;
	size_t i, n_hops = tal_count(route);
	struct node_id *ids = tal_arr(tmpctx, struct node_id, n_hops);
	struct wallet_payment *payment = NULL;
	struct htlc_out *hout;
	struct short_channel_id *channels;
	struct routing_failure *fail;
	struct channel *channel;
	struct sphinx_path *path;
	struct pubkey pubkey;
	bool final_tlv, ret;

	/* Expiry for HTLCs is absolute.  And add one to give some margin. */
	base_expiry = get_block_height(ld->topology) + 1;

	path = sphinx_path_new(tmpctx, rhash->u.u8);
	/* Extract IDs for each hop: create_onionpacket wants array. */
	for (i = 0; i < n_hops; i++)
		ids[i] = route[i].nodeid;

	/* Create sphinx path */
	for (i = 0; i < n_hops - 1; i++) {
		ret = pubkey_from_node_id(&pubkey, &ids[i]);
		assert(ret);

		sphinx_add_nonfinal_hop(path, &pubkey,
					should_use_tlv(route[i].style),
					&route[i + 1].channel_id,
					route[i + 1].amount,
					base_expiry + route[i + 1].delay);
	}

	/* And finally set the final hop to the special values in
	 * BOLT04 */
	ret = pubkey_from_node_id(&pubkey, &ids[i]);
	assert(ret);

	final_tlv = should_use_tlv(route[i].style);
	/* BOLT-3a09bc54f8443c4757b47541a5310aff6377ee21 #4:
	 * - Unless `node_announcement`, `init` message or the
	 *   [BOLT #11](11-payment-encoding.md#tagged-fields) offers feature
	 *   `var_onion_optin`:
	 *    - MUST use the legacy payload format instead.
	 */
	/* In our case, we don't use it unless we also have a payment_secret;
	 * everyone should support this eventually */
	if (!final_tlv && payment_secret)
		final_tlv = true;

	if (!sphinx_add_final_hop(path, &pubkey,
				  final_tlv,
				  route[i].amount,
				  base_expiry + route[i].delay,
				  route[i].amount, payment_secret)) {
		return command_fail(cmd, PAY_DESTINATION_PERM_FAIL,
				    "Destination does not support"
				    " payment_secret");
	}

	/* Now, do we already have a payment? */
	payment = wallet_payment_by_hash(tmpctx, ld->wallet, rhash);
	if (payment) {
		/* FIXME: We should really do something smarter here! */
		if (payment->status == PAYMENT_PENDING) {
			log_debug(ld->log, "send_payment: previous still in progress");
			return json_sendpay_in_progress(cmd, payment);
		}
		if (payment->status == PAYMENT_COMPLETE) {
			log_debug(ld->log, "send_payment: previous succeeded");
			/* Must match successful payment parameters. */
			if (!amount_msat_eq(payment->msatoshi, msat)) {
				return command_fail(cmd, PAY_RHASH_ALREADY_USED,
						    "Already succeeded "
						    "with amount %s",
						    type_to_string(tmpctx,
								   struct amount_msat,
								   &payment->msatoshi));
			}
			if (payment->destination &&
			    !node_id_eq(payment->destination,
					&ids[n_hops - 1])) {
				return command_fail(cmd, PAY_RHASH_ALREADY_USED,
						    "Already succeeded to %s",
						    type_to_string(tmpctx,
								   struct node_id,
								   payment->destination));
			}
			return sendpay_success(cmd, payment);
		}
		log_debug(ld->log, "send_payment: found previous, retrying");
	}

	channel = active_channel_by_id(ld, &ids[0], NULL);
	if (!channel) {
		struct json_stream *data
			= json_stream_fail(cmd, PAY_TRY_OTHER_ROUTE,
					   "No connection to first "
					   "peer found");

		json_add_routefail_info(data, 0, WIRE_UNKNOWN_NEXT_PEER,
					&ld->id, &route[0].channel_id,
					node_id_idx(&ld->id, &route[0].nodeid),
					NULL);
		json_object_end(data);
		return command_failed(cmd, data);
	}

	packet = create_onionpacket(tmpctx, path, &path_secrets);
	failcode = send_onion(ld, packet, &route[0], rhash, channel, &hout);
	log_info(ld->log, "Sending %s over %zu hops to deliver %s",
		 type_to_string(tmpctx, struct amount_msat, &route[0].amount),
		 n_hops, type_to_string(tmpctx, struct amount_msat, &msat));

	if (failcode) {
		fail = immediate_routing_failure(cmd, ld,
						 failcode,
						 &route[0].channel_id,
						 &channel->peer->id);

		return sendpay_fail(cmd, payment, PAY_TRY_OTHER_ROUTE,
				    NULL, fail, "First peer not ready");
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
	payment->destination = tal_dup(payment, struct node_id, &ids[n_hops - 1]);
	payment->status = PAYMENT_PENDING;
	payment->msatoshi = msat;
	payment->msatoshi_sent = route[0].amount;
	payment->timestamp = time_now().ts.tv_sec;
	payment->payment_preimage = NULL;
	payment->path_secrets = tal_steal(payment, path_secrets);
	payment->route_nodes = tal_steal(payment, ids);
	payment->route_channels = tal_steal(payment, channels);
	payment->failonion = NULL;
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

static struct command_result *
param_route_hop(struct command *cmd, const char *name, const char *buffer,
		const jsmntok_t *tok, struct route_hop **hop)
{
	const jsmntok_t *idtok, *channeltok, *directiontok, *amounttok, *delaytok;
	struct route_hop *res;

	res = tal(cmd, struct route_hop);
	idtok = json_get_member(buffer, tok, "id");
	channeltok = json_get_member(buffer, tok, "channel");
	directiontok = json_get_member(buffer, tok, "direction");
	amounttok = json_get_member(buffer, tok, "amount_msat");
	delaytok = json_get_member(buffer, tok, "delay");

	/* General verification that all fields that we need are present. */
	if (!idtok && !channeltok)
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "Either 'id' or 'channel' is required for a route_hop");

	if (channeltok && !directiontok)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "When specifying a channel you must also "
				    "specify the direction");

	if (!amounttok)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'amount_msat' is required");

	if (!delaytok)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'delay' is required");

	/* Parsing of actual values including sanity check for all parsed
	 * values. */
	if (!idtok) {
		memset(&res->nodeid, 0, sizeof(struct node_id));
	} else if (!json_to_node_id(buffer, idtok, &res->nodeid)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'%s' should be a node_id, not '%.*s'",
				    name, tok->end - tok->start,
				    buffer + tok->start);
	}

	if (!channeltok) {
		memset(&res->channel_id, 0, sizeof(struct node_id));
	} else if (!json_to_short_channel_id(buffer, channeltok, &res->channel_id)) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "'%s' should be a short_channel_id, not '%.*s'", name,
		    tok->end - tok->start, buffer + tok->start);
	}

	if (directiontok && (!json_to_int(buffer, directiontok, &res->direction) ||
			     res->direction > 1 || res->direction < 0))
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "'%s' should be an integer in [0,1], not '%.*s'", name,
		    tok->end - tok->start, buffer + tok->start);

	if (!json_to_msat(buffer, amounttok, &res->amount))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'%s' should be a valid amount_msat, not '%.*s'",
				    name, tok->end - tok->start,
				    buffer + tok->start);

	if (!json_to_number(buffer, delaytok, &res->delay) || res->delay < 1)
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "'%s' should be a positive, non-zero, number, not '%.*s'",
		    name, tok->end - tok->start, buffer + tok->start);

	*hop = res;
	return NULL;
}

static struct command_result *json_sendonion(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	u8 *onion;
	struct onionpacket *packet;
	enum onion_type failcode;
	struct htlc_out *hout;
	struct route_hop *first_hop;
	struct sha256 *payment_hash;
	struct channel *channel;
	struct lightningd *ld = cmd->ld;
	struct wallet_payment *payment;
	const char *label;
	struct secret *path_secrets;

	if (!param(cmd, buffer, params,
		   p_req("onion", param_bin_from_hex, &onion),
		   p_req("first_hop", param_route_hop, &first_hop),
		   p_req("payment_hash", param_sha256, &payment_hash),
		   p_opt("label", param_escaped_string, &label),
		   p_opt("shared_secrets", param_secrets_array, &path_secrets),
		   NULL))
		return command_param_failed();

	packet = parse_onionpacket(cmd, onion, tal_bytelen(onion), &failcode);

	if (!packet)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Could not parse the onion. Parsing failed "
				    "with failcode=%d",
				    failcode);

	/* Now, do we already have a payment? */
	payment = wallet_payment_by_hash(tmpctx, ld->wallet, payment_hash);
	if (payment) {
		if (payment->status == PAYMENT_PENDING) {
			log_debug(ld->log, "send_payment: previous still in progress");
			return json_sendpay_in_progress(cmd, payment);
		}
		if (payment->status == PAYMENT_COMPLETE) {
			log_debug(ld->log, "send_payment: previous succeeded");
			return sendpay_success(cmd, payment);
		}
		log_debug(ld->log, "send_payment: found previous, retrying");
	}

	channel = active_channel_by_id(ld, &first_hop->nodeid, NULL);
	if (!channel) {
		struct json_stream *data
			= json_stream_fail(cmd, PAY_TRY_OTHER_ROUTE,
					   "No connection to first "
					   "peer found");

		json_add_routefail_info(data, 0, WIRE_UNKNOWN_NEXT_PEER,
					&ld->id, &first_hop->channel_id,
					node_id_idx(&ld->id, &first_hop->nodeid),
					NULL);
		json_object_end(data);
		return command_failed(cmd, data);
	}

	/* Cleanup any prior payment. We're about to retry. */
	if (payment) {
		wallet_payment_delete(ld->wallet, payment_hash);
		wallet_local_htlc_out_delete(ld->wallet, channel, payment_hash);
	}

	failcode = send_onion(cmd->ld, packet, first_hop, payment_hash, channel,
			  &hout);

	payment = tal(hout, struct wallet_payment);
	payment->id = 0;
	payment->payment_hash = *payment_hash;
	payment->status = PAYMENT_PENDING;
	payment->msatoshi = AMOUNT_MSAT(0);
	payment->msatoshi_sent = first_hop->amount;
	payment->timestamp = time_now().ts.tv_sec;

	/* These are not available for sendonion payments since the onion is
	 * opaque and we can't extract them. Errors have to be handled
	 * externally, since we can't decrypt them.*/
	payment->destination = NULL;
	payment->payment_preimage = NULL;
	payment->route_nodes = NULL;
	payment->route_channels = NULL;
	payment->bolt11 = NULL;
	payment->failonion = NULL;
	payment->path_secrets = tal_steal(payment, path_secrets);

	if (label != NULL)
		payment->label = tal_strdup(payment, label);
	else
		payment->label = NULL;

	/* We write this into db when HTLC is actually sent. */
	wallet_payment_setup(ld->wallet, payment);

	add_sendpay_waiter(ld, cmd, payment_hash);
	return command_still_pending(cmd);
}
static const struct json_command sendonion_command = {
	"sendonion",
	"payment",
	json_sendonion,
	"Send a payment with a pre-computed onion."
};
AUTODATA(json_command, &sendonion_command);

/*-----------------------------------------------------------------------------
JSON-RPC sendpay interface
-----------------------------------------------------------------------------*/

static struct command_result *param_route_hop_style(struct command *cmd,
						    const char *name,
						    const char *buffer,
						    const jsmntok_t *tok,
						    enum route_hop_style **style)
{
	*style = tal(cmd, enum route_hop_style);
	if (json_tok_streq(buffer, tok, "legacy")) {
		**style = ROUTE_HOP_LEGACY;
		return NULL;
	} else if (json_tok_streq(buffer, tok, "tlv")) {
		**style = ROUTE_HOP_TLV;
		return NULL;
	}

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "'%s' should be a legacy or tlv, not '%.*s'",
			    name, json_tok_full_len(tok),
			    json_tok_full(buffer, tok));
}

static struct command_result *json_sendpay(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	const jsmntok_t *routetok;
	const jsmntok_t *t;
	size_t i;
	struct sha256 *rhash;
	struct route_hop *route;
	struct amount_msat *msat;
	const char *b11str, *label = NULL;
	struct command_result *res;
	struct secret *payment_secret;

	/* For generating help, give new-style. */
	if (!params || !deprecated_apis) {
		if (!param(cmd, buffer, params,
			   p_req("route", param_array, &routetok),
			   p_req("payment_hash", param_sha256, &rhash),
			   p_opt("label", param_escaped_string, &label),
			   p_opt("msatoshi", param_msat, &msat),
			   p_opt("bolt11", param_string, &b11str),
			   p_opt("payment_secret", param_secret,
				 &payment_secret),
			   NULL))
			return command_param_failed();
	} else if (params->type == JSMN_ARRAY) {
		if (!param(cmd, buffer, params,
			   p_req("route", param_array, &routetok),
			   p_req("payment_hash", param_sha256, &rhash),
			   p_opt("label_or_description", param_escaped_string, &label),
			   p_opt("msatoshi", param_msat, &msat),
			   p_opt("bolt11", param_string, &b11str),
			   p_opt("payment_secret", param_secret,
				 &payment_secret),
			   NULL))
			return command_param_failed();
	} else {
		const char *desc = NULL;
		if (!param(cmd, buffer, params,
			   p_req("route", param_array, &routetok),
			   p_req("payment_hash", param_sha256, &rhash),
			   p_opt("label", param_escaped_string, &label),
			   p_opt("description", param_escaped_string, &desc),
			   p_opt("msatoshi", param_msat, &msat),
			   p_opt("bolt11", param_string, &b11str),
			   p_opt("payment_secret", param_secret,
				 &payment_secret),
			   NULL))
			return command_param_failed();

		if (!label && desc)
			label = desc;
	}

	if (routetok->size == 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "Empty route");

	route = tal_arr(cmd, struct route_hop, routetok->size);
	json_for_each_arr(i, t, routetok) {
		struct amount_msat *msat, *amount_msat;
		struct node_id *id;
		struct short_channel_id *channel;
		unsigned *delay, *direction;
		enum route_hop_style *style;

		if (!param(cmd, buffer, t,
			   /* Only *one* of these is required */
			   p_opt("msatoshi", param_msat, &msat),
			   p_opt("amount_msat", param_msat, &amount_msat),
			   /* These three actually required */
			   p_opt("id", param_node_id, &id),
			   p_opt("delay", param_number, &delay),
			   p_opt("channel", param_short_channel_id, &channel),
			   p_opt("direction", param_number, &direction),
			   p_opt_def("style", param_route_hop_style, &style,
				     ROUTE_HOP_LEGACY),
			   NULL))
			return command_param_failed();

		if (!msat && !amount_msat)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "route[%zi]: must have msatoshi"
					    " or amount_msat", i);
		if (!id || !channel || !delay)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "route[%zi]: must have id, channel"
					    " and delay", i);
		if (msat && amount_msat && !amount_msat_eq(*msat, *amount_msat))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "route[%zi]: msatoshi %s != amount_msat %s",
					    i,
					    type_to_string(tmpctx,
							   struct amount_msat,
							   msat),
					    type_to_string(tmpctx,
							   struct amount_msat,
							   amount_msat));
		if (!msat)
			msat = amount_msat;

		route[i].amount = *msat;
		route[i].nodeid = *id;
		route[i].delay = *delay;
		route[i].channel_id = *channel;
		route[i].style = *style;
		/* FIXME: Actually ignored by sending code! */
		route[i].direction = direction ? *direction : 0;
	}

	/* The given msatoshi is the actual payment that the payee is
	 * requesting. The final hop amount is what we actually give, which can
	 * be from the msatoshi to twice msatoshi. */

	/* if not: msatoshi <= finalhop.amount <= 2 * msatoshi, fail. */
	if (msat) {
		struct amount_msat limit = route[routetok->size-1].amount;

		if (amount_msat_less(*msat, limit))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi %s less than final %s",
					    type_to_string(tmpctx,
							   struct amount_msat,
							   msat),
					    type_to_string(tmpctx,
							   struct amount_msat,
							   &route[routetok->size-1].amount));
		limit.millisatoshis *= 2; /* Raw: sanity check */
		if (amount_msat_greater(*msat, limit))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi %s more than twice final %s",
					    type_to_string(tmpctx,
							   struct amount_msat,
							   msat),
					    type_to_string(tmpctx,
							   struct amount_msat,
							   &route[routetok->size-1].amount));
	}

	/* It's easier to leave this in the API, then ignore it here. */
#if !EXPERIMENTAL_FEATURES
	if (payment_secret) {
		log_unusual(cmd->ld->log,
			    "sendpay: we don't support payment_secret yet, ignoring");
		payment_secret = NULL;
	}
#endif

	res = send_payment(cmd->ld, cmd, rhash, route,
			   msat ? *msat : route[routetok->size-1].amount,
			   label, b11str, payment_secret);
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

static const struct json_command listsendpays_command = {
	"listsendpays",
	"payment",
	json_listsendpays,
	"Show sendpay, old and current, optionally limiting to {bolt11} or {payment_hash}."
};
AUTODATA(json_command, &listsendpays_command);

static struct command_result *json_createonion(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	struct json_stream *response;
	struct secret *session_key, *shared_secrets;
	struct sphinx_path *sp;
	u8 *assocdata, *serialized;
	struct onionpacket *packet;
	struct sphinx_hop *hops;

	if (!param(cmd, buffer, params,
		   p_req("hops", param_hops_array, &hops),
		   p_req("assocdata", param_bin_from_hex, &assocdata),
		   p_opt("session_key", param_secret, &session_key),
		   NULL)) {
		return command_param_failed();
	}

	if (session_key == NULL)
		sp = sphinx_path_new(cmd, assocdata);
	else
		sp = sphinx_path_new_with_key(cmd, assocdata, session_key);

	for (size_t i=0; i<tal_count(hops); i++)
		sphinx_add_raw_hop(sp, &hops[i].pubkey, hops[i].type,
				   hops[i].payload);

	packet = create_onionpacket(cmd, sp, &shared_secrets);
	if (!packet)
		return command_fail(cmd, LIGHTNINGD,
				    "Could not create onion packet");

	serialized = serialize_onionpacket(cmd, packet);

	response = json_stream_success(cmd);
	json_add_hex(response, "onion", serialized, tal_bytelen(serialized));
	json_array_start(response, "shared_secrets");
	for (size_t i=0; i<tal_count(hops); i++) {
		json_add_secret(response, NULL, &shared_secrets[i]);
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command createonion_command = {
	"createonion",
	"payment",
	json_createonion,
	"Create an onion going through the provided nodes, each with its own payload"
};
AUTODATA(json_command, &createonion_command);
