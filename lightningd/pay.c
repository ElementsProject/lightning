#include "pay.h"
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bolt11.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/onion.h>
#include <common/onionreply.h>
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
	u64 partid;
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
		   const struct sha256 *payment_hash,
		   u64 partid)
{
	struct sendpay_command *pc = tal(cmd, struct sendpay_command);

	pc->payment_hash = *payment_hash;
	pc->partid = partid;
	pc->cmd = cmd;
	list_add(&ld->sendpay_commands, &pc->list);
	tal_add_destructor(pc, destroy_sendpay_command);
}

/* Owned by cmd, if cmd is deleted, then sendpay_success/sendpay_fail will
 * no longer be called. */
static void
add_waitsendpay_waiter(struct lightningd *ld,
		       struct command *cmd,
		       const struct sha256 *payment_hash,
		       u64 partid)
{
	struct sendpay_command *pc = tal(cmd, struct sendpay_command);

	pc->payment_hash = *payment_hash;
	pc->partid = partid;
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
	if (t->partid)
		json_add_u64(response, "partid", t->partid);
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
			      errcode_t pay_errcode,
			      const struct onionreply *onionreply,
			      const struct routing_failure *fail)
{
	/* "immediate_routing_failure" is before payment creation. */
	if (payment)
		json_add_payment_fields(js, payment);
	if (pay_errcode == PAY_UNPARSEABLE_ONION && onionreply)
		json_add_hex_talarr(js, "onionreply", onionreply->contents);
	else
		json_add_routefail_info(js,
					fail->erring_index,
					fail->failcode,
					fail->erring_node,
					fail->erring_channel,
					fail->channel_dir,
					fail->msg);
}

static const char *sendpay_errmsg_fmt(const tal_t *ctx, errcode_t pay_errcode,
				      const struct routing_failure *fail,
				      const char *details)
{
	char *errmsg;
	if (pay_errcode == PAY_UNPARSEABLE_ONION)
		errmsg = "Malformed error reply";
	else {
		assert(fail);
		errmsg = tal_fmt(ctx, "failed: %s (%s)",
				 onion_type_name(fail->failcode), details);
	}
	return errmsg;
}

/* onionreply used if pay_errcode == PAY_UNPARSEABLE_ONION */
static struct command_result *
sendpay_fail(struct command *cmd,
	     const struct wallet_payment *payment,
	     errcode_t pay_errcode,
	     const struct onionreply *onionreply,
	     const struct routing_failure *fail,
	     const char *errmsg)
{
	struct json_stream *data;

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
			"Monitor status with listpays or waitsendpay");
	json_add_payment_fields(response, payment);
	return command_success(cmd, response);
}

static void tell_waiters_failed(struct lightningd *ld,
				const struct sha256 *payment_hash,
				const struct wallet_payment *payment,
				errcode_t pay_errcode,
				const struct onionreply *onionreply,
				const struct routing_failure *fail,
				const char *details)
{
	struct sendpay_command *pc;
	struct sendpay_command *next;
	const char *errmsg =
	    sendpay_errmsg_fmt(tmpctx, pay_errcode, fail, details);

	/* Careful: sendpay_fail deletes cmd */
	list_for_each_safe(&ld->waitsendpay_commands, pc, next, list) {
		if (!sha256_eq(payment_hash, &pc->payment_hash))
			continue;
		if (payment->partid != pc->partid)
			continue;

		sendpay_fail(pc->cmd, payment, pay_errcode, onionreply, fail,
			     errmsg);
	}

	notify_sendpay_failure(ld,
			       payment,
			       pay_errcode,
			       onionreply,
			       fail,
			       errmsg);
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
		if (payment->partid != pc->partid)
			continue;

		sendpay_success(pc->cmd, payment);
	}
	notify_sendpay_success(ld, payment);
}

void payment_succeeded(struct lightningd *ld, struct htlc_out *hout,
		       const struct preimage *rval)
{
	struct wallet_payment *payment;

	wallet_payment_set_status(ld->wallet, &hout->payment_hash,
				  hout->partid,
				  PAYMENT_COMPLETE, rval);
	payment = wallet_payment_by_hash(tmpctx, ld->wallet,
					 &hout->payment_hash,
					 hout->partid);
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

	routing_failure = tal(ctx, struct routing_failure);
	routing_failure->erring_index = 0;
	routing_failure->failcode = fromwire_peektype(hout->failmsg);

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
		  routing_failure->failcode,
		  onion_type_name(routing_failure->failcode));
	return routing_failure;
}

/* Fills in *pay_errcode with PAY_TRY_OTHER_ROUTE or PAY_DESTINATION_PERM_FAIL */
static struct routing_failure*
remote_routing_failure(const tal_t *ctx,
		       struct lightningd *ld,
		       const struct wallet_payment *payment,
		       const u8 *failuremsg,
		       int origin_index,
		       struct log *log,
		       errcode_t *pay_errcode)
{
	enum onion_type failcode = fromwire_peektype(failuremsg);
	struct routing_failure *routing_failure;
	const struct node_id *route_nodes;
	const struct node_id *erring_node;
	const struct short_channel_id *route_channels;
	const struct short_channel_id *erring_channel;
	int dir;

	routing_failure = tal(ctx, struct routing_failure);
	route_nodes = payment->route_nodes;
	route_channels = payment->route_channels;

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
		if (failcode & BADONION)
			*pay_errcode = PAY_UNPARSEABLE_ONION;
		else if (failcode & PERM)
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
				  failcode, tal_hex(tmpctx, failuremsg));
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
							   failuremsg);
		subd_send_msg(ld->gossip, take(gossip_msg));
	}

	routing_failure->erring_index = (unsigned int) (origin_index + 1);
	routing_failure->failcode = failcode;
	routing_failure->msg = tal_dup_talarr(routing_failure, u8, failuremsg);

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

void payment_store(struct lightningd *ld, struct wallet_payment *payment TAKES)
{
	struct sendpay_command *pc;
	struct sendpay_command *next;
	/* Need to remember here otherwise wallet_payment_store will free us. */
	bool ptaken = taken(payment);

	wallet_payment_store(ld->wallet, payment);

	/* Trigger any sendpay commands waiting for the store to occur. */
	list_for_each_safe(&ld->sendpay_commands, pc, next, list) {
		if (!sha256_eq(&payment->payment_hash, &pc->payment_hash))
			continue;

		/* Deletes from list, frees pc */
		json_sendpay_in_progress(pc->cmd, payment);
	}

	if (ptaken)
		tal_free(payment);
}

void payment_failed(struct lightningd *ld, const struct htlc_out *hout,
		    const char *localfail)
{
	struct wallet_payment *payment;
	struct routing_failure* fail = NULL;
	const char *failstr;
	errcode_t pay_errcode;
	const u8 *failmsg;
	int origin_index;

	payment = wallet_payment_by_hash(tmpctx, ld->wallet,
					 &hout->payment_hash,
					 hout->partid);

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
		failstr = localfail;
		pay_errcode = PAY_TRY_OTHER_ROUTE;
	} else if (payment->path_secrets == NULL) {
		/* This was a payment initiated with `sendonion`, we therefore
		 * don't have the path secrets and cannot decode the error
		 * onion. Let's store it and hope whatever called `sendonion`
		 * knows how to deal with these. */

		pay_errcode = PAY_UNPARSEABLE_ONION;
		fail = NULL;
		failstr = NULL;
	} else if (hout->failmsg) {
		/* This can happen when a direct peer told channeld it's a
		 * malformed onion using update_fail_malformed_htlc. */
		failstr = "local failure";
		failmsg = hout->failmsg;
		origin_index = 0;
		pay_errcode = PAY_TRY_OTHER_ROUTE;
		goto use_failmsg;
	} else {
		/* Must be normal remote fail with an onion-wrapped error. */
		failstr = "reply from remote";
		/* Try to parse reply. */
		struct secret *path_secrets = payment->path_secrets;

		failmsg = unwrap_onionreply(tmpctx, path_secrets,
					    tal_count(path_secrets),
					    hout->failonion, &origin_index);
		if (!failmsg) {
			log_info(hout->key.channel->log,
				 "htlc %"PRIu64" failed with bad reply (%s)",
				 hout->key.id,
				 tal_hex(tmpctx, hout->failonion->contents));
			/* Cannot record failure. */
			fail = NULL;
			pay_errcode = PAY_UNPARSEABLE_ONION;
		} else {
			enum onion_type failcode;

		use_failmsg:
			failcode = fromwire_peektype(failmsg);
			log_info(hout->key.channel->log,
				 "htlc %"PRIu64" "
				 "failed from %ith node "
				 "with code 0x%04x (%s)",
				 hout->key.id,
				 origin_index,
				 failcode, onion_type_name(failcode));
			fail = remote_routing_failure(tmpctx, ld,
						      payment, failmsg,
						      origin_index,
						      hout->key.channel->log,
						      &pay_errcode);
		}
	}

	/* Save to DB */
	payment_store(ld, payment);
	wallet_payment_set_status(ld->wallet, &hout->payment_hash,
				  hout->partid,
				  PAYMENT_FAILED, NULL);
	wallet_payment_set_failinfo(ld->wallet,
				    &hout->payment_hash,
				    hout->partid,
				    fail ? NULL : hout->failonion,
				    pay_errcode == PAY_DESTINATION_PERM_FAIL,
				    fail ? fail->erring_index : -1,
				    fail ? fail->failcode : 0,
				    fail ? fail->erring_node : NULL,
				    fail ? fail->erring_channel : NULL,
				    NULL,
				    failstr,
				    fail ? fail->channel_dir : 0);

	tell_waiters_failed(ld, &hout->payment_hash, payment, pay_errcode,
			    hout->failonion, fail, failstr);
}

/* Wait for a payment. If cmd is deleted, then wait_payment()
 * no longer be called.
 * Return callback if we called already, otherwise NULL. */
static struct command_result *wait_payment(struct lightningd *ld,
					   struct command *cmd,
					   const struct sha256 *payment_hash,
					   u64 partid)
{
	struct wallet_payment *payment;
	struct onionreply *failonionreply;
	bool faildestperm;
	int failindex;
	enum onion_type failcode;
	struct node_id *failnode;
	struct short_channel_id *failchannel;
	u8 *failupdate;
	char *faildetail;
	struct routing_failure *fail;
	int faildirection;
	errcode_t rpcerrorcode;

	payment = wallet_payment_by_hash(tmpctx, ld->wallet,
					 payment_hash, partid);
	if (!payment) {
		return command_fail(cmd, PAY_NO_SUCH_PAYMENT,
				    "Never attempted payment part %"PRIu64
				    " for '%s'",
				    partid,
				    type_to_string(tmpctx, struct sha256,
						   payment_hash));
	}

	log_debug(cmd->ld->log, "Payment part %"PRIu64"/%"PRIu64" status %u",
		  partid, payment->partid, payment->status);

	switch (payment->status) {
	case PAYMENT_PENDING:
		add_waitsendpay_waiter(ld, cmd, payment_hash, partid);
		return NULL;

	case PAYMENT_COMPLETE:
		return sendpay_success(cmd, payment);

	case PAYMENT_FAILED:
		/* Get error from DB */
		wallet_payment_get_failinfo(tmpctx, ld->wallet,
					    payment_hash,
					    partid,
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
			return sendpay_fail(
			    cmd, payment, PAY_UNPARSEABLE_ONION, failonionreply,
			    NULL,
			    sendpay_errmsg_fmt(tmpctx, PAY_UNPARSEABLE_ONION,
					       NULL, faildetail));
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

			rpcerrorcode = faildestperm ? PAY_DESTINATION_PERM_FAIL
						    : PAY_TRY_OTHER_ROUTE;

			return sendpay_fail(
			    cmd, payment, rpcerrorcode, NULL, fail,
			    sendpay_errmsg_fmt(tmpctx, rpcerrorcode, fail,
					       faildetail));
		}
	}

	/* Impossible. */
	abort();
}

static bool should_use_tlv(enum route_hop_style style)
{
	switch (style) {
	case ROUTE_HOP_TLV:
		return true;
		/* Otherwise fall thru */
	case ROUTE_HOP_LEGACY:
		return false;
	}
	abort();
}

/* Returns failmsg on failure, tallocated off ctx */
static const u8 *send_onion(const tal_t *ctx, struct lightningd *ld,
				  const struct onionpacket *packet,
				  const struct route_hop *first_hop,
				  const struct sha256 *payment_hash,
				  u64 partid,
				  struct channel *channel,
				  struct htlc_out **hout)
{
	const u8 *onion;
	unsigned int base_expiry;
	bool dont_care_about_channel_update;
	base_expiry = get_block_height(ld->topology) + 1;
	onion = serialize_onionpacket(tmpctx, packet);
	return send_htlc_out(ctx, channel, first_hop->amount,
			     base_expiry + first_hop->delay,
			     payment_hash, partid, onion, NULL, hout,
			     &dont_care_about_channel_update);
}

/* destination/route_channels/route_nodes are NULL (and path_secrets may be NULL)
 * if we're sending a raw onion. */
static struct command_result *
send_payment_core(struct lightningd *ld,
		  struct command *cmd,
		  const struct sha256 *rhash,
		  u64 partid,
		  const struct route_hop *first_hop,
		  struct amount_msat msat,
		  struct amount_msat total_msat,
		  const char *label TAKES,
		  const char *b11str TAKES,
		  const struct onionpacket *packet,
		  const struct node_id *destination,
		  struct node_id *route_nodes TAKES,
		  struct short_channel_id *route_channels TAKES,
		  struct secret *path_secrets)
{
	const struct wallet_payment **payments, *old_payment = NULL;
	struct channel *channel;
	const u8 *failmsg;
	struct htlc_out *hout;
	struct routing_failure *fail;
	struct amount_msat msat_already_pending = AMOUNT_MSAT(0);

	/* Now, do we already have one or more payments? */
	payments = wallet_payment_list(tmpctx, ld->wallet, rhash);
	for (size_t i = 0; i < tal_count(payments); i++) {
		log_debug(ld->log, "Payment %zu/%zu: %s %s",
			  i, tal_count(payments),
			  type_to_string(tmpctx, struct amount_msat,
					 &payments[i]->msatoshi),
			  payments[i]->status == PAYMENT_COMPLETE ? "COMPLETE"
			  : payments[i]->status == PAYMENT_PENDING ? "PENDING"
			  : "FAILED");

		switch (payments[i]->status) {
		case PAYMENT_COMPLETE:
			if (payments[i]->partid != partid)
				continue;

			/* Must match successful payment parameters. */
			if (!amount_msat_eq(payments[i]->msatoshi, msat)) {
				return command_fail(cmd, PAY_RHASH_ALREADY_USED,
						    "Already succeeded "
						    "with amount %s",
						    type_to_string(tmpctx,
								   struct amount_msat,
								   &payments[i]->msatoshi));
			}
			if (payments[i]->destination && destination
			    && !node_id_eq(payments[i]->destination,
					   destination)) {
				return command_fail(cmd, PAY_RHASH_ALREADY_USED,
						    "Already succeeded to %s",
						    type_to_string(tmpctx,
								   struct node_id,
								   payments[i]->destination));
			}
			return sendpay_success(cmd, payments[i]);

		case PAYMENT_PENDING:
			/* Can't mix non-parallel and parallel payments! */
			if (!payments[i]->partid != !partid) {
				return command_fail(cmd, PAY_IN_PROGRESS,
						    "Already have %s payment in progress",
						    payments[i]->partid ? "parallel" : "non-parallel");
			}
			if (payments[i]->partid == partid)
				return json_sendpay_in_progress(cmd, payments[i]);
			/* You shouldn't change your mind about amount being
			 * sent, since we'll use it in onion! */
			else if (!amount_msat_eq(payments[i]->total_msat,
						 total_msat))
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "msatoshi was previously %s, now %s",
						    type_to_string(tmpctx,
								   struct amount_msat,
								   &payments[i]->total_msat),
						    type_to_string(tmpctx,
								   struct amount_msat,
								   &total_msat));


			if (!amount_msat_add(&msat_already_pending,
					     msat_already_pending,
					     payments[i]->msatoshi)) {
				return command_fail(cmd, LIGHTNINGD,
						    "Internal amount overflow!"
						    " %s + %s in %zu/%zu",
						    type_to_string(tmpctx,
								   struct amount_msat,
								   &msat_already_pending),
						    type_to_string(tmpctx,
								   struct amount_msat,
								   &payments[i]->msatoshi),
						    i, tal_count(payments));
			}
			break;

		case PAYMENT_FAILED:
			if (payments[i]->partid == partid)
				old_payment = payments[i];
 		}
	}

	/* BOLT #4:
	 *
	 * - MUST NOT send another HTLC if the total `amount_msat` of the HTLC
	 *   set is already greater or equal to `total_msat`.
	 */
	/* We don't do this for single 0-value payments (sendonion does this) */
	if (!amount_msat_eq(total_msat, AMOUNT_MSAT(0))
	    && amount_msat_greater_eq(msat_already_pending, total_msat)) {
		return command_fail(cmd, PAY_IN_PROGRESS,
				    "Already have %s of %s payments in progress",
				    type_to_string(tmpctx, struct amount_msat,
						   &msat_already_pending),
				    type_to_string(tmpctx, struct amount_msat,
						   &total_msat));
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

	failmsg = send_onion(tmpctx, ld, packet, first_hop, rhash, partid,
			      channel, &hout);

	if (failmsg) {
		fail = immediate_routing_failure(cmd, ld,
						 fromwire_peektype(failmsg),
						 &first_hop->channel_id,
						 &channel->peer->id);

		return sendpay_fail(
		    cmd, old_payment, PAY_TRY_OTHER_ROUTE, NULL, fail,
		    sendpay_errmsg_fmt(tmpctx, PAY_TRY_OTHER_ROUTE, fail,
				       "First peer not ready"));
	}

	/* If we're retrying, delete all trace of previous one.  We delete
	 * outgoing HTLC, too, otherwise it gets reported to onchaind as
	 * a possibility, and we end up in handle_missing_htlc_output->
	 * onchain_failed_our_htlc->payment_failed with no payment.
	 */
	if (old_payment) {
		wallet_payment_delete(ld->wallet, rhash, partid);
		wallet_local_htlc_out_delete(ld->wallet, channel, rhash,
					     partid);
	}

	/* If hout fails, payment should be freed too. */
	struct wallet_payment *payment = tal(hout, struct wallet_payment);
	payment->id = 0;
	payment->payment_hash = *rhash;
	payment->partid = partid;
	if (destination)
		payment->destination = tal_dup(payment, struct node_id, destination);
	else
		payment->destination = NULL;
	payment->status = PAYMENT_PENDING;
	payment->msatoshi = msat;
	payment->msatoshi_sent = first_hop->amount;
	payment->total_msat = total_msat;
	payment->timestamp = time_now().ts.tv_sec;
	payment->payment_preimage = NULL;
	payment->path_secrets = tal_steal(payment, path_secrets);
	if (route_nodes)
		payment->route_nodes = tal_steal(payment, route_nodes);
	else
		payment->route_nodes = NULL;
	if (route_channels)
		payment->route_channels = tal_steal(payment, route_channels);
	else
		payment->route_channels = NULL;
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

	add_sendpay_waiter(ld, cmd, rhash, partid);
	return command_still_pending(cmd);
}

static struct command_result *
send_payment(struct lightningd *ld,
	     struct command *cmd,
	     const struct sha256 *rhash,
	     u64 partid,
	     const struct route_hop *route,
	     struct amount_msat msat,
	     struct amount_msat total_msat,
	     const char *label TAKES,
	     const char *b11str TAKES,
	     const struct secret *payment_secret)
{
	unsigned int base_expiry;
	struct onionpacket *packet;
	struct secret *path_secrets;
	size_t i, n_hops = tal_count(route);
	struct node_id *ids = tal_arr(tmpctx, struct node_id, n_hops);
	struct short_channel_id *channels;
	struct sphinx_path *path;
	struct pubkey pubkey;
	bool final_tlv, ret;
	u8 *onion;

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

		sphinx_add_hop(path, &pubkey,
			       take(onion_nonfinal_hop(NULL,
					should_use_tlv(route[i].style),
					&route[i + 1].channel_id,
					route[i + 1].amount,
					base_expiry + route[i + 1].delay)));
	}

	/* And finally set the final hop to the special values in
	 * BOLT04 */
	ret = pubkey_from_node_id(&pubkey, &ids[i]);
	assert(ret);

	final_tlv = should_use_tlv(route[i].style);
	/* BOLT #4:
	 * - Unless `node_announcement`, `init` message or the
	 *   [BOLT #11](11-payment-encoding.md#tagged-fields) offers feature
	 *   `var_onion_optin`:
	 *    - MUST use the legacy payload format instead.
	 */
	/* In our case, we don't use it unless we also have a payment_secret;
	 * everyone should support this eventually */
	if (!final_tlv && payment_secret)
		final_tlv = true;

	/* Parallel payments are invalid for legacy. */
	if (partid && !final_tlv)
		return command_fail(cmd, PAY_DESTINATION_PERM_FAIL,
				    "Cannot do parallel payments to legacy node");

	onion = onion_final_hop(cmd,
				final_tlv,
				route[i].amount,
				base_expiry + route[i].delay,
				total_msat, payment_secret);
	if (!onion) {
		return command_fail(cmd, PAY_DESTINATION_PERM_FAIL,
				    "Destination does not support"
				    " payment_secret");
	}
	sphinx_add_hop(path, &pubkey, onion);

	/* Copy channels used along the route. */
	channels = tal_arr(tmpctx, struct short_channel_id, n_hops);
	for (i = 0; i < n_hops; ++i)
		channels[i] = route[i].channel_id;

	log_info(ld->log, "Sending %s over %zu hops to deliver %s",
		 type_to_string(tmpctx, struct amount_msat, &route[0].amount),
		 n_hops, type_to_string(tmpctx, struct amount_msat, &msat));
	packet = create_onionpacket(tmpctx, path, &path_secrets);
	return send_payment_core(ld, cmd, rhash, partid, &route[0],
				 msat, total_msat, label, b11str,
				 packet, &ids[n_hops - 1], ids,
				 channels, path_secrets);
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
	struct onionpacket packet;
	enum onion_type failcode;
	struct route_hop *first_hop;
	struct sha256 *payment_hash;
	struct lightningd *ld = cmd->ld;
	const char *label;
	struct secret *path_secrets;
	u64 *partid;

	if (!param(cmd, buffer, params,
		   p_req("onion", param_bin_from_hex, &onion),
		   p_req("first_hop", param_route_hop, &first_hop),
		   p_req("payment_hash", param_sha256, &payment_hash),
		   p_opt("label", param_escaped_string, &label),
		   p_opt("shared_secrets", param_secrets_array, &path_secrets),
		   p_opt_def("partid", param_u64, &partid, 0),
		   NULL))
		return command_param_failed();

	failcode = parse_onionpacket(onion, tal_bytelen(onion), &packet);

	if (failcode != 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Could not parse the onion. Parsing failed "
				    "with failcode=%d",
				    failcode);

	return send_payment_core(ld, cmd, payment_hash, *partid,
				 first_hop, AMOUNT_MSAT(0), AMOUNT_MSAT(0),
				 label, NULL, &packet, NULL, NULL, NULL,
				 path_secrets);
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
	const char *b11str, *label;
	u64 *partid;
	struct secret *payment_secret;

	/* For generating help, give new-style. */
	if (!param(cmd, buffer, params,
		   p_req("route", param_array, &routetok),
		   p_req("payment_hash", param_sha256, &rhash),
		   p_opt("label", param_escaped_string, &label),
		   p_opt("msatoshi", param_msat, &msat),
		   p_opt("bolt11", param_string, &b11str),
		   p_opt("payment_secret", param_secret, &payment_secret),
		   p_opt_def("partid", param_u64, &partid, 0),
		   NULL))
		return command_param_failed();

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

	if (*partid && !msat)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Must specify msatoshi with partid");

	const struct amount_msat final_amount = route[routetok->size-1].amount;

	if (msat && !*partid && !amount_msat_eq(*msat, final_amount))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Do not specify msatoshi (%s) without"
				    " partid: if you do, it must be exactly"
				    " the final amount (%s)",
				    type_to_string(tmpctx, struct amount_msat,
						   msat),
				    type_to_string(tmpctx, struct amount_msat,
						   &final_amount));

	/* For MPP, the total we send must *exactly* equal the amount
	 * we promise to send (msatoshi).  So no single payment can be
	 * > than that. */
	if (*partid) {
		if (amount_msat_greater(final_amount, *msat))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Final amount %s is greater than"
					    " %s, despite MPP",
					    type_to_string(tmpctx,
							   struct amount_msat,
							   &final_amount),
					    type_to_string(tmpctx,
							   struct amount_msat,
							   msat));
	}

	if (*partid && !payment_secret)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "partid requires payment_secret");

	return send_payment(cmd->ld, cmd, rhash, *partid,
			    route,
			    final_amount,
			    msat ? *msat : final_amount,
			    label, b11str, payment_secret);
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
	u64 *partid;

	if (!param(cmd, buffer, params,
		   p_req("payment_hash", param_sha256, &rhash),
		   p_opt("timeout", param_number, &timeout),
		   p_opt_def("partid", param_u64, &partid, 0),
		   NULL))
		return command_param_failed();

	res = wait_payment(cmd->ld, cmd, rhash, *partid);
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
		sphinx_add_hop(sp, &hops[i].pubkey, hops[i].raw_payload);

	if (sphinx_path_payloads_size(sp) > ROUTING_INFO_SIZE)
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "Payloads exceed maximum onion packet size.");

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
