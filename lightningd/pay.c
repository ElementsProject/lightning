#include "config.h"
#include <ccan/json_escape/json_escape.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/bolt12_merkle.h>
#include <common/configdir.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/onionreply.h>
#include <common/route.h>
#include <common/timeout.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/invoice.h>
#include <lightningd/notification.h>
#include <lightningd/pay.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_htlcs.h>
#include <wallet/invoices.h>

/* Routing failure object */
struct routing_failure {
	unsigned int erring_index;
	enum onion_wire failcode;
	const struct node_id *erring_node;
	const struct short_channel_id *erring_channel;
	int channel_dir;
	/* If remote sent us a message, this is it. */
	const u8 *msg;
};

/* waitsendpay command */
struct waitsendpay_command {
	struct list_node list;

	struct sha256 payment_hash;
	u64 partid;
	u64 groupid;
	struct command *cmd;
	void *arg;

	struct command_result *(*success)(struct command *cmd,
					  const struct wallet_payment *payment,
					  void *arg);
	struct command_result *(*fail)(struct command *cmd,
				       const struct wallet_payment *payment,
				       enum jsonrpc_errcode pay_errcode,
				       const struct onionreply *onionreply,
				       const struct routing_failure *fail,
				       const char *errmsg,
				       void *arg);
};

static bool string_to_payment_status(const char *status_str, size_t len,
				     enum payment_status *status)
{
	if (memeqstr(status_str, len, "complete")) {
		*status = PAYMENT_COMPLETE;
		return true;
	} else if (memeqstr(status_str, len, "pending")) {
		*status = PAYMENT_PENDING;
		return true;
	} else if (memeqstr(status_str, len, "failed")) {
		*status = PAYMENT_FAILED;
		return true;
	}
	return false;
}

static const char *payment_status_to_string(const enum payment_status status)
{
	switch (status) {
	case PAYMENT_COMPLETE:
		return "complete";
	case PAYMENT_FAILED:
		return "failed";
	case PAYMENT_PENDING:
		return "pending";
	}
	//This should never happen
	abort();
}


static void destroy_waitsendpay_command(struct waitsendpay_command *pc)
{
	list_del(&pc->list);
}

/* Owned by cmd, if cmd is deleted, then sendpay_success/sendpay_fail will
 * no longer be called. */
static void
add_waitsendpay_waiter_(struct lightningd *ld,
			struct command *cmd,
			const struct sha256 *payment_hash,
			u64 partid, u64 groupid,
			struct command_result *(*success)(struct command *cmd,
							  const struct wallet_payment *payment,
							  void *arg),
			struct command_result *(*fail)(struct command *cmd,
						       const struct wallet_payment *payment,
						       enum jsonrpc_errcode pay_errcode,
						       const struct onionreply *onionreply,
						       const struct routing_failure *fail,
						       const char *errmsg,
						       void *arg),
			void *arg)
{
	struct waitsendpay_command *pc = tal(cmd, struct waitsendpay_command);

	pc->payment_hash = *payment_hash;
	pc->partid = partid;
	pc->groupid = groupid;
	pc->cmd = cmd;
	pc->arg = arg;
	pc->success = success;
	pc->fail = fail;
	list_add(&ld->waitsendpay_commands, &pc->list);
	tal_add_destructor(pc, destroy_waitsendpay_command);
}

#define add_waitsendpay_waiter(ld, cmd, payment_hash, partid, groupid, success, fail, arg) \
	add_waitsendpay_waiter_((ld), (cmd), (payment_hash), (partid), (groupid), \
				typesafe_cb_preargs(struct command_result *, void *, \
						    (success), (arg),	\
						    struct command *,	\
						    const struct wallet_payment *), \
				typesafe_cb_preargs(struct command_result *, void *, \
						    (fail), (arg),	\
						    struct command *,	\
						    const struct wallet_payment *, \
						    enum jsonrpc_errcode, \
						    const struct onionreply *, \
						    const struct routing_failure *, \
						    const char *),	\
				(arg))

/* Outputs fields, not a separate object*/
void json_add_payment_fields(struct json_stream *response,
			     const struct wallet_payment *t)
{
	json_add_u64(response, "created_index", t->id);
	json_add_u64(response, "id", t->id);
	json_add_sha256(response, "payment_hash", &t->payment_hash);
	json_add_u64(response, "groupid", t->groupid);
	if (t->updated_index)
		json_add_u64(response, "updated_index", t->updated_index);
	if (t->partid)
		json_add_u64(response, "partid", t->partid);
	if (t->destination != NULL)
		json_add_node_id(response, "destination", t->destination);

	/* If we have a 0 amount delivered at the remote end we simply don't
	 * know since the onion was generated externally. */
	if (amount_msat_greater(t->msatoshi, AMOUNT_MSAT(0)))
		json_add_amount_msat(response, "amount_msat", t->msatoshi);

	json_add_amount_msat(response, "amount_sent_msat", t->msatoshi_sent);
	json_add_u32(response, "created_at", t->timestamp);
	if (t->completed_at)
		json_add_u32(response, "completed_at", *t->completed_at);

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
	if (t->invstring) {
		if (strstarts(t->invstring, "lni"))
			json_add_string(response, "bolt12", t->invstring);
		else
			json_add_string(response, "bolt11", t->invstring);
	}
	if (t->description)
		json_add_string(response, "description", t->description);

	if (t->failonion)
		json_add_hex(response, "erroronion", t->failonion,
			     tal_count(t->failonion));
}

static struct command_result *sendpay_success(struct command *cmd,
					      const struct wallet_payment *payment,
					      void *unused)
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
			enum onion_wire failcode,
			const struct node_id *erring_node,
			const struct short_channel_id *erring_channel,
			int channel_dir,
			const u8 *msg)
{
	const char *failcodename = onion_wire_name(failcode);

	json_add_num(js, "erring_index", erring_index);
	json_add_num(js, "failcode", failcode);
	/* FIXME: Better way to detect this? */
	if (!strstarts(failcodename, "INVALID "))
		json_add_string(js, "failcodename", failcodename);

	if (erring_node != NULL)
		json_add_node_id(js, "erring_node", erring_node);

	if (erring_channel != NULL) {
		json_add_short_channel_id(js, "erring_channel", *erring_channel);
		json_add_num(js, "erring_direction", channel_dir);
	}

	if (msg)
		json_add_hex_talarr(js, "raw_message", msg);
}

void json_sendpay_fail_fields(struct json_stream *js,
			      const struct wallet_payment *payment,
			      enum jsonrpc_errcode pay_errcode,
			      const struct onionreply *onionreply,
			      const struct routing_failure *fail)
{
	/* "immediate_routing_failure" is before payment creation. */
	if (payment)
		json_add_payment_fields(js, payment);
	if (pay_errcode == PAY_UNPARSEABLE_ONION && onionreply)
		json_add_hex_talarr(js, "onionreply", onionreply->contents);
	else if (fail)
		json_add_routefail_info(js,
					fail->erring_index,
					fail->failcode,
					fail->erring_node,
					fail->erring_channel,
					fail->channel_dir,
					fail->msg);
}

static const char *sendpay_errmsg_fmt(const tal_t *ctx, enum jsonrpc_errcode pay_errcode,
				      const struct routing_failure *fail,
				      const char *details)
{
	char *errmsg;
	if (pay_errcode == PAY_UNPARSEABLE_ONION)
		errmsg = "Malformed error reply";
	else {
		assert(fail);
		errmsg = tal_fmt(ctx, "failed: %s (%s)",
				 onion_wire_name(fail->failcode), details);
	}
	return errmsg;
}

/* onionreply used if pay_errcode == PAY_UNPARSEABLE_ONION */
static struct command_result *
sendpay_fail(struct command *cmd,
	     const struct wallet_payment *payment,
	     enum jsonrpc_errcode pay_errcode,
	     const struct onionreply *onionreply,
	     const struct routing_failure *fail,
	     const char *errmsg,
	     void *unused)
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
				enum jsonrpc_errcode pay_errcode,
				const struct onionreply *onionreply,
				const struct routing_failure *fail,
				const char *details)
{
	struct waitsendpay_command *pc;
	struct waitsendpay_command *next;
	const char *errmsg =
	    sendpay_errmsg_fmt(tmpctx, pay_errcode, fail, details);

	/* Careful: ->fail deletes cmd */
	list_for_each_safe(&ld->waitsendpay_commands, pc, next, list) {
		if (!sha256_eq(payment_hash, &pc->payment_hash))
			continue;
		if (payment->partid != pc->partid)
			continue;
		if (payment->groupid != pc->groupid)
			continue;

		pc->fail(pc->cmd, payment, pay_errcode, onionreply, fail, errmsg, pc->arg);
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
	struct waitsendpay_command *pc;
	struct waitsendpay_command *next;

	/* Careful: sendpay_success deletes cmd */
	list_for_each_safe(&ld->waitsendpay_commands, pc, next, list) {
		if (!sha256_eq(payment_hash, &pc->payment_hash))
			continue;
		if (payment->partid != pc->partid)
			continue;
		if (payment->groupid != pc->groupid)
			continue;

		pc->success(pc->cmd, payment, pc->arg);
	}
	notify_sendpay_success(ld, payment);
}

void payment_succeeded(struct lightningd *ld,
		       const struct sha256 *payment_hash,
		       u64 partid, u64 groupid,
		       const struct preimage *rval)
{
	struct wallet_payment *payment;

	wallet_payment_set_status(ld->wallet, payment_hash,
				  partid, groupid,
				  PAYMENT_COMPLETE, rval);
	payment = wallet_payment_by_hash(tmpctx, ld->wallet,
					 payment_hash,
					 partid, groupid);
	assert(payment);

	if (payment->local_invreq_id)
		wallet_invoice_request_mark_used(ld->wallet->db,
						 payment->local_invreq_id);
	tell_waiters_success(ld, payment_hash, payment);
}

/* Return a struct routing_failure for an immediate failure
 * (returned directly from send_htlc_out). The returned
 * failure is allocated from the given context. */
static struct routing_failure*
immediate_routing_failure(const tal_t *ctx,
			  const struct lightningd *ld,
			  enum onion_wire failcode,
			  struct short_channel_id channel0,
			  const struct node_id *dstid)
{
	struct routing_failure *routing_failure;

	assert(failcode);

	routing_failure = tal(ctx, struct routing_failure);
	routing_failure->erring_index = 0;
	routing_failure->failcode = failcode;
	routing_failure->erring_node =
	    tal_dup(routing_failure, struct node_id, &ld->our_nodeid);
	routing_failure->erring_channel =
	    tal_dup(routing_failure, struct short_channel_id, &channel0);
	routing_failure->channel_dir = node_id_idx(&ld->our_nodeid, dstid);
	routing_failure->msg = NULL;

	return routing_failure;
}

/* Return a struct routing_failure for a local failure allocated
 * from the given context. */
static struct routing_failure*
local_routing_failure(const tal_t *ctx,
		      const struct lightningd *ld,
		      const struct htlc_out *hout,
		      enum onion_wire failcode,
		      const struct wallet_payment *payment)
{
	struct routing_failure *routing_failure;

	routing_failure = tal(ctx, struct routing_failure);
	routing_failure->erring_index = 0;
	routing_failure->failcode = failcode;

	routing_failure->erring_node =
	    tal_dup(routing_failure, struct node_id, &ld->our_nodeid);

	if (payment->route_nodes != NULL && payment->route_channels != NULL) {
		routing_failure->erring_channel =
		    tal_dup(routing_failure, struct short_channel_id,
			    &payment->route_channels[0]);
		routing_failure->channel_dir =
		    node_id_idx(&ld->our_nodeid, &payment->route_nodes[0]);
	} else {
		routing_failure->erring_channel = NULL;
	}

	routing_failure->msg = NULL;

	log_debug(hout->key.channel->log, "local_routing_failure: %u (%s)",
		  routing_failure->failcode,
		  onion_wire_name(routing_failure->failcode));
	return routing_failure;
}

/* Fills in *pay_errcode with PAY_TRY_OTHER_ROUTE or PAY_DESTINATION_PERM_FAIL */
static struct routing_failure*
remote_routing_failure(const tal_t *ctx,
		       struct lightningd *ld,
		       const struct wallet_payment *payment,
		       const u8 *failuremsg,
		       int origin_index,
		       struct logger *log,
		       enum jsonrpc_errcode *pay_errcode)
{
	enum onion_wire failcode = fromwire_peektype(failuremsg);
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
			dir = node_id_idx(&ld->our_nodeid,
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
	}

	routing_failure->erring_index = (unsigned int) (origin_index + 1);
	routing_failure->failcode = failcode;
	routing_failure->msg = tal_dup_talarr(routing_failure, u8, failuremsg);

	routing_failure->erring_node =
		tal_dup_or_null(routing_failure, struct node_id, erring_node);

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

void payment_failed(struct lightningd *ld, const struct htlc_out *hout,
		    const char *localfail)
{
	struct wallet_payment *payment;
	struct routing_failure* fail = NULL;
	const char *failstr;
	enum jsonrpc_errcode pay_errcode;
	const u8 *failmsg;
	int origin_index;

	payment = wallet_payment_by_hash(tmpctx, ld->wallet,
					 &hout->payment_hash,
					 hout->partid, hout->groupid);

#ifdef COMPAT_V052
	/* Prior to "pay: delete HTLC when we delete payment." we would
	 * delete a payment on retry, but leave the HTLC. */
	if (!payment) {
		log_unusual(hout->key.channel->log,
			    "No payment for %s:"
			    " was this an old database?",
			    fmt_sha256(tmpctx, &hout->payment_hash));
		return;
	}
#else
	assert(payment);
#endif
	assert((payment->route_channels == NULL) == (payment->route_nodes == NULL));

	/* This gives more details than a generic failure message */
	if (localfail) {
		/* Use temporary_channel_failure if failmsg has it */
		enum onion_wire failcode;
		failcode = fromwire_peektype(hout->failmsg);

		fail = local_routing_failure(tmpctx, ld, hout, failcode,
					     payment);
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
			enum onion_wire failcode;

		use_failmsg:
			failcode = fromwire_peektype(failmsg);
			log_info(hout->key.channel->log,
				 "htlc %"PRIu64" "
				 "failed from %ith node "
				 "with code 0x%04x (%s)",
				 hout->key.id,
				 origin_index,
				 failcode, onion_wire_name(failcode));
			fail = remote_routing_failure(tmpctx, ld,
						      payment, failmsg,
						      origin_index,
						      hout->key.channel->log,
						      &pay_errcode);
		}
	}

	wallet_payment_set_status(ld->wallet, &hout->payment_hash,
				  hout->partid, hout->groupid,
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
					   u64 partid, u64 groupid)
{
	struct wallet_payment *payment;
	struct onionreply *failonionreply;
	bool faildestperm;
	int failindex;
	enum onion_wire failcode;
	struct node_id *failnode;
	struct short_channel_id *failchannel;
	u8 *failupdate;
	char *faildetail;
	struct routing_failure *fail;
	int faildirection;
	enum jsonrpc_errcode rpcerrorcode;

	payment = wallet_payment_by_hash(tmpctx, ld->wallet,
					 payment_hash, partid, groupid);
	if (!payment) {
		return command_fail(cmd, PAY_NO_SUCH_PAYMENT,
				    "Never attempted payment part %"PRIu64
				    " for '%s'",
				    partid,
				    fmt_sha256(tmpctx, payment_hash));
	}

	log_debug(cmd->ld->log, "Payment part %"PRIu64"/%"PRIu64"/%"PRIu64" status %u",
		  partid, payment->partid, payment->groupid, payment->status);

	switch (payment->status) {
	case PAYMENT_PENDING:
		add_waitsendpay_waiter(ld, cmd, payment_hash, partid, groupid,
				       sendpay_success, sendpay_fail, NULL);
		return NULL;

	case PAYMENT_COMPLETE:
		return sendpay_success(cmd, payment, NULL);

	case PAYMENT_FAILED:
		/* Get error from DB */
		wallet_payment_get_failinfo(tmpctx, ld->wallet,
					    payment_hash,
					    partid,
					    groupid,
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
					       NULL, faildetail),
			    NULL);
		} else {
			/* Parsed onion error, get its details */
			assert(failnode);
			fail = tal(tmpctx, struct routing_failure);
			fail->erring_index = failindex;
			fail->failcode = failcode;
			fail->erring_node =
			    tal_dup(fail, struct node_id, failnode);

			if (failchannel) {
				fail->erring_channel = tal_dup(
				    fail, struct short_channel_id, failchannel);
				fail->channel_dir = faildirection;
			} else {
				fail->erring_channel = NULL;
			}

			/* FIXME: We don't store this! */
			fail->msg = NULL;

			rpcerrorcode = faildestperm ? PAY_DESTINATION_PERM_FAIL
						    : PAY_TRY_OTHER_ROUTE;

			return sendpay_fail(
			    cmd, payment, rpcerrorcode, NULL, fail,
			    sendpay_errmsg_fmt(tmpctx, rpcerrorcode, fail,
					       faildetail),
			    NULL);
		}
	}

	/* Impossible. */
	abort();
}

/* Returns failmsg on failure, tallocated off ctx */
static const u8 *send_onion(const tal_t *ctx, struct lightningd *ld,
			    const struct onionpacket *packet,
			    const struct route_hop *first_hop,
			    const struct amount_msat final_amount,
			    const struct sha256 *payment_hash,
			    const struct pubkey *path_key,
			    u64 partid,
			    u64 groupid,
			    struct channel *channel,
			    struct htlc_out **hout)
{
	const u8 *onion;
	unsigned int base_expiry;

	/* Use bitcoind's block height, even if we're behind in processing */
	base_expiry = get_network_blockheight(ld->topology) + 1;
	onion = serialize_onionpacket(tmpctx, packet);
	return send_htlc_out(ctx, channel, first_hop->amount,
			     base_expiry + first_hop->delay,
			     final_amount, payment_hash,
			     path_key, partid, groupid, onion, NULL, hout);
}

static struct command_result *check_invoice_request_usage(struct command *cmd,
							  const struct sha256 *local_invreq_id)
{
	enum offer_status status;
	struct db_stmt *stmt;

	if (!local_invreq_id)
		return NULL;

	if (!wallet_invoice_request_find(tmpctx, cmd->ld->wallet,
					 local_invreq_id,
					 NULL, &status))
		return command_fail(cmd, PAY_INVOICE_REQUEST_INVALID,
				    "Unknown invoice_request %s",
				    fmt_sha256(tmpctx, local_invreq_id));

	if (!offer_status_active(status))
		return command_fail(cmd, PAY_INVOICE_REQUEST_INVALID,
				    "Inactive invoice_request %s",
				    fmt_sha256(tmpctx, local_invreq_id));

	if (!offer_status_single(status))
		return NULL;

	/* OK, we must not attempt more than one payment at once for
	 * single_use invoice_request we publish! */
	stmt = payments_by_invoice_request(cmd->ld->wallet, local_invreq_id);
	if (stmt) {
		const struct wallet_payment *payment;
		payment = payment_get_details(tmpctx, stmt);

		tal_free(stmt);
		switch (payment->status) {
		case PAYMENT_COMPLETE:
			return command_fail(cmd, PAY_INVOICE_REQUEST_INVALID,
					    "Single-use invoice_request already paid"
					    " with %s",
					    fmt_sha256(tmpctx,
						       &payment->payment_hash));
		case PAYMENT_PENDING:
			return command_fail(cmd, PAY_INVOICE_REQUEST_INVALID,
					    "Single-use invoice_request already"
					    " in progress with %s",
					    fmt_sha256(tmpctx,
						       &payment->payment_hash));
		case PAYMENT_FAILED:
			break;
		}
	}

	return NULL;
}

static struct channel *
find_channel_for_htlc_add(struct lightningd *ld,
			  struct command *cmd,
			  const struct node_id *node,
			  struct short_channel_id scid_or_alias,
			  const struct amount_msat *amount)
{
	struct channel *channel;
	struct short_channel_id scid;
	struct peer *peer = peer_by_id(ld, node);
	if (!peer)
		return NULL;

	channel = find_channel_by_scid(peer, scid_or_alias);
	if (channel && channel_state_can_add_htlc(channel->state)) {
		goto found;
	}

	channel = find_channel_by_alias(peer, scid_or_alias, LOCAL);
	if (channel && channel_state_can_add_htlc(channel->state)) {
		goto found;
	}

	/* All-zero means "any" */
	if (!channel && memeqzero(&scid_or_alias, sizeof(scid_or_alias))) {
		list_for_each(&peer->channels, channel, list) {
			if (channel_state_can_add_htlc(channel->state) &&
			    amount_msat_greater(channel->our_msat, *amount)) {
				goto found;
			}
		}
	}

	log_debug(ld->log, "No channel found for selector %s (%s)",
		  fmt_short_channel_id(tmpctx, scid_or_alias),
		  fmt_amount_msat(tmpctx, *amount));
	return NULL;

found:
	scid = channel_scid_or_local_alias(channel);
	log_debug(
	    ld->log, "Selected channel %s (%s) for selector %s (%s)",
	    fmt_short_channel_id(tmpctx, scid),
	    fmt_amount_msat(tmpctx, channel->our_msat),
	    fmt_short_channel_id(tmpctx, scid_or_alias),
	    fmt_amount_msat(tmpctx, *amount));

	return channel;
}

/* Check if payment already in progress.  Returns NULL if all good */
static struct command_result *check_progress(struct lightningd *ld,
					     struct command *cmd,
					     const struct sha256 *rhash,
					     struct amount_msat msat,
					     struct amount_msat total_msat,
					     u64 partid,
					     u64 group,
					     const struct node_id *destination)
{
	bool have_complete = false;
	struct amount_msat msat_already_pending = AMOUNT_MSAT(0);

	/* Now, do we already have one or more payments? */
	for (struct db_stmt *stmt = payments_by_hash(cmd->ld->wallet, rhash);
	     stmt;
	     stmt = payments_next(cmd->ld->wallet, stmt)) {
		const struct wallet_payment *payment;

		payment = payment_get_details(tmpctx, stmt);
		log_debug(ld->log, "Payment: %s %s",
			  fmt_amount_msat(tmpctx, payment->msatoshi),
			  payment->status == PAYMENT_COMPLETE ? "COMPLETE"
			  : payment->status == PAYMENT_PENDING ? "PENDING"
			  : "FAILED");

		switch (payment->status) {
		case PAYMENT_COMPLETE:
			have_complete = true;
			if (payment->partid != partid)
				continue;

			tal_free(stmt);

			/* Must match successful payment parameters. */
			if (!amount_msat_eq(payment->msatoshi, msat)) {
				return command_fail(cmd, PAY_RHASH_ALREADY_USED,
						    "Already succeeded "
						    "with amount %s (not %s)",
						    fmt_amount_msat(tmpctx,
								    payment->msatoshi),
						    fmt_amount_msat(tmpctx,
								    msat));
			}
			if (payment->destination && destination
			    && !node_id_eq(payment->destination,
					   destination)) {
				return command_fail(cmd, PAY_RHASH_ALREADY_USED,
						    "Already succeeded to %s",
						    fmt_node_id(tmpctx,
								payment->destination));
			}
			return sendpay_success(cmd, payment, NULL);

		case PAYMENT_PENDING:
			/* At most one payment group can be in-flight at any
			 * time. */
			if (payment->groupid != group) {
				tal_free(stmt);
				return command_fail(
				    cmd, PAY_IN_PROGRESS,
				    "Payment with groupid=%" PRIu64
				    " still in progress, cannot retry before "
				    "that completes.",
				    payment->groupid);
			}

			/* Can't mix non-parallel and parallel payments! */
			if (!payment->partid != !partid) {
				tal_free(stmt);
				return command_fail(cmd, PAY_IN_PROGRESS,
						    "Already have %s payment in progress",
						    payment->partid ? "parallel" : "non-parallel");
			}

			if (payment->partid == partid) {
				tal_free(stmt);
				/* You can't change details while it's pending */
				if (!amount_msat_eq(payment->msatoshi, msat)) {
					return command_fail(cmd, PAY_RHASH_ALREADY_USED,
						    "Already pending "
						    "with amount %s (not %s)",
						    fmt_amount_msat(tmpctx,
								    payment->msatoshi),
						    fmt_amount_msat(tmpctx,
								    msat));
				}
				if (payment->destination && destination
				    && !node_id_eq(payment->destination,
						   destination)) {
					return command_fail(cmd, PAY_RHASH_ALREADY_USED,
							    "Already pending to %s",
							    fmt_node_id(tmpctx,
									   payment->destination));
				}
				return json_sendpay_in_progress(cmd, payment);
			}
			/* You shouldn't change your mind about amount being
			 * sent, since we'll use it in onion! */
			else if (!amount_msat_eq(payment->total_msat,
						 total_msat)) {
				tal_free(stmt);
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "msatoshi was previously %s, now %s",
						    fmt_amount_msat(tmpctx,
								    payment->total_msat),
						    fmt_amount_msat(tmpctx,
								    total_msat));
			}

			if (!amount_msat_accumulate(&msat_already_pending,
						    payment->msatoshi)) {
				tal_free(stmt);
				return command_fail(cmd, LIGHTNINGD,
						    "Internal amount overflow!"
						    " %s + %s",
						    fmt_amount_msat(tmpctx,
								    msat_already_pending),
						    fmt_amount_msat(tmpctx,
								    payment->msatoshi));
			}
			break;

		case PAYMENT_FAILED:
			break;
 		}
		/* There is no way for us to add a payment with the
		 * same (payment_hash, partid, groupid) tuple since
		 * it'd collide with the database primary key. So
		 * report this as soon as possible. */

		if (payment->partid == partid && payment->groupid == group) {
			tal_free(stmt);
			return command_fail(
			    cmd, PAY_RHASH_ALREADY_USED,
			    "There already is a payment with payment_hash=%s, "
			    "groupid=%" PRIu64 ", partid=%" PRIu64
			    ". Either change the partid, or wait for the "
			    "payment to complete and start a new group.",
			    fmt_sha256(tmpctx, rhash), group,
			    partid);
		}
	}

	/* If any part has succeeded, you can't start a new one! */
	if (have_complete) {
		return command_fail(cmd, PAY_RHASH_ALREADY_USED,
				    "Already succeeded other parts");
	}

	/* BOLT #4:
	 *
	 * - MUST NOT send another HTLC if the total `amt_to_forward` of the HTLC
	 *   set is already greater or equal to `total_msat`.
	 */
	/* We don't do this for single 0-value payments (sendonion does this) */
	if (!amount_msat_is_zero(total_msat)
	    && amount_msat_greater_eq(msat_already_pending, total_msat)) {
		return command_fail(cmd, PAY_IN_PROGRESS,
				    "Already have %s of %s payments in progress",
				    fmt_amount_msat(tmpctx,
						    msat_already_pending),
				    fmt_amount_msat(tmpctx, total_msat));
	}

	return NULL;
}

/* destination/route_channels/route_nodes are NULL (and path_secrets may be NULL)
 * if we're sending a raw onion. */
static struct command_result *
send_payment_core(struct lightningd *ld,
		  struct command *cmd,
		  const struct sha256 *rhash,
		  u64 partid,
		  u64 group,
		  const struct route_hop *first_hop,
		  struct amount_msat msat,
		  struct amount_msat total_msat,
		  const char *label TAKES,
		  const char *invstring TAKES,
		  const char *description TAKES,
		  const struct onionpacket *packet,
		  const struct node_id *destination,
		  struct node_id *route_nodes TAKES,
		  struct short_channel_id *route_channels TAKES,
		  struct secret *path_secrets,
		  const struct sha256 *local_invreq_id)
{
	struct channel *channel;
	const u8 *failmsg;
	struct htlc_out *hout;
	struct routing_failure *fail;
	struct command_result *ret;
	struct wallet_payment *payment;

	/* Reconcile this with previous attempts */
	ret = check_progress(ld, cmd, rhash, msat, total_msat, partid, group,
			     destination);
	if (ret)
		return ret;

	ret = check_invoice_request_usage(cmd, local_invreq_id);
	if (ret)
		return ret;

	channel = find_channel_for_htlc_add(ld, cmd, &first_hop->node_id,
					    first_hop->scid, &msat);
	if (!channel) {
		struct json_stream *data
			= json_stream_fail(cmd, PAY_TRY_OTHER_ROUTE,
					   "No connection to first "
					   "peer found");

		json_add_routefail_info(data, 0, WIRE_UNKNOWN_NEXT_PEER,
					&ld->our_nodeid, NULL,
					node_id_idx(&ld->our_nodeid,
						    &first_hop->node_id),
					NULL);
		json_object_end(data);
		return command_failed(cmd, data);
	}

	if (route_channels)
		log_info(ld->log, "Sending %s over %zu hops to deliver %s",
			 fmt_amount_msat(tmpctx, first_hop->amount),
			 tal_count(route_channels),
			 fmt_amount_msat(tmpctx, msat));
	else
		log_info(ld->log, "Sending %s in onion to deliver %s",
			 fmt_amount_msat(tmpctx, first_hop->amount),
			 fmt_amount_msat(tmpctx, msat));

	failmsg = send_onion(tmpctx, ld, packet, first_hop, msat,
			     rhash, NULL, partid,
			     group, channel, &hout);

	if (failmsg) {
		fail = immediate_routing_failure(
		    cmd, ld, fromwire_peektype(failmsg),
		    channel_scid_or_local_alias(channel),
		    &channel->peer->id);

		return sendpay_fail(
		    cmd, NULL, PAY_TRY_OTHER_ROUTE, NULL, fail,
		    sendpay_errmsg_fmt(tmpctx, PAY_TRY_OTHER_ROUTE, fail,
				       "First peer not ready"),
		    NULL);
	}

	payment = wallet_add_payment(cmd,
				     ld->wallet,
				     time_now().ts.tv_sec,
				     NULL,
				     rhash,
				     partid,
				     group,
				     PAYMENT_PENDING,
				     destination,
				     msat,
				     first_hop->amount,
				     total_msat,
				     NULL,
				     path_secrets,
				     route_nodes,
				     route_channels,
				     invstring,
				     label,
				     description,
				     NULL,
				     local_invreq_id);

	return json_sendpay_in_progress(cmd, payment);
}

static struct command_result *
send_payment(struct lightningd *ld,
	     struct command *cmd,
	     const struct sha256 *rhash,
	     u64 partid,
	     u64 group,
	     const struct route_hop *route,
	     struct amount_msat msat,
	     struct amount_msat total_msat,
	     const char *label TAKES,
	     const char *invstring TAKES,
	     const char *description TAKES,
	     const struct sha256 *local_invreq_id,
	     const struct secret *payment_secret,
	     const u8 *payment_metadata,
	     bool dev_legacy_hop)
{
	unsigned int base_expiry;
	struct onionpacket *packet;
	struct secret *path_secrets;
	size_t i, n_hops = tal_count(route);
	struct node_id *ids = tal_arr(tmpctx, struct node_id, n_hops);
	struct short_channel_id *channels;
	struct sphinx_path *path;
	struct pubkey pubkey;
	bool ret;
	u8 *onion;

	/* Expiry for HTLCs is absolute.  And add one to give some margin,
	   and use bitcoind's block height, even if we're behind in processing */
	base_expiry = get_network_blockheight(ld->topology) + 1;

	path = sphinx_path_new(tmpctx, rhash->u.u8);
	/* Extract IDs for each hop: create_onionpacket wants array. */
	for (i = 0; i < n_hops; i++)
		ids[i] = route[i].node_id;

	/* Create sphinx path */
	for (i = 0; i < n_hops - 1; i++) {
		ret = pubkey_from_node_id(&pubkey, &ids[i]);
		assert(ret);

		if (dev_legacy_hop && i == n_hops - 2) {
			sphinx_add_v0_hop(path, &pubkey,
					  &route[i + 1].scid,
					  route[i + 1].amount,
					  base_expiry + route[i + 1].delay);
			continue;
		}

		sphinx_add_hop_has_length(path, &pubkey,
			       take(onion_nonfinal_hop(NULL,
					&route[i + 1].scid,
					route[i + 1].amount,
					base_expiry + route[i + 1].delay)));
	}

	/* And finally set the final hop to the special values in
	 * BOLT04 */
	ret = pubkey_from_node_id(&pubkey, &ids[i]);
	assert(ret);

	onion = onion_final_hop(cmd,
				route[i].amount,
				base_expiry + route[i].delay,
				total_msat,
				payment_secret, payment_metadata);
	if (!onion) {
		return command_fail(cmd, PAY_DESTINATION_PERM_FAIL,
				    "Destination does not support"
				    " payment_secret");
	}
	sphinx_add_hop_has_length(path, &pubkey, onion);

	/* Copy channels used along the route. */
	channels = tal_arr(tmpctx, struct short_channel_id, n_hops);
	for (i = 0; i < n_hops; ++i)
		channels[i] = route[i].scid;

	packet = create_onionpacket(tmpctx, path, ROUTING_INFO_SIZE, &path_secrets);
	return send_payment_core(ld, cmd, rhash, partid, group, &route[0],
				 msat, total_msat,
				 label, invstring, description,
				 packet, &ids[n_hops - 1], ids,
				 channels, path_secrets, local_invreq_id);
}

static struct command_result *
param_route_hop(struct command *cmd, const char *name, const char *buffer,
		const jsmntok_t *tok, struct route_hop **hop)
{
	const jsmntok_t *idtok, *channeltok, *amounttok, *delaytok;
	struct route_hop *res;

	res = tal(cmd, struct route_hop);
	idtok = json_get_member(buffer, tok, "id");
	channeltok = json_get_member(buffer, tok, "channel");
	amounttok = json_get_member(buffer, tok, "amount_msat");
	delaytok = json_get_member(buffer, tok, "delay");

	/* General verification that all fields that we need are present. */
	if (!idtok && !channeltok)
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "Either 'id' or 'channel' is required for a route_hop");

	if (!amounttok)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'amount_msat' is required");

	if (!delaytok)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'delay' is required");

	/* Parsing of actual values including sanity check for all parsed
	 * values. */
	if (!idtok) {
		memset(&res->node_id, 0, sizeof(struct node_id));
	} else if (!json_to_node_id(buffer, idtok, &res->node_id)) {
		return command_fail_badparam(cmd, name, buffer, idtok,
					     "should be a node_id");
	}

	if (!channeltok) {
		memset(&res->scid, 0, sizeof(struct short_channel_id));
	} else if (!json_to_short_channel_id(buffer, channeltok, &res->scid)) {
		return command_fail_badparam(cmd, name, buffer, channeltok,
					     "should be a short_channel_id");
	}

	if (!json_to_msat(buffer, amounttok, &res->amount))
		return command_fail_badparam(cmd, name, buffer, amounttok,
					     "should be a valid amount_msat");

	if (!json_to_number(buffer, delaytok, &res->delay) || res->delay < 1)
		return command_fail_badparam(cmd, name, buffer, delaytok,
					     "should be a positive, non-zero, number");

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
	enum onion_wire failcode;
	struct route_hop *first_hop;
	struct sha256 *payment_hash;
	struct lightningd *ld = cmd->ld;
	const char *label, *invstring, *description;
	struct node_id *destination;
	struct secret *path_secrets;
	struct amount_msat *msat;
	u64 *partid, *group;
	struct sha256 *local_invreq_id = NULL;

	if (!param_check(cmd, buffer, params,
			 p_req("onion", param_bin_from_hex, &onion),
			 p_req("first_hop", param_route_hop, &first_hop),
			 p_req("payment_hash", param_sha256, &payment_hash),
			 p_opt("label", param_escaped_string, &label),
			 p_opt("shared_secrets", param_secrets_array, &path_secrets),
			 p_opt_def("partid", param_u64, &partid, 0),
			 /* FIXME: parameter should be invstring now */
			 p_opt("bolt11", param_invstring, &invstring),
			 p_opt_def("amount_msat", param_msat, &msat, AMOUNT_MSAT(0)),
			 p_opt("destination", param_node_id, &destination),
			 p_opt("localinvreqid", param_sha256, &local_invreq_id),
			 p_opt("groupid", param_u64, &group),
			 p_opt("description", param_string, &description),
			 NULL))
		return command_param_failed();

	/* If groupid was not provided default to incrementing from the previous one. */
	if (group == NULL) {
		group = tal(tmpctx, u64);
		*group =
		    wallet_payment_get_groupid(cmd->ld->wallet, payment_hash) +
		    1;
	}

	packet = parse_onionpacket(cmd, onion, tal_bytelen(onion), &failcode);

	if (!packet)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Could not parse the onion. Parsing failed "
				    "with failcode=%d",
				    failcode);

	if (command_check_only(cmd))
		return command_check_done(cmd);

	return send_payment_core(ld, cmd, payment_hash, *partid, *group,
				 first_hop, *msat, AMOUNT_MSAT(0),
				 label, invstring, description,
				 packet, destination, NULL, NULL,
				 path_secrets, local_invreq_id);
}

static const struct json_command sendonion_command = {
	"sendonion",
	json_sendonion,
};
AUTODATA(json_command, &sendonion_command);

/*-----------------------------------------------------------------------------
JSON-RPC sendpay interface
-----------------------------------------------------------------------------*/

/* FIXME: We accept his parameter for now, will deprecate eventually */
static struct command_result *param_route_hop_style(struct command *cmd,
						    const char *name,
						    const char *buffer,
						    const jsmntok_t *tok,
						    int **unused)
{
	if (json_tok_streq(buffer, tok, "tlv")) {
		return NULL;
	}

	return command_fail_badparam(cmd, name, buffer, tok,
			    "should be 'tlv' ('legacy' not supported)");
}

static struct command_result *param_route_hops(struct command *cmd,
					       const char *name,
					       const char *buffer,
					       const jsmntok_t *tok,
					       struct route_hop **hops)
{
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s must be an array", name);

	*hops = tal_arr(cmd, struct route_hop, tok->size);
	json_for_each_arr(i, t, tok) {
		struct amount_msat *amount_msat;
		struct node_id *id;
		struct short_channel_id *channel;
		unsigned *delay, *direction;
		int *ignored;

		if (!param(cmd, buffer, t,
			   p_req("amount_msat", param_msat, &amount_msat),
			   p_req("id", param_node_id, &id),
			   p_req("delay", param_number, &delay),
			   p_req("channel", param_short_channel_id, &channel),
			   /* Allowed (getroute supplies it) but ignored */
			   p_opt("direction", param_number, &direction),
			   p_opt("style", param_route_hop_style, &ignored),
			   NULL))
			return command_param_failed();

		(*hops)[i].amount = *amount_msat;
		(*hops)[i].node_id = *id;
		(*hops)[i].delay = *delay;
		(*hops)[i].scid = *channel;
	}

	return NULL;
}

/* We're paying ourselves! */
static struct command_result *self_payment(struct lightningd *ld,
					   struct command *cmd,
					   const struct sha256 *rhash,
					   u64 partid,
					   u64 groupid,
					   struct amount_msat msat,
					   const char *label TAKES,
					   const char *invstring TAKES,
					   const char *description TAKES,
					   const struct sha256 *local_invreq_id,
					   const struct secret *payment_secret,
					   const u8 *payment_metadata)
{
	struct wallet_payment *payment;
	const struct invoice_details *inv;
	u64 inv_dbid;
	const char *err;

	payment = wallet_add_payment(tmpctx,
				     ld->wallet,
				     time_now().ts.tv_sec,
				     NULL,
				     rhash,
				     partid,
				     groupid,
				     PAYMENT_PENDING,
				     &ld->our_nodeid,
				     msat,
				     msat,
				     msat,
				     NULL,
				     NULL,
				     NULL,
				     NULL,
				     invstring,
				     label,
				     description,
				     NULL,
				     local_invreq_id);

	/* Now, resolve the invoice */
	inv = invoice_check_payment(tmpctx, ld, rhash, msat, payment_secret, &err);
	if (!inv) {
		struct routing_failure *fail;
		wallet_payment_set_status(ld->wallet, rhash, partid, groupid,
					  PAYMENT_FAILED, NULL);

		/* tell_waiters_failed expects one of these! */
		fail = tal(payment, struct routing_failure);
		fail->failcode = WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS;
		fail->erring_node = &ld->our_nodeid;
		fail->erring_index = 0;
		fail->erring_channel = NULL;
		fail->msg = NULL;

		/* Only some of these fields make sense for self payments */
		wallet_payment_set_failinfo(ld->wallet,
					    rhash,
					    partid, NULL,
					    true,
					    0,
					    fail->failcode, fail->erring_node,
					    NULL, NULL,
					    err,
					    0);
		/* We do this even though there really can't be any waiters,
		 * since we didn't block. */
		tell_waiters_failed(ld, rhash, payment, PAY_DESTINATION_PERM_FAIL,
				    NULL, fail, err);
		return sendpay_fail(cmd, payment, PAY_DESTINATION_PERM_FAIL, NULL,
				    fail, err, NULL);
	}

	/* These should not fail, given the above succeded! */
	if (!invoices_find_by_rhash(ld->wallet->invoices, &inv_dbid, rhash)
	    || !invoices_resolve(ld->wallet->invoices, inv_dbid, msat, inv->label, NULL)) {
		log_broken(ld->log, "Could not resolve invoice %"PRIu64"!?!", inv_dbid);
		return sendpay_fail(cmd, payment, PAY_DESTINATION_PERM_FAIL, NULL, NULL, "broken", NULL);
	}

	log_info(ld->log, "Self-resolved invoice '%s' with amount %s",
		 inv->label->s,
		 fmt_amount_msat(tmpctx, msat));
	notify_invoice_payment(ld, msat, &inv->r, inv->label, NULL);

	/* Now resolve the payment */
	payment_succeeded(ld, rhash, partid, groupid,  &inv->r);

	/* Now the specific command which called this. */
	payment->status = PAYMENT_COMPLETE;
	payment->payment_preimage = tal_dup(payment, struct preimage, &inv->r);
	return sendpay_success(cmd, payment, NULL);
}

static struct command_result *json_sendpay(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	struct sha256 *rhash;
	struct route_hop *route;
	struct amount_msat *msat;
	const char *invstring, *label, *description;
	u64 *partid, *group;
	struct secret *payment_secret;
	struct sha256 *local_invreq_id;
	u8 *payment_metadata;
	bool *dev_legacy_hop;

	if (!param_check(cmd, buffer, params,
			 p_req("route", param_route_hops, &route),
			 p_req("payment_hash", param_sha256, &rhash),
			 p_opt("label", param_escaped_string, &label),
			 p_opt("amount_msat", param_msat, &msat),
			 /* FIXME: parameter should be invstring now */
			 p_opt("bolt11", param_invstring, &invstring),
			 p_opt("payment_secret", param_secret, &payment_secret),
			 p_opt_def("partid", param_u64, &partid, 0),
			 p_opt("localinvreqid", param_sha256, &local_invreq_id),
			 p_opt("groupid", param_u64, &group),
			 p_opt("payment_metadata", param_bin_from_hex, &payment_metadata),
			 p_opt("description", param_string, &description),
			 p_opt_dev("dev_legacy_hop", param_bool, &dev_legacy_hop, false),
		   NULL))
		return command_param_failed();

	if (*partid && !msat)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Must specify msatoshi with partid");

	/* If groupid was not provided default to incrementing from the previous one. */
	if (group == NULL) {
		group = tal(tmpctx, u64);
		*group = wallet_payment_get_groupid(cmd->ld->wallet, rhash) + 1;
	}

	if (tal_count(route) == 0) {
		if (!msat)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Self-payment requires amount_msat");
		if (*partid)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Self-payment does not allow (non-zero) partid");
		if (command_check_only(cmd))
			return command_check_done(cmd);

		return self_payment(cmd->ld, cmd, rhash, *partid, *group, *msat,
				    label, invstring, description, local_invreq_id,
				    payment_secret, payment_metadata);
	}

	const struct amount_msat final_amount = route[tal_count(route)-1].amount;

	if (msat && !*partid && !amount_msat_eq(*msat, final_amount))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Do not specify msatoshi (%s) without"
				    " partid: if you do, it must be exactly"
				    " the final amount (%s)",
				    fmt_amount_msat(tmpctx, *msat),
				    fmt_amount_msat(tmpctx, final_amount));

	/* For MPP, the total we send must *exactly* equal the amount
	 * we promise to send (msatoshi).  So no single payment can be
	 * > than that. */
	if (*partid) {
		if (amount_msat_greater(final_amount, *msat))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Final amount %s is greater than"
					    " %s, despite MPP",
					    fmt_amount_msat(tmpctx, final_amount),
					    fmt_amount_msat(tmpctx, *msat));
	}

	if (*partid && !payment_secret)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "partid requires payment_secret");

	if (command_check_only(cmd))
		return command_check_done(cmd);

	return send_payment(cmd->ld, cmd, rhash, *partid, *group,
			    route,
			    final_amount,
			    msat ? *msat : final_amount,
			    label, invstring, description, local_invreq_id,
			    payment_secret, payment_metadata, *dev_legacy_hop);
}

static const struct json_command sendpay_command = {
	"sendpay",
	json_sendpay,
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
	u64 *partid, *groupid;

	if (!param(cmd, buffer, params,
		   p_req("payment_hash", param_sha256, &rhash),
		   p_opt("timeout", param_number, &timeout),
		   p_opt_def("partid", param_u64, &partid, 0),
		   p_opt("groupid", param_u64, &groupid),
		   NULL))
		return command_param_failed();

	if (groupid == NULL) {
		groupid = tal(cmd, u64);
		*groupid = wallet_payment_get_groupid(cmd->ld->wallet, rhash);
	}
	res = wait_payment(cmd->ld, cmd, rhash, *partid, *groupid);
	if (res)
		return res;

	if (timeout)
		new_reltimer(cmd->ld->timers, cmd, time_from_sec(*timeout),
			     &waitsendpay_timeout, cmd);
	return command_still_pending(cmd);
}

static const struct json_command waitsendpay_command = {
	"waitsendpay",
	json_waitsendpay,
};
AUTODATA(json_command, &waitsendpay_command);

static u64 sendpay_index_inc(struct lightningd *ld,
			     const struct sha256 *payment_hash,
			     u64 partid,
			     u64 groupid,
			     enum payment_status status,
			     enum wait_index idx)
{
	return wait_index_increment(ld, WAIT_SUBSYSTEM_SENDPAY, idx,
				    "status", payment_status_to_string(status),
				    "=partid", tal_fmt(tmpctx, "%"PRIu64, partid),
				    "=groupid", tal_fmt(tmpctx, "%"PRIu64, groupid),
				    "payment_hash",
				    fmt_sha256(tmpctx, payment_hash),
				    NULL);
}

void sendpay_index_deleted(struct lightningd *ld,
			   const struct sha256 *payment_hash,
			   u64 partid,
			   u64 groupid,
			   enum payment_status status)
{
	sendpay_index_inc(ld, payment_hash, partid, groupid, status, WAIT_INDEX_DELETED);
}

/* Fortuntely, dbids start at 1, not 0! */
u64 sendpay_index_created(struct lightningd *ld,
			  const struct sha256 *payment_hash,
			  u64 partid,
			  u64 groupid,
			  enum payment_status status)
{
	return sendpay_index_inc(ld, payment_hash, partid, groupid, status,
				 WAIT_INDEX_CREATED);
}

u64 sendpay_index_update_status(struct lightningd *ld,
				const struct sha256 *payment_hash,
				u64 partid,
				u64 groupid,
				enum payment_status status)
{
	return sendpay_index_inc(ld, payment_hash, partid, groupid, status,
				 WAIT_INDEX_UPDATED);
}

static struct command_result *param_payment_status(struct command *cmd,
						   const char *name,
						   const char *buffer,
						   const jsmntok_t *tok,
						   enum payment_status **status)
{
	*status = tal(cmd, enum payment_status);
	if (string_to_payment_status(buffer + tok->start,
				     tok->end - tok->start,
				     *status))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be an invoice status");
}

static struct command_result *json_listsendpays(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	struct json_stream *response;
	struct sha256 *rhash;
	const char *invstring;
	enum payment_status *status;
	struct db_stmt *stmt;
	enum wait_index *listindex;
	u64 *liststart;
	u32 *listlimit;

	if (!param_check(cmd, buffer, params,
			 /* FIXME: parameter should be invstring now */
			 p_opt("bolt11", param_invstring, &invstring),
			 p_opt("payment_hash", param_sha256, &rhash),
			 p_opt("status", param_payment_status, &status),
			 p_opt("index", param_index, &listindex),
			 p_opt_def("start", param_u64, &liststart, 0),
			 p_opt("limit", param_u32, &listlimit),
			 NULL))
		return command_param_failed();

	if (rhash && invstring) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can only specify one of"
				    " {bolt11} or {payment_hash}");
	}

	if (*liststart != 0 && !listindex) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can only specify {start} with {index}");
	}
	if (listlimit && !listindex) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can only specify {limit} with {index}");
	}

	if ((rhash || invstring) && *liststart != 0) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Cannot use start with bolt11 or payment_hash");
	}

	if (invstring) {
		struct bolt11 *b11;
		char *fail;

		b11 = bolt11_decode(cmd, invstring, cmd->ld->our_features, NULL,
				    chainparams, &fail);
		if (b11) {
			rhash = &b11->payment_hash;
		} else {
			struct tlv_invoice *b12;

			b12 = invoice_decode(cmd, invstring, strlen(invstring),
					     cmd->ld->our_features,
					     chainparams, &fail);
			if (b12 && b12->invoice_payment_hash)
				rhash = b12->invoice_payment_hash;
			else
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "Invalid invstring: %s", fail);
		}
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	response = json_stream_success(cmd);

	json_array_start(response, "payments");
	if (rhash)
		stmt = payments_by_hash(cmd->ld->wallet, rhash);
	else if (status)
		stmt = payments_by_status(cmd->ld->wallet, *status,
					  listindex, *liststart, listlimit);
	else
		stmt = payments_first(cmd->ld->wallet,
				      listindex, *liststart, listlimit);

	for (; stmt; stmt = payments_next(cmd->ld->wallet, stmt)) {
		json_object_start(response, NULL);
		json_add_payment_fields(response, payment_get_details(tmpctx, stmt));
		json_object_end(response);
	}
	json_array_end(response);

	return command_success(cmd, response);
}

static const struct json_command listsendpays_command = {
	"listsendpays",
	json_listsendpays,
};
AUTODATA(json_command, &listsendpays_command);

static struct command_result *
param_payment_status_nopending(struct command *cmd,
			       const char *name,
			       const char *buffer,
			       const jsmntok_t *tok,
			       enum payment_status **status)
{
	struct command_result *res;

	res = param_payment_status(cmd, name, buffer, tok, status);
	if (res)
		return res;

	switch (**status) {
	case PAYMENT_COMPLETE:
	case PAYMENT_FAILED:
		break;
	case PAYMENT_PENDING:
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Cannot delete pending status");
	}
	return NULL;
}

static struct command_result *json_delpay(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	const enum payment_status *found_status = NULL;
	struct json_stream *response;
	const struct wallet_payment **payments;
	enum payment_status *status;
	struct sha256 *payment_hash;
	u64 *groupid, *partid;
	struct db_stmt *stmt;

	if (!param_check(cmd, buffer, params,
			 p_req("payment_hash", param_sha256, &payment_hash),
			 p_req("status", param_payment_status_nopending, &status),
			 p_opt("partid", param_u64, &partid),
			 p_opt("groupid", param_u64, &groupid),
			 NULL))
		return command_param_failed();

	if ((partid != NULL) != (groupid != NULL))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Must set both partid and groupid, or neither");

	stmt = payments_by_hash(cmd->ld->wallet, payment_hash);
	if (!stmt)
		return command_fail(cmd, PAY_NO_SUCH_PAYMENT, "Unknown payment with payment_hash: %s",
				    fmt_sha256(tmpctx, payment_hash));

	payments = tal_arr(cmd, const struct wallet_payment *, 0);
	for (; stmt; stmt = payments_next(cmd->ld->wallet, stmt)) {
		struct wallet_payment *payment;
		payment = payment_get_details(payments, stmt);
		if (groupid && payment->groupid != *groupid)
			continue;
		if (partid && payment->partid != *partid)
			continue;

		if (payment->status == *status)
			tal_arr_expand(&payments, payment);
		else
			found_status = &payment->status;
	}

	if (tal_count(payments) == 0) {
		if (found_status)
			return command_fail(cmd, PAY_NO_SUCH_PAYMENT, "Payment with hash %s has %s status but it different from the one provided %s",
				fmt_sha256(tmpctx, payment_hash),
				payment_status_to_string(*found_status),
				payment_status_to_string(*status));

		return command_fail(cmd, PAY_NO_SUCH_PAYMENT,
				    "No payment for that payment_hash with that partid and groupid");
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	wallet_payment_delete(cmd->ld->wallet, payment_hash, groupid, partid, status);

	response = json_stream_success(cmd);
	json_array_start(response, "payments");
	for (int i = 0; i < tal_count(payments); i++) {
		json_object_start(response, NULL);
		json_add_payment_fields(response, payments[i]);
		json_object_end(response);
	}
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command delpay_command = {
	"delpay",
	json_delpay,
};
AUTODATA(json_command, &delpay_command);

static struct command_result *json_createonion(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	struct json_stream *response;
	struct secret *session_key, *shared_secrets;
	struct sphinx_path *sp;
	u8 *assocdata, *serialized;
	u32 *packet_size;
	struct onionpacket *packet;
	struct sphinx_hop *hops;

	if (!param_check(cmd, buffer, params,
			 p_req("hops", param_hops_array, &hops),
			 p_req("assocdata", param_bin_from_hex, &assocdata),
			 p_opt("session_key", param_secret, &session_key),
			 p_opt_def("onion_size", param_number, &packet_size, ROUTING_INFO_SIZE),
			 NULL)) {
		return command_param_failed();
	}

	if (session_key == NULL)
		sp = sphinx_path_new(cmd, assocdata);
	else
		sp = sphinx_path_new_with_key(cmd, assocdata, session_key);

	for (size_t i=0; i<tal_count(hops); i++) {
		if (!sphinx_add_hop_has_length(sp, &hops[i].pubkey, hops[i].raw_payload))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "hops[%zi] payload is not prefixed with length!",
					    i);
	}

	if (sphinx_path_payloads_size(sp) > *packet_size)
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "Payloads exceed maximum onion packet size.");

	packet = create_onionpacket(cmd, sp, *packet_size, &shared_secrets);
	if (!packet)
		return command_fail(cmd, LIGHTNINGD,
				    "Could not create onion packet");

	if (command_check_only(cmd))
		return command_check_done(cmd);

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
	json_createonion,
};
AUTODATA(json_command, &createonion_command);
