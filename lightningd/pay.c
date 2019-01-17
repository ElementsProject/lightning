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
	struct pubkey erring_node;
	struct short_channel_id erring_channel;
	int channel_dir;
};

/* Result of send_payment */
struct sendpay_result {
	/* Did the payment succeed? */
	bool succeeded;
	/* Preimage. Only loaded if payment succeeded. */
	struct preimage preimage;
	/* Error code, one of the PAY_* macro in jsonrpc_errors.h.
	 * Only loaded if payment failed. */
	int errorcode;
	/* Pointer to the payment. Only loaded if payment
	 * succeeded or if error is PAY_IN_PROGRESS */
	const struct wallet_payment *payment;
	/* Unparseable onion reply. Only loaded if payment failed,
	 * and errorcode == PAY_UNPARSEABLE_ONION. */
	const u8* onionreply;
	/* Routing failure object. Only loaded if payment failed,
	 * and errorcode == PAY_DESTINATION_PERM_FAIL or
	 * errorcode == PAY_TRY_OTHER_ROUTE */
	struct routing_failure* routing_failure;
	/* Error message. Only loaded if payment failed. */
	const char *details;
};

/* sendpay command */
struct sendpay_command {
	struct list_node list;

	struct sha256 payment_hash;

	void (*cb)(const struct sendpay_result *, void*);
	void *cbarg;
};

static void destroy_sendpay_command(struct sendpay_command *pc)
{
	list_del(&pc->list);
}

/* Owned by cxt, if cxt is deleted, then cb will
 * no longer be called. */
static void
add_sendpay_waiter(const tal_t *cxt,
		   const struct sha256 *payment_hash,
		   struct lightningd *ld,
		   void (*cb)(const struct sendpay_result *, void*),
		   void *cbarg)
{
	struct sendpay_command *pc = tal(cxt, struct sendpay_command);

	pc->payment_hash = *payment_hash;
	pc->cb = cb;
	pc->cbarg = cbarg;
	list_add(&ld->sendpay_commands, &pc->list);
	tal_add_destructor(pc, destroy_sendpay_command);
}

/* Owned by cxt; if cxt is deleted, then cb will
 * no longer be called. */
static void
add_waitsendpay_waiter(const tal_t *cxt,
		       const struct sha256 *payment_hash,
		       struct lightningd *ld,
		       void (*cb)(const struct sendpay_result *, void*),
		       void *cbarg)
{
	struct sendpay_command *pc = tal(cxt, struct sendpay_command);

	pc->payment_hash = *payment_hash;
	pc->cb = cb;
	pc->cbarg = cbarg;
	list_add(&ld->waitsendpay_commands, &pc->list);
	tal_add_destructor(pc, destroy_sendpay_command);
}

/* Caller responsible for freeing ctx. */
static void waitsendpay_resolve(const tal_t *ctx,
				struct lightningd *ld,
				const struct sha256 *payment_hash,
				const struct sendpay_result *result)
{
	struct sendpay_command *pc;
	struct sendpay_command *next;
	list_for_each_safe(&ld->waitsendpay_commands, pc, next, list) {
		if (!sha256_eq(payment_hash, &pc->payment_hash))
			continue;

		/* Delete later (in our own caller) if callback did
		 * not delete. */
		tal_steal(ctx, pc);
		pc->cb(result, pc->cbarg);
	}
}

static struct sendpay_result*
sendpay_result_success(const tal_t *ctx,
		       const struct preimage *payment_preimage,
		       const struct wallet_payment *payment)
{
	struct sendpay_result *result = tal(ctx, struct sendpay_result);
	result->succeeded = true;
	result->preimage = *payment_preimage;
	result->payment = payment;
	return result;
}

static void payment_trigger_success(struct lightningd *ld,
				    const struct sha256 *payment_hash)
{
	struct sendpay_result *result;
	struct wallet_payment *payment;

	payment = wallet_payment_by_hash(tmpctx, ld->wallet, payment_hash);
	assert(payment);

	result = sendpay_result_success(tmpctx, payment->payment_preimage, payment);

	waitsendpay_resolve(tmpctx, ld, payment_hash, result);
}

static struct sendpay_result*
sendpay_result_route_failure(const tal_t *ctx,
			     bool retry_plausible,
			     struct routing_failure *fail,
			     const u8 *onionreply,
			     const char *details)
{
	struct sendpay_result *result = tal(ctx, struct sendpay_result);
	result->succeeded = false;
	result->errorcode =
		(!fail) ?		PAY_UNPARSEABLE_ONION :
		(!retry_plausible) ?	PAY_DESTINATION_PERM_FAIL :
		/*otherwise*/		PAY_TRY_OTHER_ROUTE ;
	result->onionreply = onionreply;
	result->routing_failure = fail;
	result->details = details;
	return result;
}

static void payment_route_failure(struct lightningd *ld,
				  const struct sha256 *payment_hash,
				  bool retry_plausible,
				  struct routing_failure *fail,
				  const u8 *onionreply,
				  const char *details)
{
	struct sendpay_result *result;

	result = sendpay_result_route_failure(tmpctx,
					      retry_plausible,
					      fail,
					      onionreply,
					      details);

	waitsendpay_resolve(tmpctx, ld, payment_hash, result);
}

static struct sendpay_result *
sendpay_result_simple_fail(const tal_t *ctx,
			   int errorcode,
			   char const *details)
{
	struct sendpay_result *result = tal(ctx, struct sendpay_result);
	result->succeeded = false;
	result->errorcode = errorcode;
	result->details = details;
	return result;
}

static struct sendpay_result *
sendpay_result_in_progress(const tal_t *ctx,
			   const struct wallet_payment* payment,
			   char const *details)
{
	struct sendpay_result *result = tal(ctx, struct sendpay_result);
	result->succeeded = false;
	result->errorcode = PAY_IN_PROGRESS;
	result->payment = payment;
	result->details = details;
	return result;
}

void payment_succeeded(struct lightningd *ld, struct htlc_out *hout,
		       const struct preimage *rval)
{
	wallet_payment_set_status(ld->wallet, &hout->payment_hash,
				  PAYMENT_COMPLETE, rval);
	payment_trigger_success(ld, &hout->payment_hash);
}

/* Return a struct routing_failure for an immediate failure
 * (returned directly from send_htlc_out). The returned
 * failure is allocated from the given context. */
static struct routing_failure*
immediate_routing_failure(const tal_t *ctx,
			  const struct lightningd *ld,
			  enum onion_type failcode,
			  const struct short_channel_id *channel0,
			  const struct pubkey *dstid)
{
	struct routing_failure *routing_failure;

	assert(failcode);

	routing_failure = tal(ctx, struct routing_failure);
	routing_failure->erring_index = 0;
	routing_failure->failcode = failcode;
	routing_failure->erring_node = ld->id;
	routing_failure->erring_channel = *channel0;
	if (dstid)
		routing_failure->channel_dir = pubkey_idx(&ld->id, dstid);
	/* FIXME: Don't set at all unless we know. */
	else
		routing_failure->channel_dir = 0;

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
	routing_failure->channel_dir = pubkey_idx(&ld->id,
						  &payment->route_nodes[0]);

	log_debug(hout->key.channel->log, "local_routing_failure: %u (%s)",
		  hout->failcode, onion_type_name(hout->failcode));
	return routing_failure;
}

/* Return false if permanent failure at the destination, true if
 * retrying is plausible. Fill *routing_failure with NULL if
 * we cannot report the remote failure, or with the routing
 * failure to report (allocated from ctx) otherwise. */
static struct routing_failure*
remote_routing_failure(const tal_t *ctx,
		       struct lightningd *ld,
		       bool *p_retry_plausible,
		       const struct wallet_payment *payment,
		       const struct onionreply *failure,
		       struct log *log)
{
	enum onion_type failcode = fromwire_peektype(failure->msg);
	struct routing_failure *routing_failure;
	const struct pubkey *route_nodes;
	const struct pubkey *erring_node;
	const struct short_channel_id *route_channels;
	const struct short_channel_id *erring_channel;
	static const struct short_channel_id dummy_channel = { 0 };
	int origin_index;
	bool retry_plausible;
	int dir;

	routing_failure = tal(ctx, struct routing_failure);
	route_nodes = payment->route_nodes;
	route_channels = payment->route_channels;
	origin_index = failure->origin_index;
	retry_plausible = true;

	assert(origin_index < tal_count(route_nodes));

	/* Check if at destination. */
	if (origin_index == tal_count(route_nodes) - 1) {
		/* FIXME: Don't set erring_channel or dir in this case! */
		erring_channel = &dummy_channel;
		dir = 0;

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
		erring_node = &route_nodes[origin_index];
	} else {
		u8 *gossip_msg;

		/* Report the *next* channel as failing. */
		erring_channel = &route_channels[origin_index + 1];

		dir = pubkey_idx(&route_nodes[origin_index],
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

	*p_retry_plausible = retry_plausible;

	return routing_failure;
}

void payment_store(struct lightningd *ld,
		   const struct sha256 *payment_hash)
{
	struct sendpay_command *pc;
	struct sendpay_command *next;
	struct sendpay_result *result;
	const struct wallet_payment *payment;

	wallet_payment_store(ld->wallet, payment_hash);
	payment = wallet_payment_by_hash(tmpctx, ld->wallet, payment_hash);
	assert(payment);

	/* Invent a sendpay result with PAY_IN_PROGRESS. */
	result = sendpay_result_in_progress(tmpctx, payment,
					    "Payment is still in progress");

	/* Trigger any sendpay commands waiting for the store to occur. */
	list_for_each_safe(&ld->sendpay_commands, pc, next, list) {
		if (!sha256_eq(payment_hash, &pc->payment_hash))
			continue;

		/* Delete later if callback did not delete. */
		tal_steal(tmpctx, pc);
		pc->cb(result, pc->cbarg);
	}
}

void payment_failed(struct lightningd *ld, const struct htlc_out *hout,
		    const char *localfail)
{
	struct wallet_payment *payment;
	struct routing_failure* fail = NULL;
	const char *failmsg;
	bool retry_plausible;

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
		retry_plausible = true;
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
			retry_plausible = true;
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
						      &retry_plausible,
						      payment, reply,
						      hout->key.channel->log);
		}
	}

	/* Save to DB */
	payment_store(ld, &hout->payment_hash);
	wallet_payment_set_status(ld->wallet, &hout->payment_hash,
				  PAYMENT_FAILED, NULL);
	wallet_payment_set_failinfo(ld->wallet,
				    &hout->payment_hash,
				    fail ? NULL : hout->failuremsg,
				    (fail && !retry_plausible),
				    fail ? fail->erring_index : -1,
				    fail ? fail->failcode : 0,
				    fail ? &fail->erring_node : NULL,
				    fail ? &fail->erring_channel : NULL,
				    NULL,
				    failmsg,
				    fail ? fail->channel_dir : 0);

	/* Report to client. */
	payment_route_failure(ld, &hout->payment_hash,
			      retry_plausible, fail, hout->failuremsg,
			      failmsg);
}

/* Wait for a payment. If cxt is deleted, then cb will
 * no longer be called.
 * Return false if we called callback already, true if
 * callback is scheduled for later. */
static bool wait_payment(const tal_t *cxt,
			 struct lightningd *ld,
			 const struct sha256 *payment_hash,
			 void (*cb)(const struct sendpay_result *, void*),
			 void *cbarg)
{
	struct wallet_payment *payment;
	struct sendpay_result *result;
	char const *details;
	bool cb_not_called;
	u8 *failonionreply;
	bool faildestperm;
	int failindex;
	enum onion_type failcode;
	struct pubkey *failnode;
	struct short_channel_id *failchannel;
	u8 *failupdate;
	char *faildetail;
	struct routing_failure *fail;
	int faildirection;

	payment = wallet_payment_by_hash(tmpctx, ld->wallet, payment_hash);
	if (!payment) {
		details = tal_fmt(tmpctx,
				  "Never attempted payment for '%s'",
				  type_to_string(tmpctx, struct sha256,
					  	 payment_hash));
		result = sendpay_result_simple_fail(tmpctx,
						    PAY_NO_SUCH_PAYMENT,
						    details);
		cb(result, cbarg);
		cb_not_called = false;
		goto end;
	}

	switch (payment->status) {
	case PAYMENT_PENDING:
		add_waitsendpay_waiter(cxt, payment_hash, ld, cb, cbarg);
		cb_not_called = true;
		goto end;

	case PAYMENT_COMPLETE:
		result = sendpay_result_success(tmpctx,
						payment->payment_preimage,
						payment);
		cb(result, cbarg);
		cb_not_called = false;
		goto end;

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
		if (!failonionreply && !failnode)
			result = sendpay_result_simple_fail(tmpctx,
							    PAY_UNSPECIFIED_ERROR,
							    "Payment failure reason unknown");
		else if (failonionreply) {
			/* failed to parse returned onion error */
			result = sendpay_result_route_failure(tmpctx, true, NULL, failonionreply, faildetail);
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
			result = sendpay_result_route_failure(tmpctx, !faildestperm, fail, NULL, faildetail);
		}

		cb(result, cbarg);
		cb_not_called = false;
		goto end;
	}

	/* Impossible. */
	abort();

end:
	return cb_not_called;
}

/* Returns false if cb was called, true if cb not yet called. */
static bool
send_payment(const tal_t *ctx,
	     struct lightningd* ld,
	     const struct sha256 *rhash,
	     const struct route_hop *route,
	     u64 msatoshi,
	     const char *description TAKES,
	     void (*cb)(const struct sendpay_result *, void*),
	     void *cbarg)
{
	const u8 *onion;
	u8 sessionkey[32];
	unsigned int base_expiry;
	struct onionpacket *packet;
	struct secret *path_secrets;
	enum onion_type failcode;
	size_t i, n_hops = tal_count(route);
	struct hop_data *hop_data = tal_arr(tmpctx, struct hop_data, n_hops);
	struct pubkey *ids = tal_arr(tmpctx, struct pubkey, n_hops);
	struct wallet_payment *payment = NULL;
	struct htlc_out *hout;
	struct short_channel_id *channels;
	struct routing_failure *fail;
	struct channel *channel;
	struct sendpay_result *result;

	/* Expiry for HTLCs is absolute.  And add one to give some margin. */
	base_expiry = get_block_height(ld->topology) + 1;

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
	payment = wallet_payment_by_hash(tmpctx, ld->wallet, rhash);
	if (payment) {
		/* FIXME: We should really do something smarter here! */
		log_debug(ld->log, "send_payment: found previous");
		if (payment->status == PAYMENT_PENDING) {
			log_add(ld->log, "Payment is still in progress");
			result = sendpay_result_in_progress(tmpctx,
							    payment,
							    "Payment is still in progress");
			cb(result, cbarg);
			return false;
		}
		if (payment->status == PAYMENT_COMPLETE) {
			log_add(ld->log, "... succeeded");
			/* Must match successful payment parameters. */
			if (payment->msatoshi != msatoshi) {
				char *msg = tal_fmt(tmpctx,
						    "Already succeeded "
						    "with amount %"PRIu64,
						    payment->msatoshi);
				result = sendpay_result_simple_fail(tmpctx,
								    PAY_RHASH_ALREADY_USED,
								    msg);
				cb(result, cbarg);
				return false;
			}
			if (!pubkey_eq(&payment->destination, &ids[n_hops-1])) {
				char *msg = tal_fmt(tmpctx,
						    "Already succeeded to %s",
						    type_to_string(tmpctx,
								   struct pubkey,
								   &payment->destination));
				result = sendpay_result_simple_fail(tmpctx,
								    PAY_RHASH_ALREADY_USED,
								    msg);
				cb(result, cbarg);
				return false;
			}
			result = sendpay_result_success(tmpctx,
							payment->payment_preimage,
							payment);
			cb(result, cbarg);
			return false;
		}
		log_add(ld->log, "... retrying");
	}

	channel = active_channel_by_id(ld, &ids[0], NULL);
	if (!channel) {
		/* Report routing failure to gossipd */
		fail = immediate_routing_failure(ctx, ld,
						 WIRE_UNKNOWN_NEXT_PEER,
						 &route[0].channel_id,
						 0);

		/* Report routing failure to caller */
		result = sendpay_result_route_failure(tmpctx, true, fail, NULL,
						      "No connection to first "
						      "peer found");
		cb(result, cbarg);
		return false;
	}

	randombytes_buf(&sessionkey, sizeof(sessionkey));

	/* Onion will carry us from first peer onwards. */
	packet = create_onionpacket(tmpctx, ids, hop_data, sessionkey, rhash->u.u8,
				    sizeof(struct sha256), &path_secrets);
	onion = serialize_onionpacket(tmpctx, packet);

	log_info(ld->log, "Sending %"PRIu64" over %zu hops to deliver %"PRIu64"",
		 route[0].amount, n_hops, msatoshi);

	failcode = send_htlc_out(channel, route[0].amount,
				 base_expiry + route[0].delay,
				 rhash, onion, NULL, &hout);
	if (failcode) {
		/* Report routing failure to gossipd */
		fail = immediate_routing_failure(ctx, ld,
						 failcode,
						 &route[0].channel_id,
						 &channel->peer->id);

		/* Report routing failure to caller */
		result = sendpay_result_route_failure(tmpctx, true, fail, NULL,
						      "First peer not ready");
		cb(result, cbarg);
		return false;
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
	payment->msatoshi = msatoshi;
	payment->msatoshi_sent = route[0].amount;
	payment->timestamp = time_now().ts.tv_sec;
	payment->payment_preimage = NULL;
	payment->path_secrets = tal_steal(payment, path_secrets);
	payment->route_nodes = tal_steal(payment, ids);
	payment->route_channels = tal_steal(payment, channels);
	if (description != NULL)
		payment->description = tal_strdup(payment, description);
	else
		payment->description = NULL;

	/* We write this into db when HTLC is actually sent. */
	wallet_payment_setup(ld->wallet, payment);

	add_sendpay_waiter(ctx, rhash, ld, cb, cbarg);

	return true;
}

/*-----------------------------------------------------------------------------
JSON-RPC sendpay interface
-----------------------------------------------------------------------------*/

/* Outputs fields, not a separate object*/
static void
json_add_payment_fields(struct json_stream *response,
			const struct wallet_payment *t)
{
	json_add_u64(response, "id", t->id);
	json_add_hex(response, "payment_hash", &t->payment_hash, sizeof(t->payment_hash));
	json_add_pubkey(response, "destination", &t->destination);
	json_add_u64(response, "msatoshi", t->msatoshi);
	json_add_u64(response, "msatoshi_sent", t->msatoshi_sent);
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
	if (t->description)
		json_add_string(response, "description", t->description);
}

static void
json_sendpay_success(struct command *cmd,
		     const struct sendpay_result *r)
{
	struct json_stream *response;

	assert(r->payment->status == PAYMENT_COMPLETE);

	response = json_stream_success(cmd);
	json_object_start(response, NULL);
	json_add_payment_fields(response, r->payment);
	json_object_end(response);
	was_pending(command_success(cmd, response));
}

static void json_waitsendpay_on_resolve(const struct sendpay_result *r,
				    void *vcmd)
{
	struct command *cmd = (struct command*) vcmd;

	const char *msg = NULL;
	struct routing_failure *fail;

	if (r->succeeded)
		json_sendpay_success(cmd, r);
	else {
		struct json_stream *data;
		switch (r->errorcode) {
			/* We will never handle this case */
		case PAY_IN_PROGRESS:
			abort();

		case PAY_RHASH_ALREADY_USED:
		case PAY_UNSPECIFIED_ERROR:
		case PAY_NO_SUCH_PAYMENT:
			was_pending(command_fail(cmd, r->errorcode, "%s",
						 r->details));
			return;

		case PAY_UNPARSEABLE_ONION:
			msg = tal_fmt(tmpctx,
				      "failed: WIRE_PERMANENT_NODE_FAILURE "
				      "(%s)",
				      r->details);

			data = json_stream_fail(cmd, r->errorcode, msg);
			json_object_start(data, NULL);
			json_add_hex_talarr(data, "onionreply", r->onionreply);
			json_object_end(data);
			was_pending(command_failed(cmd, data));
			return;

		case PAY_DESTINATION_PERM_FAIL:
		case PAY_TRY_OTHER_ROUTE:
			fail = r->routing_failure;
			msg = tal_fmt(cmd,
				      "failed: %s (%s)",
				      onion_type_name(fail->failcode),
				      r->details);
			data = json_stream_fail(cmd, r->errorcode, msg);

			json_object_start(data, NULL);
			json_add_num(data, "erring_index",
				     fail->erring_index);
			json_add_num(data, "failcode",
				     (unsigned) fail->failcode);
			json_add_pubkey(data, "erring_node", &fail->erring_node);
			json_add_short_channel_id(data, "erring_channel",
						  &fail->erring_channel);
			json_add_num(data, "erring_direction",
				     fail->channel_dir);
			json_object_end(data);
			was_pending(command_failed(cmd, data));
			return;
		}
		abort();
	}
}

static void json_sendpay_on_resolve(const struct sendpay_result* r,
				    void *vcmd)
{
	struct command *cmd = (struct command*) vcmd;

	if (!r->succeeded && r->errorcode == PAY_IN_PROGRESS) {
		/* This is normal for sendpay. Succeed. */
		struct json_stream *response = json_stream_success(cmd);
		json_object_start(response, NULL);
		json_add_string(response, "message",
				"Monitor status with listpayments or waitsendpay");
		json_add_payment_fields(response, r->payment);
		json_object_end(response);
		was_pending(command_success(cmd, response));
	} else
		json_waitsendpay_on_resolve(r, cmd);
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
	u64 *msatoshi;
	const char *description;

	if (!param(cmd, buffer, params,
		   p_req("route", param_array, &routetok),
		   p_req("payment_hash", param_sha256, &rhash),
		   p_opt("description", param_escaped_string, &description),
		   p_opt("msatoshi", param_u64, &msatoshi),
		   NULL))
		return command_param_failed();

	if (routetok->size == 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "Empty route");

	route = tal_arr(cmd, struct route_hop, routetok->size);
	json_for_each_arr(i, t, routetok) {
		u64 *amount;
		struct pubkey *id;
		struct short_channel_id *channel;
		unsigned *delay, *direction;

		if (!param(cmd, buffer, t,
			   p_req("msatoshi", param_u64, &amount),
			   p_req("id", param_pubkey, &id),
			   p_req("delay", param_number, &delay),
			   p_req("channel", param_short_channel_id, &channel),
			   p_opt("direction", param_number, &direction),
			   NULL))
			return command_param_failed();

		route[i].amount = *amount;
		route[i].nodeid = *id;
		route[i].delay = *delay;
		route[i].channel_id = *channel;
		/* FIXME: Actually ignored by sending code! */
		route[i].direction = direction ? *direction : 0;
	}

	/* The given msatoshi is the actual payment that the payee is
	 * requesting. The final hop amount is what we actually give, which can
	 * be from the msatoshi to twice msatoshi. */

	/* if not: msatoshi <= finalhop.amount <= 2 * msatoshi, fail. */
	if (msatoshi) {
		if (!(*msatoshi <= route[routetok->size-1].amount &&
		      route[routetok->size-1].amount <= 2 * *msatoshi)) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi %"PRIu64" out of range",
					    *msatoshi);
		}
	}

	if (send_payment(cmd, cmd->ld, rhash, route,
			 msatoshi ? *msatoshi : route[routetok->size-1].amount,
			 description,
			 &json_sendpay_on_resolve, cmd))
		return command_still_pending(cmd);
	return command_its_complicated("send_payment is called in multiple paths,"
				       " patching return value through is hard");
}

static const struct json_command sendpay_command = {
	"sendpay",
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

	if (!param(cmd, buffer, params,
		   p_req("payment_hash", param_sha256, &rhash),
		   p_opt("timeout", param_number, &timeout),
		   NULL))
		return command_param_failed();

	if (!wait_payment(cmd, cmd->ld, rhash, &json_waitsendpay_on_resolve, cmd))
		return command_its_complicated("wait_payment called in multiple"
					       " paths, patching return value"
					       " through is hard");

	if (timeout)
		new_reltimer(&cmd->ld->timers, cmd, time_from_sec(*timeout),
			     &waitsendpay_timeout, cmd);
	return command_still_pending(cmd);
}

static const struct json_command waitsendpay_command = {
	"waitsendpay",
	json_waitsendpay,
	"Wait for payment attempt on {payment_hash} to succeed or fail, "
	"but only up to {timeout} seconds."
};
AUTODATA(json_command, &waitsendpay_command);

static struct command_result *json_listpayments(struct command *cmd,
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
	json_object_start(response, NULL);

	json_array_start(response, "payments");
	for (size_t i = 0; i < tal_count(payments); i++) {
		json_object_start(response, NULL);
		json_add_payment_fields(response, payments[i]);
		json_object_end(response);
	}
	json_array_end(response);

	json_object_end(response);
	return command_success(cmd, response);
}

static const struct json_command listpayments_command = {
	"listpayments",
	json_listpayments,
	"Show outgoing payments"
};
AUTODATA(json_command, &listpayments_command);
