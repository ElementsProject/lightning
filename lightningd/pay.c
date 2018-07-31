#include "pay.h"
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bolt11.h>
#include <common/timeout.h>
#include <gossipd/gen_gossip_wire.h>
#include <lightningd/chaintopology.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
#include <lightningd/param.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/subd.h>
#include <sodium/randombytes.h>

/*-----------------------------------------------------------------------------
Internal sendpay interface
-----------------------------------------------------------------------------*/

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
		return channel_update;
	}
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
						onion_message,
						&channel_update) &&
	    !fromwire_amount_below_minimum(ctx,
					   onion_message, &unused64,
					   &channel_update) &&
	    !fromwire_fee_insufficient(ctx,
		    		       onion_message, &unused64,
				       &channel_update) &&
	    !fromwire_incorrect_cltv_expiry(ctx,
		    			    onion_message, &unused32,
					    &channel_update) &&
	    !fromwire_expiry_too_soon(ctx,
		    		      onion_message,
				      &channel_update))
		/* No channel update. */
		return NULL;

	return patch_channel_update(ctx, take(channel_update));
}

/* Return a struct routing_failure for an immediate failure
 * (returned directly from send_htlc_out). The returned
 * failure is allocated from the given context. */
static struct routing_failure*
immediate_routing_failure(const tal_t *ctx,
			  const struct lightningd *ld,
			  enum onion_type failcode,
			  const struct short_channel_id *channel0)
{
	struct routing_failure *routing_failure;

	assert(failcode);

	routing_failure = tal(ctx, struct routing_failure);
	routing_failure->erring_index = 0;
	routing_failure->failcode = failcode;
	routing_failure->erring_node = ld->id;
	routing_failure->erring_channel = *channel0;
	routing_failure->channel_update = NULL;

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
	routing_failure->channel_update = NULL;

	return routing_failure;
}

/* Return false if permanent failure at the destination, true if
 * retrying is plausible. Fill *routing_failure with NULL if
 * we cannot report the remote failure, or with the routing
 * failure to report (allocated from ctx) otherwise. */
static struct routing_failure*
remote_routing_failure(const tal_t *ctx,
		       bool *p_retry_plausible,
		       bool *p_report_to_gossipd,
		       const struct wallet_payment *payment,
		       const struct onionreply *failure,
		       struct log *log)
{
	enum onion_type failcode = fromwire_peektype(failure->msg);
	u8 *channel_update;
	struct routing_failure *routing_failure;
	const struct pubkey *route_nodes;
	const struct pubkey *erring_node;
	const struct short_channel_id *route_channels;
	const struct short_channel_id *erring_channel;
	static const struct short_channel_id dummy_channel = { 0 };
	int origin_index;
	bool retry_plausible;
	bool report_to_gossipd;

	routing_failure = tal(ctx, struct routing_failure);
	route_nodes = payment->route_nodes;
	route_channels = payment->route_channels;
	origin_index = failure->origin_index;
	channel_update
		= channel_update_from_onion_error(routing_failure,
						  failure->msg);
	if (channel_update)
		log_debug(log, "Extracted channel_update %s from onionreply %s",
			  tal_hex(tmpctx, channel_update),
			  tal_hex(tmpctx, failure->msg));

	retry_plausible = true;
	report_to_gossipd = true;

	assert(origin_index < tal_count(route_nodes));

	/* Check if at destination. */
	if (origin_index == tal_count(route_nodes) - 1) {
		erring_channel = &dummy_channel;
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
		if (failcode & NODE)
			report_to_gossipd = true;
		else
			report_to_gossipd = false;
	} else
		/* Report the *next* channel as failing. */
		erring_channel = &route_channels[origin_index + 1];

	erring_node = &route_nodes[origin_index];

	routing_failure->erring_index = (unsigned int) (origin_index + 1);
	routing_failure->failcode = failcode;
	routing_failure->erring_node = *erring_node;
	routing_failure->erring_channel = *erring_channel;
	routing_failure->channel_update = channel_update;

	*p_retry_plausible = retry_plausible;
	*p_report_to_gossipd = report_to_gossipd;

	return routing_failure;
}

static void random_mark_channel_unroutable(struct log *log,
					   struct subd *gossip,
					   struct short_channel_id *route_channels)
{
	size_t num_channels = tal_count(route_channels);
	size_t i;
	const struct short_channel_id *channel;
	u8 *msg;
	assert(num_channels != 0);

	/* Select one channel by random. */
	randombytes_buf(&i, sizeof(i));
	i = i % num_channels;
	channel = &route_channels[i];

	log_debug(log,
		  "Disable randomly %dth channel (%s) along route "
		  "(guessing due to bad reply)",
		  (int) i,
		  type_to_string(tmpctx, struct short_channel_id,
				 channel));
	msg = towire_gossip_mark_channel_unroutable(tmpctx, channel);
	subd_send_msg(gossip, msg);
}

static void report_routing_failure(struct log *log,
				   struct subd *gossip,
				   struct routing_failure *fail)
{
	u8 *gossip_msg;
	assert(fail);

	log_debug(log,
		  "Reporting route failure to gossipd: 0x%04x (%s) "
		  "node %s channel %s update %s",
		  fail->failcode, onion_type_name(fail->failcode),
		  type_to_string(tmpctx, struct pubkey,
				 &fail->erring_node),
		  type_to_string(tmpctx, struct short_channel_id,
			  	 &fail->erring_channel),
		  tal_hex(tmpctx, fail->channel_update));

	gossip_msg = towire_gossip_routing_failure(tmpctx,
						   &fail->erring_node,
						   &fail->erring_channel,
						   (u16) fail->failcode,
						   fail->channel_update);
	subd_send_msg(gossip, gossip_msg);
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
	bool report_to_gossipd;

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
#endif

	/* This gives more details than a generic failure message */
	if (localfail) {
		fail = local_routing_failure(tmpctx, ld, hout, payment);
		failmsg = localfail;
		retry_plausible = true;
		report_to_gossipd = true;
	} else {
		/* Must be remote fail. */
		assert(!hout->failcode);
		failmsg = "reply from remote";
		/* Try to parse reply. */
		struct secret *path_secrets = payment->path_secrets;
		struct onionreply *reply = unwrap_onionreply(tmpctx, path_secrets,
					  tal_count(path_secrets),
					  hout->failuremsg);
		if (!reply) {
			log_info(hout->key.channel->log,
				 "htlc %"PRIu64" failed with bad reply (%s)",
				 hout->key.id,
				 tal_hex(tmpctx, hout->failuremsg));
			/* Cannot report failure. */
			fail = NULL;
			/* Select a channel to mark unroutable by random */
			random_mark_channel_unroutable(hout->key.channel->log,
						       ld->gossip,
						       payment->route_channels);
			/* Can now retry; we selected a channel to mark
			 * unroutable by random */
			retry_plausible = true;
			/* Already reported something to gossipd, do not
			 * report anything else */
			report_to_gossipd = false;
		} else {
			enum onion_type failcode = fromwire_peektype(reply->msg);
			log_info(hout->key.channel->log,
				 "htlc %"PRIu64" "
				 "failed from %ith node "
				 "with code 0x%04x (%s)",
				 hout->key.id,
				 reply->origin_index,
				 failcode, onion_type_name(failcode));
			fail = remote_routing_failure(tmpctx,
						      &retry_plausible,
						      &report_to_gossipd,
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
				    fail ? fail->channel_update : NULL,
				    failmsg);

	/* Report to gossipd if we decided we should. */
	if (report_to_gossipd)
		report_routing_failure(ld->log, ld->gossip, fail);


	/* Report to client. */
	payment_route_failure(ld, &hout->payment_hash,
			      retry_plausible, fail, hout->failuremsg,
			      failmsg);
}

/* Wait for a payment. If cxt is deleted, then cb will
 * no longer be called.
 * Return false if we called callback already, true if
 * callback is scheduled for later. */
bool wait_payment(const tal_t *cxt,
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
					    &faildetail);
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
			fail->channel_update = failupdate;
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
bool
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
						 &route[0].channel_id);
		report_routing_failure(ld->log, ld->gossip, fail);

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
						 &route[0].channel_id);
		report_routing_failure(ld->log, ld->gossip, fail);

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

static void
json_sendpay_success(struct command *cmd,
		     const struct sendpay_result *r)
{
	struct json_result *response;

	assert(r->payment->status == PAYMENT_COMPLETE);

	response = new_json_result(cmd);
	json_object_start(response, NULL);
	json_add_payment_fields(response, r->payment);
	json_object_end(response);
	command_success(cmd, response);
}

static void json_waitsendpay_on_resolve(const struct sendpay_result *r,
				    void *vcmd)
{
	struct command *cmd = (struct command*) vcmd;

	struct json_result *data = NULL;
	const char *msg = NULL;
	struct routing_failure *fail;

	if (r->succeeded)
		json_sendpay_success(cmd, r);
	else {
		switch (r->errorcode) {
			/* We will never handle this case */
		case PAY_IN_PROGRESS:
			abort();

		case PAY_RHASH_ALREADY_USED:
		case PAY_UNSPECIFIED_ERROR:
		case PAY_NO_SUCH_PAYMENT:
			data = NULL;
			msg = r->details;
			break;

		case PAY_UNPARSEABLE_ONION:
			data = new_json_result(cmd);
			json_object_start(data, NULL);
			json_add_hex_talarr(data, "onionreply", r->onionreply);
			json_object_end(data);

			assert(r->details != NULL);
			msg = tal_fmt(cmd,
				      "failed: WIRE_PERMANENT_NODE_FAILURE "
				      "(%s)",
				      r->details);

			break;

		case PAY_DESTINATION_PERM_FAIL:
		case PAY_TRY_OTHER_ROUTE:
			fail = r->routing_failure;
			data = new_json_result(cmd);

			json_object_start(data, NULL);
			json_add_num(data, "erring_index",
				     fail->erring_index);
			json_add_num(data, "failcode",
				     (unsigned) fail->failcode);
			json_add_pubkey(data, "erring_node", &fail->erring_node);
			json_add_short_channel_id(data, "erring_channel",
						  &fail->erring_channel);
			if (fail->channel_update)
				json_add_hex_talarr(data, "channel_update",
						    fail->channel_update);
			json_object_end(data);

			assert(r->details != NULL);
			msg = tal_fmt(cmd,
				      "failed: %s (%s)",
				      onion_type_name(fail->failcode),
				      r->details);

			break;
		}

		assert(msg);
		command_fail_detailed(cmd, r->errorcode, data, "%s", msg);
	}
}

static void json_sendpay_on_resolve(const struct sendpay_result* r,
				    void *vcmd)
{
	struct command *cmd = (struct command*) vcmd;

	if (!r->succeeded && r->errorcode == PAY_IN_PROGRESS) {
		/* This is normal for sendpay. Succeed. */
		struct json_result *response = new_json_result(cmd);
		json_object_start(response, NULL);
		json_add_string(response, "message",
				"Monitor status with listpayments or waitsendpay");
		json_add_payment_fields(response, r->payment);
		json_object_end(response);
		command_success(cmd, response);
	} else
		json_waitsendpay_on_resolve(r, cmd);
}

static void json_sendpay(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	const jsmntok_t *routetok, *desctok;
	const jsmntok_t *t, *end;
	size_t n_hops;
	struct sha256 rhash;
	struct route_hop *route;
	u64 *msatoshi;
	const struct json_escaped *desc;
	const char *description;

	if (!param(cmd, buffer, params,
		   p_req("route", json_tok_tok, &routetok),
		   p_req("payment_hash", json_tok_sha256, &rhash),
		   p_opt("msatoshi", json_tok_u64, &msatoshi),
		   p_opt_tok("description", &desctok),
		   NULL))
		return;

	if (routetok->type != JSMN_ARRAY) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "'%.*s' is not an array",
			     routetok->end - routetok->start,
			     buffer + routetok->start);
		return;
	}

	end = json_next(routetok);
	n_hops = 0;
	route = tal_arr(cmd, struct route_hop, n_hops);

	for (t = routetok + 1; t < end; t = json_next(t)) {
		const jsmntok_t *amttok, *idtok, *delaytok, *chantok;

		if (t->type != JSMN_OBJECT) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "Route %zu '%.*s' is not an object",
				     n_hops,
				     t->end - t->start,
				     buffer + t->start);
			return;
		}
		amttok = json_get_member(buffer, t, "msatoshi");
		idtok = json_get_member(buffer, t, "id");
		delaytok = json_get_member(buffer, t, "delay");
		chantok = json_get_member(buffer, t, "channel");
		if (!amttok || !idtok || !delaytok || !chantok) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "Route %zu needs msatoshi/id/channel/delay",
				     n_hops);
			return;
		}

		tal_resize(&route, n_hops + 1);

		/* What that hop will forward */
		if (!json_tok_u64(buffer, amttok, &route[n_hops].amount)) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "Route %zu invalid msatoshi",
				     n_hops);
			return;
		}

		if (!json_tok_short_channel_id(buffer, chantok,
					       &route[n_hops].channel_id)) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "Route %zu invalid channel_id", n_hops);
			return;
		}
		if (!json_tok_pubkey(buffer, idtok, &route[n_hops].nodeid)) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "Route %zu invalid id", n_hops);
			return;
		}
		if (!json_tok_number(buffer, delaytok, &route[n_hops].delay)) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "Route %zu invalid delay", n_hops);
			return;
		}
		n_hops++;
	}

	if (n_hops == 0) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS, "Empty route");
		return;
	}

	/* The given msatoshi is the actual payment that the payee is
	 * requesting. The final hop amount is what we actually give, which can
	 * be from the msatoshi to twice msatoshi. */

	/* if not: msatoshi <= finalhop.amount <= 2 * msatoshi, fail. */
	if (msatoshi) {
		if (!(*msatoshi <= route[n_hops-1].amount &&
		      route[n_hops-1].amount <= 2 * *msatoshi)) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "msatoshi %"PRIu64" out of range",
				     *msatoshi);
			return;
		}
	}

	if (desctok) {
		desc = json_tok_escaped_string(cmd, buffer, desctok);
		if (!desc) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "description '%.*s' not a string",
				     desctok->end - desctok->start,
				     buffer + desctok->start);
			return;
		}
		description = json_escaped_unescape(cmd, desc);
		if (description == NULL) {
			command_fail(
			    cmd, JSONRPC2_INVALID_PARAMS,
			    "description '%.*s' not a valid escaped string",
			    desctok->end - desctok->start,
			    buffer + desctok->start);
			return;
		}
	} else {
		description = NULL;
	}

	if (send_payment(cmd, cmd->ld, &rhash, route,
			 msatoshi ? *msatoshi : route[n_hops-1].amount,
			 description,
			 &json_sendpay_on_resolve, cmd))
		command_still_pending(cmd);
}

static const struct json_command sendpay_command = {
	"sendpay",
	json_sendpay,
	"Send along {route} in return for preimage of {payment_hash}"
};
AUTODATA(json_command, &sendpay_command);

static void waitsendpay_timeout(struct command *cmd)
{
	command_fail(cmd, PAY_IN_PROGRESS, "Timed out while waiting");
}

static void json_waitsendpay(struct command *cmd, const char *buffer,
			     const jsmntok_t *params)
{
	struct sha256 rhash;
	unsigned int *timeout;

	if (!param(cmd, buffer, params,
		   p_req("payment_hash", json_tok_sha256, &rhash),
		   p_opt("timeout", json_tok_number, &timeout),
		   NULL))
		return;

	if (!wait_payment(cmd, cmd->ld, &rhash, &json_waitsendpay_on_resolve, cmd))
		return;

	if (timeout)
		new_reltimer(&cmd->ld->timers, cmd, time_from_sec(*timeout),
			     &waitsendpay_timeout, cmd);
	command_still_pending(cmd);
}

static const struct json_command waitsendpay_command = {
	"waitsendpay",
	json_waitsendpay,
	"Wait for payment attempt on {payment_hash} to succeed or fail, "
	"but only up to {timeout} seconds."
};
AUTODATA(json_command, &waitsendpay_command);

static void json_listpayments(struct command *cmd, const char *buffer,
			       const jsmntok_t *params)
{
	const struct wallet_payment **payments;
	struct json_result *response = new_json_result(cmd);
	jsmntok_t *bolt11tok, *rhashtok;
	struct sha256 *rhash = NULL;

	if (!param(cmd, buffer, params,
		   p_opt_tok("bolt11", &bolt11tok),
		   p_opt_tok("payment_hash", &rhashtok),
		   NULL))
		return;

	if (rhashtok && bolt11tok) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "Can only specify one of"
			     " {bolt11} or {payment_hash}");
		return;
	}

	if (bolt11tok) {
		struct bolt11 *b11;
		char *b11str, *fail;

		b11str = tal_strndup(cmd, buffer + bolt11tok->start,
				     bolt11tok->end - bolt11tok->start);
		b11 = bolt11_decode(cmd, b11str, NULL, &fail);
		if (!b11) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "Invalid bolt11: %s", fail);
			return;
		}
		rhash = &b11->payment_hash;
	} else if (rhashtok) {
		rhash = tal(cmd, struct sha256);
		if (!hex_decode(buffer + rhashtok->start,
				rhashtok->end - rhashtok->start,
				rhash, sizeof(*rhash))) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "'%.*s' is not a valid sha256 hash",
				     rhashtok->end - rhashtok->start,
				     buffer + rhashtok->start);
			return;
		}
	}

	payments = wallet_payment_list(cmd, cmd->ld->wallet, rhash);

	json_object_start(response, NULL);

	json_array_start(response, "payments");
	for (size_t i = 0; i < tal_count(payments); i++) {
		json_object_start(response, NULL);
		json_add_payment_fields(response, payments[i]);
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
