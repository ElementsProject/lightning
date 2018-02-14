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
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/subd.h>
#include <sodium/randombytes.h>

/*-----------------------------------------------------------------------------
Internal sendpay interface
-----------------------------------------------------------------------------*/

struct routing_failure {
	unsigned int erring_index;
	enum onion_type failcode;
	struct pubkey erring_node;
	struct short_channel_id erring_channel;
	u8 *channel_update;
};

/* Result of sendpay */
struct sendpay_result {
	/* Did the payment succeed? */
	bool succeeded;
	/* Preimage. Only loaded if payment succeeded. */
	struct preimage preimage;
	/* Error code, one of the PAY_* macro in jsonrpc_errors.h.
	 * Only loaded if payment failed. */
	int errorcode;
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

/* Owned by cxt; if cxt is deleted, then cb will
 * no longer be called. */
static struct sendpay_command *
new_sendpay_command(const tal_t *cxt,
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
	return pc;
}

/* Caller responsible for freeing ctx. */
static void sendpay_resolve(const tal_t *ctx,
			    struct lightningd *ld,
			    const struct sha256 *payment_hash,
			    const struct sendpay_result *result)
{
	struct sendpay_command *pc;
	struct sendpay_command *next;
	list_for_each_safe(&ld->sendpay_commands, pc, next, list) {
		if (!structeq(payment_hash, &pc->payment_hash))
			continue;

		/* Delete later (in our own caller) if callback did
		 * not delete. */
		tal_steal(ctx, pc);
		pc->cb(result, pc->cbarg);
	}
}

static void sendpay_success(struct lightningd *ld,
			    const struct sha256 *payment_hash,
			    const struct preimage *payment_preimage)
{
	const tal_t *tmpctx = tal_tmpctx(ld);
	struct sendpay_result *result;

	result = tal(tmpctx, struct sendpay_result);
	result->succeeded = true;
	result->preimage = *payment_preimage;

	sendpay_resolve(tmpctx, ld, payment_hash, result);

	tal_free(tmpctx);
}

static void sendpay_route_failure(struct lightningd *ld,
				  const struct sha256 *payment_hash,
				  bool retry_plausible,
				  struct routing_failure *fail,
				  const u8 *onionreply,
				  const char *details)
{
	const tal_t *tmpctx = tal_tmpctx(ld);
	struct sendpay_result *result;

	result = tal(tmpctx, struct sendpay_result);
	result->succeeded = false;
	result->errorcode =
		(!fail) ?		PAY_UNPARSEABLE_ONION :
		(!retry_plausible) ?	PAY_DESTINATION_PERM_FAIL :
		/*otherwise*/		PAY_TRY_OTHER_ROUTE ;
	result->onionreply = onionreply;
	result->routing_failure = fail;
	result->details = details;

	sendpay_resolve(tmpctx, ld, payment_hash, result);

	tal_free(tmpctx);
}

/* Immediately fail during send_payment call. */
static void sendpay_fail_now(void (*cb)(const struct sendpay_result *, void*),
			     void *cbarg,
			     int errorcode,
			     char const *details)
{
	const tal_t *tmpctx = tal_tmpctx(NULL);
	struct sendpay_result *result;

	result = tal(tmpctx, struct sendpay_result);
	result->succeeded = false;
	result->errorcode = errorcode;
	result->details = details;

	cb(result, cbarg);

	tal_free(tmpctx);
}
/* Immediately fail during send_payment call. */
static void
sendpay_succeed_now(void (*cb)(const struct sendpay_result*, void*),
		    void *cbarg,
		    const struct preimage *payment_preimage)
{
	const tal_t *tmpctx = tal_tmpctx(NULL);
	struct sendpay_result *result;

	result = tal(tmpctx, struct sendpay_result);
	result->succeeded = true;
	result->preimage = *payment_preimage;

	cb(result, cbarg);

	tal_free(tmpctx);
}

void payment_succeeded(struct lightningd *ld, struct htlc_out *hout,
		       const struct preimage *rval)
{
	wallet_payment_set_status(ld->wallet, &hout->payment_hash,
				  PAYMENT_COMPLETE, rval);
	sendpay_success(ld, &hout->payment_hash, rval);
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
		       const struct onionreply *failure)
{
	enum onion_type failcode = fromwire_peektype(failure->msg);
	u8 *channel_update;
	struct routing_failure *routing_failure;
	const struct pubkey *route_nodes;
	const struct pubkey *erring_node;
	const struct short_channel_id *route_channels;
	const struct short_channel_id *erring_channel;
	static const struct short_channel_id dummy_channel = { 0, 0, 0 };
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
	const tal_t *tmpctx = tal_tmpctx(gossip);
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

	tal_free(tmpctx);
}

static void report_routing_failure(struct log *log,
				   struct subd *gossip,
				   struct routing_failure *fail)
{
	const tal_t *tmpctx = tal_tmpctx(gossip);
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

	tal_free(tmpctx);
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
	bool report_to_gossipd;

	payment = wallet_payment_by_hash(tmpctx, ld->wallet,
					 &hout->payment_hash);

	/* This gives more details than a generic failure message */
	if (localfail) {
		fail = local_routing_failure(tmpctx, ld, hout, payment);
		failcode = fail->failcode;
		failmsg = localfail;
		retry_plausible = true;
		report_to_gossipd = true;
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
			log_info(hout->key.channel->log,
				 "htlc %"PRIu64" failed with bad reply (%s)",
				 hout->key.id,
				 tal_hex(ltmp, hout->failuremsg));
			/* Cannot report failure. */
			fail = NULL;
			failcode = WIRE_PERMANENT_NODE_FAILURE;
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
			failcode = fromwire_peektype(reply->msg);
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
						      payment, reply);
		}
	}

	/* This may invalidated the payment structure returned, so
	 * access to payment object should not be done after the
	 * below call.  */
	wallet_payment_set_status(ld->wallet, &hout->payment_hash,
				  PAYMENT_FAILED, NULL);

	/* Report to gossipd if we decided we should. */
	if (report_to_gossipd)
		report_routing_failure(ld->log, ld->gossip, fail);

	/* FIXME(ZmnSCPxj): if retrying is plausible, and we are
	 * using pay command rather than sendpay, retry routing
	 * and payment again. */
	(void) retry_plausible;

	/* Report to client. */
	sendpay_route_failure(ld, &hout->payment_hash,
			      retry_plausible, fail, hout->failuremsg,
			      failmsg);
	tal_free(tmpctx);
}

/* Returns false if we called callback directly, true if
 * callback is scheduled for later.
 *
 * This call expects that if it calls the callback, then
 * the given context should have been freed. */
static bool send_payment(const tal_t *ctx,
			 struct lightningd* ld,
			 const struct sha256 *rhash,
			 const struct route_hop *route,
			 void (*cb)(const struct sendpay_result*, void*),
			 void *cbarg)
{
	const u8 *onion;
	u8 sessionkey[32];
	unsigned int base_expiry;
	struct onionpacket *packet;
	struct secret *path_secrets;
	enum onion_type failcode;
	const tal_t *tmpctx = tal_tmpctx(ctx);
	size_t i, n_hops = tal_count(route);
	struct hop_data *hop_data = tal_arr(tmpctx, struct hop_data, n_hops);
	struct pubkey *ids = tal_arr(tmpctx, struct pubkey, n_hops);
	struct wallet_payment *payment = NULL;
	struct htlc_out *hout;
	struct short_channel_id *channels;
	struct routing_failure *fail;
	struct channel *channel;

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
			sendpay_fail_now(cb, cbarg, PAY_IN_PROGRESS,
					 "Payment is still in progress");
			return false;
		}
		if (payment->status == PAYMENT_COMPLETE) {
			log_add(ld->log, "... succeeded");
			/* Must match successful payment parameters. */
			if (payment->msatoshi != hop_data[n_hops-1].amt_forward) {
				char *msg = tal_fmt(tmpctx,
						    "Already succeeded "
						    "with amount %"PRIu64,
						    payment->msatoshi);
				sendpay_fail_now(cb, cbarg,
						 PAY_RHASH_ALREADY_USED,
						 msg);
				return false;
			}
			if (!structeq(&payment->destination, &ids[n_hops-1])) {
				char *msg = tal_fmt(tmpctx,
						    "Already succeeded to %s",
						    type_to_string(tmpctx,
								   struct pubkey,
								   &payment->destination));
				sendpay_fail_now(cb, cbarg,
						 PAY_RHASH_ALREADY_USED,
						 msg);
				return false;
			}
			sendpay_succeed_now(cb, cbarg,
					    payment->payment_preimage);
			return false;
		}
		wallet_payment_delete(ld->wallet, rhash);
		log_add(ld->log, "... retrying");
	}

	/* At this point we know there is no duplicate payment.
	 * Register it to the lightningd. Use the caller
	 * context, not our temporary context. */
	new_sendpay_command(ctx, rhash, ld, cb, cbarg);

	channel = active_channel_by_id(ld, &ids[0]);
	if (!channel) {
		/* Report routing failure to gossipd */
		fail = immediate_routing_failure(tmpctx, ld,
						 WIRE_UNKNOWN_NEXT_PEER,
						 &route[0].channel_id);
		report_routing_failure(ld->log, ld->gossip, fail);

		/* Report routing failure to user */
		sendpay_route_failure(ld, rhash, true, fail, NULL,
				      "No connection to first "
				      "peer found");
		return false;
	}

	randombytes_buf(&sessionkey, sizeof(sessionkey));

	/* Onion will carry us from first peer onwards. */
	packet = create_onionpacket(tmpctx, ids, hop_data, sessionkey, rhash->u.u8,
				    sizeof(struct sha256), &path_secrets);
	onion = serialize_onionpacket(tmpctx, packet);

	log_info(ld->log, "Sending %u over %zu hops to deliver %u",
		 route[0].amount, n_hops, route[n_hops-1].amount);

	failcode = send_htlc_out(channel, route[0].amount,
				 base_expiry + route[0].delay,
				 rhash, onion, NULL, &hout);
	if (failcode) {
		/* Report routing failure to gossipd */
		fail = immediate_routing_failure(tmpctx, ld,
						 failcode,
						 &route[0].channel_id);
		report_routing_failure(ld->log, ld->gossip, fail);

		/* Report routing failure to user */
		sendpay_route_failure(ld, rhash, true, fail, NULL,
				      "First peer not ready");
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
	wallet_payment_setup(ld->wallet, payment);

	tal_free(tmpctx);
	return true;
}

/*-----------------------------------------------------------------------------
JSON-RPC sendpay interface
-----------------------------------------------------------------------------*/

static void
json_sendpay_success(struct command *cmd,
		     const struct preimage *payment_preimage)
{
	struct json_result *response;

	response = new_json_result(cmd);
	json_object_start(response, NULL);
	json_add_hex(response, "preimage",
		     payment_preimage, sizeof(*payment_preimage));
	json_object_end(response);
	command_success(cmd, response);
}

static void json_sendpay_on_resolve(const struct sendpay_result *r,
				    void *vcmd)
{
	struct command *cmd = (struct command*) vcmd;

	struct json_result *data;
	const char *msg;
	struct routing_failure *fail;

	if (r->succeeded)
		json_sendpay_success(cmd, &r->preimage);
	else {
		switch (r->errorcode) {
		case PAY_IN_PROGRESS:
		case PAY_RHASH_ALREADY_USED:
			data = NULL;
			msg = r->details;
			break;

		case PAY_UNPARSEABLE_ONION:
			data = new_json_result(cmd);
			json_object_start(data, NULL);
			json_add_hex(data, "onionreply",
				     r->onionreply, tal_len(r->onionreply));
			json_object_end(data);

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
			json_add_hex(data, "erring_node",
				     &fail->erring_node,
				     sizeof(fail->erring_node));
			json_add_short_channel_id(data, "erring_channel",
						  &fail->erring_channel);
			if (fail->channel_update)
				json_add_hex(data, "channel_update",
					     fail->channel_update,
					     tal_len(fail->channel_update));
			json_object_end(data);

			msg = tal_fmt(cmd,
				      "failed: %s (%s)",
				      onion_type_name(fail->failcode),
				      r->details);

			break;
		}

		command_fail_detailed(cmd, r->errorcode, data, "%s", msg);
	}
}

static void json_sendpay(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *routetok, *rhashtok;
	const jsmntok_t *t, *end;
	size_t n_hops;
	struct sha256 rhash;
	struct route_hop *route;

	if (!json_get_params(cmd, buffer, params,
			     "route", &routetok,
			     "rhash", &rhashtok,
			     NULL)) {
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
			command_fail(cmd, "Route %zu '%.*s' is not an object",
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
			command_fail(cmd, "Route %zu needs msatoshi/id/channel/delay",
				     n_hops);
			return;
		}

		tal_resize(&route, n_hops + 1);

		/* What that hop will forward */
		if (!json_tok_number(buffer, amttok, &route[n_hops].amount)) {
			command_fail(cmd, "Route %zu invalid msatoshi",
				     n_hops);
			return;
		}

		if (!json_tok_short_channel_id(buffer, chantok,
					       &route[n_hops].channel_id)) {
			command_fail(cmd, "Route %zu invalid channel_id", n_hops);
			return;
		}
		if (!json_tok_pubkey(buffer, idtok, &route[n_hops].nodeid)) {
			command_fail(cmd, "Route %zu invalid id", n_hops);
			return;
		}
		if (!json_tok_number(buffer, delaytok, &route[n_hops].delay)) {
			command_fail(cmd, "Route %zu invalid delay", n_hops);
			return;
		}
		n_hops++;
	}

	if (n_hops == 0) {
		command_fail(cmd, "Empty route");
		return;
	}

	if (send_payment(cmd, cmd->ld, &rhash, route,
			 &json_sendpay_on_resolve, cmd))
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
	u64 msatoshi;
	double maxfeepercent;
};

static void json_pay_getroute_reply(struct subd *gossip,
				    const u8 *reply, const int *fds,
				    struct pay *pay)
{
	struct route_hop *route;
	u64 msatoshi_sent;
	u64 fee;
	double feepercent;
	struct json_result *data;

	fromwire_gossip_getroute_reply(reply, reply, NULL, &route);

	if (tal_count(route) == 0) {
		command_fail_detailed(pay->cmd, PAY_ROUTE_NOT_FOUND, NULL,
				      "Could not find a route");
		return;
	}

	msatoshi_sent = route[0].amount;
	fee = msatoshi_sent - pay->msatoshi;
	/* FIXME: IEEE Double-precision floating point has only 53 bits
	 * of precision. Total satoshis that can ever be created is
	 * slightly less than 2100000000000000. Total msatoshis that
	 * can ever be created is 1000 times that or
	 * 2100000000000000000, requiring 60.865 bits of precision,
	 * and thus losing precision in the below. Currently, OK, as,
	 * payments are limited to 4294967295 msatoshi. */
	feepercent = ((double) fee) * 100.0 / ((double) pay->msatoshi);
	if (feepercent > pay->maxfeepercent) {
		data = new_json_result(pay);
		json_object_start(data, NULL);
		json_add_u64(data, "fee", fee);
		json_add_double(data, "feepercent", feepercent);
		json_add_u64(data, "msatoshi", pay->msatoshi);
		json_add_double(data, "maxfeepercent", pay->maxfeepercent);
		json_object_end(data);

		command_fail_detailed(pay->cmd, PAY_ROUTE_TOO_EXPENSIVE,
				      data,
				      "Fee %"PRIu64" is %f%% "
				      "of payment %"PRIu64"; "
				      "max fee requested is %f%%",
				      fee, feepercent,
				      pay->msatoshi,
				      pay->maxfeepercent);
		return;
	}

	send_payment(pay->cmd, pay->cmd->ld, &pay->payment_hash, route,
		     &json_sendpay_on_resolve, pay->cmd);
}

static void json_pay(struct command *cmd,
		     const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *bolt11tok, *msatoshitok, *desctok, *riskfactortok, *maxfeetok;
	double riskfactor = 1.0;
	double maxfeepercent = 0.5;
	u64 msatoshi;
	struct pay *pay = tal(cmd, struct pay);
	struct bolt11 *b11;
	char *fail, *b11str, *desc;
	u8 *req;

	if (!json_get_params(cmd, buffer, params,
			     "bolt11", &bolt11tok,
			     "?msatoshi", &msatoshitok,
			     "?description", &desctok,
			     "?riskfactor", &riskfactortok,
			     "?maxfeepercent", &maxfeetok,
			     NULL)) {
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
	pay->msatoshi = msatoshi;

	if (riskfactortok
	    && !json_tok_double(buffer, riskfactortok, &riskfactor)) {
		command_fail(cmd, "'%.*s' is not a valid double",
			     (int)(riskfactortok->end - riskfactortok->start),
			     buffer + riskfactortok->start);
		return;
	}

	if (maxfeetok
	    && !json_tok_double(buffer, maxfeetok, &maxfeepercent)) {
		command_fail(cmd, "'%.*s' is not a valid double",
			     (int)(maxfeetok->end - maxfeetok->start),
			     buffer + maxfeetok->start);
		return;
	}
	/* Ensure it is in range 0.0 <= maxfeepercent <= 100.0 */
	if (!(0.0 <= maxfeepercent)) {
		command_fail(cmd, "%f maxfeepercent must be non-negative",
			     maxfeepercent);
		return;
	}
	if (!(maxfeepercent <= 100.0)) {
		command_fail(cmd, "%f maxfeepercent must be <= 100.0",
			     maxfeepercent);
		return;
	}
	pay->maxfeepercent = maxfeepercent;

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
	"Send payment specified by {bolt11} with optional {msatoshi} "
	"(if and only if {bolt11} does not have amount), "
	"{description} (required if {bolt11} uses description hash), "
	"{riskfactor} (default 1.0), and "
	"{maxfeepercent} (default 0.5) the maximum acceptable fee as a percentage (e.g. 0.5 => 0.5%)"
};
AUTODATA(json_command, &pay_command);

static void json_listpayments(struct command *cmd, const char *buffer,
			       const jsmntok_t *params)
{
	const struct wallet_payment **payments;
	struct json_result *response = new_json_result(cmd);
	jsmntok_t *bolt11tok, *rhashtok;
	struct sha256 *rhash = NULL;

	if (!json_get_params(cmd, buffer, params,
			     "?bolt11", &bolt11tok,
			     "?payment_hash", &rhashtok,
			     NULL)) {
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
