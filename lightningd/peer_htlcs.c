#include <daemon/chaintopology.h>
#include <daemon/invoice.h>
#include <daemon/log.h>
#include <lightningd/channel/gen_channel_wire.h>
#include <lightningd/gossip/gen_gossip_wire.h>
#include <lightningd/htlc_end.h>
#include <lightningd/lightningd.h>
#include <lightningd/pay.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/sphinx.h>
#include <lightningd/subd.h>
#include <overflows.h>
#include <wire/gen_onion_wire.h>

/* This obfuscates the message, whether local or forwarded. */
static void relay_htlc_failmsg(struct htlc_end *hend)
{
	u8 *reply;

	if (!hend->peer->owner)
		return;

	reply = wrap_onionreply(hend, hend->shared_secret, hend->fail_msg);
	subd_send_msg(hend->peer->owner,
		      take(towire_channel_fail_htlc(hend, hend->htlc_id, reply)));
	tal_free(reply);
}

static u8 *make_failmsg(const tal_t *ctx, const struct htlc_end *hend,
			enum onion_type failcode,
			const struct sha256 *onion_sha, const u8 *channel_update)
{
	switch (failcode) {
	case WIRE_INVALID_REALM:
		return towire_invalid_realm(ctx);
	case WIRE_TEMPORARY_NODE_FAILURE:
		return towire_temporary_node_failure(ctx);
	case WIRE_PERMANENT_NODE_FAILURE:
		return towire_permanent_node_failure(ctx);
	case WIRE_REQUIRED_NODE_FEATURE_MISSING:
		return towire_required_node_feature_missing(ctx);
	case WIRE_INVALID_ONION_VERSION:
		return towire_invalid_onion_version(ctx, onion_sha);
	case WIRE_INVALID_ONION_HMAC:
		return towire_invalid_onion_hmac(ctx, onion_sha);
	case WIRE_INVALID_ONION_KEY:
		return towire_invalid_onion_key(ctx, onion_sha);
	case WIRE_TEMPORARY_CHANNEL_FAILURE:
		return towire_temporary_channel_failure(ctx, channel_update);
	case WIRE_CHANNEL_DISABLED:
		return towire_channel_disabled(ctx);
	case WIRE_PERMANENT_CHANNEL_FAILURE:
		return towire_permanent_channel_failure(ctx);
	case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
		return towire_required_channel_feature_missing(ctx);
	case WIRE_UNKNOWN_NEXT_PEER:
		return towire_unknown_next_peer(ctx);
	case WIRE_AMOUNT_BELOW_MINIMUM:
		return towire_amount_below_minimum(ctx, hend->msatoshis, channel_update);
	case WIRE_FEE_INSUFFICIENT:
		return towire_fee_insufficient(ctx, hend->msatoshis, channel_update);
	case WIRE_INCORRECT_CLTV_EXPIRY:
		/* FIXME: ctlv! */
		return towire_incorrect_cltv_expiry(ctx, 0, channel_update);
	case WIRE_EXPIRY_TOO_SOON:
		return towire_expiry_too_soon(ctx, channel_update);
	case WIRE_UNKNOWN_PAYMENT_HASH:
		return towire_unknown_payment_hash(ctx);
	case WIRE_INCORRECT_PAYMENT_AMOUNT:
		return towire_incorrect_payment_amount(ctx);
	case WIRE_FINAL_EXPIRY_TOO_SOON:
		return towire_final_expiry_too_soon(ctx);
	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
		/* FIXME: ctlv! */
		return towire_final_incorrect_cltv_expiry(ctx, 0);
	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
		return towire_final_incorrect_htlc_amount(ctx, hend->msatoshis);
	}
	abort();
}

static void fail_htlc(struct htlc_end *hend, enum onion_type failcode,
		      const struct sha256 *onion_sha)
{
	u8 *msg;

	log_broken(hend->peer->log, "failed htlc %"PRIu64" code 0x%04x (%s)",
		   hend->htlc_id, failcode, onion_type_name(failcode));

	if (failcode & UPDATE) {
		/* FIXME: Ask gossip daemon for channel_update. */
	}

	msg = make_failmsg(hend, hend, failcode, onion_sha, NULL);
	hend->fail_msg = create_onionreply(hend, hend->shared_secret, msg);
	tal_free(msg);

	relay_htlc_failmsg(hend);
}

/* BOLT #4:
 *
 * * `amt_to_forward` - The amount in milli-satoshi to forward to the next
 *    (outgoing) hop specified within the routing information.
 *
 *    This value MUST factor in the computed fee for this particular hop. When
 *    processing an incoming Sphinx packet along with the HTLC message it's
 *    encapsulated within, if the following inequality doesn't hold, then the
 *    HTLC should be rejected as it indicates a prior node in the path has
 *    deviated from the specified parameters:
 *
 *       incoming_htlc_amt - fee >= amt_to_forward
 *
 *    Where `fee` is calculated according to the receiving node's advertised fee
 *    schema as described in [BOLT 7](https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#htlc-fees), or 0 if this node is the
 *    final hop.
 */
static bool check_amount(struct htlc_end *hend,
			 u64 amt_to_forward, u64 amt_in_htlc, u64 fee)
{
	if (amt_in_htlc - fee >= amt_to_forward)
		return true;
	log_debug(hend->peer->ld->log, "HTLC %"PRIu64" incorrect amount:"
		  " %"PRIu64" in, %"PRIu64" out, fee reqd %"PRIu64,
		  hend->htlc_id, amt_in_htlc, amt_to_forward, fee);
	return false;
}

/* BOLT #4:
 *
 *  * `outgoing_cltv_value` - The CLTV value that the _outgoing_ HTLC carrying
 *     the packet should have.
 *
 *        cltv_expiry - cltv_expiry_delta = outgoing_cltv_value
 *
 *     Inclusion of this field allows a node to both authenticate the information
 *     specified by the original sender and the parameters of the HTLC forwarded,
 *	 and ensure the original sender is using the current `cltv_expiry_delta`  value.
 *     If there is no next hop, `cltv_expiry_delta` is zero.
 *     If the values don't correspond, then the HTLC should be failed+rejected as
 *     this indicates the incoming node has tampered with the intended HTLC
 *     values, or the origin has an obsolete `cltv_expiry_delta` value.
 *     The node MUST be consistent in responding to an unexpected
 *     `outgoing_cltv_value` whether it is the final hop or not, to avoid
 *     leaking that information.
 */
static bool check_ctlv(struct htlc_end *hend,
		       u32 ctlv_expiry, u32 outgoing_cltv_value, u32 delta)
{
	if (ctlv_expiry - delta == outgoing_cltv_value)
		return true;
	log_debug(hend->peer->ld->log, "HTLC %"PRIu64" incorrect CLTV:"
		  " %u in, %u out, delta reqd %u",
		  hend->htlc_id, ctlv_expiry, outgoing_cltv_value, delta);
	return false;
}

static void fulfill_htlc(struct htlc_end *hend, const struct preimage *preimage)
{
	u8 *msg;

	hend->peer->balance[LOCAL] += hend->msatoshis;
	hend->peer->balance[REMOTE] -= hend->msatoshis;

	/* FIXME: fail the peer if it doesn't tell us that htlc fulfill is
	 * committed before deadline.
	 */
	msg = towire_channel_fulfill_htlc(hend->peer, hend->htlc_id, preimage);
	subd_send_msg(hend->peer->owner, take(msg));
}

static void handle_localpay(struct htlc_end *hend,
			    u32 cltv_expiry,
			    const struct sha256 *payment_hash,
			    u64 amt_to_forward,
			    u32 outgoing_cltv_value)
{
	enum onion_type failcode;
	struct invoice *invoice;

	/* BOLT #4:
	 *
	 * If the `amt_to_forward` is higher than `incoming_htlc_amt` of
	 * the HTLC at the final hop:
	 *
	 * 1. type: 19 (`final_incorrect_htlc_amount`)
	 * 2. data:
	 *    * [`4`:`incoming_htlc_amt`]
	 */
	if (!check_amount(hend, amt_to_forward, hend->msatoshis, 0)) {
		failcode = WIRE_FINAL_INCORRECT_HTLC_AMOUNT;
		goto fail;
	}

	/* BOLT #4:
	 *
	 * If the `outgoing_cltv_value` does not match the `ctlv_expiry` of
	 * the HTLC at the final hop:
	 *
	 * 1. type: 18 (`final_incorrect_cltv_expiry`)
	 * 2. data:
	 *   * [`4`:`cltv_expiry`]
	 */
	if (!check_ctlv(hend, cltv_expiry, outgoing_cltv_value, 0)) {
		failcode = WIRE_FINAL_INCORRECT_CLTV_EXPIRY;
		goto fail;
	}

	invoice = find_unpaid(hend->peer->ld->dstate.invoices, payment_hash);
	if (!invoice) {
		failcode = WIRE_UNKNOWN_PAYMENT_HASH;
		goto fail;
	}

	/* BOLT #4:
	 *
	 * If the amount paid is less than the amount expected, the final node
	 * MUST fail the HTLC.  If the amount paid is more than twice the
	 * amount expected, the final node SHOULD fail the HTLC.  This allows
	 * the sender to reduce information leakage by altering the amount,
	 * without allowing accidental gross overpayment:
	 *
	 * 1. type: PERM|16 (`incorrect_payment_amount`)
	 */
	if (hend->msatoshis < invoice->msatoshi) {
		failcode = WIRE_INCORRECT_PAYMENT_AMOUNT;
		goto fail;
	} else if (hend->msatoshis > invoice->msatoshi * 2) {
		failcode = WIRE_INCORRECT_PAYMENT_AMOUNT;
		goto fail;
	}

	/* BOLT #4:
	 *
	 * If the `cltv_expiry` is too low, the final node MUST fail the HTLC:
	 */
	if (get_block_height(hend->peer->ld->topology)
	    + hend->peer->ld->dstate.config.deadline_blocks >= cltv_expiry) {
		log_debug(hend->peer->log,
			  "Expiry cltv %u too close to current %u + deadline %u",
			  cltv_expiry,
			  get_block_height(hend->peer->ld->topology),
			  hend->peer->ld->dstate.config.deadline_blocks);
		failcode = WIRE_FINAL_EXPIRY_TOO_SOON;
		goto fail;
	}

	connect_htlc_end(&hend->peer->ld->htlc_ends, hend);

	log_info(hend->peer->ld->log, "Resolving invoice '%s' with HTLC %"PRIu64,
		 invoice->label, hend->htlc_id);
	fulfill_htlc(hend, &invoice->r);
	resolve_invoice(&hend->peer->ld->dstate, invoice);
	return;

fail:
	fail_htlc(hend, failcode, NULL);
}

/*
 * A catchall in case outgoing peer disconnects before getting fwd.
 *
 * We could queue this and wait for it to come back, but this is simple.
 */
static void hend_subd_died(struct htlc_end *hend)
{
	log_debug(hend->other_end->peer->owner->log,
		  "Failing HTLC %"PRIu64" due to peer death",
		  hend->other_end->htlc_id);

	fail_htlc(hend->other_end, WIRE_TEMPORARY_CHANNEL_FAILURE, NULL);
}

static bool rcvd_htlc_reply(struct subd *subd, const u8 *msg, const int *fds,
			    struct htlc_end *hend)
{
	u16 failure_code;
	u8 *failurestr;

	if (!fromwire_channel_offer_htlc_reply(msg, msg, NULL,
					       &hend->htlc_id,
					       &failure_code,
					       &failurestr)) {
		log_broken(subd->log, "Bad channel_offer_htlc_reply");
		tal_free(hend);
		return false;
	}

	if (failure_code) {
		log_debug(hend->other_end->peer->owner->log,
			  "HTLC failed from other daemon: %s (%.*s)",
			  onion_type_name(failure_code),
			  (int)tal_len(failurestr), (char *)failurestr);

		fail_htlc(hend->other_end, failure_code, NULL);
		return true;
	}

	tal_del_destructor(hend, hend_subd_died);

	/* Add it to lookup table. */
	connect_htlc_end(&hend->peer->ld->htlc_ends, hend);
	return true;
}

static void forward_htlc(struct htlc_end *hend,
			 u32 cltv_expiry,
			 const struct sha256 *payment_hash,
			 u64 amt_to_forward,
			 u32 outgoing_cltv_value,
			 const struct pubkey *next_hop,
			 const u8 next_onion[TOTAL_PACKET_SIZE])
{
	u8 *msg;
	enum onion_type failcode;
	u64 fee;
	struct lightningd *ld = hend->peer->ld;
	struct peer *next = peer_by_id(ld, next_hop);

	if (!next) {
		failcode = WIRE_UNKNOWN_NEXT_PEER;
		goto fail;
	}

	if (!peer_can_add_htlc(next)) {
		log_info(next->log, "Attempt to forward HTLC but not ready");
		failcode = WIRE_UNKNOWN_NEXT_PEER;
		goto fail;
	}

	/* BOLT #7:
	 *
	 * The node creating `channel_update` SHOULD accept HTLCs which pay a
	 * fee equal or greater than:
	 *
	 *    fee_base_msat + amount_msat * fee_proportional_millionths / 1000000
	 */
	if (mul_overflows_u64(amt_to_forward,
			      ld->dstate.config.fee_per_satoshi)) {
		failcode = WIRE_FEE_INSUFFICIENT;
		goto fail;
	}
	fee = ld->dstate.config.fee_base
		+ amt_to_forward * ld->dstate.config.fee_per_satoshi / 1000000;
	if (!check_amount(hend, amt_to_forward, hend->msatoshis, fee)) {
		failcode = WIRE_FEE_INSUFFICIENT;
		goto fail;
	}

	if (!check_ctlv(hend, cltv_expiry, outgoing_cltv_value,
			ld->dstate.config.deadline_blocks)) {
		failcode = WIRE_INCORRECT_CLTV_EXPIRY;
		goto fail;
	}

	/* BOLT #4:
	 *
	 * If the ctlv-expiry is too near, we tell them the the current channel
	 * setting for the outgoing channel:
	 * 1. type: UPDATE|14 (`expiry_too_soon`)
	 * 2. data:
	 *    * [`2`:`len`]
	 *    * [`len`:`channel_update`]
	 */
	if (get_block_height(next->ld->topology)
	    + next->ld->dstate.config.deadline_blocks >= outgoing_cltv_value) {
		log_debug(hend->peer->log,
			  "Expiry cltv %u too close to current %u + deadline %u",
			  outgoing_cltv_value,
			  get_block_height(next->ld->topology),
			  next->ld->dstate.config.deadline_blocks);
		failcode = WIRE_EXPIRY_TOO_SOON;
		goto fail;
	}

	/* Make sure daemon owns it, in case it fails. */
	hend->other_end = tal(next->owner, struct htlc_end);
	hend->other_end->which_end = HTLC_DST;
	hend->other_end->peer = next;
	hend->other_end->other_end = hend;
	hend->other_end->pay_command = NULL;
	hend->other_end->msatoshis = amt_to_forward;
	tal_add_destructor(hend->other_end, hend_subd_died);

	msg = towire_channel_offer_htlc(next, amt_to_forward,
					outgoing_cltv_value,
					payment_hash, next_onion);
	subd_req(next->owner, next->owner, take(msg), -1, 0,
		 rcvd_htlc_reply, hend->other_end);
	return;

fail:
	fail_htlc(hend, failcode, NULL);
}

/* We received a resolver reply, which gives us the node_ids of the
 * channel we want to forward over */
static bool channel_resolve_reply(struct subd *gossip, const u8 *msg,
				  const int *fds, struct htlc_end *hend)
{
	struct pubkey *nodes, *peer_id;

	if (!fromwire_gossip_resolve_channel_reply(msg, msg, NULL, &nodes)) {
		log_broken(gossip->log,
			   "bad fromwire_gossip_resolve_channel_reply %s",
			   tal_hex(msg, msg));
		return false;
	}

	if (tal_count(nodes) == 0) {
		fail_htlc(hend, WIRE_UNKNOWN_NEXT_PEER, NULL);
		return true;
	} else if (tal_count(nodes) != 2) {
		log_broken(gossip->log,
			   "fromwire_gossip_resolve_channel_reply has %zu nodes",
			   tal_count(nodes));
		return false;
	}

	/* Get the other peer matching the id that is not us */
	if (pubkey_cmp(&nodes[0], &gossip->ld->dstate.id) == 0) {
		peer_id = &nodes[1];
	} else {
		peer_id = &nodes[0];
	}

	forward_htlc(hend, hend->cltv_expiry, &hend->payment_hash,
		     hend->amt_to_forward, hend->outgoing_cltv_value, peer_id,
		     hend->next_onion);
	/* FIXME(cdecker) Cleanup things we stuffed into hend before (maybe?) */
	return true;
}

int peer_accepted_htlc(struct peer *peer, const u8 *msg)
{
	struct htlc_end *hend;
	u8 *req;
	u8 onion[TOTAL_PACKET_SIZE];
	struct onionpacket *op;
	struct route_step *rs;
	struct sha256 bad_onion_sha;

	hend = tal(msg, struct htlc_end);
	hend->shared_secret = tal(hend, struct secret);
	if (!fromwire_channel_accepted_htlc(msg, NULL,
					    &hend->htlc_id, &hend->msatoshis,
					    &hend->cltv_expiry,
					    &hend->payment_hash,
					    hend->shared_secret,
					    onion)) {
		log_broken(peer->log, "bad fromwire_channel_accepted_htlc %s",
			   tal_hex(peer, msg));
		return -1;
	}

	/* channeld tests this, so we shouldn't see it! */
	op = parse_onionpacket(msg, onion, TOTAL_PACKET_SIZE);
	if (!op) {
		log_broken(peer->log, "bad onion in fromwire_channel_accepted_htlc %s",
			   tal_hex(peer, msg));
		return -1;
	}

	tal_steal(peer, hend);
	hend->which_end = HTLC_SRC;
	hend->peer = peer;
	hend->other_end = NULL;
	hend->pay_command = NULL;
	hend->fail_msg = NULL;

	/* If it's crap, not their fault, just fail it */
	rs = process_onionpacket(msg, op, hend->shared_secret->data,
				 hend->payment_hash.u.u8,
				 sizeof(hend->payment_hash));
	if (!rs) {
		sha256(&bad_onion_sha, onion, sizeof(onion));
		fail_htlc(hend, WIRE_INVALID_ONION_HMAC, &bad_onion_sha);
		return 0;
	}

	/* Unknown realm isn't a bad onion, it's a normal failure. */
	if (rs->hop_data.realm != 0) {
		fail_htlc(hend, WIRE_INVALID_REALM, NULL);
		return 0;
	}

	hend->amt_to_forward = rs->hop_data.amt_forward;
	hend->outgoing_cltv_value = rs->hop_data.outgoing_cltv;
	hend->next_channel = rs->hop_data.channel_id;

	if (rs->nextcase == ONION_FORWARD) {
		hend->next_onion = serialize_onionpacket(hend, rs->next);
		req = towire_gossip_resolve_channel_request(msg, &hend->next_channel);
		log_broken(peer->log, "Asking gossip to resolve channel %d/%d/%d", hend->next_channel.blocknum, hend->next_channel.txnum, hend->next_channel.outnum);
		subd_req(hend, peer->ld->gossip, req, -1, 0, channel_resolve_reply, hend);
		/* FIXME(cdecker) Stuff all this info into hend */
	} else
		handle_localpay(hend, hend->cltv_expiry, &hend->payment_hash,
				hend->amt_to_forward, hend->outgoing_cltv_value);
	return 0;
}

int peer_fulfilled_htlc(struct peer *peer, const u8 *msg)
{
	u64 id;
	struct preimage preimage;
	struct htlc_end *hend;

	if (!fromwire_channel_fulfilled_htlc(msg, NULL, &id, &preimage)) {
		log_broken(peer->log, "bad fromwire_channel_fulfilled_htlc %s",
			   tal_hex(peer, msg));
		return -1;
	}

	hend = find_htlc_end(&peer->ld->htlc_ends, peer, id, HTLC_DST);
	if (!hend) {
		log_broken(peer->log,
			   "channel_fulfilled_htlc unknown htlc %"PRIu64,
			   id);
		return -1;
	}

	/* They fulfilled our HTLC.  Credit them, forward as required. */
	peer->balance[REMOTE] += hend->msatoshis;
	peer->balance[LOCAL] -= hend->msatoshis;

	if (hend->other_end)
		fulfill_htlc(hend->other_end, &preimage);
	else
		payment_succeeded(peer->ld, hend, &preimage);
	tal_free(hend);

	return 0;
}

int peer_failed_htlc(struct peer *peer, const u8 *msg)
{
	u64 id;
	u8 *reason;
	struct htlc_end *hend;
	enum onion_type failcode;
	struct onionreply *reply;

	if (!fromwire_channel_failed_htlc(msg, msg, NULL, &id, &reason)) {
		log_broken(peer->log, "bad fromwire_channel_failed_htlc %s",
			   tal_hex(peer, msg));
		return -1;
	}

	hend = find_htlc_end(&peer->ld->htlc_ends, peer, id, HTLC_DST);
	if (!hend) {
		log_broken(peer->log,
			   "channel_failed_htlc unknown htlc %"PRIu64,
			   id);
		return -1;
	}

	if (hend->other_end) {
		hend->other_end->fail_msg = tal_steal(hend->other_end, reason);
		relay_htlc_failmsg(hend->other_end);
	} else {
		size_t numhops = tal_count(hend->path_secrets);
		struct secret *shared_secrets = tal_arr(hend, struct secret, numhops);
		for (size_t i=0; i<numhops; i++) {
			shared_secrets[i] = hend->path_secrets[i];
		}
		reply = unwrap_onionreply(msg, shared_secrets, numhops, reason);
		if (!reply) {
			log_info(peer->log, "htlc %"PRIu64" failed with bad reply (%s)",
				 id, tal_hex(msg, msg));
			failcode = WIRE_PERMANENT_NODE_FAILURE;
		} else {
			failcode = fromwire_peektype(reply->msg);
			log_info(peer->log, "htlc %"PRIu64" failed with code 0x%04x (%s)",
				 id, failcode, onion_type_name(failcode));
		}
		/* FIXME: Apply update if it contains it, etc */
		payment_failed(peer->ld, hend, NULL, failcode);
	}

	return 0;
}

int peer_failed_malformed_htlc(struct peer *peer, const u8 *msg)
{
	u64 id;
	struct htlc_end *hend;
	struct sha256 sha256_of_onion;
	u16 failcode;

	if (!fromwire_channel_malformed_htlc(msg, NULL, &id,
					     &sha256_of_onion, &failcode)) {
		log_broken(peer->log, "bad fromwire_channel_malformed_htlc %s",
			   tal_hex(peer, msg));
		return -1;
	}

	hend = find_htlc_end(&peer->ld->htlc_ends, peer, id, HTLC_DST);
	if (!hend) {
		log_broken(peer->log,
			   "channel_malformed_htlc unknown htlc %"PRIu64,
			   id);
		return -1;
	}

	if (hend->other_end) {
		/* Not really a local failure, but since the failing
		 * peer could not derive its shared secret it cannot
		 * create a valid HMAC, so we do it on his behalf */
		fail_htlc(hend->other_end, failcode, &sha256_of_onion);
	} else {
		payment_failed(peer->ld, hend, NULL, failcode);
	}


	return 0;
}

