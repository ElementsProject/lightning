#include <ccan/build_assert/build_assert.h>
#include <ccan/mem/mem.h>
#include <daemon/chaintopology.h>
#include <daemon/invoice.h>
#include <daemon/log.h>
#include <lightningd/channel/gen_channel_wire.h>
#include <lightningd/derive_basepoints.h>
#include <lightningd/gossip/gen_gossip_wire.h>
#include <lightningd/htlc_end.h>
#include <lightningd/htlc_wire.h>
#include <lightningd/lightningd.h>
#include <lightningd/pay.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/sphinx.h>
#include <lightningd/subd.h>
#include <overflows.h>
#include <wire/gen_onion_wire.h>

/* This is where we write to the database the minimal HTLC info
 * required to do penalty transaction */
static void save_htlc_stub(struct lightningd *ld,
			   struct peer *peer,
			   enum side owner,
			   u32 cltv_value,
			   const struct sha256 *payment_hash)
{
	/* FIXME: remember peer, side, cltv and RIPEMD160(hash) */
}

/* This obfuscates the message, whether local or forwarded. */
static void relay_htlc_failmsg(struct htlc_in *hin)
{
	u8 *reply;

	if (!hin->key.peer->owner)
		return;

	reply = wrap_onionreply(hin, &hin->shared_secret, hin->failuremsg);
	subd_send_msg(hin->key.peer->owner,
		      take(towire_channel_fail_htlc(hin, hin->key.id, reply)));
	tal_free(reply);
}

static u8 *make_failmsg(const tal_t *ctx, const struct htlc_in *hin,
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
		return towire_amount_below_minimum(ctx, hin->msatoshi, channel_update);
	case WIRE_FEE_INSUFFICIENT:
		return towire_fee_insufficient(ctx, hin->msatoshi, channel_update);
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
		return towire_final_incorrect_htlc_amount(ctx, hin->msatoshi);
	}
	abort();
}

static void fail_htlc(struct htlc_in *hin, enum onion_type failcode,
		      const struct sha256 *onion_sha)
{
	u8 *msg;

	log_broken(hin->key.peer->log, "failed htlc %"PRIu64" code 0x%04x (%s)",
		   hin->key.id, failcode, onion_type_name(failcode));

	if (failcode & UPDATE) {
		/* FIXME: Ask gossip daemon for channel_update. */
	}

	msg = make_failmsg(hin, hin, failcode, onion_sha, NULL);
	hin->failuremsg = create_onionreply(hin, &hin->shared_secret, msg);
	tal_free(msg);

	relay_htlc_failmsg(hin);
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
static bool check_amount(struct htlc_in *hin,
			 u64 amt_to_forward, u64 amt_in_htlc, u64 fee)
{
	if (amt_in_htlc - fee >= amt_to_forward)
		return true;
	log_debug(hin->key.peer->ld->log, "HTLC %"PRIu64" incorrect amount:"
		  " %"PRIu64" in, %"PRIu64" out, fee reqd %"PRIu64,
		  hin->key.id, amt_in_htlc, amt_to_forward, fee);
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
static bool check_ctlv(struct htlc_in *hin,
		       u32 ctlv_expiry, u32 outgoing_cltv_value, u32 delta)
{
	if (ctlv_expiry - delta == outgoing_cltv_value)
		return true;
	log_debug(hin->key.peer->ld->log, "HTLC %"PRIu64" incorrect CLTV:"
		  " %u in, %u out, delta reqd %u",
		  hin->key.id, ctlv_expiry, outgoing_cltv_value, delta);
	return false;
}

static void fulfill_htlc(struct htlc_in *hin, const struct preimage *preimage)
{
	u8 *msg;

	hin->key.peer->balance[LOCAL] += hin->msatoshi;
	hin->key.peer->balance[REMOTE] -= hin->msatoshi;

	/* FIXME: fail the peer if it doesn't tell us that htlc fulfill is
	 * committed before deadline.
	 */
	msg = towire_channel_fulfill_htlc(hin->key.peer, hin->key.id, preimage);
	subd_send_msg(hin->key.peer->owner, take(msg));
}

static void handle_localpay(struct htlc_in *hin,
			    u32 cltv_expiry,
			    const struct sha256 *payment_hash,
			    u64 amt_to_forward,
			    u32 outgoing_cltv_value)
{
	enum onion_type failcode;
	struct invoice *invoice;
	struct lightningd *ld = hin->key.peer->ld;

	/* BOLT #4:
	 *
	 * If the `amt_to_forward` is higher than `incoming_htlc_amt` of
	 * the HTLC at the final hop:
	 *
	 * 1. type: 19 (`final_incorrect_htlc_amount`)
	 * 2. data:
	 *    * [`4`:`incoming_htlc_amt`]
	 */
	if (!check_amount(hin, amt_to_forward, hin->msatoshi, 0)) {
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
	if (!check_ctlv(hin, cltv_expiry, outgoing_cltv_value, 0)) {
		failcode = WIRE_FINAL_INCORRECT_CLTV_EXPIRY;
		goto fail;
	}

	invoice = find_unpaid(ld->dstate.invoices, payment_hash);
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
	if (hin->msatoshi < invoice->msatoshi) {
		failcode = WIRE_INCORRECT_PAYMENT_AMOUNT;
		goto fail;
	} else if (hin->msatoshi > invoice->msatoshi * 2) {
		failcode = WIRE_INCORRECT_PAYMENT_AMOUNT;
		goto fail;
	}

	/* BOLT #4:
	 *
	 * If the `cltv_expiry` is too low, the final node MUST fail the HTLC:
	 */
	if (get_block_height(ld->topology) + ld->dstate.config.deadline_blocks
	    >= cltv_expiry) {
		log_debug(hin->key.peer->log,
			  "Expiry cltv %u too close to current %u + deadline %u",
			  cltv_expiry,
			  get_block_height(ld->topology),
			  ld->dstate.config.deadline_blocks);
		failcode = WIRE_FINAL_EXPIRY_TOO_SOON;
		goto fail;
	}

	log_info(ld->log, "Resolving invoice '%s' with HTLC %"PRIu64,
		 invoice->label, hin->key.id);
	fulfill_htlc(hin, &invoice->r);
	resolve_invoice(&ld->dstate, invoice);
	return;

fail:
	fail_htlc(hin, failcode, NULL);
}

/*
 * A catchall in case outgoing peer disconnects before getting fwd.
 *
 * We could queue this and wait for it to come back, but this is simple.
 */
static void hend_subd_died(struct htlc_out *hout)
{
	log_debug(hout->in->key.peer->owner->log,
		  "Failing HTLC %"PRIu64" due to peer death",
		  hout->in->key.id);

	fail_htlc(hout->in, WIRE_TEMPORARY_CHANNEL_FAILURE, NULL);
}

/* This is where channeld gives us the HTLC id, and also reports if it
 * failed immediately. */
static bool rcvd_htlc_reply(struct subd *subd, const u8 *msg, const int *fds,
			    struct htlc_out *hout)
{
	u16 failure_code;
	u8 *failurestr;

	if (!fromwire_channel_offer_htlc_reply(msg, msg, NULL,
					       &hout->key.id,
					       &failure_code,
					       &failurestr)) {
		log_broken(subd->log, "Bad channel_offer_htlc_reply");
		tal_free(hout);
		return false;
	}

	if (failure_code) {
		log_debug(hout->in->key.peer->owner->log,
			  "HTLC failed from other daemon: %s (%.*s)",
			  onion_type_name(failure_code),
			  (int)tal_len(failurestr), (char *)failurestr);

		fail_htlc(hout->in, failure_code, NULL);
		return true;
	}

	/* Add it to lookup table now we know id. */
	connect_htlc_out(&subd->ld->htlcs_out, hout);

	/* When channeld includes it in commitment, we'll make it persistent. */
	return true;
}

static void forward_htlc(struct htlc_in *hin,
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
	struct lightningd *ld = hin->key.peer->ld;
	struct peer *next = peer_by_id(ld, next_hop);
	struct htlc_out *out;

	if (!next) {
		failcode = WIRE_UNKNOWN_NEXT_PEER;
		goto fail;
	}

	if (!peer_can_add_htlc(next)) {
		log_info(next->log, "Attempt to forward HTLC but not ready (%s)",
			 peer_state_name(next->state));
		failcode = WIRE_UNKNOWN_NEXT_PEER;
		goto fail;
	}

	if (!next->owner) {
		log_info(next->log, "Attempt to forward HTLC but unowned (%s)",
			peer_state_name(next->state));
		failcode = WIRE_TEMPORARY_CHANNEL_FAILURE;
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
	if (!check_amount(hin, amt_to_forward, hin->msatoshi, fee)) {
		failcode = WIRE_FEE_INSUFFICIENT;
		goto fail;
	}

	if (!check_ctlv(hin, cltv_expiry, outgoing_cltv_value,
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
		log_debug(hin->key.peer->log,
			  "Expiry cltv %u too close to current %u + deadline %u",
			  outgoing_cltv_value,
			  get_block_height(next->ld->topology),
			  next->ld->dstate.config.deadline_blocks);
		failcode = WIRE_EXPIRY_TOO_SOON;
		goto fail;
	}

	/* Make sure daemon owns it, in case it fails. */
	out = new_htlc_out(next->owner, next, amt_to_forward,
			   outgoing_cltv_value, &hin->payment_hash,
			   next_onion, hin, NULL);
	tal_add_destructor(out, hend_subd_died);

	msg = towire_channel_offer_htlc(next, amt_to_forward,
					outgoing_cltv_value,
					payment_hash, next_onion);
	subd_req(next->owner, next->owner, take(msg), -1, 0,
		 rcvd_htlc_reply, out);
	return;

fail:
	fail_htlc(hin, failcode, NULL);
}

/* Temporary information, while we resolve the next hop */
struct gossip_resolve {
	struct short_channel_id next_channel;
	u64 amt_to_forward;
	u32 outgoing_cltv_value;
	u8 *next_onion;
	struct htlc_in *hin;
};

/* We received a resolver reply, which gives us the node_ids of the
 * channel we want to forward over */
static bool channel_resolve_reply(struct subd *gossip, const u8 *msg,
				  const int *fds, struct gossip_resolve *gr)
{
	struct pubkey *nodes, *peer_id;

	if (!fromwire_gossip_resolve_channel_reply(msg, msg, NULL, &nodes)) {
		log_broken(gossip->log,
			   "bad fromwire_gossip_resolve_channel_reply %s",
			   tal_hex(msg, msg));
		return false;
	}

	if (tal_count(nodes) == 0) {
		fail_htlc(gr->hin, WIRE_UNKNOWN_NEXT_PEER, NULL);
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

	forward_htlc(gr->hin, gr->hin->cltv_expiry, &gr->hin->payment_hash,
		     gr->amt_to_forward, gr->outgoing_cltv_value, peer_id,
		     gr->next_onion);
	tal_free(gr);
	return true;
}

static bool state_update_ok(struct peer *peer,
			    enum htlc_state oldstate, enum htlc_state newstate,
			    u64 htlc_id, const char *dir)
{
	enum htlc_state expected = oldstate + 1;

	/* We never get told about RCVD_REMOVE_HTLC or SENT_REMOVE_HTLC, so
	 * skip over those (we initialize in SENT_ADD_HTLC / RCVD_ADD_COMMIT, so
	 * those work). */
	if (expected == RCVD_REMOVE_HTLC)
		expected = RCVD_REMOVE_COMMIT;
	else if (expected == SENT_REMOVE_HTLC)
		expected = SENT_REMOVE_COMMIT;

	if (newstate != expected) {
		log_broken(peer->log, "HTLC %s %"PRIu64" invalid update %s->%s",
			   dir, htlc_id,
			   htlc_state_name(oldstate),
			   htlc_state_name(newstate));
		return false;
	}

	log_debug(peer->log, "HTLC %s %"PRIu64" %s->%s",
		  dir, htlc_id,
		  htlc_state_name(oldstate), htlc_state_name(newstate));
	return true;
}

static bool htlc_in_update_state(struct peer *peer,
				 struct htlc_in *hin,
				 enum htlc_state newstate)
{
	if (!state_update_ok(peer, hin->hstate, newstate, hin->key.id, "in"))
		return false;

	/* FIXME: db commit */
	hin->hstate = newstate;
	htlc_in_check(hin, __func__);
	return true;
}

static bool htlc_out_update_state(struct peer *peer,
				 struct htlc_out *hout,
				 enum htlc_state newstate)
{
	if (!state_update_ok(peer, hout->hstate, newstate, hout->key.id, "out"))
		return false;

	/* FIXME: db commit */
	hout->hstate = newstate;
	htlc_out_check(hout, __func__);
	return true;
}

/* Everyone is committed to this htlc of theirs */
static bool peer_accepted_htlc(struct peer *peer,
			       u64 id,
			       enum onion_type *failcode)
{
	struct htlc_in *hin;
	u8 *req;
	struct route_step *rs;
	struct onionpacket *op;
	const tal_t *tmpctx = tal_tmpctx(peer);

	hin = find_htlc_in(&peer->ld->htlcs_in, peer, id);
	if (!hin) {
		log_broken(peer->log,
			   "peer_got_revoke unknown htlc %"PRIu64, id);
		return false;
	}

	if (!htlc_in_update_state(peer, hin, RCVD_ADD_ACK_REVOCATION))
		return false;

	/* channeld tests this, so it should have set ss to zeroes. */
	op = parse_onionpacket(tmpctx, hin->onion_routing_packet,
			       sizeof(hin->onion_routing_packet));
	if (!op) {
		if (!memeqzero(&hin->shared_secret, sizeof(hin->shared_secret))){
			log_broken(peer->log,
				   "bad onion in got_revoke: %s",
				   tal_hexstr(peer, hin->onion_routing_packet,
					     sizeof(hin->onion_routing_packet)));
			tal_free(tmpctx);
			return false;
		}
		/* FIXME: could be bad version, bad key. */
		*failcode = WIRE_INVALID_ONION_VERSION;
		goto out;
	}

	/* Channeld sets this to zero if HSM won't ecdh it */
	if (memeqzero(&hin->shared_secret, sizeof(hin->shared_secret))) {
		*failcode = WIRE_INVALID_ONION_KEY;
		goto out;
	}

	/* If it's crap, not channeld's fault, just fail it */
	rs = process_onionpacket(tmpctx, op, hin->shared_secret.data,
				 hin->payment_hash.u.u8,
				 sizeof(hin->payment_hash));
	if (!rs) {
		*failcode = WIRE_INVALID_ONION_HMAC;
		goto out;
	}

	/* Unknown realm isn't a bad onion, it's a normal failure. */
	if (rs->hop_data.realm != 0) {
		*failcode = WIRE_INVALID_REALM;
		goto out;
	}

	if (rs->nextcase == ONION_FORWARD) {
		struct gossip_resolve *gr = tal(peer->ld, struct gossip_resolve);

		gr->next_onion = serialize_onionpacket(gr, rs->next);
		gr->next_channel = rs->hop_data.channel_id;
		gr->amt_to_forward = rs->hop_data.amt_forward;
		gr->outgoing_cltv_value = rs->hop_data.outgoing_cltv;
		gr->hin = hin;

		req = towire_gossip_resolve_channel_request(tmpctx,
							    &gr->next_channel);
		log_debug(peer->log, "Asking gossip to resolve channel %s",
			  type_to_string(tmpctx, struct short_channel_id,
					 &gr->next_channel));
		subd_req(hin, peer->ld->gossip, req, -1, 0,
			 channel_resolve_reply, gr);
	} else
		handle_localpay(hin, hin->cltv_expiry, &hin->payment_hash,
				rs->hop_data.amt_forward,
				rs->hop_data.outgoing_cltv);

	*failcode = 0;
out:
	log_debug(peer->log, "their htlc %"PRIu64" %s",
		  id, *failcode ? onion_type_name(*failcode) : "locked");

	tal_free(tmpctx);
	return true;
}

static bool peer_fulfilled_our_htlc(struct peer *peer,
				    const struct fulfilled_htlc *fulfilled)
{
	struct htlc_out *hout;

	hout = find_htlc_out(&peer->ld->htlcs_out, peer, fulfilled->id);
	if (!hout) {
		log_broken(peer->log,
			   "fulfilled_our_htlc unknown htlc %"PRIu64,
			   fulfilled->id);
		return false;
	}

	if (!htlc_out_update_state(peer, hout, RCVD_REMOVE_COMMIT))
		return false;

	hout->preimage = tal_dup(hout, struct preimage,
				 &fulfilled->payment_preimage);
	htlc_out_check(hout, __func__);

	/* FIXME: Save to db */

	/* They fulfilled our HTLC.  Credit them, forward immediately. */
	peer->balance[REMOTE] += hout->msatoshi;
	peer->balance[LOCAL] -= hout->msatoshi;

	if (hout->in)
		fulfill_htlc(hout->in, &fulfilled->payment_preimage);
	else
		payment_succeeded(peer->ld, hout, &fulfilled->payment_preimage);
	return true;
}

static bool peer_failed_our_htlc(struct peer *peer,
				 const struct failed_htlc *failed)
{
	struct htlc_out *hout;

	hout = find_htlc_out(&peer->ld->htlcs_out, peer, failed->id);
	if (!hout) {
		log_broken(peer->log,
			   "failed_our_htlc unknown htlc %"PRIu64,
			   failed->id);
		return false;
	}

	if (!htlc_out_update_state(peer, hout, RCVD_REMOVE_COMMIT))
		return false;

	log_debug(peer->log, "Our HTLC %"PRIu64" failed", failed->id);
	hout->failuremsg = tal_dup_arr(hout, u8, failed->failreason,
				       tal_len(failed->failreason), 0);
	htlc_out_check(hout, __func__);
	return true;
}

static void remove_htlc_in(struct peer *peer, struct htlc_in *hin)
{
	htlc_in_check(hin, __func__);
	log_debug(peer->log, "Removing in HTLC %"PRIu64" state %s",
		  hin->key.id, htlc_state_name(hin->hstate));
	tal_free(hin);
}

static void remove_htlc_out(struct peer *peer, struct htlc_out *hout)
{
	htlc_out_check(hout, __func__);
	log_debug(peer->log, "Removing out HTLC %"PRIu64" state %s",
		  hout->key.id, htlc_state_name(hout->hstate));

	/* If it's failed, now we can forward since it's completely locked-in */
	if (hout->failuremsg) {
		if (hout->in) {
			hout->in->failuremsg
				= tal_dup_arr(hout->in, u8,
					      hout->failuremsg,
					      tal_len(hout->failuremsg), 0);
			relay_htlc_failmsg(hout->in);
		} else {
			payment_failed(peer->ld, hout);
		}
	}

	tal_free(hout);
}

static bool update_in_htlc(struct peer *peer, u64 id, enum htlc_state newstate)
{
	struct htlc_in *hin;

	hin = find_htlc_in(&peer->ld->htlcs_in, peer, id);
	if (!hin) {
		log_broken(peer->log, "Can't find in HTLC %"PRIu64, id);
		return false;
	}

	if (!htlc_in_update_state(peer, hin, newstate))
		return false;

	if (newstate == SENT_REMOVE_ACK_REVOCATION)
		remove_htlc_in(peer, hin);

	return true;
}

static bool update_out_htlc(struct peer *peer, u64 id, enum htlc_state newstate)
{
	struct htlc_out *hout;

	hout = find_htlc_out(&peer->ld->htlcs_out, peer, id);
	if (!hout) {
		log_broken(peer->log, "Can't find out HTLC %"PRIu64, id);
		return false;
	}

	if (!htlc_out_update_state(peer, hout, newstate))
		return false;

	/* First transition into commitment; now it outlives peer. */
	if (newstate == SENT_ADD_COMMIT) {
		tal_del_destructor(hout, hend_subd_died);
		tal_steal(peer->ld, hout);

		/* From now onwards, penalty tx might need this */
		save_htlc_stub(peer->ld, peer, LOCAL,
			       hout->cltv_expiry,
			       &hout->payment_hash);
	} else if (newstate == RCVD_REMOVE_ACK_REVOCATION) {
		remove_htlc_out(peer, hout);
	}
	return true;
}

static bool changed_htlc(struct peer *peer,
			 const struct changed_htlc *changed)
{
	if (htlc_state_owner(changed->newstate) == LOCAL)
		return update_out_htlc(peer, changed->id, changed->newstate);
	else
		return update_in_htlc(peer, changed->id, changed->newstate);
}

int peer_sending_commitsig(struct peer *peer, const u8 *msg)
{
	u64 commitnum;
	struct changed_htlc *changed_htlcs;
	size_t i;

	if (!fromwire_channel_sending_commitsig(msg, msg, NULL,
						&commitnum,
						&changed_htlcs)) {
		log_broken(peer->log, "bad channel_sending_commitsig %s",
			   tal_hex(peer, msg));
		return -1;
	}

	for (i = 0; i < tal_count(changed_htlcs); i++) {
		if (!changed_htlc(peer, changed_htlcs + i)) {
			log_broken(peer->log,
				   "channel_sending_commitsig: update failed");
			return -1;
		}
	}

	/* Tell it we've got it, and to go ahead with commitment_signed. */
	subd_send_msg(peer->owner,
		      take(towire_channel_sending_commitsig_reply(msg)));
	return 0;
}

static void added_their_htlc(struct peer *peer,
			     const struct added_htlc *added,
			     const struct secret *shared_secret)
{
	struct htlc_in *hin;

	/* This stays around even if we fail it immediately: it *is*
	 * part of the current commitment. */
	hin = new_htlc_in(peer, peer, added->id, added->amount_msat,
			  added->cltv_expiry, &added->payment_hash,
			  shared_secret, added->onion_routing_packet);

	/* FIXME: Save to db */

	log_debug(peer->log, "Adding their HTLC %"PRIu64, added->id);
	connect_htlc_in(&peer->ld->htlcs_in, hin);

	/* Technically this can't be needed for a penalty transaction until
	 * after we send revoke_and_ack, then commit, then receive their
	 * revoke_and_ack.  But might as well record it while we have it:
	 * a few extra entries won't hurt */
	save_htlc_stub(peer->ld, peer, REMOTE, hin->cltv_expiry,
		       &hin->payment_hash);

}

/* The peer doesn't tell us this separately, but logically it's a separate
 * step to receiving commitsig */
static bool peer_sending_revocation(struct peer *peer,
				    struct added_htlc *added,
				    struct fulfilled_htlc *fulfilled,
				    struct failed_htlc *failed,
				    struct changed_htlc *changed)
{
	size_t i;

	for (i = 0; i < tal_count(added); i++) {
		if (!update_in_htlc(peer, added[i].id, SENT_ADD_REVOCATION))
			return false;
	}
	for (i = 0; i < tal_count(fulfilled); i++) {
		if (!update_out_htlc(peer, fulfilled[i].id,
				     SENT_REMOVE_REVOCATION))
			return false;
	}
	for (i = 0; i < tal_count(failed); i++) {
		if (!update_out_htlc(peer, failed[i].id, SENT_REMOVE_REVOCATION))
			return false;
	}
	for (i = 0; i < tal_count(changed); i++) {
		if (changed[i].newstate == RCVD_ADD_ACK_COMMIT) {
			if (!update_out_htlc(peer, changed[i].id,
					     SENT_ADD_ACK_REVOCATION))
				return false;
		} else {
			if (!update_in_htlc(peer, changed[i].id,
					    SENT_REMOVE_ACK_REVOCATION))
				return false;
		}
	}

	return true;
}

/* This also implies we're sending revocation */
int peer_got_commitsig(struct peer *peer, const u8 *msg)
{
	u64 commitnum;
	secp256k1_ecdsa_signature commit_sig;
	secp256k1_ecdsa_signature *htlc_sigs;
	struct added_htlc *added;
	struct secret *shared_secrets;
	struct fulfilled_htlc *fulfilled;
	struct failed_htlc *failed;
	struct changed_htlc *changed;
	size_t i;

	if (!fromwire_channel_got_commitsig(msg, msg, NULL,
					    &commitnum,
					    &commit_sig,
					    &htlc_sigs,
					    &added,
					    &shared_secrets,
					    &fulfilled,
					    &failed,
					    &changed)) {
		log_broken(peer->log, "bad fromwire_channel_got_commitsig %s",
			   tal_hex(peer, msg));
		return -1;
	}

	log_debug(peer->log,
		  "got commitsig %"PRIu64
		  ": %zu added, %zu fulfilled, %zu failed, %zu changed",
		  commitnum, tal_count(added), tal_count(fulfilled),
		  tal_count(failed), tal_count(changed));

	/* FIXME: store commit & htlc signature information. */

	/* New HTLCs */
	for (i = 0; i < tal_count(added); i++)
		added_their_htlc(peer, &added[i], &shared_secrets[i]);

	/* Save information now for fulfilled & failed HTLCs */
	for (i = 0; i < tal_count(fulfilled); i++) {
		if (!peer_fulfilled_our_htlc(peer, &fulfilled[i]))
			return -1;
	}

	for (i = 0; i < tal_count(failed); i++) {
		if (!peer_failed_our_htlc(peer, &failed[i]))
			return -1;
	}

	for (i = 0; i < tal_count(changed); i++) {
		if (!changed_htlc(peer, &changed[i])) {
			log_broken(peer->log,
				   "got_commitsig: update failed");
			return -1;
		}
	}

	/* Since we're about to send revoke, bump state again. */
	if (!peer_sending_revocation(peer, added, fulfilled, failed, changed))
		return -1;

	/* Tell it we've committed, and to go ahead with revoke. */
	msg = towire_channel_got_commitsig_reply(msg);
	subd_send_msg(peer->owner, take(msg));
	return 0;
}

/* Shuffle them over, forgetting the ancient one. */
static void update_per_commit_point(struct peer *peer,
				    const struct pubkey *per_commitment_point)
{
	peer->channel_info->their_per_commit_point
		= *peer->next_per_commitment_point;
	tal_free(peer->next_per_commitment_point);
	peer->next_per_commitment_point = tal_dup(peer, struct pubkey,
						  per_commitment_point);
}

/* FIXME: add to ccan/shachain */
static shachain_index_t shachain_next_index(const struct shachain *chain)
{
	if (chain->num_valid == 0)
		return (shachain_index_t)(UINT64_MAX >> (64 - SHACHAIN_BITS));
	else
		return chain->min_index - 1;
}

int peer_got_revoke(struct peer *peer, const u8 *msg)
{
	u64 revokenum, shachainidx;
	struct sha256 per_commitment_secret;
	struct pubkey next_per_commitment_point;
	struct changed_htlc *changed;
	enum onion_type *failcodes;
	size_t i;

	if (!fromwire_channel_got_revoke(msg, msg, NULL,
					 &revokenum, &per_commitment_secret,
					 &next_per_commitment_point,
					 &changed)) {
		log_broken(peer->log, "bad fromwire_channel_got_revoke %s",
			   tal_hex(peer, msg));
		return -1;
	}

	log_debug(peer->log,
		  "got revoke %"PRIu64": %zu changed",
		  revokenum, tal_count(changed));

	/* Save any immediate failures for after we reply. */
	failcodes = tal_arrz(msg, enum onion_type, tal_count(changed));
	for (i = 0; i < tal_count(changed); i++) {
		/* If we're doing final accept, we need to forward */
		if (changed[i].newstate == RCVD_ADD_ACK_REVOCATION) {
			if (!peer_accepted_htlc(peer, changed[i].id,
						&failcodes[i]))
				return -1;
		} else {
			if (!changed_htlc(peer, &changed[i])) {
				log_broken(peer->log,
					   "got_revoke: update failed");
				return -1;
			}
		}
	}

	if (revokenum >= (1ULL << 48)) {
		log_broken(peer->log, "got_revoke: too many txs %"PRIu64,
			   revokenum);
		return -1;
	}

	shachainidx = shachain_index(revokenum);
	/* Channeld must feed us these in order. */
	if (shachainidx != shachain_next_index(&peer->their_shachain)) {
		log_broken(peer->log, "got_revoke: bad revoke number %"PRIu64
			   " != %"PRIu64,
			   revokenum,
			   (u64)281474976710655
			   - shachain_next_index(&peer->their_shachain));
		return -1;
	}

	/* BOLT #2:
	 *
	 * A receiving node MAY fail if the `per_commitment_secret` was not
	 * generated by the protocol in [BOLT #3]
	 */
	if (!shachain_add_hash(&peer->their_shachain,
			       shachainidx, &per_commitment_secret)) {
		peer_fail(peer, "Bad per_commitment_secret %s for %"PRIu64,
			  type_to_string(msg, struct sha256,
					 &per_commitment_secret),
			  revokenum);
		return -1;
	}

	/* FIXME: Check per_commitment_secret -> per_commit_point */
	update_per_commit_point(peer, &next_per_commitment_point);

	/* FIXME: Commit shachain and next_per_commit_point to db */

	/* Tell it we've committed, and to go ahead with revoke. */
	msg = towire_channel_got_revoke_reply(msg);
	subd_send_msg(peer->owner, take(msg));

	/* Now, any HTLCs we need to immediately fail? */
	for (i = 0; i < tal_count(changed); i++) {
		struct sha256 bad_onion_sha;
		struct htlc_in *hin;

		if (!failcodes[i])
			continue;

		hin = find_htlc_in(&peer->ld->htlcs_in, peer, changed[i].id);
		sha256(&bad_onion_sha, hin->onion_routing_packet,
		       sizeof(hin->onion_routing_packet));
		fail_htlc(hin, failcodes[i], &bad_onion_sha);
	}
	return 0;
}

