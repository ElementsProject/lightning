#include <bitcoin/tx.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/cast/cast.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <channeld/gen_channel_wire.h>
#include <common/json_escaped.h>
#include <common/overflows.h>
#include <common/sphinx.h>
#include <gossipd/gen_gossip_wire.h>
#include <lightningd/chaintopology.h>
#include <lightningd/htlc_end.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/param.h>
#include <lightningd/pay.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/subd.h>
#include <onchaind/gen_onchain_wire.h>
#include <onchaind/onchain_wire.h>
#include <wallet/wallet.h>
#include <wire/gen_onion_wire.h>

static bool state_update_ok(struct channel *channel,
			    enum htlc_state oldstate, enum htlc_state newstate,
			    u64 htlc_id, const char *dir)
{
	enum htlc_state expected = oldstate + 1;

	/* We never get told about RCVD_REMOVE_HTLC, so skip over that
	 * (we initialize in SENT_ADD_HTLC / RCVD_ADD_COMMIT, so those
	 * work). */
	if (expected == RCVD_REMOVE_HTLC)
		expected = RCVD_REMOVE_COMMIT;

	if (newstate != expected) {
		channel_internal_error(channel,
				       "HTLC %s %"PRIu64" invalid update %s->%s",
				       dir, htlc_id,
				       htlc_state_name(oldstate),
				       htlc_state_name(newstate));
		return false;
	}

	log_debug(channel->log, "HTLC %s %"PRIu64" %s->%s",
		  dir, htlc_id,
		  htlc_state_name(oldstate), htlc_state_name(newstate));
	return true;
}

static bool htlc_in_update_state(struct channel *channel,
				 struct htlc_in *hin,
				 enum htlc_state newstate)
{
	if (!state_update_ok(channel, hin->hstate, newstate, hin->key.id, "in"))
		return false;

	wallet_htlc_update(channel->peer->ld->wallet,
			   hin->dbid, newstate, hin->preimage);

	hin->hstate = newstate;
	htlc_in_check(hin, __func__);
	return true;
}

static bool htlc_out_update_state(struct channel *channel,
				 struct htlc_out *hout,
				 enum htlc_state newstate)
{
	if (!state_update_ok(channel, hout->hstate, newstate, hout->key.id,
			     "out"))
		return false;

	wallet_htlc_update(channel->peer->ld->wallet, hout->dbid, newstate,
			   NULL);

	hout->hstate = newstate;
	htlc_out_check(hout, __func__);
	return true;
}

static void fail_in_htlc(struct htlc_in *hin,
			 enum onion_type failcode,
			 const u8 *failuremsg,
			 const struct short_channel_id *out_channelid)
{
	struct failed_htlc failed_htlc;
	assert(!hin->preimage);

	assert(failcode || failuremsg);
	hin->failcode = failcode;
	if (failuremsg)
		hin->failuremsg = tal_dup_arr(hin, u8, failuremsg, tal_count(failuremsg), 0);

	/* We need this set, since we send it to channeld. */
	if (hin->failcode & UPDATE)
		hin->failoutchannel = *out_channelid;
	else
		memset(&hin->failoutchannel, 0, sizeof(hin->failoutchannel));

	/* We update state now to signal it's in progress, for persistence. */
	htlc_in_update_state(hin->key.channel, hin, SENT_REMOVE_HTLC);

	/* Tell peer, if we can. */
	if (!hin->key.channel->owner)
		return;

	/* onchaind doesn't care, it can't do anything but wait */
	if (channel_on_chain(hin->key.channel))
		return;

	failed_htlc.id = hin->key.id;
	failed_htlc.failcode = hin->failcode;
	failed_htlc.failreason = cast_const(u8 *, hin->failuremsg);
	if (failed_htlc.failcode & UPDATE)
		failed_htlc.scid = &hin->failoutchannel;
	else
		failed_htlc.scid = NULL;
	subd_send_msg(hin->key.channel->owner,
		      take(towire_channel_fail_htlc(NULL, &failed_htlc)));
}

/* This is used for cases where we can immediately fail the HTLC. */
static void local_fail_htlc(struct htlc_in *hin, enum onion_type failcode,
			    const struct short_channel_id *out_channel)
{
	log_info(hin->key.channel->log, "failed htlc %"PRIu64" code 0x%04x (%s)",
		 hin->key.id, failcode, onion_type_name(failcode));

	fail_in_htlc(hin, failcode, NULL, out_channel);
}

/* localfail are for handing to the local payer if it's local. */
static void fail_out_htlc(struct htlc_out *hout, const char *localfail)
{
	htlc_out_check(hout, __func__);
	assert(hout->failcode || hout->failuremsg);
	if (hout->in) {
		fail_in_htlc(hout->in, hout->failcode, hout->failuremsg,
			     hout->key.channel->scid);
	} else {
		payment_failed(hout->key.channel->peer->ld, hout, localfail);
	}
}

/* BOLT #4:
 *
 * * `amt_to_forward`: The amount, in millisatoshis, to forward to the next
 *   receiving peer specified within the routing information.
 *
 *   This value amount MUST include the origin node's computed _fee_ for the
 *   receiving peer. When processing an incoming Sphinx packet and the HTLC
 *   message that it is encapsulated within, if the following inequality
 *   doesn't hold, then the HTLC should be rejected as it would indicate that
 *   a prior hop has deviated from the specified parameters:
 *
 *     incoming_htlc_amt - fee >= amt_to_forward
 *
 *   Where `fee` is either calculated according to the receiving peer's
 *   advertised fee schema (as described in [BOLT
 *   #7](07-routing-gossip.md#htlc-fees)) or is 0, if the processing node is
 *   the final node.
 */
static bool check_amount(struct htlc_in *hin,
			 u64 amt_to_forward, u64 amt_in_htlc, u64 fee)
{
	if (amt_in_htlc - fee >= amt_to_forward)
		return true;
	log_debug(hin->key.channel->log, "HTLC %"PRIu64" incorrect amount:"
		  " %"PRIu64" in, %"PRIu64" out, fee reqd %"PRIu64,
		  hin->key.id, amt_in_htlc, amt_to_forward, fee);
	return false;
}

/* BOLT #4:
 *
 *  * `outgoing_cltv_value`: The CLTV value that the _outgoing_ HTLC carrying
 *     the packet should have.
 *
 *        cltv_expiry - cltv_expiry_delta >= outgoing_cltv_value
 *
 *     Inclusion of this field allows a hop to both authenticate the
 *     information specified by the origin node, and the parameters of the
 *     HTLC forwarded, and ensure the origin node is using the current
 *     `cltv_expiry_delta` value.  If there is no next hop,
 *     `cltv_expiry_delta` is 0.  If the values don't correspond, then the
 *     HTLC should be failed and rejected, as this indicates that either a
 *     forwarding node has tampered with the intended HTLC values or that the
 *     origin node has an obsolete `cltv_expiry_delta` value.  The hop MUST be
 *     consistent in responding to an unexpected `outgoing_cltv_value`,
 *     whether it is the final node or not, to avoid leaking its position in
 *     the route.
 */
static bool check_cltv(struct htlc_in *hin,
		       u32 cltv_expiry, u32 outgoing_cltv_value, u32 delta)
{
	if (cltv_expiry - delta >= outgoing_cltv_value)
		return true;
	log_debug(hin->key.channel->log, "HTLC %"PRIu64" incorrect CLTV:"
		  " %u in, %u out, delta reqd %u",
		  hin->key.id, cltv_expiry, outgoing_cltv_value, delta);
	return false;
}

static void fulfill_htlc(struct htlc_in *hin, const struct preimage *preimage)
{
	u8 *msg;
	struct channel *channel = hin->key.channel;
	struct wallet *wallet = channel->peer->ld->wallet;

	hin->preimage = tal_dup(hin, struct preimage, preimage);
	htlc_in_check(hin, __func__);

	/* We update state now to signal it's in progress, for persistence. */
	htlc_in_update_state(channel, hin, SENT_REMOVE_HTLC);
	/* Update channel stats */
	wallet_channel_stats_incr_in_fulfilled(wallet,
					       channel->dbid,
					       hin->msatoshi);

	/* No owner?  We'll either send to channeld in peer_htlcs, or
	 * onchaind in onchaind_tell_fulfill. */
	if (!channel->owner) {
		log_debug(channel->log, "HTLC fulfilled, but no owner.");
		return;
	}

	if (channel_on_chain(channel)) {
		msg = towire_onchain_known_preimage(hin, preimage);
	} else {
		struct fulfilled_htlc fulfilled_htlc;
		fulfilled_htlc.id = hin->key.id;
		fulfilled_htlc.payment_preimage = *preimage;
		msg = towire_channel_fulfill_htlc(hin, &fulfilled_htlc);
	}
	subd_send_msg(channel->owner, take(msg));
}

static void handle_localpay(struct htlc_in *hin,
			    u32 cltv_expiry,
			    const struct sha256 *payment_hash,
			    u64 amt_to_forward,
			    u32 outgoing_cltv_value)
{
	enum onion_type failcode;
	struct invoice invoice;
	const struct invoice_details *details;
	struct lightningd *ld = hin->key.channel->peer->ld;

	/* BOLT #4:
	 *
	 * 1. type: 19 (`final_incorrect_htlc_amount`)
	 * 2. data:
	 *    * [`4`:`incoming_htlc_amt`]
	 *
	 * The amount in the HTLC doesn't match the value in the onion.
	 */
	if (!check_amount(hin, amt_to_forward, hin->msatoshi, 0)) {
		failcode = WIRE_FINAL_INCORRECT_HTLC_AMOUNT;
		goto fail;
	}

	/* BOLT #4:
	 *
	 * 1. type: 18 (`final_incorrect_cltv_expiry`)
	 * 2. data:
	 *    * [`4`:`cltv_expiry`]
	 *
	 * The CLTV expiry in the HTLC doesn't match the value in the onion.
	 */
	if (!check_cltv(hin, cltv_expiry, outgoing_cltv_value, 0)) {
		failcode = WIRE_FINAL_INCORRECT_CLTV_EXPIRY;
		goto fail;
	}

	if (!wallet_invoice_find_unpaid(ld->wallet, &invoice, payment_hash)) {
		failcode = WIRE_UNKNOWN_PAYMENT_HASH;
		goto fail;
	}
	details = wallet_invoice_details(tmpctx, ld->wallet, invoice);

	/* BOLT #4:
	 *
	 * An _intermediate hop_ MUST NOT, but the _final node_:
	 *...
	 *   - if the amount paid is less than the amount expected:
	 *     - MUST fail the HTLC.
	 *...
	 *   - if the amount paid is more than twice the amount expected:
	 *     - SHOULD fail the HTLC.
	 *     - SHOULD return an `incorrect_payment_amount` error.
	 *       - Note: this allows the origin node to reduce information
	 *         leakage by altering the amount while not allowing for
	 *         accidental gross overpayment.
	 */
	if (details->msatoshi != NULL && hin->msatoshi < *details->msatoshi) {
		failcode = WIRE_INCORRECT_PAYMENT_AMOUNT;
		goto fail;
	} else if (details->msatoshi != NULL && hin->msatoshi > *details->msatoshi * 2) {
		failcode = WIRE_INCORRECT_PAYMENT_AMOUNT;
		goto fail;
	}

	/* BOLT #4:
	 *
	 *   - if the `cltv_expiry` value is unreasonably near the present:
	 *     - MUST fail the HTLC.
	 *     - MUST return a `final_expiry_too_soon` error.
	 */
	if (get_block_height(ld->topology) + ld->config.cltv_final
	    > cltv_expiry) {
		log_debug(hin->key.channel->log,
			  "Expiry cltv too soon %u < %u + %u",
			  cltv_expiry,
			  get_block_height(ld->topology),
			  ld->config.cltv_final);
		failcode = WIRE_FINAL_EXPIRY_TOO_SOON;
		goto fail;
	}

	log_info(ld->log, "Resolving invoice '%s' with HTLC %"PRIu64,
		 details->label->s, hin->key.id);
	log_debug(ld->log, "%s: Actual amount %"PRIu64"msat, HTLC expiry %u",
		  details->label->s, hin->msatoshi, cltv_expiry);
	fulfill_htlc(hin, &details->r);
	wallet_invoice_resolve(ld->wallet, invoice, hin->msatoshi);

	return;

fail:
	/* Final hop never sends an UPDATE. */
	assert(!(failcode & UPDATE));
	local_fail_htlc(hin, failcode, NULL);
}

/*
 * A catchall in case outgoing peer disconnects before getting fwd.
 *
 * We could queue this and wait for it to come back, but this is simple.
 */
static void destroy_hout_subd_died(struct htlc_out *hout)
{
	log_debug(hout->key.channel->log,
		  "Failing HTLC %"PRIu64" due to peer death",
		  hout->key.id);

	hout->failcode = WIRE_TEMPORARY_CHANNEL_FAILURE;
	fail_out_htlc(hout, "Outgoing subdaemon died");
}

/* This is where channeld gives us the HTLC id, and also reports if it
 * failed immediately. */
static void rcvd_htlc_reply(struct subd *subd, const u8 *msg, const int *fds UNUSED,
			    struct htlc_out *hout)
{
	u16 failure_code;
	u8 *failurestr;
	struct lightningd *ld = subd->ld;

	if (!fromwire_channel_offer_htlc_reply(msg, msg,
					       &hout->key.id,
					       &failure_code,
					       &failurestr)) {
		channel_internal_error(subd->channel,
				       "Bad channel_offer_htlc_reply");
		tal_free(hout);
		return;
	}

	if (failure_code) {
		hout->failcode = (enum onion_type) failure_code;
		if (!hout->in) {
			char *localfail = tal_fmt(msg, "%s: %.*s",
						  onion_type_name(failure_code),
						  (int)tal_count(failurestr),
						  (const char *)failurestr);
			payment_failed(ld, hout, localfail);
		} else
			local_fail_htlc(hout->in, failure_code,
					hout->key.channel->scid);
		/* Prevent hout from being failed twice. */
		tal_del_destructor(hout, destroy_hout_subd_died);
		tal_free(hout);
		return;
	}

	if (find_htlc_out(&subd->ld->htlcs_out, hout->key.channel, hout->key.id)
	    || hout->key.id == HTLC_INVALID_ID) {
		channel_internal_error(subd->channel,
				    "Bad offer_htlc_reply HTLC id %"PRIu64
				    " is a duplicate",
				    hout->key.id);
		tal_free(hout);
		return;
	}

	/* Add it to lookup table now we know id. */
	connect_htlc_out(&subd->ld->htlcs_out, hout);

	/* When channeld includes it in commitment, we'll make it persistent. */
}

enum onion_type send_htlc_out(struct channel *out, u64 amount, u32 cltv,
			      const struct sha256 *payment_hash,
			      const u8 *onion_routing_packet,
			      struct htlc_in *in,
			      struct htlc_out **houtp)
{
	struct htlc_out *hout;
	u8 *msg;

	if (!channel_can_add_htlc(out)) {
		log_info(out->log, "Attempt to send HTLC but not ready (%s)",
			 channel_state_name(out));
		return WIRE_UNKNOWN_NEXT_PEER;
	}

	if (!out->owner) {
		log_info(out->log, "Attempt to send HTLC but unowned (%s)",
			 channel_state_name(out));
		return WIRE_TEMPORARY_CHANNEL_FAILURE;
	}

	/* Make peer's daemon own it, catch if it dies. */
	hout = new_htlc_out(out->owner, out, amount, cltv,
			    payment_hash, onion_routing_packet, in);
	tal_add_destructor(hout, destroy_hout_subd_died);

	msg = towire_channel_offer_htlc(out, amount, cltv, payment_hash,
					onion_routing_packet);
	subd_req(out->peer->ld, out->owner, take(msg), -1, 0, rcvd_htlc_reply, hout);

	if (houtp)
		*houtp = hout;
	return 0;
}

static void forward_htlc(struct htlc_in *hin,
			 u32 cltv_expiry,
			 u64 amt_to_forward,
			 u32 outgoing_cltv_value,
			 const struct pubkey *next_hop,
			 const u8 next_onion[TOTAL_PACKET_SIZE])
{
	enum onion_type failcode;
	u64 fee;
	struct lightningd *ld = hin->key.channel->peer->ld;
	struct channel *next = active_channel_by_id(ld, next_hop, NULL);

	/* Unknown peer, or peer not ready. */
	if (!next || !next->scid) {
		local_fail_htlc(hin, WIRE_UNKNOWN_NEXT_PEER, NULL);
		return;
	}

	/* BOLT #7:
	 *
	 * The origin node:
	 *   - SHOULD accept HTLCs that pay a fee equal to or greater than:
	 *     - fee_base_msat + ( amount_msat * fee_proportional_millionths / 1000000 )
	 */
	if (mul_overflows_u64(amt_to_forward,
			      ld->config.fee_per_satoshi)) {
		failcode = WIRE_FEE_INSUFFICIENT;
		goto fail;
	}
	fee = ld->config.fee_base
		+ amt_to_forward * ld->config.fee_per_satoshi / 1000000;
	if (!check_amount(hin, amt_to_forward, hin->msatoshi, fee)) {
		failcode = WIRE_FEE_INSUFFICIENT;
		goto fail;
	}

	if (!check_cltv(hin, cltv_expiry, outgoing_cltv_value,
			ld->config.cltv_expiry_delta)) {
		failcode = WIRE_INCORRECT_CLTV_EXPIRY;
		goto fail;
	}

	/* BOLT #2:
	 *
	 * An offering node:
	 *   - MUST estimate a timeout deadline for each HTLC it offers.
	 *   - MUST NOT offer an HTLC with a timeout deadline before its
	 *     `cltv_expiry`.
	 */
	/* In our case, G = 1, so we need to expire it one after it's expiration.
	 * But never offer an expired HTLC; that's dumb. */
	if (get_block_height(ld->topology) >= outgoing_cltv_value) {
		log_debug(hin->key.channel->log,
			  "Expiry cltv %u too close to current %u",
			  outgoing_cltv_value,
			  get_block_height(ld->topology));
		failcode = WIRE_EXPIRY_TOO_SOON;
		goto fail;
	}

	/* BOLT #4:
	 *
	 *   - if the `cltv_expiry` is unreasonably far in the future:
	 *     - return an `expiry_too_far` error.
	 */
	if (get_block_height(ld->topology)
	    + ld->config.locktime_max < outgoing_cltv_value) {
		log_debug(hin->key.channel->log,
			  "Expiry cltv %u too far from current %u + max %u",
			  outgoing_cltv_value,
			  get_block_height(ld->topology),
			  ld->config.locktime_max);
		failcode = WIRE_EXPIRY_TOO_FAR;
		goto fail;
	}

	failcode = send_htlc_out(next, amt_to_forward,
				 outgoing_cltv_value, &hin->payment_hash,
				 next_onion, hin, NULL);
	if (!failcode)
		return;

fail:
	local_fail_htlc(hin, failcode, next->scid);
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
static void channel_resolve_reply(struct subd *gossip, const u8 *msg,
				  const int *fds UNUSED, struct gossip_resolve *gr)
{
	struct pubkey *nodes, *peer_id;

	if (!fromwire_gossip_resolve_channel_reply(msg, msg, &nodes)) {
		log_broken(gossip->log,
			   "bad fromwire_gossip_resolve_channel_reply %s",
			   tal_hex(msg, msg));
		return;
	}

	if (tal_count(nodes) == 0) {
		local_fail_htlc(gr->hin, WIRE_UNKNOWN_NEXT_PEER, NULL);
		return;
	} else if (tal_count(nodes) != 2) {
		log_broken(gossip->log,
			   "fromwire_gossip_resolve_channel_reply has %zu nodes",
			   tal_count(nodes));
		return;
	}

	/* Get the other peer matching the id that is not us */
	if (pubkey_cmp(&nodes[0], &gossip->ld->id) == 0) {
		peer_id = &nodes[1];
	} else {
		peer_id = &nodes[0];
	}

	forward_htlc(gr->hin, gr->hin->cltv_expiry,
		     gr->amt_to_forward, gr->outgoing_cltv_value, peer_id,
		     gr->next_onion);
	tal_free(gr);
}

/* Everyone is committed to this htlc of theirs */
static bool peer_accepted_htlc(struct channel *channel,
			       u64 id,
			       enum onion_type *failcode)
{
	struct htlc_in *hin;
	u8 *req;
	struct route_step *rs;
	struct onionpacket *op;
	struct lightningd *ld = channel->peer->ld;

	hin = find_htlc_in(&ld->htlcs_in, channel, id);
	if (!hin) {
		channel_internal_error(channel,
				    "peer_got_revoke unknown htlc %"PRIu64, id);
		return false;
	}

	if (!htlc_in_update_state(channel, hin, RCVD_ADD_ACK_REVOCATION))
		return false;

#if DEVELOPER
	if (channel->peer->ignore_htlcs) {
		log_debug(channel->log, "their htlc %"PRIu64" dev_ignore_htlcs",
			  id);
		return true;
	}
#endif
	/* BOLT #2:
	 *
	 *   - SHOULD fail to route any HTLC added after it has sent `shutdown`.
	 */
	if (channel->state == CHANNELD_SHUTTING_DOWN) {
		*failcode = WIRE_PERMANENT_CHANNEL_FAILURE;
		goto out;
	}

	/* BOLT #2:
	 *
	 * A fulfilling node:
	 *   - for each HTLC it is attempting to fulfill:
	 *     - MUST estimate a fulfillment deadline.
	 *   - MUST fail (and not forward) an HTLC whose fulfillment deadline is
	 *     already past.
	 */
	/* Our deadline is half the cltv_delta we insist on, so this check is
	 * a subset of the cltv check done in handle_localpay and
	 * forward_htlc. */

	/* channeld tests this, so it should have set ss to zeroes. */
	op = parse_onionpacket(tmpctx, hin->onion_routing_packet,
			       sizeof(hin->onion_routing_packet));
	if (!op) {
		if (!memeqzero(&hin->shared_secret, sizeof(hin->shared_secret))){
			channel_internal_error(channel,
				   "bad onion in got_revoke: %s",
				   tal_hexstr(channel, hin->onion_routing_packet,
					     sizeof(hin->onion_routing_packet)));
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
		struct gossip_resolve *gr = tal(ld, struct gossip_resolve);

		gr->next_onion = serialize_onionpacket(gr, rs->next);
		gr->next_channel = rs->hop_data.channel_id;
		gr->amt_to_forward = rs->hop_data.amt_forward;
		gr->outgoing_cltv_value = rs->hop_data.outgoing_cltv;
		gr->hin = hin;

		req = towire_gossip_resolve_channel_request(tmpctx,
							    &gr->next_channel);
		log_debug(channel->log, "Asking gossip to resolve channel %s",
			  type_to_string(tmpctx, struct short_channel_id,
					 &gr->next_channel));
		subd_req(hin, ld->gossip, req, -1, 0,
			 channel_resolve_reply, gr);
	} else
		handle_localpay(hin, hin->cltv_expiry, &hin->payment_hash,
				rs->hop_data.amt_forward,
				rs->hop_data.outgoing_cltv);

	*failcode = 0;
out:
	log_debug(channel->log, "their htlc %"PRIu64" %s",
		  id, *failcode ? onion_type_name(*failcode) : "locked");

	return true;
}

static void fulfill_our_htlc_out(struct channel *channel, struct htlc_out *hout,
				 const struct preimage *preimage)
{
	struct lightningd *ld = channel->peer->ld;

	assert(!hout->preimage);
	hout->preimage = tal_dup(hout, struct preimage, preimage);
	htlc_out_check(hout, __func__);

	wallet_htlc_update(ld->wallet, hout->dbid, hout->hstate, preimage);
	/* Update channel stats */
	wallet_channel_stats_incr_out_fulfilled(ld->wallet,
						channel->dbid,
						hout->msatoshi);

	if (hout->in)
		fulfill_htlc(hout->in, preimage);
	else
		payment_succeeded(ld, hout, preimage);
}

static bool peer_fulfilled_our_htlc(struct channel *channel,
				    const struct fulfilled_htlc *fulfilled)
{
	struct lightningd *ld = channel->peer->ld;
	struct htlc_out *hout;

	hout = find_htlc_out(&ld->htlcs_out, channel, fulfilled->id);
	if (!hout) {
		channel_internal_error(channel,
				    "fulfilled_our_htlc unknown htlc %"PRIu64,
				    fulfilled->id);
		return false;
	}

	if (!htlc_out_update_state(channel, hout, RCVD_REMOVE_COMMIT))
		return false;

	fulfill_our_htlc_out(channel, hout, &fulfilled->payment_preimage);
	return true;
}

void onchain_fulfilled_htlc(struct channel *channel,
			    const struct preimage *preimage)
{
	struct htlc_out_map_iter outi;
	struct htlc_out *hout;
	struct sha256 payment_hash;
	struct lightningd *ld = channel->peer->ld;

	sha256(&payment_hash, preimage, sizeof(*preimage));

	/* FIXME: use db to look this up! */
	for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
		if (hout->key.channel != channel)
			continue;

		/* It's possible that we failed some and succeeded one,
		 * if we got multiple errors. */
		if (hout->failcode != 0 || hout->failuremsg)
			continue;

		if (!sha256_eq(&hout->payment_hash, &payment_hash))
			continue;

		/* We may have already fulfilled before going onchain, or
		 * we can fulfill onchain multiple times. */
		if (!hout->preimage)
			fulfill_our_htlc_out(channel, hout, preimage);

		/* We keep going: this is something of a leak, but onchain
		 * we have no real way of distinguishing HTLCs anyway */
	}
}

static bool peer_failed_our_htlc(struct channel *channel,
				 const struct failed_htlc *failed)
{
	struct htlc_out *hout;
	struct lightningd *ld = channel->peer->ld;

	hout = find_htlc_out(&ld->htlcs_out, channel, failed->id);
	if (!hout) {
		channel_internal_error(channel,
				    "failed_our_htlc unknown htlc %"PRIu64,
				    failed->id);
		return false;
	}

	if (!htlc_out_update_state(channel, hout, RCVD_REMOVE_COMMIT))
		return false;

	hout->failcode = failed->failcode;
	if (!failed->failcode)
		hout->failuremsg = tal_dup_arr(hout, u8, failed->failreason,
					       tal_count(failed->failreason), 0);

	else
		hout->failuremsg = NULL;

	log_debug(channel->log, "Our HTLC %"PRIu64" failed (%u)", failed->id,
		  hout->failcode);
	htlc_out_check(hout, __func__);
	return true;
}

/* FIXME: Crazy slow! */
struct htlc_out *find_htlc_out_by_ripemd(const struct channel *channel,
					 const struct ripemd160 *ripemd)
{
	struct htlc_out_map_iter outi;
	struct htlc_out *hout;
	struct lightningd *ld = channel->peer->ld;

	for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
		struct ripemd160 hash;

		if (hout->key.channel != channel)
			continue;

		ripemd160(&hash,
			  &hout->payment_hash, sizeof(hout->payment_hash));
		if (ripemd160_eq(&hash, ripemd))
			return hout;
	}
	return NULL;
}

void onchain_failed_our_htlc(const struct channel *channel,
			     const struct htlc_stub *htlc,
			     const char *why)
{
	struct lightningd *ld = channel->peer->ld;
	struct htlc_out *hout = find_htlc_out_by_ripemd(channel, &htlc->ripemd);

	/* Don't fail twice! */
	if (hout->failuremsg || hout->failcode)
		return;

	hout->failcode = WIRE_PERMANENT_CHANNEL_FAILURE;

	if (!hout->in) {
		assert(why != NULL);
		char *localfail = tal_fmt(channel, "%s: %s",
					  onion_type_name(WIRE_PERMANENT_CHANNEL_FAILURE),
					  why);
		payment_failed(ld, hout, localfail);
		tal_free(localfail);
	} else
		local_fail_htlc(hout->in, WIRE_PERMANENT_CHANNEL_FAILURE,
				hout->key.channel->scid);
}

static void remove_htlc_in(struct channel *channel, struct htlc_in *hin)
{
	htlc_in_check(hin, __func__);
	assert(hin->failuremsg || hin->preimage || hin->failcode);

	log_debug(channel->log, "Removing in HTLC %"PRIu64" state %s %s",
		  hin->key.id, htlc_state_name(hin->hstate),
		  hin->preimage ? "FULFILLED"
		  : hin->failcode ? onion_type_name(hin->failcode)
		  : "REMOTEFAIL");

	/* If we fulfilled their HTLC, credit us. */
	if (hin->preimage) {
		log_debug(channel->log, "Balance %"PRIu64" -> %"PRIu64,
			  channel->our_msatoshi,
			  channel->our_msatoshi + hin->msatoshi);
		channel->our_msatoshi += hin->msatoshi;
		if (channel->our_msatoshi > channel->msatoshi_to_us_max)
			channel->msatoshi_to_us_max = channel->our_msatoshi;
	}

	tal_free(hin);
}

static void remove_htlc_out(struct channel *channel, struct htlc_out *hout)
{
	htlc_out_check(hout, __func__);
	assert(hout->failuremsg || hout->preimage || hout->failcode);
	log_debug(channel->log, "Removing out HTLC %"PRIu64" state %s %s",
		  hout->key.id, htlc_state_name(hout->hstate),
		  hout->preimage ? "FULFILLED"
		  : hout->failcode ? onion_type_name(hout->failcode)
		  : "REMOTEFAIL");

	/* If it's failed, now we can forward since it's completely locked-in */
	if (!hout->preimage) {
		fail_out_htlc(hout, NULL);
	} else {
		/* We paid for this HTLC, so deduct balance. */
		log_debug(channel->log, "Balance %"PRIu64" -> %"PRIu64,
			  channel->our_msatoshi,
			  channel->our_msatoshi - hout->msatoshi);
		channel->our_msatoshi -= hout->msatoshi;
		if (channel->our_msatoshi < channel->msatoshi_to_us_min)
			channel->msatoshi_to_us_min = channel->our_msatoshi;
	}

	tal_free(hout);
}

static bool update_in_htlc(struct channel *channel,
			   u64 id, enum htlc_state newstate)
{
	struct htlc_in *hin;
	struct lightningd *ld = channel->peer->ld;

	hin = find_htlc_in(&ld->htlcs_in, channel, id);
	if (!hin) {
		channel_internal_error(channel, "Can't find in HTLC %"PRIu64, id);
		return false;
	}

	if (!htlc_in_update_state(channel, hin, newstate))
		return false;

	if (newstate == SENT_REMOVE_ACK_REVOCATION)
		remove_htlc_in(channel, hin);

	return true;
}

static bool update_out_htlc(struct channel *channel,
			    u64 id, enum htlc_state newstate)
{
	struct lightningd *ld = channel->peer->ld;
	struct htlc_out *hout;

	hout = find_htlc_out(&ld->htlcs_out, channel, id);
	if (!hout) {
		channel_internal_error(channel, "Can't find out HTLC %"PRIu64, id);
		return false;
	}

	if (!hout->dbid) {
		wallet_htlc_save_out(ld->wallet, channel, hout);
		/* Update channel stats */
		wallet_channel_stats_incr_out_offered(ld->wallet,
						      channel->dbid,
						      hout->msatoshi);

		/* For our own HTLCs, we commit payment to db lazily */
		if (hout->origin_htlc_id == 0)
			payment_store(ld,
				      &hout->payment_hash);
	}

	if (!htlc_out_update_state(channel, hout, newstate))
		return false;

	/* First transition into commitment; now it outlives peer. */
	if (newstate == SENT_ADD_COMMIT) {
		tal_del_destructor(hout, destroy_hout_subd_died);
		tal_steal(ld, hout);

	} else if (newstate == RCVD_REMOVE_ACK_REVOCATION) {
		remove_htlc_out(channel, hout);
	}
	return true;
}

static bool changed_htlc(struct channel *channel,
			 const struct changed_htlc *changed)
{
	if (htlc_state_owner(changed->newstate) == LOCAL)
		return update_out_htlc(channel, changed->id, changed->newstate);
	else
		return update_in_htlc(channel, changed->id, changed->newstate);
}

static bool peer_save_commitsig_received(struct channel *channel, u64 commitnum,
					 struct bitcoin_tx *tx,
					 const secp256k1_ecdsa_signature *commit_sig)
{
	if (commitnum != channel->next_index[LOCAL]) {
		channel_internal_error(channel,
			   "channel_got_commitsig: expected commitnum %"PRIu64
			   " got %"PRIu64,
			   channel->next_index[LOCAL], commitnum);
		return false;
	}

	channel->next_index[LOCAL]++;

	/* Update channel->last_sig and channel->last_tx before saving to db */
	channel_set_last_tx(channel, tx, commit_sig);

	return true;
}

static bool peer_save_commitsig_sent(struct channel *channel, u64 commitnum)
{
	struct lightningd *ld = channel->peer->ld;

	if (commitnum != channel->next_index[REMOTE]) {
		channel_internal_error(channel,
			   "channel_sent_commitsig: expected commitnum %"PRIu64
			   " got %"PRIu64,
			   channel->next_index[REMOTE], commitnum);
		return false;
	}

	channel->next_index[REMOTE]++;

	/* FIXME: Save to database, with sig and HTLCs. */
	wallet_channel_save(ld->wallet, channel);
	return true;
}

void peer_sending_commitsig(struct channel *channel, const u8 *msg)
{
	u64 commitnum;
	u32 feerate;
	struct changed_htlc *changed_htlcs;
	size_t i, maxid = 0, num_local_added = 0;
	secp256k1_ecdsa_signature commit_sig;
	secp256k1_ecdsa_signature *htlc_sigs;
	struct lightningd *ld = channel->peer->ld;

	if (!fromwire_channel_sending_commitsig(msg, msg,
						&commitnum,
						&feerate,
						&changed_htlcs,
						&commit_sig, &htlc_sigs)) {
		channel_internal_error(channel, "bad channel_sending_commitsig %s",
				       tal_hex(channel, msg));
		return;
	}

	for (i = 0; i < tal_count(changed_htlcs); i++) {
		if (!changed_htlc(channel, changed_htlcs + i)) {
			channel_internal_error(channel,
				   "channel_sending_commitsig: update failed");
			return;
		}

		/* While we're here, sanity check added ones are in
		 * ascending order. */
		if (changed_htlcs[i].newstate == SENT_ADD_COMMIT) {
			num_local_added++;
			if (changed_htlcs[i].id > maxid)
				maxid = changed_htlcs[i].id;
		}
	}

	if (num_local_added != 0) {
		if (maxid != channel->next_htlc_id + num_local_added - 1) {
			channel_internal_error(channel,
				   "channel_sending_commitsig:"
				   " Added %"PRIu64", maxid now %"PRIu64
				   " from %"PRIu64,
				   num_local_added, maxid, channel->next_htlc_id);
			return;
		}
		channel->next_htlc_id += num_local_added;
	}

	/* Update their feerate. */
	channel->channel_info.feerate_per_kw[REMOTE] = feerate;
	if (feerate > channel->max_possible_feerate)
		channel->max_possible_feerate = feerate;
	if (feerate < channel->min_possible_feerate)
		channel->min_possible_feerate = feerate;

	if (!peer_save_commitsig_sent(channel, commitnum))
		return;

	/* Last was commit. */
	channel->last_was_revoke = false;
	tal_free(channel->last_sent_commit);
	channel->last_sent_commit = tal_steal(channel, changed_htlcs);
	wallet_channel_save(ld->wallet, channel);

	/* Tell it we've got it, and to go ahead with commitment_signed. */
	subd_send_msg(channel->owner,
		      take(towire_channel_sending_commitsig_reply(msg)));
}

static bool channel_added_their_htlc(struct channel *channel,
				     const struct added_htlc *added,
				     const struct secret *shared_secret)
{
	struct lightningd *ld = channel->peer->ld;
	struct htlc_in *hin;

	/* BOLT #2:
	 *
	 *  - receiving an `amount_msat` equal to 0, OR less than its own `htlc_minimum_msat`:
	 *    - SHOULD fail the channel.
	 */
	if (added->amount_msat == 0
	    || added->amount_msat < channel->our_config.htlc_minimum_msat) {
		channel_internal_error(channel,
				    "trying to add HTLC msat %"PRIu64
				    " but minimum is %"PRIu64,
				    added->amount_msat,
				    channel->our_config.htlc_minimum_msat);
		return false;
	}

	/* This stays around even if we fail it immediately: it *is*
	 * part of the current commitment. */
	hin = new_htlc_in(channel, channel, added->id, added->amount_msat,
			  added->cltv_expiry, &added->payment_hash,
			  shared_secret, added->onion_routing_packet);

	/* Save an incoming htlc to the wallet */
	wallet_htlc_save_in(ld->wallet, channel, hin);
	/* Update channel stats */
	wallet_channel_stats_incr_in_offered(ld->wallet, channel->dbid,
					     added->amount_msat);

	log_debug(channel->log, "Adding their HTLC %"PRIu64, added->id);
	connect_htlc_in(&channel->peer->ld->htlcs_in, hin);
	return true;
}

/* The peer doesn't tell us this separately, but logically it's a separate
 * step to receiving commitsig */
static bool peer_sending_revocation(struct channel *channel,
				    struct added_htlc *added,
				    struct fulfilled_htlc *fulfilled,
				    struct failed_htlc **failed,
				    struct changed_htlc *changed)
{
	size_t i;

	for (i = 0; i < tal_count(added); i++) {
		if (!update_in_htlc(channel, added[i].id, SENT_ADD_REVOCATION))
			return false;
	}
	for (i = 0; i < tal_count(fulfilled); i++) {
		if (!update_out_htlc(channel, fulfilled[i].id,
				     SENT_REMOVE_REVOCATION))
			return false;
	}
	for (i = 0; i < tal_count(failed); i++) {
		if (!update_out_htlc(channel, failed[i]->id, SENT_REMOVE_REVOCATION))
			return false;
	}
	for (i = 0; i < tal_count(changed); i++) {
		if (changed[i].newstate == RCVD_ADD_ACK_COMMIT) {
			if (!update_out_htlc(channel, changed[i].id,
					     SENT_ADD_ACK_REVOCATION))
				return false;
		} else {
			if (!update_in_htlc(channel, changed[i].id,
					    SENT_REMOVE_ACK_REVOCATION))
				return false;
		}
	}

	channel->last_was_revoke = true;
	return true;
}

/* This also implies we're sending revocation */
void peer_got_commitsig(struct channel *channel, const u8 *msg)
{
	u64 commitnum;
	u32 feerate;
	secp256k1_ecdsa_signature commit_sig;
	secp256k1_ecdsa_signature *htlc_sigs;
	struct added_htlc *added;
	struct secret *shared_secrets;
	struct fulfilled_htlc *fulfilled;
	struct failed_htlc **failed;
	struct changed_htlc *changed;
	struct bitcoin_tx *tx;
	size_t i;
	struct lightningd *ld = channel->peer->ld;

	if (!fromwire_channel_got_commitsig(msg, msg,
					    &commitnum,
					    &feerate,
					    &commit_sig,
					    &htlc_sigs,
					    &added,
					    &shared_secrets,
					    &fulfilled,
					    &failed,
					    &changed,
					    &tx)) {
		channel_internal_error(channel,
				    "bad fromwire_channel_got_commitsig %s",
				    tal_hex(channel, msg));
		return;
	}

	log_debug(channel->log,
		  "got commitsig %"PRIu64
		  ": feerate %u, %zu added, %zu fulfilled, %zu failed, %zu changed",
		  commitnum, feerate, tal_count(added), tal_count(fulfilled),
		  tal_count(failed), tal_count(changed));

	/* New HTLCs */
	for (i = 0; i < tal_count(added); i++) {
		if (!channel_added_their_htlc(channel, &added[i], &shared_secrets[i]))
			return;
	}

	/* Save information now for fulfilled & failed HTLCs */
	for (i = 0; i < tal_count(fulfilled); i++) {
		if (!peer_fulfilled_our_htlc(channel, &fulfilled[i]))
			return;
	}

	for (i = 0; i < tal_count(failed); i++) {
		if (!peer_failed_our_htlc(channel, failed[i]))
			return;
	}

	for (i = 0; i < tal_count(changed); i++) {
		if (!changed_htlc(channel, &changed[i])) {
			channel_internal_error(channel,
					    "got_commitsig: update failed");
			return;
		}
	}

	/* Update both feerates: if we're funder, REMOTE should already be
	 * that feerate, if we're not, we're about to ACK anyway. */
	channel->channel_info.feerate_per_kw[LOCAL]
		= channel->channel_info.feerate_per_kw[REMOTE]
		= feerate;

	if (feerate > channel->max_possible_feerate)
		channel->max_possible_feerate = feerate;
	if (feerate < channel->min_possible_feerate)
		channel->min_possible_feerate = feerate;

	/* Since we're about to send revoke, bump state again. */
	if (!peer_sending_revocation(channel, added, fulfilled, failed, changed))
		return;

	if (!peer_save_commitsig_received(channel, commitnum, tx, &commit_sig))
		return;

	wallet_channel_save(ld->wallet, channel);

	tal_free(channel->last_htlc_sigs);
	channel->last_htlc_sigs = tal_steal(channel, htlc_sigs);
	wallet_htlc_sigs_save(ld->wallet, channel->dbid,
			      channel->last_htlc_sigs);

	/* Tell it we've committed, and to go ahead with revoke. */
	msg = towire_channel_got_commitsig_reply(msg);
	subd_send_msg(channel->owner, take(msg));
}

/* Shuffle them over, forgetting the ancient one. */
void update_per_commit_point(struct channel *channel,
			     const struct pubkey *per_commitment_point)
{
	struct channel_info *ci = &channel->channel_info;
	ci->old_remote_per_commit = ci->remote_per_commit;
	ci->remote_per_commit = *per_commitment_point;
}

void peer_got_revoke(struct channel *channel, const u8 *msg)
{
	u64 revokenum;
	struct secret per_commitment_secret;
	struct pubkey next_per_commitment_point;
	struct changed_htlc *changed;
	enum onion_type *failcodes;
	size_t i;
	struct lightningd *ld = channel->peer->ld;

	if (!fromwire_channel_got_revoke(msg, msg,
					 &revokenum, &per_commitment_secret,
					 &next_per_commitment_point,
					 &changed)) {
		channel_internal_error(channel, "bad fromwire_channel_got_revoke %s",
				    tal_hex(channel, msg));
		return;
	}

	log_debug(channel->log,
		  "got revoke %"PRIu64": %zu changed",
		  revokenum, tal_count(changed));

	/* Save any immediate failures for after we reply. */
	failcodes = tal_arrz(msg, enum onion_type, tal_count(changed));
	for (i = 0; i < tal_count(changed); i++) {
		/* If we're doing final accept, we need to forward */
		if (changed[i].newstate == RCVD_ADD_ACK_REVOCATION) {
			if (!peer_accepted_htlc(channel, changed[i].id,
						&failcodes[i]))
				return;
		} else {
			if (!changed_htlc(channel, &changed[i])) {
				channel_internal_error(channel,
						    "got_revoke: update failed");
				return;
			}
		}
	}

	if (revokenum >= (1ULL << 48)) {
		channel_internal_error(channel, "got_revoke: too many txs %"PRIu64,
				    revokenum);
		return;
	}

	if (revokenum != revocations_received(&channel->their_shachain.chain)) {
		channel_internal_error(channel, "got_revoke: expected %"PRIu64
				    " got %"PRIu64,
				    revocations_received(&channel->their_shachain.chain), revokenum);
		return;
	}

	/* BOLT #2:
	 *
	 *   - if the `per_commitment_secret` was not generated by the protocol
	 *     in [BOLT #3](03-transactions.md#per-commitment-secret-requirements):
	 *     - MAY fail the channel.
	 */
	if (!wallet_shachain_add_hash(ld->wallet,
				      &channel->their_shachain,
				      shachain_index(revokenum),
				      &per_commitment_secret)) {
		channel_fail_permanent(channel,
				    "Bad per_commitment_secret %s for %"PRIu64,
				    type_to_string(msg, struct secret,
						   &per_commitment_secret),
				    revokenum);
		return;
	}

	/* FIXME: Check per_commitment_secret -> per_commit_point */
	update_per_commit_point(channel, &next_per_commitment_point);

	/* Tell it we've committed, and to go ahead with revoke. */
	msg = towire_channel_got_revoke_reply(msg);
	subd_send_msg(channel->owner, take(msg));

	/* Now, any HTLCs we need to immediately fail? */
	for (i = 0; i < tal_count(changed); i++) {
		struct htlc_in *hin;

		if (!failcodes[i])
			continue;

		/* These are all errors before finding next hop. */
		assert(!(failcodes[i] & UPDATE));

		hin = find_htlc_in(&ld->htlcs_in, channel, changed[i].id);
		local_fail_htlc(hin, failcodes[i], NULL);
	}
	wallet_channel_save(ld->wallet, channel);
}

static void *tal_arr_append_(void **p, size_t size)
{
	size_t n = tal_bytelen(*p) / size;
	tal_resize_(p, size, n+1, false);
	return (char *)(*p) + n * size;
}
#define tal_arr_append(p) tal_arr_append_((void **)(p), sizeof(**(p)))

static void add_htlc(struct added_htlc **htlcs,
		     enum htlc_state **htlc_states,
		     u64 id,
		     u64 amount_msat,
		     const struct sha256 *payment_hash,
		     u32 cltv_expiry,
		     const u8 onion_routing_packet[TOTAL_PACKET_SIZE],
		     enum htlc_state state)
{
	struct added_htlc *a;
	enum htlc_state *h;

	a = tal_arr_append(htlcs);
	h = tal_arr_append(htlc_states);

	a->id = id;
	a->amount_msat = amount_msat;
	a->payment_hash = *payment_hash;
	a->cltv_expiry = cltv_expiry;
	memcpy(a->onion_routing_packet, onion_routing_packet,
	       sizeof(a->onion_routing_packet));
	*h = state;
}

static void add_fulfill(u64 id, enum side side,
			const struct preimage *payment_preimage,
			struct fulfilled_htlc **fulfilled_htlcs,
			enum side **fulfilled_sides)
{
	struct fulfilled_htlc *f;
	enum side *s;

	f = tal_arr_append(fulfilled_htlcs);
	s = tal_arr_append(fulfilled_sides);
	f->id = id;
	f->payment_preimage = *payment_preimage;
	*s = side;
}

static void add_fail(u64 id, enum side side,
		     enum onion_type failcode,
		     const struct short_channel_id *failing_channel,
		     const u8 *failuremsg,
		     const struct failed_htlc ***failed_htlcs,
		     enum side **failed_sides)
{
	struct failed_htlc **f;
	enum side *s;

	f = tal_arr_append(failed_htlcs);
	s = tal_arr_append(failed_sides);

	*f = tal(*failed_htlcs, struct failed_htlc);
	(*f)->id = id;
	(*f)->failcode = failcode;
	if (failcode & UPDATE) {
		assert(failing_channel);
		(*f)->scid = tal_dup(*f, struct short_channel_id,
				     failing_channel);
	} else
		(*f)->scid = NULL;

	if (failuremsg)
		(*f)->failreason
			= tal_dup_arr(*f, u8, failuremsg, tal_count(failuremsg), 0);
	else
		(*f)->failreason = NULL;
	*s = side;
}

/* FIXME: Load direct from db. */
void peer_htlcs(const tal_t *ctx,
		const struct channel *channel,
		struct added_htlc **htlcs,
		enum htlc_state **htlc_states,
		struct fulfilled_htlc **fulfilled_htlcs,
		enum side **fulfilled_sides,
		const struct failed_htlc ***failed_htlcs,
		enum side **failed_sides)
{
	struct htlc_in_map_iter ini;
	struct htlc_out_map_iter outi;
	struct htlc_in *hin;
	struct htlc_out *hout;
	struct lightningd *ld = channel->peer->ld;

	*htlcs = tal_arr(ctx, struct added_htlc, 0);
	*htlc_states = tal_arr(ctx, enum htlc_state, 0);
	*fulfilled_htlcs = tal_arr(ctx, struct fulfilled_htlc, 0);
	*fulfilled_sides = tal_arr(ctx, enum side, 0);
	*failed_htlcs = tal_arr(ctx, const struct failed_htlc *, 0);
	*failed_sides = tal_arr(ctx, enum side, 0);

	for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
		if (hin->key.channel != channel)
			continue;

		add_htlc(htlcs, htlc_states,
			 hin->key.id, hin->msatoshi, &hin->payment_hash,
			 hin->cltv_expiry, hin->onion_routing_packet,
			 hin->hstate);

		if (hin->failuremsg || hin->failcode)
			add_fail(hin->key.id, REMOTE, hin->failcode,
				 &hin->failoutchannel,
				 hin->failuremsg, failed_htlcs, failed_sides);
		if (hin->preimage)
			add_fulfill(hin->key.id, REMOTE, hin->preimage,
				    fulfilled_htlcs, fulfilled_sides);
	}

	for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
		if (hout->key.channel != channel)
			continue;

		add_htlc(htlcs, htlc_states,
			 hout->key.id, hout->msatoshi, &hout->payment_hash,
			 hout->cltv_expiry, hout->onion_routing_packet,
			 hout->hstate);

		if (hout->failuremsg || hout->failcode)
			add_fail(hout->key.id, LOCAL, hout->failcode,
				 hout->key.channel->scid,
				 hout->failuremsg, failed_htlcs, failed_sides);
		if (hout->preimage)
			add_fulfill(hout->key.id, LOCAL, hout->preimage,
				    fulfilled_htlcs, fulfilled_sides);
	}
}

/* If channel is NULL, free them all (for shutdown) */
void free_htlcs(struct lightningd *ld, const struct channel *channel)
{
	struct htlc_out_map_iter outi;
	struct htlc_out *hout;
	struct htlc_in_map_iter ini;
	struct htlc_in *hin;
	bool deleted;

	/* FIXME: Implement check_htlcs to ensure no dangling hout->in ptrs! */

	do {
		deleted = false;
		for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
		     hout;
		     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
			if (channel && hout->key.channel != channel)
				continue;
			tal_free(hout);
			deleted = true;
		}

		for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
		     hin;
		     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
			if (channel && hin->key.channel != channel)
				continue;
			tal_free(hin);
			deleted = true;
		}
		/* Can skip over elements due to iterating while deleting. */
	} while (deleted);
}

/* BOLT #2:
 *
 * 2. the deadline for offered HTLCs: the deadline after which the channel has
 *    to be failed and timed out on-chain. This is `G` blocks after the HTLC's
 *    `cltv_expiry`: 1 block is reasonable.
 */
static u32 htlc_out_deadline(const struct htlc_out *hout)
{
	return hout->cltv_expiry + 1;
}

/* BOLT #2:
 *
 * 3. the deadline for received HTLCs this node has fulfilled: the deadline
 * after which the channel has to be failed and the HTLC fulfilled on-chain
 * before its `cltv_expiry`. See steps 4-7 above, which imply a deadline of
 * `2R+G+S` blocks before `cltv_expiry`: 7 blocks is reasonable.
 */
/* We approximate this, by using half the cltv_expiry_delta (3R+2G+2S),
 * rounded up. */
static u32 htlc_in_deadline(const struct lightningd *ld,
			    const struct htlc_in *hin)
{
	return hin->cltv_expiry - (ld->config.cltv_expiry_delta + 1)/2;
}

void htlcs_notify_new_block(struct lightningd *ld, u32 height)
{
	bool removed;

	/* BOLT #2:
	 *
	 *   - if an HTLC which it offered is in either node's current
	 *   commitment transaction, AND is past this timeout deadline:
	 *     - MUST fail the channel.
	 */
	/* FIXME: use db to look this up in one go (earliest deadline per-peer) */
	do {
		struct htlc_out *hout;
		struct htlc_out_map_iter outi;

		removed = false;

		for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
		     hout;
		     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
			/* Not timed out yet? */
			if (height < htlc_out_deadline(hout))
				continue;

			/* Peer on chain already? */
			if (channel_on_chain(hout->key.channel))
				continue;

			/* Peer already failed, or we hit it? */
			if (hout->key.channel->error)
				continue;

			channel_fail_permanent(hout->key.channel,
					    "Offered HTLC %"PRIu64
					    " %s cltv %u hit deadline",
					    hout->key.id,
					    htlc_state_name(hout->hstate),
					    hout->cltv_expiry);
			removed = true;
		}
	/* Iteration while removing is safe, but can skip entries! */
	} while (removed);


	/* BOLT #2:
	 *
	 *   - for each HTLC it is attempting to fulfill:
	 *     - MUST estimate a fulfillment deadline.
	 *...
	 *   - if an HTLC it has fulfilled is in either node's current commitment
	 *   transaction, AND is past this fulfillment deadline:
	 *     - MUST fail the connection.
	 */
	do {
		struct htlc_in *hin;
		struct htlc_in_map_iter ini;

		removed = false;

		for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
		     hin;
		     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
			struct channel *channel = hin->key.channel;

			/* Not fulfilled?  If overdue, that's their problem... */
			if (!hin->preimage)
				continue;

			/* Not timed out yet? */
			if (height < htlc_in_deadline(ld, hin))
				continue;

			/* Peer on chain already? */
			if (channel_on_chain(channel))
				continue;

			/* Peer already failed, or we hit it? */
			if (channel->error)
				continue;

			channel_fail_permanent(channel,
					    "Fulfilled HTLC %"PRIu64
					    " %s cltv %u hit deadline",
					    hin->key.id,
					    htlc_state_name(hin->hstate),
					    hin->cltv_expiry);
			removed = true;
		}
	/* Iteration while removing is safe, but can skip entries! */
	} while (removed);
}

void notify_feerate_change(struct lightningd *ld)
{
	struct peer *peer;

	/* FIXME: We should notify onchaind about NORMAL fee change in case
	 * it's going to generate more txs. */
	list_for_each(&ld->peers, peer, list) {
		struct channel *channel = peer_active_channel(peer);
		u8 *msg;

		if (!channel || !channel_fees_can_change(channel))
			continue;

		/* FIXME: We choose not to drop to chain if we can't contact
		 * peer.  We *could* do so, however. */
		if (!channel->owner)
			continue;

		msg = towire_channel_feerates(channel,
					      get_feerate(ld->topology,
							  FEERATE_IMMEDIATE),
					      feerate_min(ld),
					      feerate_max(ld));
		subd_send_msg(channel->owner, take(msg));
	}
}

#if DEVELOPER
static void json_dev_ignore_htlcs(struct command *cmd, const char *buffer,
				  const jsmntok_t *params)
{
	struct pubkey peerid;
	struct peer *peer;
	bool ignore;

	if (!param(cmd, buffer, params,
		   p_req("id", json_tok_pubkey, &peerid),
		   p_req("ignore", json_tok_bool, &ignore),
		   NULL))
		return;

	peer = peer_by_id(cmd->ld, &peerid);
	if (!peer) {
		command_fail(cmd, LIGHTNINGD,
			     "Could not find channel with that peer");
		return;
	}
	peer->ignore_htlcs = ignore;

	command_success(cmd, null_response(cmd));
}

static const struct json_command dev_ignore_htlcs = {
	"dev-ignore-htlcs", json_dev_ignore_htlcs,
	"Set ignoring incoming HTLCs for peer {id} to {ignore}", false,
	"Set/unset ignoring of all incoming HTLCs.  For testing only."
};
AUTODATA(json_command, &dev_ignore_htlcs);
#endif /* DEVELOPER */
