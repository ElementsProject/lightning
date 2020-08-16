#include <bitcoin/preimage.h>
#include <bitcoin/tx.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/cast/cast.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <channeld/gen_channel_wire.h>
#include <common/blinding.h>
#include <common/coin_mvt.h>
#include <common/ecdh.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/onion.h>
#include <common/onionreply.h>
#include <common/overflows.h>
#include <common/param.h>
#include <common/sphinx.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <gossipd/gen_gossip_wire.h>
#include <hsmd/gen_hsm_wire.h>
#include <lightningd/chaintopology.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/htlc_end.h>
#include <lightningd/htlc_set.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
#include <lightningd/pay.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/plugin_hook.h>
#include <lightningd/subd.h>
#include <onchaind/gen_onchain_wire.h>
#include <onchaind/onchain_wire.h>
#include <wallet/wallet.h>
#include <wire/gen_onion_wire.h>
#include <wire/wire_sync.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

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
			   hin->dbid, newstate, hin->preimage,
			   hin->badonion, hin->failonion, NULL,
			   hin->we_filled);

	hin->hstate = newstate;
	return true;
}

static bool htlc_out_update_state(struct channel *channel,
				 struct htlc_out *hout,
				 enum htlc_state newstate)
{
	if (!state_update_ok(channel, hout->hstate, newstate, hout->key.id,
			     "out"))
		return false;

	bool we_filled = false;
	wallet_htlc_update(channel->peer->ld->wallet, hout->dbid, newstate,
			   hout->preimage, 0, hout->failonion,
			   hout->failmsg, &we_filled);

	hout->hstate = newstate;
	return true;
}

static struct failed_htlc *mk_failed_htlc_badonion(const tal_t *ctx,
						   const struct htlc_in *hin,
						   enum onion_type badonion)
{
	struct failed_htlc *f = tal(ctx, struct failed_htlc);

	f->id = hin->key.id;
	f->onion = NULL;
	f->badonion = badonion;
	f->sha256_of_onion = tal(f, struct sha256);
	sha256(f->sha256_of_onion, hin->onion_routing_packet,
	       sizeof(hin->onion_routing_packet));
	return f;
}

static struct failed_htlc *mk_failed_htlc(const tal_t *ctx,
					  const struct htlc_in *hin,
					  const struct onionreply *failonion)
{
	struct failed_htlc *f = tal(ctx, struct failed_htlc);

	f->id = hin->key.id;
	f->sha256_of_onion = NULL;
	f->badonion = 0;
	/* Wrap onion error */
	f->onion = wrap_onionreply(f, hin->shared_secret, failonion);

	return f;
}

static void tell_channeld_htlc_failed(const struct htlc_in *hin,
				      const struct failed_htlc *failed_htlc)
{
	/* Tell peer, if we can. */
	if (!hin->key.channel->owner)
		return;

	/* onchaind doesn't care, it can't do anything but wait */
	if (channel_on_chain(hin->key.channel))
		return;

	subd_send_msg(hin->key.channel->owner,
		      take(towire_channel_fail_htlc(NULL, failed_htlc)));
}

struct failmsg_update_cbdata {
	struct htlc_in *hin;
	const u8 *failmsg_needs_update;
};

static void failmsg_update_reply(struct subd *gossipd,
				 const u8 *msg,
				 const int *unused,
				 struct failmsg_update_cbdata *cbdata)
{
	u8 *failmsg;
	u8 *stripped_update;
	struct failed_htlc *failed_htlc;

	/* This can happen because channel never got properly announced.*/
	if (!fromwire_gossip_get_stripped_cupdate_reply(msg, msg,
							&stripped_update)
	    || !tal_count(stripped_update)) {
		failmsg = towire_temporary_node_failure(NULL);
	} else {
		/* End of failmsg is two zero bytes (empty update). */
		assert(tal_count(cbdata->failmsg_needs_update) >= 2);
		failmsg = tal_dup_arr(msg, u8,
				      cbdata->failmsg_needs_update,
				      tal_count(cbdata->failmsg_needs_update)-2,
				      0);
		towire_u16(&failmsg, tal_count(stripped_update));
		towire_u8_array(&failmsg,
				stripped_update, tal_count(stripped_update));
	}

	/* Now we replace dummy failonion with this real one */
	tal_free(cbdata->hin->failonion);
	cbdata->hin->failonion
		= create_onionreply(cbdata->hin,
				    cbdata->hin->shared_secret,
				    failmsg);

	bool we_filled = false;
	wallet_htlc_update(gossipd->ld->wallet,
			   cbdata->hin->dbid, cbdata->hin->hstate,
			   cbdata->hin->preimage,
			   cbdata->hin->badonion,
			   cbdata->hin->failonion, NULL, &we_filled);

	failed_htlc = mk_failed_htlc(tmpctx,
				     cbdata->hin, cbdata->hin->failonion);
	tell_channeld_htlc_failed(cbdata->hin, failed_htlc);
}

static void fail_in_htlc(struct htlc_in *hin,
			 const struct onionreply *failonion TAKES)
{
	struct failed_htlc *failed_htlc;
	assert(!hin->preimage);

	hin->failonion = dup_onionreply(hin, failonion);

	/* We update state now to signal it's in progress, for persistence. */
	htlc_in_update_state(hin->key.channel, hin, SENT_REMOVE_HTLC);
	htlc_in_check(hin, __func__);

#if EXPERIMENTAL_FEATURES
	/* In a blinded path, all failures become invalid_onion_blinding */
	if (hin->blinding) {
		failed_htlc = mk_failed_htlc_badonion(tmpctx, hin,
						      WIRE_INVALID_ONION_BLINDING);
	} else
#endif
		failed_htlc = mk_failed_htlc(tmpctx, hin, hin->failonion);

	tell_channeld_htlc_failed(hin, failed_htlc);
}

/* Immediately fail HTLC with a BADONION code */
static void local_fail_in_htlc_badonion(struct htlc_in *hin,
					enum onion_type badonion)
{
	struct failed_htlc *failed_htlc;
	assert(!hin->preimage);

	assert(badonion & BADONION);
	hin->badonion = badonion;
	/* We update state now to signal it's in progress, for persistence. */
	htlc_in_update_state(hin->key.channel, hin, SENT_REMOVE_HTLC);
	htlc_in_check(hin, __func__);

	failed_htlc = mk_failed_htlc_badonion(tmpctx, hin, badonion);
	tell_channeld_htlc_failed(hin, failed_htlc);
}

/* This is used for cases where we can immediately fail the HTLC. */
void local_fail_in_htlc(struct htlc_in *hin, const u8 *failmsg TAKES)
{
	struct onionreply *failonion = create_onionreply(NULL,
							 hin->shared_secret,
							 failmsg);

	if (taken(failmsg))
		tal_free(failmsg);

	fail_in_htlc(hin, take(failonion));
}

/* This is used for cases where we can immediately fail the HTLC, but
 * need to append a channel_update. */
void local_fail_in_htlc_needs_update(struct htlc_in *hin,
				     const u8 *failmsg_needs_update TAKES,
				     const struct short_channel_id *failmsg_scid)
{
	struct failmsg_update_cbdata *cbdata;

	/* To avoid the state where we have no failonion, we use a temporary
	 * one, and update once we get the reply from gossipd. */
	assert(!hin->preimage);

	hin->failonion = create_onionreply(hin,
					   hin->shared_secret,
					   towire_temporary_node_failure(tmpctx));
	/* We update state now to signal it's in progress, for persistence. */
	htlc_in_update_state(hin->key.channel, hin, SENT_REMOVE_HTLC);
	htlc_in_check(hin, __func__);

	cbdata = tal(hin, struct failmsg_update_cbdata);
	cbdata->hin = hin;
	cbdata->failmsg_needs_update
		= tal_dup_talarr(cbdata, u8, failmsg_needs_update);
	subd_req(cbdata, hin->key.channel->peer->ld->gossip,
		 take(towire_gossip_get_stripped_cupdate(NULL, failmsg_scid)),
		 -1, 0, failmsg_update_reply, cbdata);
}

/* Helper to create (common) WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS */
const u8 *failmsg_incorrect_or_unknown_(const tal_t *ctx,
					struct lightningd *ld,
					const struct htlc_in *hin,
					const char *file, int line)
{
	log_debug(ld->log, "WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS: %s:%u",
		  file, line);
	return towire_incorrect_or_unknown_payment_details(
		ctx, hin->msat,
		get_block_height(ld->topology));
}

/* localfail are for handing to the local payer if it's local. */
static void fail_out_htlc(struct htlc_out *hout,
			  const char *localfail,
			  const u8 *failmsg_needs_update TAKES)
{
	htlc_out_check(hout, __func__);
	assert(hout->failmsg || hout->failonion);

	if (hout->am_origin) {
		payment_failed(hout->key.channel->peer->ld, hout, localfail,
			       failmsg_needs_update);
		if (taken(failmsg_needs_update))
			tal_free(failmsg_needs_update);
	} else if (hout->in) {
		if (failmsg_needs_update) {
			local_fail_in_htlc_needs_update(hout->in,
							failmsg_needs_update,
							hout->key.channel->scid);
		} else {
			const struct onionreply *failonion;

			/* If we have an onion, simply copy it. */
			if (hout->failonion)
				failonion = hout->failonion;
			/* Otherwise, we need to onionize this local error. */
			else
				failonion = create_onionreply(hout,
							      hout->in->shared_secret,
							      hout->failmsg);
			fail_in_htlc(hout->in, failonion);
		}
	}
}

/* BOLT #4:
 *
 * * `amt_to_forward`: The amount, in millisatoshis, to forward to the next
 *   receiving peer specified within the routing information.
 *
 *   For non-final nodes, this value amount MUST include the origin node's computed _fee_ for the
 *   receiving peer. When processing an incoming Sphinx packet and the HTLC
 *   message that it is encapsulated within, if the following inequality
 *   doesn't hold, then the HTLC should be rejected as it would indicate that
 *   a prior hop has deviated from the specified parameters:
 *
 *     incoming_htlc_amt - fee >= amt_to_forward
 *
 *   Where `fee` is calculated according to the receiving peer's
 *   advertised fee schema (as described in [BOLT
 *   #7](07-routing-gossip.md#htlc-fees)).
 */
static bool check_fwd_amount(struct htlc_in *hin,
			     struct amount_msat amt_to_forward,
			     struct amount_msat amt_in_htlc,
			     struct amount_msat fee)
{
	struct amount_msat fwd;

	if (amount_msat_sub(&fwd, amt_in_htlc, fee)
	    && amount_msat_greater_eq(fwd, amt_to_forward))
		return true;

	log_debug(hin->key.channel->log, "HTLC %"PRIu64" incorrect amount:"
		  " %s in, %s out, fee reqd %s",
		  hin->key.id,
		  type_to_string(tmpctx, struct amount_msat, &amt_in_htlc),
		  type_to_string(tmpctx, struct amount_msat, &amt_to_forward),
		  type_to_string(tmpctx, struct amount_msat, &fee));
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
	if (delta < cltv_expiry && cltv_expiry - delta >= outgoing_cltv_value)
		return true;
	log_debug(hin->key.channel->log, "HTLC %"PRIu64" incorrect CLTV:"
		  " %u in, %u out, delta reqd %u",
		  hin->key.id, cltv_expiry, outgoing_cltv_value, delta);
	return false;
}

void fulfill_htlc(struct htlc_in *hin, const struct preimage *preimage)
{
	u8 *msg;
	struct channel *channel = hin->key.channel;
	struct wallet *wallet = channel->peer->ld->wallet;

	if (hin->hstate != RCVD_ADD_ACK_REVOCATION) {
		log_debug(channel->log,
			  "HTLC fulfilled, but not ready any more (%s).",
			  htlc_state_name(hin->hstate));
		return;
	}

	hin->preimage = tal_dup(hin, struct preimage, preimage);

	/* We update state now to signal it's in progress, for persistence. */
	htlc_in_update_state(channel, hin, SENT_REMOVE_HTLC);

	htlc_in_check(hin, __func__);

	/* Update channel stats */
	wallet_channel_stats_incr_in_fulfilled(wallet,
					       channel->dbid,
					       hin->msat);

	/* No owner?  We'll either send to channeld in peer_htlcs, or
	 * onchaind in onchaind_tell_fulfill. */
	if (!channel->owner) {
		log_debug(channel->log, "HTLC fulfilled, but no owner.");
		return;
	}

	if (channel_on_chain(channel)) {
		msg = towire_onchain_known_preimage(hin, preimage, false);
	} else {
		struct fulfilled_htlc fulfilled_htlc;
		fulfilled_htlc.id = hin->key.id;
		fulfilled_htlc.payment_preimage = *preimage;
		msg = towire_channel_fulfill_htlc(hin, &fulfilled_htlc);
	}
	subd_send_msg(channel->owner, take(msg));
}

static void handle_localpay(struct htlc_in *hin,
			    struct amount_msat amt_to_forward,
			    u32 outgoing_cltv_value,
			    struct amount_msat total_msat,
			    const struct secret *payment_secret)
{
	const u8 *failmsg;
	struct lightningd *ld = hin->key.channel->peer->ld;

	/* BOLT #4:
	 *
	 * For the final node, this value MUST be exactly equal to the
	 * incoming htlc amount, otherwise the HTLC should be rejected.
	 */
	if (!amount_msat_eq(amt_to_forward, hin->msat)) {
		log_debug(hin->key.channel->log,
			  "HTLC %"PRIu64" final incorrect amount:"
			  " %s in, %s expected",
			  hin->key.id,
			  type_to_string(tmpctx, struct amount_msat, &hin->msat),
			  type_to_string(tmpctx, struct amount_msat,
					 &amt_to_forward));
		/* BOLT #4:
		 *
		 * 1. type: 19 (`final_incorrect_htlc_amount`)
		 * 2. data:
		 *    * [`u64`:`incoming_htlc_amt`]
		 *
		 * The amount in the HTLC doesn't match the value in the onion.
		 */
		failmsg = towire_final_incorrect_htlc_amount(NULL, hin->msat);
		goto fail;
	}

	/* BOLT #4:
	 *
	 * 1. type: 18 (`final_incorrect_cltv_expiry`)
	 * 2. data:
	 *    * [`u32`:`cltv_expiry`]
	 *
	 * The CLTV expiry in the HTLC doesn't match the value in the onion.
	 */
	if (!check_cltv(hin, hin->cltv_expiry, outgoing_cltv_value, 0)) {
		failmsg = towire_final_incorrect_cltv_expiry(NULL,
							     hin->cltv_expiry);
		goto fail;
	}

	/* BOLT #4:
	 *
	 *   - if the `cltv_expiry` value is unreasonably near the present:
	 *     - MUST fail the HTLC.
	 *     - MUST return an `incorrect_or_unknown_payment_details` error.
	 */
	if (get_block_height(ld->topology) + ld->config.cltv_final
	    > hin->cltv_expiry) {
		log_debug(hin->key.channel->log,
			  "Expiry cltv too soon %u < %u + %u",
			  hin->cltv_expiry,
			  get_block_height(ld->topology),
			  ld->config.cltv_final);
		failmsg = failmsg_incorrect_or_unknown(NULL, ld, hin);
		goto fail;
	}

	htlc_set_add(ld, hin, total_msat, payment_secret);
	return;

fail:
	local_fail_in_htlc(hin, take(failmsg));
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

	/* This isn't really used, except as sanity check */
	hout->failmsg = towire_temporary_node_failure(hout);

	/* Assign a temporary state (we're about to free it!) so checks
	 * are happy that it has a failure message */
	assert(hout->hstate == SENT_ADD_HTLC);
	hout->hstate = RCVD_REMOVE_HTLC;

	fail_out_htlc(hout, "Outgoing subdaemon died",
		      take(towire_temporary_channel_failure(NULL, NULL)));
}

/* This is where channeld gives us the HTLC id, and also reports if it
 * failed immediately. */
static void rcvd_htlc_reply(struct subd *subd, const u8 *msg, const int *fds UNUSED,
			    struct htlc_out *hout)
{
	u8 *failmsg;
	char *failurestr;
	struct lightningd *ld = subd->ld;

	if (!fromwire_channel_offer_htlc_reply(msg, msg,
					       &hout->key.id,
					       &failmsg,
					       &failurestr)) {
		channel_internal_error(subd->channel,
				       "Bad channel_offer_htlc_reply");
		tal_free(hout);
		return;
	}

	if (tal_count(failmsg)) {
		hout->failmsg = tal_steal(hout, failmsg);
		if (hout->am_origin) {
			char *localfail = tal_fmt(msg, "%s: %s",
						  onion_type_name(fromwire_peektype(failmsg)),
						  failurestr);
			payment_failed(ld, hout, localfail, NULL);

		} else if (hout->in) {
			struct onionreply *failonion;

			failonion = create_onionreply(hout,
						      hout->in->shared_secret,
						      hout->failmsg);
			fail_in_htlc(hout->in, failonion);

			/* here we haven't called connect_htlc_out(),
			 * so set htlc field with NULL */
			wallet_forwarded_payment_add(ld->wallet,
					 hout->in, NULL, NULL,
					 FORWARD_LOCAL_FAILED,
						     fromwire_peektype(hout->failmsg));
		}

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

static void htlc_offer_timeout(struct channel *channel)
{
	/* Unset this in case we reconnect and start again. */
	channel->htlc_timeout = NULL;

	/* If owner died, we should already be taken care of. */
	if (!channel->owner || channel->state != CHANNELD_NORMAL)
		return;

	log_unusual(channel->owner->log,
		    "Adding HTLC too slow: killing connection");
	tal_free(channel->owner);
	channel_set_billboard(channel, false,
			      "Adding HTLC timed out: killed connection");
}

/* Returns failmsg, or NULL on success. */
const u8 *send_htlc_out(const tal_t *ctx,
			struct channel *out,
			struct amount_msat amount, u32 cltv,
			const struct sha256 *payment_hash,
			const struct pubkey *blinding,
			u64 partid,
			const u8 *onion_routing_packet,
			struct htlc_in *in,
			struct htlc_out **houtp,
			bool *needs_update_appended)
{
	u8 *msg;

	*houtp = NULL;
	*needs_update_appended = false;

	if (!channel_can_add_htlc(out)) {
		log_info(out->log, "Attempt to send HTLC but not ready (%s)",
			 channel_state_name(out));
		return towire_unknown_next_peer(ctx);
	}

	if (!out->owner) {
		log_info(out->log, "Attempt to send HTLC but unowned (%s)",
			 channel_state_name(out));
		*needs_update_appended = true;
		return towire_temporary_channel_failure(ctx, NULL);
	}

	if (!topology_synced(out->peer->ld->topology)) {
		log_info(out->log, "Attempt to send HTLC but still syncing"
			 " with bitcoin network");
		return towire_temporary_node_failure(ctx);
	}

	/* Make peer's daemon own it, catch if it dies. */
	*houtp = new_htlc_out(out->owner, out, amount, cltv,
			      payment_hash, onion_routing_packet,
			      blinding, in == NULL,
			      partid, in);
	tal_add_destructor(*houtp, destroy_hout_subd_died);

	/* Give channel 30 seconds to commit (first) htlc. */
	if (!out->htlc_timeout && !IFDEV(out->peer->ld->dev_no_htlc_timeout, 0))
		out->htlc_timeout = new_reltimer(out->peer->ld->timers,
						 out, time_from_sec(30),
						 htlc_offer_timeout,
						 out);
	msg = towire_channel_offer_htlc(out, amount, cltv, payment_hash,
					onion_routing_packet, blinding);
	subd_req(out->peer->ld, out->owner, take(msg), -1, 0, rcvd_htlc_reply,
		 *houtp);

	return NULL;
}

static void forward_htlc(struct htlc_in *hin,
			 u32 cltv_expiry,
			 struct amount_msat amt_to_forward,
			 u32 outgoing_cltv_value,
			 const struct short_channel_id *scid,
			 const u8 next_onion[TOTAL_PACKET_SIZE],
			 const struct pubkey *next_blinding)
{
	const u8 *failmsg;
	struct amount_msat fee;
	struct lightningd *ld = hin->key.channel->peer->ld;
	struct channel *next = active_channel_by_scid(ld, scid);
	struct htlc_out *hout = NULL;
	bool needs_update_appended;

	/* Unknown peer, or peer not ready. */
	if (!next || !next->scid) {
		local_fail_in_htlc(hin, take(towire_unknown_next_peer(NULL)));
		wallet_forwarded_payment_add(hin->key.channel->peer->ld->wallet,
					 hin, next ? next->scid : NULL, NULL,
					 FORWARD_LOCAL_FAILED,
					 WIRE_UNKNOWN_NEXT_PEER);
		return;
	}

	/* BOLT #7:
	 *
	 * The origin node:
	 *   - SHOULD accept HTLCs that pay a fee equal to or greater than:
	 *     - fee_base_msat + ( amount_to_forward * fee_proportional_millionths / 1000000 )
	 */
	if (!amount_msat_fee(&fee, amt_to_forward,
				next->feerate_base,
				next->feerate_ppm)) {
		log_broken(ld->log, "Fee overflow forwarding %s!",
			   type_to_string(tmpctx, struct amount_msat,
					  &amt_to_forward));
		needs_update_appended = true;
		failmsg = towire_fee_insufficient(tmpctx, hin->msat, NULL);
		goto fail;
	}
	if (!check_fwd_amount(hin, amt_to_forward, hin->msat, fee)) {
		needs_update_appended = true;
		failmsg = towire_fee_insufficient(tmpctx, hin->msat, NULL);
		goto fail;
	}

	if (!check_cltv(hin, cltv_expiry, outgoing_cltv_value,
			ld->config.cltv_expiry_delta)) {
		needs_update_appended = true;
		failmsg = towire_incorrect_cltv_expiry(tmpctx, cltv_expiry,
						       NULL);
		goto fail;
	}

	if (amount_msat_greater(amt_to_forward,
				chainparams->max_payment)) {
		/* ENOWUMBO! */
		needs_update_appended = false;
		failmsg = towire_required_channel_feature_missing(tmpctx);
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
		needs_update_appended = true;
		failmsg = towire_expiry_too_soon(tmpctx, NULL);
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
		needs_update_appended = false;
		failmsg = towire_expiry_too_far(tmpctx);
		goto fail;
	}

	failmsg = send_htlc_out(tmpctx, next, amt_to_forward,
				outgoing_cltv_value, &hin->payment_hash,
				next_blinding, 0, next_onion, hin,
				&hout, &needs_update_appended);
	if (!failmsg)
		return;

fail:
	if (needs_update_appended)
		local_fail_in_htlc_needs_update(hin, failmsg, next->scid);
	else
		local_fail_in_htlc(hin, failmsg);
	wallet_forwarded_payment_add(ld->wallet,
				 hin, next->scid, hout,
				 FORWARD_LOCAL_FAILED,
				 fromwire_peektype(failmsg));
}

/**
 * Data passed to the plugin, and as the context for the hook callback
 */
struct htlc_accepted_hook_payload {
	struct route_step *route_step;
	/* NULL if it couldn't be parsed! */
	struct onion_payload *payload;
	struct htlc_in *hin;
	struct channel *channel;
	struct lightningd *ld;
	struct pubkey *next_blinding;
	u8 *next_onion;
	u64 failtlvtype;
	size_t failtlvpos;
};

/* We only handle the simplest cases here */
static u8 *convert_failcode(const tal_t *ctx,
			    struct lightningd *ld,
			    unsigned int failure_code)
{
	switch (failure_code) {
	case WIRE_INVALID_REALM:
		return towire_invalid_realm(ctx);
	case WIRE_TEMPORARY_NODE_FAILURE:
		return towire_temporary_node_failure(ctx);
	case WIRE_PERMANENT_NODE_FAILURE:
		return towire_permanent_node_failure(ctx);
	case WIRE_REQUIRED_NODE_FEATURE_MISSING:
		return towire_required_node_feature_missing(ctx);
	case WIRE_CHANNEL_DISABLED:
		return towire_channel_disabled(ctx);
	case WIRE_PERMANENT_CHANNEL_FAILURE:
		return towire_permanent_channel_failure(ctx);
	case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
		return towire_required_channel_feature_missing(ctx);
	case WIRE_UNKNOWN_NEXT_PEER:
		return towire_unknown_next_peer(ctx);
	default:
		log_broken(ld->log,
			   "htlc_accepted_hook plugin returned failure_code %u,"
			   " turning to WIRE_TEMPORARY_NODE_FAILURE",
			   failure_code);
		return towire_temporary_node_failure(ctx);
	}
}

static void
htlc_accepted_hook_try_resolve(struct htlc_accepted_hook_payload *request,
			       struct preimage *payment_preimage)
{
	struct sha256 payment_hash;
	struct htlc_in *hin = request->hin;
	u8 *unknown_details;
	/* Verify that the provided secret hashes to what we need. */
	sha256(&payment_hash, payment_preimage, sizeof(struct preimage));

	if (!sha256_eq(&payment_hash, &hin->payment_hash)) {
		log_broken(
		    request->channel->log,
		    "Plugin returned a preimage (sha256(%s) = %s) that doesn't "
		    "match the HTLC hash (%s) it tries to resolve.",
		    type_to_string(tmpctx, struct preimage, payment_preimage),
		    type_to_string(tmpctx, struct sha256, &payment_hash),
		    type_to_string(tmpctx, struct sha256, &hin->payment_hash));

		unknown_details = tal_arr(NULL, u8, 0);
		towire_u16(&unknown_details, 0x400f);
		local_fail_in_htlc(hin, take(unknown_details));
	} else {
		hin->we_filled = tal(hin, bool);
		*hin->we_filled = true;
		fulfill_htlc(hin, payment_preimage);
	}
}

static u8 *prepend_length(const tal_t *ctx, const u8 *payload TAKES)
{
	u8 buf[BIGSIZE_MAX_LEN], *ret;
	size_t len;

	len = bigsize_put(buf, tal_bytelen(payload));
	ret = tal_arr(ctx, u8, len + tal_bytelen(payload));
	memcpy(ret, buf, len);
	memcpy(ret + len, payload, tal_bytelen(payload));
	if (taken(payload))
		tal_free(payload);
	return ret;
}

/**
 * Callback when a plugin answers to the htlc_accepted hook
 */
static bool htlc_accepted_hook_deserialize(struct htlc_accepted_hook_payload *request,
					   const char *buffer,
					   const jsmntok_t *toks)
{
	struct route_step *rs = request->route_step;
	struct htlc_in *hin = request->hin;
	struct lightningd *ld = request->ld;
	struct preimage payment_preimage;
	const jsmntok_t *resulttok, *paykeytok, *payloadtok;
	u8 *payload;

	if (!toks || !buffer)
		return true;

	resulttok = json_get_member(buffer, toks, "result");

	/* If the result is "continue" we can just return NULL since
	 * this is the default behavior for this hook anyway */
	if (!resulttok) {
		fatal("Plugin return value does not contain 'result' key %s",
		      json_strdup(tmpctx, buffer, toks));
	}

	payloadtok = json_get_member(buffer, toks, "payload");
	if (payloadtok) {
		payload = json_tok_bin_from_hex(rs, buffer, payloadtok);
		if (!payload)
			fatal("Bad payload for htlc_accepted"
			      " hook: %.*s",
			      payloadtok->end - payloadtok->start,
			      buffer + payloadtok->start);
		tal_free(request->payload);
		tal_free(rs->raw_payload);

		rs->raw_payload = prepend_length(rs, take(payload));
		request->payload = onion_decode(request, rs,
						hin->blinding, &hin->blinding_ss,
						&request->failtlvtype,
						&request->failtlvpos);

	} else
		payload = NULL;

	if (json_tok_streq(buffer, resulttok, "continue")) {
		return true;
	}

	if (json_tok_streq(buffer, resulttok, "fail")) {
		u8 *failmsg;
		const jsmntok_t *failmsgtok, *failcodetok;

		failmsgtok = json_get_member(buffer, toks, "failure_message");
		if (failmsgtok) {
			failmsg = json_tok_bin_from_hex(NULL, buffer,
							failmsgtok);
			if (!failmsg)
				fatal("Bad failure_message for htlc_accepted"
				      " hook: %.*s",
				      failmsgtok->end - failmsgtok->start,
				      buffer + failmsgtok->start);
		} else if (deprecated_apis
			   && (failcodetok = json_get_member(buffer, toks,
							     "failure_code"))) {
			unsigned int failcode;
			if (!json_to_number(buffer, failcodetok, &failcode))
				fatal("Bad failure_code for htlc_accepted"
				      " hook: %.*s",
				      failcodetok->end
				      - failcodetok->start,
				      buffer + failcodetok->start);
			failmsg = convert_failcode(NULL, ld, failcode);
		} else
			failmsg = towire_temporary_node_failure(NULL);
		local_fail_in_htlc(hin, take(failmsg));
		return false;
	} else if (json_tok_streq(buffer, resulttok, "resolve")) {
		paykeytok = json_get_member(buffer, toks, "payment_key");
		if (!paykeytok)
			fatal(
			    "Plugin did not specify a 'payment_key' in return "
			    "value to the htlc_accepted hook: %s",
			    json_strdup(tmpctx, buffer, resulttok));

		if (!json_to_preimage(buffer, paykeytok, &payment_preimage))
			fatal("Plugin specified an invalid 'payment_key': %s",
			      json_tok_full(buffer, resulttok));
		htlc_accepted_hook_try_resolve(request, &payment_preimage);
		return false;
	} else {
		fatal("Plugin responded with an unknown result to the "
		      "htlc_accepted hook: %s",
		      json_strdup(tmpctx, buffer, resulttok));
	}
}

static void htlc_accepted_hook_serialize(struct htlc_accepted_hook_payload *p,
					 struct json_stream *s)
{
	const struct route_step *rs = p->route_step;
	const struct htlc_in *hin = p->hin;
	s32 expiry = hin->cltv_expiry, blockheight = p->ld->topology->tip->height;
	json_object_start(s, "onion");

	json_add_hex_talarr(s, "payload", rs->raw_payload);
	if (p->payload) {
		switch (p->payload->type) {
		case ONION_V0_PAYLOAD:
			if (deprecated_apis) {
				json_object_start(s, "per_hop_v0");
				json_add_string(s, "realm", "00");
				json_add_short_channel_id(s, "short_channel_id",
							  p->payload->forward_channel);
				json_add_amount_msat_only(s, "forward_amount",
							  p->payload->amt_to_forward);
				json_add_u64(s, "outgoing_cltv_value",
					     p->payload->outgoing_cltv);
				json_object_end(s);
			}
			json_add_string(s, "type", "legacy");
			break;

		case ONION_TLV_PAYLOAD:
			json_add_string(s, "type", "tlv");
			break;
		}

		if (p->payload->forward_channel)
			json_add_short_channel_id(s, "short_channel_id",
						  p->payload->forward_channel);
		json_add_amount_msat_only(s, "forward_amount",
					  p->payload->amt_to_forward);
		json_add_u32(s, "outgoing_cltv_value", p->payload->outgoing_cltv);
		/* These are specified together in TLV, so only print total_msat
		 * if payment_secret set (ie. modern, and final hop) */
		if (p->payload->payment_secret) {
			json_add_amount_msat_only(s, "total_msat",
						  *p->payload->total_msat);
			json_add_secret(s, "payment_secret",
					p->payload->payment_secret);
		}
	}
	json_add_hex_talarr(s, "next_onion", p->next_onion);
	json_add_secret(s, "shared_secret", hin->shared_secret);
	json_object_end(s);

	json_object_start(s, "htlc");
	json_add_amount_msat_only(s, "amount", hin->msat);
	json_add_u32(s, "cltv_expiry", expiry);
	json_add_s32(s, "cltv_expiry_relative", expiry - blockheight);
	json_add_sha256(s, "payment_hash", &hin->payment_hash);
	json_object_end(s);
}

/**
 * Callback when a plugin answers to the htlc_accepted hook
 */
static void
htlc_accepted_hook_final(struct htlc_accepted_hook_payload *request STEALS)
{
	struct route_step *rs = request->route_step;
	struct htlc_in *hin = request->hin;
	struct channel *channel = request->channel;

	/* *Now* we barf if it failed to decode */
	if (!request->payload) {
		log_debug(channel->log,
			  "Failing HTLC because of an invalid payload");
		local_fail_in_htlc(hin,
				   take(towire_invalid_onion_payload(
						NULL, request->failtlvtype,
						request->failtlvpos)));
	} else if (rs->nextcase == ONION_FORWARD) {
		forward_htlc(hin, hin->cltv_expiry,
			     request->payload->amt_to_forward,
			     request->payload->outgoing_cltv,
			     request->payload->forward_channel,
			     serialize_onionpacket(tmpctx, rs->next),
			     request->next_blinding);
	} else
		handle_localpay(hin,
				request->payload->amt_to_forward,
				request->payload->outgoing_cltv,
				*request->payload->total_msat,
				request->payload->payment_secret);

	tal_free(request);
}

REGISTER_PLUGIN_HOOK(htlc_accepted,
		     htlc_accepted_hook_deserialize,
		     htlc_accepted_hook_final,
		     htlc_accepted_hook_serialize,
		     struct htlc_accepted_hook_payload *);

/* Apply tweak to ephemeral key if blinding is non-NULL, then do ECDH */
static bool ecdh_maybe_blinding(const struct pubkey *ephemeral_key,
				const struct pubkey *blinding,
				const struct secret *blinding_ss,
				struct secret *ss)
{
	struct pubkey point = *ephemeral_key;

#if EXPERIMENTAL_FEATURES
	if (blinding) {
		struct secret hmac;

		/* b(i) = HMAC256("blinded_node_id", ss(i)) * k(i) */
		subkey_from_hmac("blinded_node_id", blinding_ss, &hmac);

		/* We instead tweak the *ephemeral* key from the onion and use
		 * our normal privkey: since hsmd knows only how to ECDH with
		 * our real key */
		if (secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
						  &point.pubkey,
						  hmac.data) != 1) {
			return false;
		}
	}
#endif /* EXPERIMENTAL_FEATURES */
	ecdh(&point, ss);
	return true;
}

/**
 * Everyone is committed to this htlc of theirs
 *
 * @param ctx: context for failmsg, if any.
 * @param channel: The channel this HTLC was accepted from.
 * @param id: the ID of the HTLC we accepted
 * @param replay: Are we loading from the database and therefore should not
 *        perform the transition to RCVD_ADD_ACK_REVOCATION?
 * @param[out] badonion: Set non-zero if the onion was bad.
 * @param[out] failmsg: If there was some other error.
 *
 * If this returns false, exactly one of @badonion or @failmsg is set.
 */
static bool peer_accepted_htlc(const tal_t *ctx,
			       struct channel *channel, u64 id,
			       bool replay,
			       enum onion_type *badonion,
			       u8 **failmsg)
{
	struct htlc_in *hin;
	struct route_step *rs;
	struct onionpacket op;
	struct lightningd *ld = channel->peer->ld;
	struct htlc_accepted_hook_payload *hook_payload;

	*failmsg = NULL;
	*badonion = 0;

	hin = find_htlc_in(&ld->htlcs_in, channel, id);
	if (!hin) {
		channel_internal_error(channel,
				    "peer_got_revoke unknown htlc %"PRIu64, id);
		*failmsg = towire_temporary_node_failure(ctx);
		goto fail;
	}

	if (!replay && !htlc_in_update_state(channel, hin, RCVD_ADD_ACK_REVOCATION)) {
		*failmsg = towire_temporary_node_failure(ctx);
		goto fail;
	}

	htlc_in_check(hin, __func__);

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
		*failmsg = towire_permanent_channel_failure(ctx);
		log_debug(channel->log,
			  "Rejecting their htlc %"PRIu64
			  " since we're shutting down",
			  id);
		goto fail;
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

	*badonion = parse_onionpacket(hin->onion_routing_packet,
				      sizeof(hin->onion_routing_packet),
				      &op);
	if (*badonion) {
		log_debug(channel->log,
			  "Rejecting their htlc %"PRIu64
			  " since onion is unparsable %s",
			  id, onion_type_name(*badonion));
		/* Now we can fail it. */
		goto fail;
	}

	rs = process_onionpacket(tmpctx, &op, hin->shared_secret,
				 hin->payment_hash.u.u8,
				 sizeof(hin->payment_hash), true);
	if (!rs) {
		*badonion = WIRE_INVALID_ONION_HMAC;
		log_debug(channel->log,
			  "Rejecting their htlc %"PRIu64
			  " since onion is unprocessable %s ss=%s",
			  id, onion_type_name(*badonion),
			  type_to_string(tmpctx, struct secret, hin->shared_secret));
		goto fail;
	}

	hook_payload = tal(NULL, struct htlc_accepted_hook_payload);

	hook_payload->route_step = tal_steal(hook_payload, rs);
	hook_payload->payload = onion_decode(hook_payload, rs,
					     hin->blinding, &hin->blinding_ss,
					     &hook_payload->failtlvtype,
					     &hook_payload->failtlvpos);
	hook_payload->ld = ld;
	hook_payload->hin = hin;
	hook_payload->channel = channel;
	hook_payload->next_onion = serialize_onionpacket(hook_payload, rs->next);

#if EXPERIMENTAL_FEATURES
	/* We could have blinding from hin or from inside onion. */
	if (hook_payload->payload && hook_payload->payload->blinding) {
		struct sha256 sha;
		blinding_hash_e_and_ss(hook_payload->payload->blinding,
				       &hook_payload->payload->blinding_ss,
				       &sha);
		hook_payload->next_blinding = tal(hook_payload, struct pubkey);
		blinding_next_pubkey(hook_payload->payload->blinding, &sha,
				     hook_payload->next_blinding);
	} else
#endif
		hook_payload->next_blinding = NULL;

	plugin_hook_call_htlc_accepted(ld, hook_payload);

	/* Falling through here is ok, after all the HTLC locked */
	return true;

fail:
#if EXPERIMENTAL_FEATURES
	/* In a blinded path, *all* failures are "invalid_onion_blinding" */
	if (hin->blinding) {
		*failmsg = tal_free(*failmsg);
		*badonion = WIRE_INVALID_ONION_BLINDING;
	}
#endif
	return false;
}

static void fulfill_our_htlc_out(struct channel *channel, struct htlc_out *hout,
				 const struct preimage *preimage)
{
	struct lightningd *ld = channel->peer->ld;
	bool we_filled = false;

	assert(!hout->preimage);
	hout->preimage = tal_dup(hout, struct preimage, preimage);
	htlc_out_check(hout, __func__);

	wallet_htlc_update(ld->wallet, hout->dbid, hout->hstate,
			   hout->preimage, 0, hout->failonion,
			   hout->failmsg, &we_filled);
	/* Update channel stats */
	wallet_channel_stats_incr_out_fulfilled(ld->wallet,
						channel->dbid,
						hout->msat);

	if (hout->am_origin)
		payment_succeeded(ld, hout, preimage);
	else if (hout->in) {
		fulfill_htlc(hout->in, preimage);
		wallet_forwarded_payment_add(ld->wallet, hout->in,
					     hout->key.channel->scid, hout,
					     FORWARD_SETTLED, 0);
	}
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
		if (hout->failmsg || hout->failonion)
			continue;

		if (!sha256_eq(&hout->payment_hash, &payment_hash))
			continue;

		/* We may have already fulfilled before going onchain, or
		 * we can fulfill onchain multiple times. */
		if (!hout->preimage) {
			/* Force state to something which allows a preimage */
			hout->hstate = RCVD_REMOVE_HTLC;
			fulfill_our_htlc_out(channel, hout, preimage);
		}

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

	if (failed->sha256_of_onion) {
		struct sha256 our_sha256_of_onion;
		u8 *failmsg;

		/* BOLT #2:
		 *
		 *   - if the `sha256_of_onion` in `update_fail_malformed_htlc`
		 *     doesn't match the onion it sent:
		 *    - MAY retry or choose an alternate error response.
		 */
		sha256(&our_sha256_of_onion, hout->onion_routing_packet,
		       sizeof(hout->onion_routing_packet));
		if (!sha256_eq(failed->sha256_of_onion, &our_sha256_of_onion))
			log_unusual(channel->log,
				    "update_fail_malformed_htlc for bad onion"
				       " for htlc with id %"PRIu64".",
				    hout->key.id);

		/* BOLT #2:
		 *
		 * - otherwise, a receiving node which has an outgoing HTLC
		 *   canceled by `update_fail_malformed_htlc`:
		 *
		 * - MUST return an error in the `update_fail_htlc`
		 *   sent to the link which originally sent the HTLC, using the
		 *   `failure_code` given and setting the data to
		 *   `sha256_of_onion`.
		 */
		/* All badonion codes are the same form, so we make them
		 * manually, which covers any unknown cases too.  Grep fodder:
		 * towire_invalid_onion_version, towire_invalid_onion_hmac,
		 * towire_invalid_onion_key. */
		failmsg = tal_arr(hout, u8, 0);
		towire_u16(&failmsg, failed->badonion);
		towire_sha256(&failmsg, failed->sha256_of_onion);
		hout->failmsg = failmsg;
	} else {
		hout->failonion = dup_onionreply(hout, failed->onion);
	}

	log_debug(channel->log, "Our HTLC %"PRIu64" failed (%u)", failed->id,
		  fromwire_peektype(hout->failmsg));
	htlc_out_check(hout, __func__);

	if (hout->in)
		wallet_forwarded_payment_add(ld->wallet, hout->in,
					     channel->scid,
					     hout, FORWARD_FAILED,
					     hout->failmsg
					     ? fromwire_peektype(hout->failmsg)
					     : 0);

	return true;
}

void onchain_failed_our_htlc(const struct channel *channel,
			     const struct htlc_stub *htlc,
			     const char *why)
{
	struct lightningd *ld = channel->peer->ld;
	struct htlc_out *hout;

	hout = find_htlc_out(&ld->htlcs_out, channel, htlc->id);
	if (!hout)
		return;

	/* Don't fail twice (or if already succeeded)! */
	if (hout->failonion || hout->failmsg || hout->preimage)
		return;

	hout->failmsg = towire_permanent_channel_failure(hout);

	/* Force state to something which expects a failure, and save to db */
	hout->hstate = RCVD_REMOVE_HTLC;
	htlc_out_check(hout, __func__);

	bool we_filled = false;
	wallet_htlc_update(ld->wallet, hout->dbid, hout->hstate,
			   hout->preimage, 0, hout->failonion,
			   hout->failmsg, &we_filled);

	if (hout->am_origin) {
		assert(why != NULL);
		char *localfail = tal_fmt(channel, "%s: %s",
					  onion_type_name(WIRE_PERMANENT_CHANNEL_FAILURE),
					  why);
		payment_failed(ld, hout, localfail, NULL);
		tal_free(localfail);
	} else if (hout->in) {
		local_fail_in_htlc(hout->in,
				   take(towire_permanent_channel_failure(NULL)));
		wallet_forwarded_payment_add(hout->key.channel->peer->ld->wallet,
					 hout->in, channel->scid, hout,
					 FORWARD_LOCAL_FAILED,
					 hout->failmsg
					 ? fromwire_peektype(hout->failmsg)
					 : 0);
	}
}

static void remove_htlc_in(struct channel *channel, struct htlc_in *hin)
{
	htlc_in_check(hin, __func__);
	assert(hin->failonion || hin->preimage || hin->badonion);

	log_debug(channel->log, "Removing in HTLC %"PRIu64" state %s %s",
		  hin->key.id, htlc_state_name(hin->hstate),
		  hin->preimage ? "FULFILLED"
		  : hin->badonion ? onion_type_name(hin->badonion)
		  : "REMOTEFAIL");

	/* If we fulfilled their HTLC, credit us. */
	if (hin->preimage) {
		struct amount_msat oldamt = channel->our_msat;
		const struct channel_coin_mvt *mvt;

		if (!amount_msat_add(&channel->our_msat, channel->our_msat,
				     hin->msat)) {
			channel_internal_error(channel,
					       "Overflow our_msat %s + HTLC %s",
					       type_to_string(tmpctx,
							      struct amount_msat,
							      &channel->our_msat),
					       type_to_string(tmpctx,
							      struct amount_msat,
							      &hin->msat));
		}
		log_debug(channel->log, "Balance %s -> %s",
			  type_to_string(tmpctx, struct amount_msat, &oldamt),
			  type_to_string(tmpctx, struct amount_msat,
					 &channel->our_msat));
		if (amount_msat_greater(channel->our_msat,
					channel->msat_to_us_max))
			channel->msat_to_us_max = channel->our_msat;

		/* Coins have definitively moved, log a movement */
		if (hin->we_filled)
			mvt = new_channel_mvt_invoice_hin(hin, hin, channel);
		else
			mvt = new_channel_mvt_routed_hin(hin, hin, channel);

		notify_channel_mvt(channel->peer->ld, mvt);
	}

	tal_free(hin);
}

static void remove_htlc_out(struct channel *channel, struct htlc_out *hout)
{
	htlc_out_check(hout, __func__);
	assert(hout->failonion || hout->preimage || hout->failmsg);
	log_debug(channel->log, "Removing out HTLC %"PRIu64" state %s %s",
		  hout->key.id, htlc_state_name(hout->hstate),
		  hout->preimage ? "FULFILLED"
		  : hout->failmsg ? onion_type_name(fromwire_peektype(hout->failmsg))
		  : "REMOTEFAIL");

	/* If it's failed, now we can forward since it's completely locked-in */
	if (!hout->preimage) {
		fail_out_htlc(hout, NULL, NULL);
	} else {
		const struct channel_coin_mvt *mvt;
		struct amount_msat oldamt = channel->our_msat;
		/* We paid for this HTLC, so deduct balance. */
		if (!amount_msat_sub(&channel->our_msat, channel->our_msat,
				     hout->msat)) {
			channel_internal_error(channel,
					       "Underflow our_msat %s - HTLC %s",
					       type_to_string(tmpctx,
							      struct amount_msat,
							      &channel->our_msat),
					       type_to_string(tmpctx,
							      struct amount_msat,
							      &hout->msat));
		}

		log_debug(channel->log, "Balance %s -> %s",
			  type_to_string(tmpctx, struct amount_msat, &oldamt),
			  type_to_string(tmpctx, struct amount_msat,
					 &channel->our_msat));
		if (amount_msat_less(channel->our_msat, channel->msat_to_us_min))
			channel->msat_to_us_min = channel->our_msat;

		/* Coins have definitively moved, log a movement */
		if (hout->am_origin)
			mvt = new_channel_mvt_invoice_hout(hout, hout, channel);
		else
			mvt = new_channel_mvt_routed_hout(hout, hout, channel);

		notify_channel_mvt(channel->peer->ld, mvt);
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

	htlc_in_check(hin, __func__);
	if (newstate == SENT_REMOVE_ACK_REVOCATION)
		remove_htlc_in(channel, hin);

	return true;
}

static bool update_out_htlc(struct channel *channel,
			    u64 id, enum htlc_state newstate)
{
	struct lightningd *ld = channel->peer->ld;
	struct htlc_out *hout;
	struct wallet_payment *payment;

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
						      hout->msat);

		if (hout->in) {
			wallet_forwarded_payment_add(ld->wallet, hout->in,
						     channel->scid, hout,
						     FORWARD_OFFERED, 0);
		}

		/* For our own HTLCs, we commit payment to db lazily */
		if (hout->am_origin) {
			payment = wallet_payment_by_hash(tmpctx, ld->wallet,
							 &hout->payment_hash,
							 hout->partid);
			assert(payment);
			payment_store(ld, take(payment));
		}
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

/* FIXME: This should be a complete check, not just a sanity check.
 * Perhaps that means we need a cookie from the HSM? */
static bool valid_commitment_tx(struct channel *channel,
				const struct bitcoin_tx *tx)
{
	/* We've had past issues where all outputs are trimmed. */
	if (tx->wtx->num_outputs == 0) {
		channel_internal_error(channel,
				       "channel_got_commitsig: zero output tx! %s",
				       type_to_string(tmpctx, struct bitcoin_tx, tx));
		return false;
	}
	return true;
}

static bool peer_save_commitsig_received(struct channel *channel, u64 commitnum,
					 struct bitcoin_tx *tx,
					 const struct bitcoin_signature *commit_sig)
{
	if (commitnum != channel->next_index[LOCAL]) {
		channel_internal_error(channel,
			   "channel_got_commitsig: expected commitnum %"PRIu64
			   " got %"PRIu64,
			   channel->next_index[LOCAL], commitnum);
		return false;
	}

	/* Basic sanity check */
	if (!valid_commitment_tx(channel, tx))
		return false;

	channel->next_index[LOCAL]++;

	/* Update channel->last_sig and channel->last_tx before saving to db */
	channel_set_last_tx(channel, tx, commit_sig, TX_CHANNEL_UNILATERAL);

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

static void adjust_channel_feerate_bounds(struct channel *channel, u32 feerate)
{
	if (feerate > channel->max_possible_feerate)
		channel->max_possible_feerate = feerate;
	if (feerate < channel->min_possible_feerate)
		channel->min_possible_feerate = feerate;
}

void peer_sending_commitsig(struct channel *channel, const u8 *msg)
{
	u64 commitnum;
	struct fee_states *fee_states;
	struct changed_htlc *changed_htlcs;
	size_t i, maxid = 0, num_local_added = 0;
	struct bitcoin_signature commit_sig;
	secp256k1_ecdsa_signature *htlc_sigs;
	struct lightningd *ld = channel->peer->ld;
	struct penalty_base *pbase;

	channel->htlc_timeout = tal_free(channel->htlc_timeout);

	if (!fromwire_channel_sending_commitsig(msg, msg,
						&commitnum,
						&pbase,
						&fee_states,
						&changed_htlcs,
						&commit_sig, &htlc_sigs)
	    || !fee_states_valid(fee_states, channel->opener)) {
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

	/* FIXME: We could detect if this changed, and adjust bounds and write
	 * it to db iff it has. */
	tal_free(channel->channel_info.fee_states);
	channel->channel_info.fee_states = tal_steal(channel, fee_states);
	adjust_channel_feerate_bounds(channel,
				      get_feerate(fee_states,
						  channel->opener,
						  REMOTE));

	if (!peer_save_commitsig_sent(channel, commitnum))
		return;

	/* Last was commit. */
	channel->last_was_revoke = false;
	tal_free(channel->last_sent_commit);
	channel->last_sent_commit = tal_steal(channel, changed_htlcs);
	wallet_channel_save(ld->wallet, channel);

	if (pbase)
		wallet_penalty_base_add(ld->wallet, channel->dbid, pbase);

	/* Tell it we've got it, and to go ahead with commitment_signed. */
	subd_send_msg(channel->owner,
		      take(towire_channel_sending_commitsig_reply(msg)));
}

static bool channel_added_their_htlc(struct channel *channel,
				     const struct added_htlc *added)
{
	struct lightningd *ld = channel->peer->ld;
	struct htlc_in *hin;
	struct secret shared_secret;
	struct onionpacket op;
	enum onion_type failcode;

	/* BOLT #2:
	 *
	 *  - receiving an `amount_msat` equal to 0, OR less than its own `htlc_minimum_msat`:
	 *    - SHOULD fail the channel.
	 */
	if (amount_msat_eq(added->amount, AMOUNT_MSAT(0))
	    || amount_msat_less(added->amount, channel->our_config.htlc_minimum)) {
		channel_internal_error(channel,
				       "trying to add HTLC amount %s"
				       " but minimum is %s",
				       type_to_string(tmpctx,
						      struct amount_msat,
						      &added->amount),
				       type_to_string(tmpctx,
						      struct amount_msat,
						      &channel->our_config.htlc_minimum));
		return false;
	}

	/* Do the work of extracting shared secret now if possible. */
	/* FIXME: We do this *again* in peer_accepted_htlc! */
	failcode = parse_onionpacket(added->onion_routing_packet,
				     sizeof(added->onion_routing_packet),
				     &op);
	if (!failcode) {
		if (!ecdh_maybe_blinding(&op.ephemeralkey,
					 added->blinding, &added->blinding_ss,
					 &shared_secret)) {
			log_debug(channel->log, "htlc %"PRIu64
				  ": can't tweak pubkey", added->id);
			return false;
		}
	}

	/* This stays around even if we fail it immediately: it *is*
	 * part of the current commitment. */
	hin = new_htlc_in(channel, channel, added->id, added->amount,
			  added->cltv_expiry, &added->payment_hash,
			  failcode ? NULL : &shared_secret,
			  added->blinding, &added->blinding_ss,
			  added->onion_routing_packet);

	/* Save an incoming htlc to the wallet */
	wallet_htlc_save_in(ld->wallet, channel, hin);
	/* Update channel stats */
	wallet_channel_stats_incr_in_offered(ld->wallet, channel->dbid,
					     added->amount);

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

struct deferred_commitsig {
	struct channel *channel;
	const u8 *msg;
};

static void retry_deferred_commitsig(struct chain_topology *topo,
				     struct deferred_commitsig *d)
{
	peer_got_commitsig(d->channel, d->msg);
	tal_free(d);
}

/* This also implies we're sending revocation */
void peer_got_commitsig(struct channel *channel, const u8 *msg)
{
	u64 commitnum;
	struct fee_states *fee_states;
	struct bitcoin_signature commit_sig;
	secp256k1_ecdsa_signature *htlc_sigs;
	struct added_htlc *added;
	struct fulfilled_htlc *fulfilled;
	struct failed_htlc **failed;
	struct changed_htlc *changed;
	struct bitcoin_tx *tx;
	size_t i;
	struct lightningd *ld = channel->peer->ld;

	if (!fromwire_channel_got_commitsig(msg, msg,
					    &commitnum,
					    &fee_states,
					    &commit_sig,
					    &htlc_sigs,
					    &added,
					    &fulfilled,
					    &failed,
					    &changed,
					    &tx)
	    || !fee_states_valid(fee_states, channel->opener)) {
		channel_internal_error(channel,
				    "bad fromwire_channel_got_commitsig %s",
				    tal_hex(channel, msg));
		return;
	}

	/* If we're not synced with bitcoin network, we can't accept
	 * any new HTLCs.  We stall at this point, in the hope that it
	 * won't take long! */
	if (added && !topology_synced(ld->topology)) {
		struct deferred_commitsig *d;

		log_unusual(channel->log,
			    "Deferring incoming commit until we sync");

		/* If subdaemon dies, we want to forget this. */
		d = tal(channel->owner, struct deferred_commitsig);
		d->channel = channel;
		d->msg = tal_dup_talarr(d, u8, msg);
		topology_add_sync_waiter(d, ld->topology,
					 retry_deferred_commitsig, d);
		return;
	}

	tx->chainparams = chainparams;

	log_debug(channel->log,
		  "got commitsig %"PRIu64
		  ": feerate %u, %zu added, %zu fulfilled, %zu failed, %zu changed",
		  commitnum, get_feerate(fee_states, channel->opener, LOCAL),
		  tal_count(added), tal_count(fulfilled),
		  tal_count(failed), tal_count(changed));

	/* New HTLCs */
	for (i = 0; i < tal_count(added); i++) {
		if (!channel_added_their_htlc(channel, &added[i]))
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

	tal_free(channel->channel_info.fee_states);
	channel->channel_info.fee_states = tal_steal(channel, fee_states);
	adjust_channel_feerate_bounds(channel,
				      get_feerate(fee_states,
						  channel->opener,
						  LOCAL));

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

struct commitment_revocation_payload {
	struct bitcoin_txid commitment_txid;
	const struct bitcoin_tx *penalty_tx;
	struct wallet *wallet;
	u64 channel_id;
	u64 commitnum;
};

static void commitment_revocation_hook_serialize(
    struct commitment_revocation_payload *payload, struct json_stream *stream)
{
	json_add_txid(stream, "commitment_txid", &payload->commitment_txid);
	json_add_tx(stream, "penalty_tx", payload->penalty_tx);
}

static void
commitment_revocation_hook_cb(struct commitment_revocation_payload *p STEALS){
	wallet_penalty_base_delete(p->wallet, p->channel_id, p->commitnum);
}

static bool
commitment_revocation_hook_deserialize(struct commitment_revocation_payload *p,
				       const char *buffer,
				       const jsmntok_t *toks)
{
	return true;
}


REGISTER_PLUGIN_HOOK(commitment_revocation,
		     commitment_revocation_hook_deserialize,
		     commitment_revocation_hook_cb,
		     commitment_revocation_hook_serialize,
		     struct commitment_revocation_payload *);

void peer_got_revoke(struct channel *channel, const u8 *msg)
{
	u64 revokenum;
	struct secret per_commitment_secret;
	struct pubkey next_per_commitment_point;
	struct changed_htlc *changed;
	enum onion_type *badonions;
	u8 **failmsgs;
	size_t i;
	struct lightningd *ld = channel->peer->ld;
	struct fee_states *fee_states;
	struct penalty_base *pbase;
	struct commitment_revocation_payload *payload;
	struct bitcoin_tx *penalty_tx;

	if (!fromwire_channel_got_revoke(msg, msg,
					 &revokenum, &per_commitment_secret,
					 &next_per_commitment_point,
					 &fee_states,
					 &changed,
					 &pbase,
					 &penalty_tx)
	    || !fee_states_valid(fee_states, channel->opener)) {
		channel_internal_error(channel, "bad fromwire_channel_got_revoke %s",
				    tal_hex(channel, msg));
		return;
	}

	log_debug(channel->log,
		  "got revoke %"PRIu64": %zu changed",
		  revokenum, tal_count(changed));

	/* Save any immediate failures for after we reply. */
	badonions = tal_arrz(msg, enum onion_type, tal_count(changed));
	failmsgs = tal_arrz(msg, u8 *, tal_count(changed));
	for (i = 0; i < tal_count(changed); i++) {
		/* If we're doing final accept, we need to forward */
		if (changed[i].newstate == RCVD_ADD_ACK_REVOCATION) {
			peer_accepted_htlc(failmsgs,
					   channel, changed[i].id, false,
					   &badonions[i], &failmsgs[i]);
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

	tal_free(channel->channel_info.fee_states);
	channel->channel_info.fee_states = tal_steal(channel, fee_states);

	/* FIXME: Check per_commitment_secret -> per_commit_point */
	update_per_commit_point(channel, &next_per_commitment_point);

	/* Tell it we've committed, and to go ahead with revoke. */
	msg = towire_channel_got_revoke_reply(msg);
	subd_send_msg(channel->owner, take(msg));

	/* Now, any HTLCs we need to immediately fail? */
	for (i = 0; i < tal_count(changed); i++) {
		struct htlc_in *hin;

		if (badonions[i]) {
			hin = find_htlc_in(&ld->htlcs_in, channel,
					   changed[i].id);
			local_fail_in_htlc_badonion(hin, badonions[i]);
		} else if (failmsgs[i]) {
			hin = find_htlc_in(&ld->htlcs_in, channel,
					   changed[i].id);
			local_fail_in_htlc(hin, failmsgs[i]);
		} else
			continue;

		// in fact, now we don't know if this htlc is a forward or localpay!
		wallet_forwarded_payment_add(ld->wallet,
					 hin, NULL, NULL,
					 FORWARD_LOCAL_FAILED,
					 badonions[i] ? badonions[i]
					     : fromwire_peektype(failmsgs[i]));
	}
	wallet_channel_save(ld->wallet, channel);

	if (penalty_tx == NULL)
		return;

	payload = tal(tmpctx, struct commitment_revocation_payload);
	payload->commitment_txid = pbase->txid;
	payload->penalty_tx = tal_steal(payload, penalty_tx);
	payload->wallet = ld->wallet;
	payload->channel_id = channel->dbid;
	payload->commitnum = pbase->commitment_num;
	plugin_hook_call_commitment_revocation(ld, payload);
}


/* FIXME: Load direct from db. */
const struct existing_htlc **peer_htlcs(const tal_t *ctx,
					const struct channel *channel)
{
	struct existing_htlc **htlcs;
	struct htlc_in_map_iter ini;
	struct htlc_out_map_iter outi;
	struct htlc_in *hin;
	struct htlc_out *hout;
	struct lightningd *ld = channel->peer->ld;

	htlcs = tal_arr(ctx, struct existing_htlc *, 0);

	for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
		struct failed_htlc *f;
		struct existing_htlc *existing;

		if (hin->key.channel != channel)
			continue;

		if (hin->badonion)
			f = take(mk_failed_htlc_badonion(NULL, hin, hin->badonion));
		else if (hin->failonion)
			f = take(mk_failed_htlc(NULL, hin, hin->failonion));
		else
			f = NULL;

		existing = new_existing_htlc(htlcs, hin->key.id, hin->hstate,
					     hin->msat, &hin->payment_hash,
					     hin->cltv_expiry,
					     hin->onion_routing_packet,
					     hin->blinding,
					     hin->preimage,
					     f);
		tal_arr_expand(&htlcs, existing);
	}

	for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
		struct failed_htlc *f;
		struct existing_htlc *existing;

		if (hout->key.channel != channel)
			continue;

		/* Note that channeld doesn't actually care *why* outgoing
		 * HTLCs failed, so just use a dummy here. */
		if (hout->failonion || hout->failmsg) {
			f = take(tal(NULL, struct failed_htlc));
			f->id = hout->key.id;
			f->sha256_of_onion = tal(f, struct sha256);
			memset(f->sha256_of_onion, 0,
			       sizeof(*f->sha256_of_onion));
			f->badonion = BADONION;
			f->onion = NULL;
		} else
			f = NULL;

		existing = new_existing_htlc(htlcs, hout->key.id, hout->hstate,
					     hout->msat, &hout->payment_hash,
					     hout->cltv_expiry,
					     hout->onion_routing_packet,
					     hout->blinding,
					     hout->preimage,
					     f);
		tal_arr_expand(&htlcs, existing);
	}

	return cast_const2(const struct existing_htlc **, htlcs);
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
	 *     - MUST fail the channel.
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

#ifdef COMPAT_V061
static void fixup_hout(struct lightningd *ld, struct htlc_out *hout)
{
	const char *fix;

	/* We didn't save HTLC failure information to the database.  So when
	 * busy nodes restarted (y'know, our most important users!) they would
	 * find themselves with missing fields.
	 *
	 * Fortunately, most of the network is honest: re-sending an old HTLC
	 * just causes failure (though we assert() when we try to push the
	 * failure to the incoming HTLC which has already succeeded!).
	 */

	/* We care about HTLCs being removed only, not those being added. */
	if (hout->hstate < RCVD_REMOVE_HTLC)
		return;

	/* Successful ones are fine. */
	if (hout->preimage)
		return;

	/* Failed ones (only happens after db fixed!) OK. */
	if (hout->failmsg || hout->failonion)
		return;

	/* payment_preimage for HTLC in *was* stored, so look for that. */
	if (hout->in && hout->in->preimage) {
		hout->preimage = tal_dup(hout, struct preimage,
					 hout->in->preimage);
		fix = "restoring preimage from incoming HTLC";
	} else {
		hout->failmsg = towire_temporary_node_failure(hout);
		fix = "subsituting temporary node failure";
	}

	log_broken(ld->log, "HTLC #%"PRIu64" (%s) "
		   " for amount %s"
		   " to %s"
		   " is missing a resolution: %s.",
		   hout->key.id, htlc_state_name(hout->hstate),
		   type_to_string(tmpctx, struct amount_msat, &hout->msat),
		   type_to_string(tmpctx, struct node_id,
				  &hout->key.channel->peer->id),
		   fix);
}

void fixup_htlcs_out(struct lightningd *ld)
{
	struct htlc_out_map_iter outi;
	struct htlc_out *hout;

	for (hout = htlc_out_map_first(&ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(&ld->htlcs_out, &outi)) {
		if (!hout->am_origin)
			fixup_hout(ld, hout);
	}
}
#endif /* COMPAT_V061 */

void htlcs_resubmit(struct lightningd *ld,
		    struct htlc_in_map *unconnected_htlcs_in)
{
	struct htlc_in *hin;
	struct htlc_in_map_iter ini;
	enum onion_type badonion COMPILER_WANTS_INIT("gcc7.4.0 bad, 8.3 OK");
	u8 *failmsg;

	/* Now retry any which were stuck. */
	for (hin = htlc_in_map_first(unconnected_htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(unconnected_htlcs_in, &ini)) {
		if (hin->hstate != RCVD_ADD_ACK_REVOCATION)
			continue;

		log_unusual(hin->key.channel->log,
			    "Replaying old unprocessed HTLC #%"PRIu64,
			    hin->key.id);
		if (!peer_accepted_htlc(tmpctx, hin->key.channel, hin->key.id,
					true, &badonion, &failmsg)) {
			if (failmsg)
				local_fail_in_htlc(hin, failmsg);
			else
				local_fail_in_htlc_badonion(hin, badonion);
		}
	}

	/* Don't leak memory! */
	htlc_in_map_clear(unconnected_htlcs_in);
	tal_free(unconnected_htlcs_in);
}

#if DEVELOPER
static struct command_result *json_dev_ignore_htlcs(struct command *cmd,
						    const char *buffer,
						    const jsmntok_t *obj UNNEEDED,
						    const jsmntok_t *params)
{
	struct node_id *peerid;
	struct peer *peer;
	bool *ignore;

	if (!param(cmd, buffer, params,
		   p_req("id", param_node_id, &peerid),
		   p_req("ignore", param_bool, &ignore),
		   NULL))
		return command_param_failed();

	peer = peer_by_id(cmd->ld, peerid);
	if (!peer) {
		return command_fail(cmd, LIGHTNINGD,
				    "Could not find channel with that peer");
	}
	peer->ignore_htlcs = *ignore;

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command dev_ignore_htlcs = {
	"dev-ignore-htlcs",
	"developer",
	json_dev_ignore_htlcs,
	"Set ignoring incoming HTLCs for peer {id} to {ignore}", false,
	"Set/unset ignoring of all incoming HTLCs.  For testing only."
};

AUTODATA(json_command, &dev_ignore_htlcs);
#endif /* DEVELOPER */

/* Warp this process to ensure the consistent json object structure
 * between 'listforwards' API and 'forward_event' notification. */
void json_format_forwarding_object(struct json_stream *response,
				   const char *fieldname,
				   const struct forwarding *cur)
{
	json_object_start(response, fieldname);

	/* See 6d333f16cc0f3aac7097269bf0985b5fa06d59b4: we may have deleted HTLC. */
	if (cur->payment_hash)
		json_add_sha256(response, "payment_hash", cur->payment_hash);
	json_add_short_channel_id(response, "in_channel", &cur->channel_in);

	/* This can be unknown if we failed before channel lookup */
	if (cur->channel_out.u64 != 0)
		json_add_short_channel_id(response, "out_channel",
					  &cur->channel_out);
	json_add_amount_msat_compat(response,
				    cur->msat_in,
				    "in_msatoshi", "in_msat");

	/* These can be unset (aka zero) if we failed before channel lookup */
	if (cur->channel_out.u64 != 0) {
		json_add_amount_msat_compat(response,
					    cur->msat_out,
					    "out_msatoshi",  "out_msat");
		json_add_amount_msat_compat(response,
					    cur->fee,
					    "fee", "fee_msat");
	}
	json_add_string(response, "status", forward_status_name(cur->status));

	if (cur->failcode != 0) {
		json_add_num(response, "failcode", cur->failcode);
		json_add_string(response, "failreason",
				onion_type_name(cur->failcode));
	}

#ifdef COMPAT_V070
		/* If a forwarding doesn't have received_time it was created
		 * before we added the tracking, do not include it here. */
	if (cur->received_time.ts.tv_sec) {
		json_add_timeabs(response, "received_time", cur->received_time);
		if (cur->resolved_time)
			json_add_timeabs(response, "resolved_time", *cur->resolved_time);
	}
#else
	json_add_timeabs(response, "received_time", cur->received_time);
	if (cur->resolved_time)
		json_add_timeabs(response, "resolved_time", *cur->resolved_time);
#endif
	json_object_end(response);
}


static void listforwardings_add_forwardings(struct json_stream *response, struct wallet *wallet)
{
	const struct forwarding *forwardings;
	forwardings = wallet_forwarded_payments_get(wallet, tmpctx);

	json_array_start(response, "forwards");
	for (size_t i=0; i<tal_count(forwardings); i++) {
		const struct forwarding *cur = &forwardings[i];
		json_format_forwarding_object(response, NULL, cur);
	}
	json_array_end(response);

	tal_free(forwardings);
}

static struct command_result *json_listforwards(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	struct json_stream *response;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	listforwardings_add_forwardings(response, cmd->ld->wallet);

	return command_success(cmd, response);
}

static const struct json_command listforwards_command = {
	"listforwards",
	"channels",
	json_listforwards,
	"List all forwarded payments and their information", false,
	"List all forwarded payments and their information"
};

AUTODATA(json_command, &listforwards_command);
