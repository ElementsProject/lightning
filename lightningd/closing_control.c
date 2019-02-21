#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <closingd/gen_closing_wire.h>
#include <common/close_tx.h>
#include <common/initial_commit_tx.h>
#include <common/utils.h>
#include <errno.h>
#include <gossipd/gen_gossip_wire.h>
#include <inttypes.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/closing_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

static struct amount_sat calc_tx_fee(struct amount_sat sat_in,
				     const struct bitcoin_tx *tx)
{
	struct amount_sat fee = sat_in;
	for (size_t i = 0; i < tal_count(tx->output); i++) {
		if (!amount_sat_sub(&fee, fee, tx->output[i].amount))
			fatal("Tx spends more than input %s? %s",
			      type_to_string(tmpctx, struct amount_sat, &sat_in),
			      type_to_string(tmpctx, struct bitcoin_tx, tx));
	}
	return fee;
}

/* Is this better than the last tx we were holding?  This can happen
 * even without closingd misbehaving, if we have multiple,
 * interrupted, rounds of negotiation. */
static bool better_closing_fee(struct lightningd *ld,
			       struct channel *channel,
			       const struct bitcoin_tx *tx)
{
	struct amount_sat fee, last_fee, min_fee;
	u64 weight;
	u32 min_feerate;
	bool feerate_unknown;

	/* Calculate actual fee (adds in eliminated outputs) */
	fee = calc_tx_fee(channel->funding, tx);
	last_fee = calc_tx_fee(channel->funding, channel->last_tx);

	log_debug(channel->log, "Their actual closing tx fee is %s"
		 " vs previous %s",
		  type_to_string(tmpctx, struct amount_sat, &fee),
		  type_to_string(tmpctx, struct amount_sat, &last_fee));

	/* Weight once we add in sigs. */
	weight = measure_tx_weight(tx) + 74 * 2;

	/* If we don't have a feerate estimate, this gives feerate_floor */
	min_feerate = feerate_min(ld, &feerate_unknown);

	min_fee = amount_tx_fee(min_feerate, weight);
	if (amount_sat_less(fee, min_fee)) {
		log_debug(channel->log, "... That's below our min %s"
			  " for weight %"PRIu64" at feerate %u",
			  type_to_string(tmpctx, struct amount_sat, &fee),
			  weight, min_feerate);
		return false;
	}

	/* In case of a tie, prefer new over old: this covers the preference
	 * for a mutual close over a unilateral one. */

	/* If we don't know the feerate, prefer higher fee. */
	if (feerate_unknown)
		return amount_sat_greater_eq(fee, last_fee);

	/* Otherwise prefer lower fee. */
	return amount_sat_less_eq(fee, last_fee);
}

static void peer_received_closing_signature(struct channel *channel,
					    const u8 *msg)
{
	struct bitcoin_signature sig;
	struct bitcoin_tx *tx;
	struct lightningd *ld = channel->peer->ld;

	if (!fromwire_closing_received_signature(msg, msg, &sig, &tx)) {
		channel_internal_error(channel, "Bad closing_received_signature %s",
				       tal_hex(msg, msg));
		return;
	}

	/* FIXME: Make sure signature is correct! */
	if (better_closing_fee(ld, channel, tx)) {
		channel_set_last_tx(channel, tx, &sig);
		/* TODO(cdecker) Selectively save updated fields to DB */
		wallet_channel_save(ld->wallet, channel);
	}

	/* OK, you can continue now. */
	subd_send_msg(channel->owner,
		      take(towire_closing_received_signature_reply(channel)));
}

static void peer_closing_complete(struct channel *channel, const u8 *msg)
{
	if (!fromwire_closing_complete(msg)) {
		channel_internal_error(channel, "Bad closing_complete %s",
				       tal_hex(msg, msg));
		return;
	}

	/* Don't report spurious failure when closingd exits. */
	channel_set_owner(channel, NULL, false);
	/* Clear any transient negotiation messages */
	channel_set_billboard(channel, false, NULL);

	/* Retransmission only, ignore closing. */
	if (channel->state == CLOSINGD_COMPLETE)
		return;

	/* Channel gets dropped to chain cooperatively. */
	drop_to_chain(channel->peer->ld, channel, true);
	channel_set_state(channel, CLOSINGD_SIGEXCHANGE, CLOSINGD_COMPLETE);
}

static unsigned closing_msg(struct subd *sd, const u8 *msg, const int *fds UNUSED)
{
	enum closing_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CLOSING_RECEIVED_SIGNATURE:
		peer_received_closing_signature(sd->channel, msg);
		break;

	case WIRE_CLOSING_COMPLETE:
		peer_closing_complete(sd->channel, msg);
		break;

	/* We send these, not receive them */
	case WIRE_CLOSING_INIT:
	case WIRE_CLOSING_RECEIVED_SIGNATURE_REPLY:
		break;
	}

	return 0;
}

void peer_start_closingd(struct channel *channel,
			 const struct crypto_state *cs,
			 int peer_fd, int gossip_fd,
			 bool reconnected,
			 const u8 *channel_reestablish)
{
	u8 *initmsg;
	u32 feerate;
	struct amount_sat minfee, startfee, feelimit;
	u64 num_revocations;
	struct amount_msat their_msat;
	int hsmfd;
	struct lightningd *ld = channel->peer->ld;

	if (!channel->remote_shutdown_scriptpubkey) {
		channel_internal_error(channel,
				       "Can't start closing: no remote info");
		return;
	}

	hsmfd = hsm_get_client_fd(ld, &channel->peer->id, channel->dbid,
				  HSM_CAP_SIGN_CLOSING_TX);

	channel_set_owner(channel,
			  new_channel_subd(ld,
					   "lightning_closingd",
					   channel, channel->log, true,
					   closing_wire_type_name, closing_msg,
					   channel_errmsg,
					   channel_set_billboard,
					   take(&peer_fd), take(&gossip_fd),
					   take(&hsmfd),
					   NULL),
			  false);

	if (!channel->owner) {
		log_unusual(channel->log, "Could not subdaemon closing: %s",
			    strerror(errno));
		channel_fail_transient(channel, "Failed to subdaemon closing");
		return;
	}

	/* BOLT #2:
	 *
	 * The sending node:
	 *  - MUST set `fee_satoshis` less than or equal to the base
	 *    fee of the final commitment transaction, as calculated in
	 *    [BOLT #3](03-transactions.md#fee-calculation).
	 */
	feelimit = commit_tx_base_fee(channel->channel_info.feerate_per_kw[LOCAL],
				      0);

	/* Pick some value above slow feerate (or min possible if unknown) */
	minfee = commit_tx_base_fee(feerate_min(ld, NULL), 0);

	/* If we can't determine feerate, start at half unilateral feerate. */
	feerate = mutual_close_feerate(ld->topology);
	if (!feerate) {
		feerate = channel->channel_info.feerate_per_kw[LOCAL] / 2;
		if (feerate < feerate_floor())
			feerate = feerate_floor();
	}
	startfee = commit_tx_base_fee(feerate, 0);

	if (amount_sat_greater(startfee, feelimit))
		startfee = feelimit;
	if (amount_sat_greater(minfee, feelimit))
		minfee = feelimit;

	num_revocations
		= revocations_received(&channel->their_shachain.chain);

	/* BOLT #3:
	 *
	 * Each node offering a signature:
	 *  - MUST round each output down to whole satoshis.
	 */
	/* What is not ours is theirs */
	if (!amount_sat_sub_msat(&their_msat,
				 channel->funding, channel->our_msat)) {
		log_broken(channel->log, "our_msat overflow funding %s minus %s",
			  type_to_string(tmpctx, struct amount_sat,
					 &channel->funding),
			  type_to_string(tmpctx, struct amount_msat,
					 &channel->our_msat));
		channel_fail_permanent(channel, "our_msat overflow on closing");
		return;
	}
	initmsg = towire_closing_init(tmpctx,
				      cs,
				      &channel->funding_txid,
				      channel->funding_outnum,
				      channel->funding,
				      &channel->local_funding_pubkey,
				      &channel->channel_info.remote_fundingkey,
				      channel->funder,
				      amount_msat_to_sat_round_down(channel->our_msat),
				      amount_msat_to_sat_round_down(their_msat),
				      channel->our_config.dust_limit,
				      minfee, feelimit, startfee,
				      p2wpkh_for_keyidx(tmpctx, ld,
							channel->final_key_idx),
				      channel->remote_shutdown_scriptpubkey,
				      reconnected,
				      channel->next_index[LOCAL],
				      channel->next_index[REMOTE],
				      num_revocations,
				      channel_reestablish,
				      p2wpkh_for_keyidx(tmpctx, ld,
							channel->final_key_idx));

	/* We don't expect a response: it will give us feedback on
	 * signatures sent and received, then closing_complete. */
	subd_send_msg(channel->owner, take(initmsg));

	/* Now tell gossipd that we're closing and that neither direction should
	 * be used. */
	if (channel->scid)
		subd_send_msg(channel->peer->ld->gossip,
			      take(towire_gossip_local_channel_close(
				  tmpctx, channel->scid)));
}
