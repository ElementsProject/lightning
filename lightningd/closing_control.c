#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <closingd/closingd_wiregen.h>
#include <common/close_tx.h>
#include <common/fee_states.h>
#include <common/initial_commit_tx.h>
#include <common/per_peer_state.h>
#include <common/utils.h>
#include <errno.h>
#include <gossipd/gossipd_wiregen.h>
#include <inttypes.h>
#include <lightningd/bitcoind.h>
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
	struct amount_asset amt;
	struct amount_sat fee = sat_in;
	const u8 *oscript;
	size_t scriptlen;
	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		amt = bitcoin_tx_output_get_amount(tx, i);
		oscript = bitcoin_tx_output_get_script(NULL, tx, i);
		scriptlen = tal_bytelen(oscript);
		tal_free(oscript);

		if (chainparams->is_elements && scriptlen == 0)
			continue;

		/* Ignore outputs that are not denominated in our main
		 * currency. */
		if (!amount_asset_is_main(&amt))
			continue;

		if (!amount_sat_sub(&fee, fee, amount_asset_to_sat(&amt)))
			fatal("Tx spends more than input %s? %s",
			      type_to_string(tmpctx, struct amount_sat, &sat_in),
			      type_to_string(tmpctx, struct bitcoin_tx, tx));
	}
	return fee;
}

/* Assess whether a proposed closing fee is acceptable. */
static bool closing_fee_is_acceptable(struct lightningd *ld,
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
	weight = bitcoin_tx_weight(tx) + bitcoin_tx_input_sig_weight() * 2;

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

	/* Prefer new over old: this covers the preference
	 * for a mutual close over a unilateral one. */

	return true;
}

static void peer_received_closing_signature(struct channel *channel,
					    const u8 *msg)
{
	struct bitcoin_signature sig;
	struct bitcoin_tx *tx;
	struct bitcoin_txid tx_id;
	struct lightningd *ld = channel->peer->ld;

	if (!fromwire_closingd_received_signature(msg, msg, &sig, &tx)) {
		channel_internal_error(channel, "Bad closing_received_signature %s",
				       tal_hex(msg, msg));
		return;
	}
	tx->chainparams = chainparams;

	/* FIXME: Make sure signature is correct! */
	if (closing_fee_is_acceptable(ld, channel, tx)) {
		channel_set_last_tx(channel, tx, &sig, TX_CHANNEL_CLOSE);
		wallet_channel_save(ld->wallet, channel);
	}


	// Send back the txid so we can update the billboard on selection.
	bitcoin_txid(channel->last_tx, &tx_id);
	/* OK, you can continue now. */
	subd_send_msg(channel->owner,
		      take(towire_closingd_received_signature_reply(channel, &tx_id)));
}

static void peer_closing_complete(struct channel *channel, const u8 *msg)
{
	if (!fromwire_closingd_complete(msg)) {
		channel_internal_error(channel, "Bad closing_complete %s",
				       tal_hex(msg, msg));
		return;
	}

	/* Don't report spurious failure when closingd exits. */
	channel_set_owner(channel, NULL);
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
	enum closingd_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CLOSINGD_RECEIVED_SIGNATURE:
		peer_received_closing_signature(sd->channel, msg);
		break;

	case WIRE_CLOSINGD_COMPLETE:
		peer_closing_complete(sd->channel, msg);
		break;

	/* We send these, not receive them */
	case WIRE_CLOSINGD_INIT:
	case WIRE_CLOSINGD_RECEIVED_SIGNATURE_REPLY:
		break;
	}

	return 0;
}

void peer_start_closingd(struct channel *channel,
			 struct per_peer_state *pps,
			 bool reconnected,
			 const u8 *channel_reestablish)
{
	u8 *initmsg;
	u32 feerate;
	struct amount_sat minfee, startfee, feelimit;
	u64 num_revocations;
	struct amount_msat their_msat;
	int hsmfd;
	struct secret last_remote_per_commit_secret;
	struct lightningd *ld = channel->peer->ld;
	u32 final_commit_feerate;

	if (!channel->shutdown_scriptpubkey[REMOTE]) {
		channel_internal_error(channel,
				       "Can't start closing: no remote info");
		return;
	}

	hsmfd = hsm_get_client_fd(ld, &channel->peer->id, channel->dbid,
				  HSM_CAP_SIGN_CLOSING_TX
				  | HSM_CAP_COMMITMENT_POINT);

	channel_set_owner(channel,
			  new_channel_subd(ld,
					   "lightning_closingd",
					   channel, &channel->peer->id,
					   channel->log, true,
					   closingd_wire_name, closing_msg,
					   channel_errmsg,
					   channel_set_billboard,
					   take(&pps->peer_fd),
					   take(&pps->gossip_fd),
					   take(&pps->gossip_store_fd),
					   take(&hsmfd),
					   NULL));

	if (!channel->owner) {
		log_broken(channel->log, "Could not subdaemon closing: %s",
			    strerror(errno));
		channel_fail_reconnect_later(channel,
					     "Failed to subdaemon closing");
		return;
	}

	/* BOLT #2:
	 *
	 * The sending node:
	 *  - MUST set `fee_satoshis` less than or equal to the base
	 *    fee of the final commitment transaction, as calculated in
	 *    [BOLT #3](03-transactions.md#fee-calculation).
	 */
	final_commit_feerate = get_feerate(channel->fee_states,
					   channel->opener, LOCAL);
	feelimit = commit_tx_base_fee(final_commit_feerate, 0,
				      channel->option_anchor_outputs);

	/* Pick some value above slow feerate (or min possible if unknown) */
	minfee = commit_tx_base_fee(feerate_min(ld, NULL), 0,
				    channel->option_anchor_outputs);

	/* If we can't determine feerate, start at half unilateral feerate. */
	feerate = mutual_close_feerate(ld->topology);
	if (!feerate) {
		feerate = final_commit_feerate / 2;
		if (feerate < feerate_floor())
			feerate = feerate_floor();
	}
	startfee = commit_tx_base_fee(feerate, 0,
				      channel->option_anchor_outputs);

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

	/* BOLT #2:
	 *     - if `next_revocation_number` equals 0:
	 *       - MUST set `your_last_per_commitment_secret` to all zeroes
	 *     - otherwise:
	 *       - MUST set `your_last_per_commitment_secret` to the last
	 *         `per_commitment_secret` it received
	 */
	if (num_revocations == 0)
		memset(&last_remote_per_commit_secret, 0,
		       sizeof(last_remote_per_commit_secret));
	else if (!shachain_get_secret(&channel->their_shachain.chain,
				      num_revocations-1,
				      &last_remote_per_commit_secret)) {
		channel_fail_permanent(channel,
				       "Could not get revocation secret %"PRIu64,
				       num_revocations-1);
		return;
	}
	initmsg = towire_closingd_init(tmpctx,
				      chainparams,
				      pps,
				      &channel->cid,
				      &channel->funding_txid,
				      channel->funding_outnum,
				      channel->funding,
				      &channel->local_funding_pubkey,
				      &channel->channel_info.remote_fundingkey,
				      channel->opener,
				      amount_msat_to_sat_round_down(channel->our_msat),
				      amount_msat_to_sat_round_down(their_msat),
				      channel->our_config.dust_limit,
				      minfee, feelimit, startfee,
				      channel->shutdown_scriptpubkey[LOCAL],
				      channel->shutdown_scriptpubkey[REMOTE],
				      channel->closing_fee_negotiation_step,
				      channel->closing_fee_negotiation_step_unit,
				      reconnected,
				      channel->next_index[LOCAL],
				      channel->next_index[REMOTE],
				      num_revocations,
				      channel_reestablish,
				      &last_remote_per_commit_secret,
				      IFDEV(ld->dev_fast_gossip, false));

	/* We don't expect a response: it will give us feedback on
	 * signatures sent and received, then closing_complete. */
	subd_send_msg(channel->owner, take(initmsg));

	/* Now tell gossipd that we're closing and that neither direction should
	 * be used. */
	if (channel->scid)
		subd_send_msg(channel->peer->ld->gossip,
			      take(towire_gossipd_local_channel_close(
				  tmpctx, channel->scid)));
}
