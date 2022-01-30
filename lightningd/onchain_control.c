#include "config.h"
#include <bitcoin/feerate.h>
#include <common/key_derive.h>
#include <common/type_to_string.h>
#include <errno.h>
#include <hsmd/capabilities.h>
#include <inttypes.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/hsm_control.h>
#include <lightningd/onchain_control.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <onchaind/onchaind_wiregen.h>
#include <wallet/txfilter.h>

/* We dump all the known preimages when onchaind starts up. */
static void onchaind_tell_fulfill(struct channel *channel)
{
	struct htlc_in_map_iter ini;
	struct htlc_in *hin;
	u8 *msg;
	struct lightningd *ld = channel->peer->ld;

	for (hin = htlc_in_map_first(&ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(&ld->htlcs_in, &ini)) {
		if (hin->key.channel != channel)
			continue;

		/* BOLT #5:
		 *
		 * A local node:

		 *  - if it receives (or already possesses) a payment preimage
		 *  for an unresolved HTLC output that it has been offered AND
		 *  for which it has committed to an outgoing HTLC:
		 *    - MUST *resolve* the output by spending it, using the
		 *      HTLC-success transaction.
		 *    - MUST NOT reveal its own preimage when it's not the final recipient...
		 *    - MUST resolve the output of that HTLC-success transaction.
		 *  - otherwise:
		 *      - if the *remote node* is NOT irrevocably committed to
		 *        the HTLC:
		 *        - MUST NOT *resolve* the output by spending it.
		 */

		/* We only set preimage once it's irrevocably committed, and
		 * we spend even if we don't have an outgoing HTLC (eg. local
		 * payment complete) */
		if (!hin->preimage)
			continue;

		msg = towire_onchaind_known_preimage(channel, hin->preimage);
		subd_send_msg(channel->owner, take(msg));
	}
}

/* If we want to know if this HTLC is missing, return depth. */
static bool tell_if_missing(const struct channel *channel,
			    struct htlc_stub *stub,
			    bool *tell_immediate)
{
	struct htlc_out *hout;

	/* Keep valgrind happy. */
	*tell_immediate = false;

	/* Don't care about incoming HTLCs, just ones we offered. */
	if (stub->owner == REMOTE)
		return false;

	/* Might not be a current HTLC. */
	hout = find_htlc_out(&channel->peer->ld->htlcs_out, channel, stub->id);
	if (!hout)
		return false;

	/* BOLT #5:
	 *
	 *   - for any committed HTLC that does NOT have an output in this
	 *     commitment transaction:
	 *     - once the commitment transaction has reached reasonable depth:
	 *       - MUST fail the corresponding incoming HTLC (if any).
	 *     - if no *valid* commitment transaction contains an output
	 *       corresponding to the HTLC.
	 *       - MAY fail the corresponding incoming HTLC sooner.
	 */
	if (hout->hstate >= RCVD_ADD_REVOCATION
	    && hout->hstate < SENT_REMOVE_REVOCATION)
		*tell_immediate = true;

	log_debug(channel->log,
		  "We want to know if htlc %"PRIu64" is missing (%s)",
		  hout->key.id, *tell_immediate ? "immediate" : "later");
	return true;
}

static void handle_onchain_init_reply(struct channel *channel, const u8 *msg)
{
	struct htlc_stub *stubs;
	u64 commit_num;
	bool *tell, *tell_immediate;

	if (!fromwire_onchaind_init_reply(msg, &commit_num)) {
		channel_internal_error(channel, "Invalid onchaind_init_reply %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* FIXME: We may already be ONCHAIN state when we implement restart! */
	channel_set_state(channel,
			  FUNDING_SPEND_SEEN,
			  ONCHAIN,
			  REASON_UNKNOWN,
			  "Onchain init reply");

	/* Tell it about any relevant HTLCs */
	/* FIXME: Filter by commitnum! */
	stubs = wallet_htlc_stubs(tmpctx, channel->peer->ld->wallet, channel,
				  commit_num);
	tell = tal_arr(stubs, bool, tal_count(stubs));
	tell_immediate = tal_arr(stubs, bool, tal_count(stubs));

	for (size_t i = 0; i < tal_count(stubs); i++) {
		tell[i] = tell_if_missing(channel, &stubs[i],
					  &tell_immediate[i]);
	}
	msg = towire_onchaind_htlcs(channel, stubs, tell, tell_immediate);
	subd_send_msg(channel->owner, take(msg));

	/* Tell it about any preimages we know. */
	onchaind_tell_fulfill(channel);
}

/**
 * Notify onchaind about the depth change of the watched tx.
 */
static void onchain_tx_depth(struct channel *channel,
			     const struct bitcoin_txid *txid,
			     unsigned int depth)
{
	u8 *msg;
	msg = towire_onchaind_depth(channel, txid, depth);
	subd_send_msg(channel->owner, take(msg));
}

/**
 * Entrypoint for the txwatch callback, calls onchain_tx_depth.
 */
static enum watch_result onchain_tx_watched(struct lightningd *ld,
					    struct channel *channel,
					    const struct bitcoin_txid *txid,
					    const struct bitcoin_tx *tx,
					    unsigned int depth)
{
	u32 blockheight = get_block_height(ld->topology);

	if (tx != NULL) {
		struct bitcoin_txid txid2;

		bitcoin_txid(tx, &txid2);
		if (!bitcoin_txid_eq(txid, &txid2)) {
			channel_internal_error(channel, "Txid for %s is not %s",
					       type_to_string(tmpctx,
							      struct bitcoin_tx,
							      tx),
					       type_to_string(tmpctx,
							      struct bitcoin_txid,
							      txid));
			return DELETE_WATCH;
		}
	}

	if (depth == 0) {
		log_unusual(channel->log, "Chain reorganization!");
		channel_set_owner(channel, NULL);

		/* We will most likely be freed, so this is a noop */
		return KEEP_WATCHING;
	}

	/* Store the channeltx so we can replay later */
	wallet_channeltxs_add(ld->wallet, channel,
			      WIRE_ONCHAIND_DEPTH, txid, 0, blockheight);

	onchain_tx_depth(channel, txid, depth);
	return KEEP_WATCHING;
}

static void watch_tx_and_outputs(struct channel *channel,
				 const struct bitcoin_tx *tx);

/**
 * Notify onchaind that an output was spent and register new watches.
 */
static void onchain_txo_spent(struct channel *channel, const struct bitcoin_tx *tx, size_t input_num, u32 blockheight)
{
	u8 *msg;
	/* Onchaind needs all inputs, since it uses those to compare
	 * with existing spends (which can vary, with feerate changes). */
	struct tx_parts *parts = tx_parts_from_wally_tx(tmpctx, tx->wtx,
							-1, -1);

	watch_tx_and_outputs(channel, tx);

	msg = towire_onchaind_spent(channel, parts, input_num, blockheight);
	subd_send_msg(channel->owner, take(msg));

}

/**
 * Entrypoint for the txowatch callback, stores tx and calls onchain_txo_spent.
 */
static enum watch_result onchain_txo_watched(struct channel *channel,
					     const struct bitcoin_tx *tx,
					     size_t input_num,
					     const struct block *block)
{
	struct bitcoin_txid txid;
	bitcoin_txid(tx, &txid);

	/* Store the channeltx so we can replay later */
	wallet_channeltxs_add(channel->peer->ld->wallet, channel,
			      WIRE_ONCHAIND_SPENT, &txid, input_num,
			      block->height);

	onchain_txo_spent(channel, tx, input_num, block->height);

	/* We don't need to keep watching: If this output is double-spent
	 * (reorg), we'll get a zero depth cb to onchain_tx_watched, and
	 * restart onchaind. */
	return DELETE_WATCH;
}

/* To avoid races, we watch the tx and all outputs. */
static void watch_tx_and_outputs(struct channel *channel,
				 const struct bitcoin_tx *tx)
{
	struct bitcoin_outpoint outpoint;
	struct txwatch *txw;
	struct lightningd *ld = channel->peer->ld;

	bitcoin_txid(tx, &outpoint.txid);

	/* Make txwatch a parent of txo watches, so we can unwatch together. */
	txw = watch_tx(channel->owner, ld->topology, channel, tx,
		       onchain_tx_watched);

	for (outpoint.n = 0; outpoint.n < tx->wtx->num_outputs; outpoint.n++)
		watch_txo(txw, ld->topology, channel, &outpoint,
			  onchain_txo_watched);
}

static void handle_onchain_log_coin_move(struct channel *channel, const u8 *msg)
{
	struct chain_coin_mvt *mvt = tal(NULL, struct chain_coin_mvt);

	if (!fromwire_onchaind_notify_coin_mvt(msg, mvt)) {
		channel_internal_error(channel, "Invalid onchain notify_coin_mvt");
		return;
	}

	/* Any 'ignored' payments get registed to the wallet */
	if (!mvt->account_name)
		mvt->account_name = type_to_string(mvt, struct channel_id,
						   &channel->cid);
	else if (chain_mvt_is_external(mvt))
		mvt->originating_acct = type_to_string(mvt, struct channel_id,
						       &channel->cid);
	notify_chain_mvt(channel->peer->ld, mvt);
	tal_free(mvt);
}

/** handle_onchain_broadcast_rbf_tx_cb
 *
 * @brief suppresses the rebroadcast of a
 * transaction.
 *
 * @desc when using the `bitcoin_tx` function,
 * if a callback is not given, the transaction
 * will be rebroadcast automatically by
 * chaintopology.
 * However, in the case of an RBF transaction
 * from `onchaind`, `onchaind` will periodically
 * create a new, higher-fee replacement, thus
 * `onchaind` will trigger rebroadcast (with a
 * higher fee) by itself, which the `lightningd`
 * chaintopology should not repeat.
 * This callback exists to suppress the
 * rebroadcast behavior of chaintopology.
 *
 * @param channel - the channel for which the
 * transaction was broadcast.
 * @param success - whether the tx was broadcast.
 * @param err - the error received from the
 * underlying sendrawtx.
 */
static void handle_onchain_broadcast_rbf_tx_cb(struct channel *channel,
					       bool success,
					       const char *err)
{
	/* Victory is boring.  */
	if (success)
		return;

	/* Failure is unusual but not broken: it is possible that just
	 * as we were about to broadcast, a new block came in which
	 * contains a previous version of the transaction, thus
	 * causing the higher-fee replacement to fail broadcast.
	 *
	 * ...or it could be a bug in onchaind which prevents it from
	 * successfully RBFing out the transaction, in which case we
	 * should log it for devs to check.
	 */
	log_unusual(channel->log,
		    "Broadcast of RBF tx failed, "
		    "did a new block just come in? "
		    "error: %s",
		    err);
}

static void handle_onchain_broadcast_tx(struct channel *channel,
					const u8 *msg)
{
	struct bitcoin_tx *tx;
	struct wallet *w = channel->peer->ld->wallet;
	struct bitcoin_txid txid;
	enum wallet_tx_type type;
	bool is_rbf;

	if (!fromwire_onchaind_broadcast_tx(msg, msg, &tx, &type, &is_rbf)) {
		channel_internal_error(channel, "Invalid onchain_broadcast_tx");
		return;
	}

	tx->chainparams = chainparams;

	bitcoin_txid(tx, &txid);
	wallet_transaction_add(w, tx->wtx, 0, 0);
	wallet_transaction_annotate(w, &txid, type, channel->dbid);

	/* We don't really care if it fails, we'll respond via watch. */
	/* If the onchaind signals this as RBF-able, then we also
	 * set allowhighfees, as the transaction may be RBFed into
	 * high feerates as protection against the MAD-HTLC attack.  */
	broadcast_tx_ahf(channel->peer->ld->topology, channel,
			 tx, is_rbf,
			 is_rbf ? &handle_onchain_broadcast_rbf_tx_cb : NULL);
}

static void handle_onchain_unwatch_tx(struct channel *channel, const u8 *msg)
{
	struct bitcoin_txid txid;
	struct txwatch *txw;

	if (!fromwire_onchaind_unwatch_tx(msg, &txid)) {
		channel_internal_error(channel, "Invalid onchain_unwatch_tx");
		return;
	}

	/* Frees the txo watches, too: see watch_tx_and_outputs() */
	txw = find_txwatch(channel->peer->ld->topology, &txid, channel);
	if (!txw)
		log_unusual(channel->log, "Can't unwatch txid %s",
			    type_to_string(tmpctx, struct bitcoin_txid, &txid));
	tal_free(txw);
}

static void handle_extracted_preimage(struct channel *channel, const u8 *msg)
{
	struct preimage preimage;

	if (!fromwire_onchaind_extracted_preimage(msg, &preimage)) {
		channel_internal_error(channel, "Invalid extracted_preimage");
		return;
	}

	onchain_fulfilled_htlc(channel, &preimage);
}

static void handle_missing_htlc_output(struct channel *channel, const u8 *msg)
{
	struct htlc_stub htlc;

	if (!fromwire_onchaind_missing_htlc_output(msg, &htlc)) {
		channel_internal_error(channel, "Invalid missing_htlc_output");
		return;
	}

	/* BOLT #5:
	 *
	 *   - for any committed HTLC that does NOT have an output in this
	 *     commitment transaction:
	 *     - once the commitment transaction has reached reasonable depth:
	 *       - MUST fail the corresponding incoming HTLC (if any).
	 *     - if no *valid* commitment transaction contains an output
	 *       corresponding to the HTLC.
	 *       - MAY fail the corresponding incoming HTLC sooner.
	 */
	onchain_failed_our_htlc(channel, &htlc, "missing in commitment tx");
}

static void handle_onchain_htlc_timeout(struct channel *channel, const u8 *msg)
{
	struct htlc_stub htlc;

	if (!fromwire_onchaind_htlc_timeout(msg, &htlc)) {
		channel_internal_error(channel, "Invalid onchain_htlc_timeout");
		return;
	}

	/* BOLT #5:
	 *
	 *   - if the commitment transaction HTLC output has *timed out* and
	 *     hasn't been *resolved*:
	 *     - MUST *resolve* the output by spending it using the HTLC-timeout
	 *     transaction.
	 */
	onchain_failed_our_htlc(channel, &htlc, "timed out");
}

static void handle_irrevocably_resolved(struct channel *channel, const u8 *msg UNUSED)
{
	/* FIXME: Implement check_htlcs to ensure no dangling hout->in ptrs! */
	free_htlcs(channel->peer->ld, channel);

	log_info(channel->log, "onchaind complete, forgetting peer");

	/* This will also free onchaind. */
	delete_channel(channel);
}


/**
 * onchain_add_utxo -- onchaind is telling us about an UTXO we own
 */
static void onchain_add_utxo(struct channel *channel, const u8 *msg)
{
	struct chain_coin_mvt *mvt;
	u32 blockheight;
	struct bitcoin_outpoint outpoint;
	u32 csv_lock;
	struct amount_sat amount;
	struct pubkey *commitment_point;
	u8 *scriptPubkey;

	if (!fromwire_onchaind_add_utxo(
		tmpctx, msg, &outpoint, &commitment_point,
		&amount, &blockheight, &scriptPubkey,
		&csv_lock)) {
		log_broken(channel->log,
			   "onchaind gave invalid add_utxo message: %s",
			   tal_hex(msg, msg));
		return;
	}

	assert(blockheight);
	outpointfilter_add(channel->peer->ld->wallet->owned_outpoints,
			   &outpoint);
	log_debug(channel->log, "adding utxo to watch %s, csv %u",
		  type_to_string(tmpctx, struct bitcoin_outpoint, &outpoint),
		  csv_lock);

	wallet_add_onchaind_utxo(channel->peer->ld->wallet,
				 &outpoint, scriptPubkey,
				 blockheight, amount, channel,
				 commitment_point,
				 csv_lock);

	mvt = new_coin_wallet_deposit(msg, &outpoint, blockheight,
			              amount, CHANNEL_CLOSE);

	notify_chain_mvt(channel->peer->ld, mvt);
}

static void onchain_annotate_txout(struct channel *channel, const u8 *msg)
{
	struct bitcoin_outpoint outpoint;
	enum wallet_tx_type type;
	if (!fromwire_onchaind_annotate_txout(msg, &outpoint, &type))
		fatal("onchaind gave invalid onchain_annotate_txout "
		      "message: %s",
		      tal_hex(msg, msg));
	wallet_annotate_txout(channel->peer->ld->wallet, &outpoint, type,
			      channel->dbid);
}

static void onchain_annotate_txin(struct channel *channel, const u8 *msg)
{
	struct bitcoin_txid txid;
	enum wallet_tx_type type;
	u32 innum;
	if (!fromwire_onchaind_annotate_txin(msg, &txid, &innum, &type))
		fatal("onchaind gave invalid onchain_annotate_txin "
		      "message: %s",
		      tal_hex(msg, msg));
	wallet_annotate_txin(channel->peer->ld->wallet, &txid, innum, type,
				    channel->dbid);
}

static unsigned int onchain_msg(struct subd *sd, const u8 *msg, const int *fds UNUSED)
{
	enum onchaind_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_ONCHAIND_INIT_REPLY:
		handle_onchain_init_reply(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_BROADCAST_TX:
		handle_onchain_broadcast_tx(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_UNWATCH_TX:
		handle_onchain_unwatch_tx(sd->channel, msg);
		break;

 	case WIRE_ONCHAIND_EXTRACTED_PREIMAGE:
		handle_extracted_preimage(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_MISSING_HTLC_OUTPUT:
		handle_missing_htlc_output(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_HTLC_TIMEOUT:
		handle_onchain_htlc_timeout(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_ALL_IRREVOCABLY_RESOLVED:
		handle_irrevocably_resolved(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_ADD_UTXO:
		onchain_add_utxo(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_ANNOTATE_TXIN:
		onchain_annotate_txin(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_ANNOTATE_TXOUT:
		onchain_annotate_txout(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_NOTIFY_COIN_MVT:
		handle_onchain_log_coin_move(sd->channel, msg);
		break;

	/* We send these, not receive them */
	case WIRE_ONCHAIND_INIT:
	case WIRE_ONCHAIND_SPENT:
	case WIRE_ONCHAIND_DEPTH:
	case WIRE_ONCHAIND_HTLCS:
	case WIRE_ONCHAIND_KNOWN_PREIMAGE:
	case WIRE_ONCHAIND_DEV_MEMLEAK:
	case WIRE_ONCHAIND_DEV_MEMLEAK_REPLY:
		break;
	}

	return 0;
}

/* Only error onchaind can get is if it dies. */
static void onchain_error(struct channel *channel,
			  struct peer_fd *pps UNUSED,
			  const struct channel_id *channel_id UNUSED,
			  const char *desc,
			  bool warning UNUSED,
			  const u8 *err_for_them UNUSED)
{
	channel_set_owner(channel, NULL);

	/* This happens on shutdown: fine */
	if (channel->peer->ld->state == LD_STATE_SHUTDOWN)
		return;

	/* FIXME: re-launch? */
	log_broken(channel->log, "%s", desc);
	channel_set_billboard(channel, true, desc);
}

/* With a reorg, this can get called multiple times; each time we'll kill
 * onchaind (like any other owner), and restart */
enum watch_result onchaind_funding_spent(struct channel *channel,
					 const struct bitcoin_tx *tx,
					 u32 blockheight)
{
	u8 *msg;
	struct bitcoin_txid our_last_txid;
	struct lightningd *ld = channel->peer->ld;
	struct pubkey final_key;
	int hsmfd;
	u32 feerates[3];
	enum state_change reason;

	/* use REASON_ONCHAIN or closer's reason, if known */
	reason = REASON_ONCHAIN;
	if (channel->closer != NUM_SIDES)
		reason = REASON_UNKNOWN;  /* will use last cause as reason */

	channel_fail_permanent(channel, reason, "Funding transaction spent");

	/* We could come from almost any state. */
	/* NOTE(mschmoock) above comment is wrong, since we failed above! */
	channel_set_state(channel,
			  channel->state,
			  FUNDING_SPEND_SEEN,
			  reason,
			  "Onchain funding spend");

	hsmfd = hsm_get_client_fd(ld, &channel->peer->id,
				  channel->dbid,
				  HSM_CAP_SIGN_ONCHAIN_TX
				  | HSM_CAP_COMMITMENT_POINT);

	channel_set_owner(channel, new_channel_subd(ld,
						    "lightning_onchaind",
						    channel,
						    &channel->peer->id,
						    channel->log, false,
						    onchaind_wire_name,
						    onchain_msg,
						    onchain_error,
						    channel_set_billboard,
						    take(&hsmfd),
						    NULL));

	if (!channel->owner) {
		log_broken(channel->log, "Could not subdaemon onchain: %s",
			   strerror(errno));
		return KEEP_WATCHING;
	}

	if (!bip32_pubkey(ld->wallet->bip32_base, &final_key,
			  channel->final_key_idx)) {
		log_broken(channel->log, "Could not derive onchain key %"PRIu64,
			   channel->final_key_idx);
		return KEEP_WATCHING;
	}
	/* This could be a mutual close, but it doesn't matter. */
	bitcoin_txid(channel->last_tx, &our_last_txid);

	/* We try to get the feerate for each transaction type, 0 if estimation
	 * failed. */
	feerates[0] = delayed_to_us_feerate(ld->topology);
	feerates[1] = htlc_resolution_feerate(ld->topology);
	feerates[2] = penalty_feerate(ld->topology);
	/* We check them separately but there is a high chance that if estimation
	 * failed for one, it failed for all.. */
	for (size_t i = 0; i < 3; i++) {
		if (!feerates[i]) {
			/* We have at least one data point: the last tx's feerate. */
			struct amount_sat fee = channel->funding_sats;
			for (size_t i = 0;
			     i < channel->last_tx->wtx->num_outputs; i++) {
				struct amount_asset asset =
					bitcoin_tx_output_get_amount(channel->last_tx, i);
				struct amount_sat amt;
				assert(amount_asset_is_main(&asset));
				amt = amount_asset_to_sat(&asset);
				if (!amount_sat_sub(&fee, fee, amt)) {
					log_broken(channel->log, "Could not get fee"
						   " funding %s tx %s",
						   type_to_string(tmpctx,
								  struct amount_sat,
								  &channel->funding_sats),
						   type_to_string(tmpctx,
								  struct bitcoin_tx,
								  channel->last_tx));
					return KEEP_WATCHING;
				}
			}

			feerates[i] = fee.satoshis / bitcoin_tx_weight(tx); /* Raw: reverse feerate extraction */
			if (feerates[i] < feerate_floor())
				feerates[i] = feerate_floor();
		}
	}

	log_debug(channel->log, "channel->static_remotekey_start[LOCAL] %"PRIu64,
		  channel->static_remotekey_start[LOCAL]);

	msg = towire_onchaind_init(channel,
				  &channel->their_shachain.chain,
				  chainparams,
				  channel->funding_sats,
				  channel->our_msat,
				  &channel->channel_info.old_remote_per_commit,
				  &channel->channel_info.remote_per_commit,
				   /* BOLT #2:
				    * `to_self_delay` is the number of blocks
				    * that the other node's to-self outputs
				    * must be delayed */
				   /* So, these are reversed: they specify ours,
				    * we specify theirs. */
				  channel->channel_info.their_config.to_self_delay,
				  channel->our_config.to_self_delay,
				  /* delayed_to_us, htlc, and penalty. */
				  feerates[0], feerates[1], feerates[2],
				  channel->our_config.dust_limit,
				  &our_last_txid,
				  channel->shutdown_scriptpubkey[LOCAL],
				  channel->shutdown_scriptpubkey[REMOTE],
				  &final_key,
				  channel->opener,
				  &channel->local_basepoints,
				  &channel->channel_info.theirbase,
				  tx_parts_from_wally_tx(tmpctx, tx->wtx, -1, -1),
				  tx->wtx->locktime,
				  blockheight,
				  /* FIXME: config for 'reasonable depth' */
				  3,
				  channel->last_htlc_sigs,
				  channel->min_possible_feerate,
				  channel->max_possible_feerate,
				  channel->future_per_commitment_point,
				  &channel->local_funding_pubkey,
				  &channel->channel_info.remote_fundingkey,
				  channel->static_remotekey_start[LOCAL],
				  channel->static_remotekey_start[REMOTE],
				   channel_has(channel, OPT_ANCHOR_OUTPUTS),
				  feerate_min(ld, NULL));
	subd_send_msg(channel->owner, take(msg));

	watch_tx_and_outputs(channel, tx);

	/* We keep watching until peer finally deleted, for reorgs. */
	return KEEP_WATCHING;
}

void onchaind_replay_channels(struct lightningd *ld)
{
	u32 *onchaind_ids;
	struct channeltx *txs;
	struct channel *chan;

	db_begin_transaction(ld->wallet->db);
	onchaind_ids = wallet_onchaind_channels(ld->wallet, ld);

	for (size_t i = 0; i < tal_count(onchaind_ids); i++) {
		log_info(ld->log, "Restarting onchaind for channel %d",
			 onchaind_ids[i]);

		txs = wallet_channeltxs_get(ld->wallet, onchaind_ids,
					    onchaind_ids[i]);
		chan = channel_by_dbid(ld, onchaind_ids[i]);

		for (size_t j = 0; j < tal_count(txs); j++) {
			if (txs[j].type == WIRE_ONCHAIND_INIT) {
				onchaind_funding_spent(chan, txs[j].tx,
						       txs[j].blockheight);

			} else if (txs[j].type == WIRE_ONCHAIND_SPENT) {
				onchain_txo_spent(chan, txs[j].tx,
						  txs[j].input_num,
						  txs[j].blockheight);

			} else if (txs[j].type == WIRE_ONCHAIND_DEPTH) {
				onchain_tx_depth(chan, &txs[j].txid,
						 txs[j].depth);

			} else {
				fatal("unknown message of type %d during "
				      "onchaind replay",
				      txs[j].type);
			}
		}
		tal_free(txs);
	}
	tal_free(onchaind_ids);

	db_commit_transaction(ld->wallet->db);
}
