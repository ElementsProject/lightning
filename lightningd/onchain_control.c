#include "config.h"
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/htlc_tx.h>
#include <common/key_derive.h>
#include <common/psbt_keypath.h>
#include <common/type_to_string.h>
#include <db/exec.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <hsmd/permissions.h>
#include <inttypes.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_control.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/hsm_control.h>
#include <lightningd/onchain_control.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <onchaind/onchaind_wiregen.h>
#include <wallet/txfilter.h>
#include <wally_bip32.h>
#include <wally_psbt.h>
#include <wire/wire_sync.h>

/* We dump all the known preimages when onchaind starts up. */
static void onchaind_tell_fulfill(struct channel *channel)
{
	struct htlc_in_map_iter ini;
	struct htlc_in *hin;
	u8 *msg;
	struct lightningd *ld = channel->peer->ld;

	for (hin = htlc_in_map_first(ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(ld->htlcs_in, &ini)) {
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
	hout = find_htlc_out(channel->peer->ld->htlcs_out, channel, stub->id);
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
					    const struct bitcoin_txid *txid,
					    const struct bitcoin_tx *tx,
					    unsigned int depth,
					    struct channel *channel)
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
	txw = watch_txid(channel->owner, ld->topology,
			 &outpoint.txid,
			 onchain_tx_watched, channel);

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
	else
		mvt->originating_acct = type_to_string(mvt, struct channel_id,
						       &channel->cid);
	notify_chain_mvt(channel->peer->ld, mvt);
	tal_free(mvt);
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
	txw = find_txwatch(channel->peer->ld->topology, &txid,
			   onchain_tx_watched, channel);
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

	/* We only set tell_if_missing on LOCAL htlcs */
	if (htlc.owner != LOCAL) {
		channel_internal_error(channel,
				       "onchaind_missing_htlc_output: htlc %"PRIu64" is not local!",
				       htlc.id);
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
	onchain_failed_our_htlc(channel, &htlc, "missing in commitment tx", false);
}

static void handle_onchain_htlc_timeout(struct channel *channel, const u8 *msg)
{
	struct htlc_stub htlc;

	if (!fromwire_onchaind_htlc_timeout(msg, &htlc)) {
		channel_internal_error(channel, "Invalid onchain_htlc_timeout");
		return;
	}

	/* It should tell us about timeouts on our LOCAL htlcs */
	if (htlc.owner != LOCAL) {
		channel_internal_error(channel,
				       "onchaind_htlc_timeout: htlc %"PRIu64" is not local!",
				       htlc.id);
		return;
	}

	/* BOLT #5:
	 *
	 *   - if the commitment transaction HTLC output has *timed out* and
	 *     hasn't been *resolved*:
	 *     - MUST *resolve* the output by spending it using the HTLC-timeout
	 *     transaction.
	 */
	onchain_failed_our_htlc(channel, &htlc, "timed out", true);
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
			              amount, DEPOSIT);
	mvt->originating_acct = type_to_string(mvt, struct channel_id,
					       &channel->cid);

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

/* All onchaind-produced txs are actually of the same form: */
struct onchain_signing_info {
	/* Fields common to every callback: */
	struct channel *channel;

	/* Minimum block */
	u32 minblock;

	/* Block we want this mined by */
	u32 deadline_block;

	/* Witness script for tx */
	u8 *wscript;
	/* Trailing element for witness stack */
	const tal_t *stack_elem;

	/* Information for consider_onchain_rebroadcast */
	struct amount_sat fee;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats;
	u32 to_self_delay;
	u32 locktime;
	u8 *(*sign)(const tal_t *ctx,
		    const struct bitcoin_tx *tx,
		    const struct onchain_signing_info *info);

	/* Information for consider_onchain_htlc_tx_rebroadcast */
	struct bitcoin_tx *raw_htlc_tx;

	/* Tagged union (for sanity checking!) */
	enum onchaind_wire msgtype;
	union {
		/* WIRE_ONCHAIND_SPEND_HTLC_TIMEDOUT */
		struct {
			u64 commit_num;
		} htlc_timedout;
		/* WIRE_ONCHAIND_SPEND_PENALTY */
		struct {
			struct secret remote_per_commitment_secret;
		} spend_penalty;
		/* WIRE_ONCHAIND_SPEND_HTLC_SUCCESS */
		struct {
			u64 commit_num;
			struct bitcoin_signature remote_htlc_sig;
			struct preimage preimage;
		} htlc_success;
		/* WIRE_ONCHAIND_SPEND_HTLC_TIMEOUT */
		struct {
			u64 commit_num;
			struct bitcoin_signature remote_htlc_sig;
		} htlc_timeout;
		/* WIRE_ONCHAIND_SPEND_FULFILL */
		struct {
			struct pubkey remote_per_commitment_point;
			struct preimage preimage;
		} fulfill;
		/* WIRE_ONCHAIND_SPEND_HTLC_EXPIRED */
		struct {
			struct pubkey remote_per_commitment_point;
		} htlc_expired;
	} u;
};

/* If we don't care / don't know */
static u32 infinite_block_deadline(const struct chain_topology *topo)
{
	return get_block_height(topo) + 300;
}

static struct onchain_signing_info *new_signing_info(const tal_t *ctx,
						     struct channel *channel,
						     enum onchaind_wire msgtype)
{
	struct onchain_signing_info *info = tal(ctx, struct onchain_signing_info);
	info->channel = channel;
	info->msgtype = msgtype;
	return info;
}

static u8 *sign_tx_to_us(const tal_t *ctx,
			 const struct bitcoin_tx *tx,
			 const struct onchain_signing_info *info)
{
	assert(info->msgtype == WIRE_ONCHAIND_SPEND_TO_US);
	return towire_hsmd_sign_any_delayed_payment_to_us(ctx,
							  info->u.htlc_timedout.commit_num,
							  tx, info->wscript,
							  0,
							  &info->channel->peer->id,
							  info->channel->dbid);
}

static u8 *sign_penalty(const tal_t *ctx,
			const struct bitcoin_tx *tx,
			const struct onchain_signing_info *info)
{
	assert(info->msgtype == WIRE_ONCHAIND_SPEND_PENALTY);
	return towire_hsmd_sign_any_penalty_to_us(ctx,
						  &info->u.spend_penalty.remote_per_commitment_secret,
						  tx, info->wscript,
						  0,
						  &info->channel->peer->id,
						  info->channel->dbid);
}

static u8 *sign_htlc_success(const tal_t *ctx,
			     const struct bitcoin_tx *tx,
			     const struct onchain_signing_info *info)
{
	const bool anchor_outputs = channel_type_has_anchors(info->channel->type);

	assert(info->msgtype == WIRE_ONCHAIND_SPEND_HTLC_SUCCESS);
	return towire_hsmd_sign_any_local_htlc_tx(ctx,
						  info->u.htlc_success.commit_num,
						  tx, info->wscript,
						  anchor_outputs,
						  0,
						  &info->channel->peer->id,
						  info->channel->dbid);
}

static u8 *sign_htlc_timeout(const tal_t *ctx,
			     const struct bitcoin_tx *tx,
			     const struct onchain_signing_info *info)
{
	const bool anchor_outputs = channel_type_has_anchors(info->channel->type);

	assert(info->msgtype == WIRE_ONCHAIND_SPEND_HTLC_TIMEOUT);
	return towire_hsmd_sign_any_local_htlc_tx(ctx,
						  info->u.htlc_timeout.commit_num,
						  tx, info->wscript,
						  anchor_outputs,
						  0,
						  &info->channel->peer->id,
						  info->channel->dbid);
}

static u8 *sign_fulfill(const tal_t *ctx,
			const struct bitcoin_tx *tx,
			const struct onchain_signing_info *info)
{
	const bool anchor_outputs = channel_type_has_anchors(info->channel->type);

	assert(info->msgtype == WIRE_ONCHAIND_SPEND_FULFILL);
	return towire_hsmd_sign_any_remote_htlc_to_us(ctx,
						      &info->u.fulfill.remote_per_commitment_point,
						      tx, info->wscript,
						      anchor_outputs,
						      0,
						      &info->channel->peer->id,
						      info->channel->dbid);
}

static u8 *sign_htlc_expired(const tal_t *ctx,
			     const struct bitcoin_tx *tx,
			     const struct onchain_signing_info *info)
{
	const bool anchor_outputs = channel_type_has_anchors(info->channel->type);

	assert(info->msgtype == WIRE_ONCHAIND_SPEND_HTLC_EXPIRED);
	return towire_hsmd_sign_any_remote_htlc_to_us(ctx,
						      &info->u.htlc_expired.remote_per_commitment_point,
						      tx, info->wscript,
						      anchor_outputs,
						      0,
						      &info->channel->peer->id,
						      info->channel->dbid);
}

/* Matches bitcoin_witness_sig_and_element! */
static const struct onchain_witness_element **
onchain_witness_sig_and_element(const tal_t *ctx, u8 **witness)
{
	struct onchain_witness_element **welements;
	welements = tal_arr(ctx, struct onchain_witness_element *,
			    tal_count(witness));

	for (size_t i = 0; i < tal_count(welements); i++) {
		welements[i] = tal(welements, struct onchain_witness_element);
		/* See bitcoin_witness_sig_and_element */
		welements[i]->is_signature = (i == 0);
		welements[i]->witness = tal_dup_talarr(welements[i], u8,
						       witness[i]);
	}
	return cast_const2(const struct onchain_witness_element **, welements);
}

/* Matches bitcoin_witness_htlc_success_tx & bitcoin_witness_htlc_timeout_tx! */
static const struct onchain_witness_element **
onchain_witness_htlc_tx(const tal_t *ctx, u8 **witness)
{
	struct onchain_witness_element **welements;
	welements = tal_arr(ctx, struct onchain_witness_element *,
			    tal_count(witness));

	for (size_t i = 0; i < tal_count(welements); i++) {
		welements[i] = tal(welements, struct onchain_witness_element);
		/* See bitcoin_witness_htlc_success_tx / bitcoin_witness_htlc_timeout_tx */
		welements[i]->is_signature = (i == 1 || i == 2);
		welements[i]->witness = tal_dup_talarr(welements[i], u8,
						       witness[i]);
	}
	return cast_const2(const struct onchain_witness_element **, welements);
}

/* Make normal 1-input-1-output tx to us, but don't sign it yet.
 *
 * If worthwhile is not NULL, we set it to true normally, or false if
 * we had to lower fees so much it's unlikely to get mined
 * (i.e. "don't wait up!").
*/
static struct bitcoin_tx *onchaind_tx_unsigned(const tal_t *ctx,
					       struct channel *channel,
					       const struct onchain_signing_info *info,
					       struct amount_sat *fee,
					       bool *worthwhile)
{
	struct bitcoin_tx *tx;
	struct amount_sat amt;
	size_t weight;
	struct pubkey final_key;
	struct ext_key final_wallet_ext_key;
	u64 block_target;
	struct lightningd *ld = channel->peer->ld;

	bip32_pubkey(ld, &final_key, channel->final_key_idx);
	if (bip32_key_from_parent(ld->bip32_base,
				  channel->final_key_idx,
				  BIP32_FLAG_KEY_PUBLIC,
				  &final_wallet_ext_key) != WALLY_OK) {
 		channel_internal_error(channel,
				       "Could not derive final_wallet_ext_key %"PRIu64,
				       channel->final_key_idx);
		return NULL;
	}

	tx = bitcoin_tx(ctx, chainparams, 1, 1, info->locktime);
	bitcoin_tx_add_input(tx, &info->out, info->to_self_delay,
			     NULL, info->out_sats, NULL, info->wscript);

	/* FIXME should this be p2tr now? */
	bitcoin_tx_add_output(
	    tx, scriptpubkey_p2wpkh(tmpctx, &final_key), NULL, info->out_sats);
	psbt_add_keypath_to_last_output(tx, channel->final_key_idx, &final_wallet_ext_key, false /* is_taproot */);

	/* Worst-case sig is 73 bytes */
	weight = bitcoin_tx_weight(tx) + 1 + 3 + 73 + 0 + tal_count(info->wscript);
	weight += elements_tx_overhead(chainparams, 1, 1);

	block_target = info->deadline_block;
	for (;;) {
		u32 feerate;

		feerate = feerate_for_target(ld->topology, block_target);
		*fee = amount_tx_fee(feerate, weight);

		log_debug(channel->log,
			  "Feerate for target %"PRIu64" (%+"PRId64" blocks) is %u, fee %s of %s",
			  block_target,
			  block_target - get_block_height(ld->topology),
			  feerate,
			  type_to_string(tmpctx, struct amount_sat, fee),
			  type_to_string(tmpctx, struct amount_sat,
					 &info->out_sats));

		/* If we can afford fee and it's not dust, we're done */
		if (amount_sat_sub(&amt, info->out_sats, *fee)
		    && amount_sat_greater_eq(amt, channel->our_config.dust_limit))
			break;

		/* Hmm, can't afford with recommended fee.  Try increasing deadline! */
		block_target++;

		/* If we can't even afford at FEERATE_FLOOR, something is wrong! */
		if (feerate == FEERATE_FLOOR) {
			amt = channel->our_config.dust_limit;
			/* Not quite true, but Never Happens */
			*fee = AMOUNT_SAT(0);
			log_broken(channel->log, "TX can't afford minimal feerate"
				   "; setting output to %s",
				   type_to_string(tmpctx, struct amount_sat, &amt));
			break;
		}
	}

	/* If we anticipate waiting a long time (say, 20 blocks past
	 * the deadline), tell onchaind not to wait */
	if (worthwhile) {
		*worthwhile = (block_target < info->deadline_block + (u64)20);
		if (!*worthwhile) {
			log_unusual(channel->log,
				    "Lowballing feerate for %s sats from %u to %u (deadline %u->%"PRIu64"):"
				    " won't count on it being spent!",
				    type_to_string(tmpctx, struct amount_sat, &info->out_sats),
				    feerate_for_target(ld->topology, info->deadline_block),
				    feerate_for_target(ld->topology, block_target),
				    info->deadline_block, block_target);
		}
	}

	/* If we came close to target, it's worthwhile to wait for. */
	if (block_target != info->deadline_block)
		log_debug(channel->log, "Had to adjust deadline from %u to %"PRIu64" for %s",
			  info->deadline_block, block_target,
			  type_to_string(tmpctx, struct amount_sat, &info->out_sats));
	bitcoin_tx_output_set_amount(tx, 0, amt);
	bitcoin_tx_finalize(tx);

	return tx;
}

static u8 **sign_and_get_witness(const tal_t *ctx,
				 const struct channel *channel,
				 struct bitcoin_tx *tx,
				 const struct onchain_signing_info *info)
{
	const u8 *msg;
	struct bitcoin_signature sig;
	struct lightningd *ld = channel->peer->ld;

	msg = hsm_sync_req(tmpctx, ld, take(info->sign(NULL, tx, info)));
	if (!fromwire_hsmd_sign_tx_reply(msg, &sig))
		fatal("Reading sign_tx_reply: %s", tal_hex(tmpctx, msg));

	return bitcoin_witness_sig_and_element(ctx, &sig, info->stack_elem,
					       tal_bytelen(info->stack_elem),
					       info->wscript);
}

/* Always sets *welements, returns tx.  Sets *worthwhile to false if
 * it wasn't worthwhile at the given feerate (and it had to drop feerate).
 * Returns NULL iff it called channel_internal_error().
 */
static struct bitcoin_tx *onchaind_tx(const tal_t *ctx,
				      struct channel *channel,
				      const struct onchain_signing_info *info,
				      struct amount_sat *fee,
				      bool *worthwhile,
				      const struct onchain_witness_element ***welements)
{
	struct bitcoin_tx *tx;
	u8 **witness;

	tx = onchaind_tx_unsigned(ctx, channel, info, fee, worthwhile);
	if (!tx)
		return NULL;

	/* Now sign, and set witness */
	witness = sign_and_get_witness(NULL, channel, tx, info);
	*welements = onchain_witness_sig_and_element(ctx, witness);
	bitcoin_tx_input_set_witness(tx, 0, take(witness));

	return tx;
}

static bool consider_onchain_rebroadcast(struct channel *channel,
					 const struct bitcoin_tx **tx,
					 struct onchain_signing_info *info)
{
	struct bitcoin_tx *newtx;
	struct amount_sat newfee;
	struct bitcoin_txid oldtxid, newtxid;
	u8 **witness;

	newtx = onchaind_tx_unsigned(tmpctx, channel, info, &newfee, NULL);
	if (!newtx)
		return true;

	/* FIXME: Don't RBF if fee is not sufficiently increased? */

	/* OK!  RBF time! */
	witness = sign_and_get_witness(NULL, channel, newtx, info);
	bitcoin_tx_input_set_witness(newtx, 0, take(witness));

	bitcoin_txid(newtx, &newtxid);
	bitcoin_txid(*tx, &oldtxid);

	/* Don't spam the logs! */
	log_(channel->log,
	     amount_sat_less_eq(newfee, info->fee) ? LOG_DBG : LOG_INFORM,
	     NULL, false,
	     "RBF onchain txid %s (fee %s) with txid %s (fee %s)",
	     type_to_string(tmpctx, struct bitcoin_txid, &oldtxid),
	     fmt_amount_sat(tmpctx, info->fee),
	     type_to_string(tmpctx, struct bitcoin_txid, &newtxid),
	     fmt_amount_sat(tmpctx, newfee));

	log_debug(channel->log,
		  "RBF %s->%s",
		  type_to_string(tmpctx, struct bitcoin_tx, *tx),
		  type_to_string(tmpctx, struct bitcoin_tx, newtx));

	/* FIXME: This is ugly, but we want the same parent as old tx. */
	tal_steal(tal_parent(*tx), newtx);
	tal_free(*tx);
	*tx = newtx;
	info->fee = newfee;
	return true;
}

static bool consider_onchain_htlc_tx_rebroadcast(struct channel *channel,
						 const struct bitcoin_tx **tx,
						 struct onchain_signing_info *info)
{
	struct amount_sat change, excess;
	struct utxo **utxos;
	u32 feerate;
	size_t weight;
	struct bitcoin_tx *newtx;
	size_t locktime;
	struct bitcoin_txid oldtxid, newtxid;
	struct wally_psbt *psbt;
	const u8 *msg;
	struct amount_sat oldfee, newfee;
	struct lightningd *ld = channel->peer->ld;

	/* We can't do much without anchor outputs (we could CPFP?) */
	if (!channel_type_has_anchors(channel->type))
		return true;

	/* Note that we can have UTXOs taken from us if there are a lot of
	 * closes going on, so we re-fetch them every time.  This is messy,
	 * but since that bitcoind will take the highest feerate ones, it will
	 * priority order them for us. */

	feerate = feerate_for_target(ld->topology, info->deadline_block);

	/* Make a copy to play with */
	newtx = clone_bitcoin_tx(tmpctx, info->raw_htlc_tx);
	weight = bitcoin_tx_weight(newtx);
	utxos = tal_arr(tmpctx, struct utxo *, 0);

	/* We'll need this to regenerate PSBT */
	if (wally_psbt_get_locktime(newtx->psbt, &locktime) != WALLY_OK) {
		log_broken(channel->log, "Cannot get psbt locktime?!");
		return true;
	}

	/* Keep attaching input inputs until we get sufficient fees */
	while (tx_feerate(newtx) < feerate) {
		struct utxo *utxo;

		/* Get fresh utxo */
		utxo = wallet_find_utxo(tmpctx, ld->wallet,
					get_block_height(ld->topology),
					NULL,
					0, /* FIXME: unused! */
					0, false,
					cast_const2(const struct utxo **, utxos));
		if (!utxo) {
			/* Did we get nothing at all? */
			if (tal_count(utxos) == 0) {
				log_unusual(channel->log,
					    "We want to bump HTLC fee, but no funds!");
				return true;
			}
			/* At least we got something, right? */
			break;
		}

		/* Add to any UTXOs we have already */
		tal_arr_expand(&utxos, utxo);
		weight += bitcoin_tx_simple_input_weight(utxo->is_p2sh);
	}

	/* We were happy with feerate already (can't happen with zero-fee
	 * anchors!)? */
	if (tal_count(utxos) == 0)
		return true;

	/* PSBT knows how to spend utxos; append to existing. */
	psbt = psbt_using_utxos(tmpctx, ld->wallet, utxos, locktime,
				BITCOIN_TX_RBF_SEQUENCE, newtx->psbt);

	/* Subtract how much we pay in fees for this tx, to calc excess. */
	if (!amount_sat_sub(&excess,
			    psbt_compute_fee(psbt),
			    amount_sat((u64)weight * feerate / 1000))) {
		excess = AMOUNT_SAT(0);
	}

	change = change_amount(excess, feerate, weight);
	if (!amount_sat_eq(change, AMOUNT_SAT(0))) {
		/* Append change output. */
		struct pubkey final_key;
		bip32_pubkey(ld, &final_key, channel->final_key_idx);
		psbt_append_output(psbt,
				   scriptpubkey_p2wpkh(tmpctx, &final_key),
				   change);
	}

	/* Sanity check: are we paying more in fees than HTLC is worth? */
	if (amount_sat_greater(psbt_compute_fee(psbt), info->out_sats)) {
		log_unusual(channel->log,
			    "Not spending %s in fees to get an HTLC worth %s!",
			    fmt_amount_sat(tmpctx, psbt_compute_fee(psbt)),
			    fmt_amount_sat(tmpctx, info->out_sats));
		return true;
	}

	/* Now, get HSM to sign off. */
	msg = towire_hsmd_sign_htlc_tx_mingle(NULL,
					      &channel->peer->id,
					      channel->dbid,
					      cast_const2(const struct utxo **,
							  utxos),
					      psbt);
	msg = hsm_sync_req(tmpctx, ld, take(msg));
	if (!fromwire_hsmd_sign_htlc_tx_mingle_reply(tmpctx, msg, &psbt))
		fatal("Reading sign_htlc_tx_mingle_reply: %s",
		      tal_hex(tmpctx, msg));

	if (!psbt_finalize(psbt))
		fatal("Non-final PSBT from hsm: %s",
		      type_to_string(tmpctx, struct wally_psbt, psbt));

	newtx = tal(tal_parent(*tx), struct bitcoin_tx);
	newtx->chainparams = chainparams;
	newtx->wtx = psbt_final_tx(newtx, psbt);
	assert(newtx->wtx);
	newtx->psbt = tal_steal(newtx, psbt);

	bitcoin_txid(*tx, &oldtxid);
	bitcoin_txid(newtx, &newtxid);

	oldfee = bitcoin_tx_compute_fee(*tx);
	newfee = bitcoin_tx_compute_fee(newtx);

	/* Don't spam the logs! */
	log_(channel->log,
	     amount_sat_less_eq(newfee, oldfee) ? LOG_DBG : LOG_INFORM,
	     NULL, false,
	     "RBF HTLC txid %s (fee %s) with txid %s (fee %s)",
	     type_to_string(tmpctx, struct bitcoin_txid, &oldtxid),
	     fmt_amount_sat(tmpctx, oldfee),
	     type_to_string(tmpctx, struct bitcoin_txid, &newtxid),
	     fmt_amount_sat(tmpctx, newfee));

	tal_free(*tx);
	*tx = newtx;
	return true;
}

/* We want to mine a success tx before they can timeout */
static u32 htlc_incoming_deadline(const struct channel *channel, u64 htlc_id)
{
	struct htlc_in *hin;

	hin = find_htlc_in(channel->peer->ld->htlcs_in, channel, htlc_id);
	if (!hin) {
		log_broken(channel->log, "No htlc IN %"PRIu64", using infinite deadline",
			   htlc_id);
		return infinite_block_deadline(channel->peer->ld->topology);
	}

	return hin->cltv_expiry - 1;
}

/* If there's a corresponding incoming HTLC, we want this mined in time so
 * we can fail incoming before incoming peer closes on us! */
static u32 htlc_outgoing_incoming_deadline(const struct channel *channel, u64 htlc_id)
{
	struct htlc_out *hout;

	hout = find_htlc_out(channel->peer->ld->htlcs_out, channel, htlc_id);
	if (!hout) {
		log_broken(channel->log, "No htlc OUT %"PRIu64", using infinite deadline",
			   htlc_id);
		return infinite_block_deadline(channel->peer->ld->topology);
	}

	/* If it's ours, no real pressure, but let's avoid leaking
	 * that information by using our standard setting. */
	if (!hout->in)
		return hout->cltv_expiry;

	/* Give us at least six blocks to redeem! */
	return hout->in->cltv_expiry - 6;
}

/* Create the onchain tx and tell onchaind about it */
static void create_onchain_tx(struct channel *channel,
			      const struct bitcoin_outpoint *out,
			      struct amount_sat out_sats,
			      u32 to_self_delay,
			      u32 locktime,
			      u8 *(*sign)(const tal_t *ctx,
					  const struct bitcoin_tx *tx,
					  const struct onchain_signing_info *info),
			      struct onchain_signing_info *info STEALS,
			      const char *caller)
{
	struct bitcoin_tx *tx;
	const struct onchain_witness_element **welements;
	bool worthwhile;
	struct lightningd *ld = channel->peer->ld;

	/* Save these in case we need to RBF.  We could extract from
	 * tx, but this is clearer and simpler. */
	info->out = *out;
	info->out_sats = out_sats;
	info->to_self_delay = to_self_delay;
	info->locktime = locktime;
	info->sign = sign;

	tx = onchaind_tx(tmpctx, channel, info, &info->fee, &worthwhile, &welements);
	if (!tx) {
		tal_free(info);
		return;
	}

	log_debug(channel->log, "Broadcast for onchaind tx %s%s",
		  type_to_string(tmpctx, struct bitcoin_tx, tx),
		  worthwhile ? "" : "(NOT WORTHWHILE, LOWBALL FEE!)");

	/* We allow "excessive" fees, as we may be fighting with censors and
	 * we'd rather spend fees than have our adversary win. */
	broadcast_tx(channel, ld->topology,
		     channel, take(tx), NULL, true, info->minblock,
		     NULL, consider_onchain_rebroadcast, take(info));

	subd_send_msg(channel->owner,
		      take(towire_onchaind_spend_created(NULL,
							 worthwhile,
							 welements)));
}

static void handle_onchaind_spend_to_us(struct channel *channel,
					const u8 *msg)
{
	struct onchain_signing_info *info;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats;

	info = new_signing_info(msg, channel, WIRE_ONCHAIND_SPEND_TO_US);

	/* BOLT #3:
	 * #### `to_local` Output
	 *...
	 * The output is spent by an input with `nSequence` field set to `to_self_delay` (which can only be valid after that duration has passed) and witness:
 	 *
	 *    <local_delayedsig> <>
	 */

	/* BOLT #3:
	 * ## HTLC-Timeout and HTLC-Success Transactions
	 *
	 * These HTLC transactions are almost identical, except the HTLC-timeout transaction is timelocked.
	 *...
	 * To spend this via penalty, the remote node uses a witness stack
	 * `<revocationsig> 1`, and to collect the output, the local node uses
	 * an input with nSequence `to_self_delay` and a witness stack
	 * `<local_delayedsig> 0`.
	 */
	info->stack_elem = NULL;

	if (!fromwire_onchaind_spend_to_us(info, msg,
					   &out, &out_sats,
					   &info->minblock,
					   &info->u.htlc_timedout.commit_num,
					   &info->wscript)) {
		channel_internal_error(channel, "Invalid onchaind_spend_to_us %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* No real deadline on this, it's just returning to our wallet. */
	info->deadline_block = infinite_block_deadline(channel->peer->ld->topology);
	create_onchain_tx(channel, &out, out_sats,
			  channel->channel_info.their_config.to_self_delay, 0,
			  sign_tx_to_us, info,
			  __func__);
}

static void handle_onchaind_spend_penalty(struct channel *channel,
					  const u8 *msg)
{
	struct onchain_signing_info *info;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats;
	u8 *stack_elem;

	info = new_signing_info(msg, channel, WIRE_ONCHAIND_SPEND_PENALTY);
	/* We can always spend penalty txs immediately */
	info->minblock = 0;
	if (!fromwire_onchaind_spend_penalty(info, msg,
					     &out, &out_sats,
					     &info->u.spend_penalty.remote_per_commitment_secret,
					     &stack_elem,
					     &info->wscript)) {
		channel_internal_error(channel, "Invalid onchaind_spend_penalty %s",
				       tal_hex(tmpctx, msg));
		return;
	}
	/* info->stack_elem is const void * */
	info->stack_elem = stack_elem;

	/* FIXME: deadline for HTLCs is actually a bit longer, but for
	 * their output it's channel->our_config.to_self_delay after
	 * the commitment tx is mined. */
	info->deadline_block = *channel->close_blockheight
		+ channel->our_config.to_self_delay;
	create_onchain_tx(channel, &out, out_sats,
			  0, 0,
			  sign_penalty, info,
			  __func__);
}

static void handle_onchaind_spend_fulfill(struct channel *channel,
					  const u8 *msg)
{
	struct onchain_signing_info *info;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats;
	struct preimage preimage;
	u64 htlc_id;
	const bool anchor_outputs = channel_type_has_anchors(channel->type);

	info = new_signing_info(msg, channel, WIRE_ONCHAIND_SPEND_FULFILL);
	info->minblock = 0;

	if (!fromwire_onchaind_spend_fulfill(info, msg,
					     &out, &out_sats,
					     &htlc_id,
					     &info->u.fulfill.remote_per_commitment_point,
					     &preimage,
					     &info->wscript)) {
		channel_internal_error(channel, "Invalid onchaind_spend_fulfill %s",
				       tal_hex(tmpctx, msg));
		return;
	}
	info->stack_elem = tal_dup(info, struct preimage, &preimage);

	info->deadline_block = htlc_incoming_deadline(channel, htlc_id);
	/* BOLT #3:
	 *
	 * Note that if `option_anchors` applies, the nSequence field of
	 * the spending input must be `1`.
	 */
	create_onchain_tx(channel, &out, out_sats,
			  anchor_outputs ? 1 : 0,
			  0,
			  sign_fulfill, info,
			  __func__);
}

static void handle_onchaind_spend_htlc_success(struct channel *channel,
					       const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	struct onchain_signing_info *info;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats, fee;
	u64 htlc_id;
	u8 *htlc_wscript;
	struct bitcoin_tx *tx;
	u8 **witness;
	struct bitcoin_signature sig;
	const struct onchain_witness_element **welements;
	const bool option_anchor_outputs = channel_has(channel, OPT_ANCHOR_OUTPUTS);
	const bool option_anchors_zero_fee_htlc_tx = channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);

	info = new_signing_info(msg, channel, WIRE_ONCHAIND_SPEND_HTLC_SUCCESS);
	info->minblock = 0;

	if (!fromwire_onchaind_spend_htlc_success(info, msg,
						  &out, &out_sats, &fee,
						  &htlc_id,
						  &info->u.htlc_success.commit_num,
						  &info->u.htlc_success.remote_htlc_sig,
						  &info->u.htlc_success.preimage,
						  &info->wscript,
						  &htlc_wscript)) {
		channel_internal_error(channel, "Invalid onchaind_spend_htlc_success %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* BOLT #3:
	 * * locktime: `0` for HTLC-success, `cltv_expiry` for HTLC-timeout
	 */
	tx = htlc_tx(NULL, chainparams, &out, info->wscript, out_sats, htlc_wscript, fee,
		     0, option_anchor_outputs, option_anchors_zero_fee_htlc_tx);
	tal_free(htlc_wscript);
	if (!tx) {
		/* Can only happen if fee > out_sats */
		channel_internal_error(channel, "Invalid onchaind_spend_htlc_success %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* FIXME: tell onchaind if HTLC is too small for current
	 * feerate! */
	info->deadline_block = htlc_incoming_deadline(channel, htlc_id);

	/* Now sign, and set witness */
	msg = hsm_sync_req(tmpctx, ld, take(sign_htlc_success(NULL, tx, info)));
	if (!fromwire_hsmd_sign_tx_reply(msg, &sig))
		fatal("Reading sign_tx_reply: %s", tal_hex(tmpctx, msg));

	witness = bitcoin_witness_htlc_success_tx(NULL, &sig,
						  &info->u.htlc_success.remote_htlc_sig,
						  &info->u.htlc_success.preimage,
						  info->wscript);
	welements = onchain_witness_htlc_tx(tmpctx, witness);
	bitcoin_tx_input_set_witness(tx, 0, take(witness));

	info->raw_htlc_tx = clone_bitcoin_tx(info, tx);
	info->out_sats = out_sats;

	/* Immediately consider RBF. */
	consider_onchain_htlc_tx_rebroadcast(channel,
					     cast_const2(const struct bitcoin_tx **, &tx),
					     info);

	log_debug(channel->log, "Broadcast for onchaind tx %s",
		  type_to_string(tmpctx, struct bitcoin_tx, tx));
	broadcast_tx(channel, channel->peer->ld->topology,
		     channel, take(tx), NULL, false,
		     info->minblock, NULL,
		     consider_onchain_htlc_tx_rebroadcast, take(info));

	msg = towire_onchaind_spend_created(NULL, true, welements);
	subd_send_msg(channel->owner, take(msg));
}

static void handle_onchaind_spend_htlc_timeout(struct channel *channel,
					       const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	struct onchain_signing_info *info;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats, fee;
	u64 htlc_id;
	u32 cltv_expiry;
	u8 *htlc_wscript;
	struct bitcoin_tx *tx;
	u8 **witness;
	struct bitcoin_signature sig;
	const struct onchain_witness_element **welements;
	const bool option_anchor_outputs = channel_has(channel, OPT_ANCHOR_OUTPUTS);
	const bool option_anchors_zero_fee_htlc_tx = channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX);

	info = new_signing_info(msg, channel, WIRE_ONCHAIND_SPEND_HTLC_TIMEOUT);

	if (!fromwire_onchaind_spend_htlc_timeout(info, msg,
						  &out, &out_sats, &fee,
						  &htlc_id,
						  &cltv_expiry,
						  &info->u.htlc_timeout.commit_num,
						  &info->u.htlc_timeout.remote_htlc_sig,
						  &info->wscript,
						  &htlc_wscript)) {
		channel_internal_error(channel, "Invalid onchaind_spend_htlc_timeout %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* BOLT #3:
	 * * locktime: `0` for HTLC-success, `cltv_expiry` for HTLC-timeout
	 */
	tx = htlc_tx(NULL, chainparams, &out, info->wscript, out_sats, htlc_wscript, fee,
		     cltv_expiry, option_anchor_outputs, option_anchors_zero_fee_htlc_tx);
	tal_free(htlc_wscript);
	if (!tx) {
		/* Can only happen if fee > out_sats */
		channel_internal_error(channel, "Invalid onchaind_spend_htlc_timeout %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* FIXME: tell onchaind if HTLC is too small for current
	 * feerate! */
	info->deadline_block = htlc_outgoing_incoming_deadline(channel, htlc_id);

	/* nLocktime: we have to be *after* that block! */
	info->minblock = cltv_expiry + 1;

	/* Now sign, and set witness */
	msg = hsm_sync_req(tmpctx, ld, take(sign_htlc_timeout(NULL, tx, info)));
	if (!fromwire_hsmd_sign_tx_reply(msg, &sig))
		fatal("Reading sign_tx_reply: %s", tal_hex(tmpctx, msg));

	witness = bitcoin_witness_htlc_timeout_tx(NULL, &sig,
						  &info->u.htlc_timeout.remote_htlc_sig,
						  info->wscript);
	welements = onchain_witness_htlc_tx(tmpctx, witness);
	bitcoin_tx_input_set_witness(tx, 0, take(witness));

	info->raw_htlc_tx = clone_bitcoin_tx(info, tx);
	info->out_sats = out_sats;

	/* Immediately consider RBF. */
	consider_onchain_htlc_tx_rebroadcast(channel,
					     cast_const2(const struct bitcoin_tx **, &tx),
					     info);

	log_debug(channel->log, "Broadcast for onchaind tx %s",
		  type_to_string(tmpctx, struct bitcoin_tx, tx));
	broadcast_tx(channel, channel->peer->ld->topology,
		     channel, take(tx), NULL, false,
		     info->minblock, NULL,
		     consider_onchain_htlc_tx_rebroadcast, take(info));

	msg = towire_onchaind_spend_created(NULL, true, welements);
	subd_send_msg(channel->owner, take(msg));
}

static void handle_onchaind_spend_htlc_expired(struct channel *channel,
					       const u8 *msg)
{
	struct onchain_signing_info *info;
	struct bitcoin_outpoint out;
	struct amount_sat out_sats;
	u64 htlc_id;
	u32 cltv_expiry;
	const bool anchor_outputs = channel_type_has_anchors(channel->type);

	info = new_signing_info(msg, channel, WIRE_ONCHAIND_SPEND_HTLC_EXPIRED);

	/* BOLT #5:
	 *
	 * ## HTLC Output Handling: Remote Commitment, Local Offers
	 * ...
	 *
	 *   - if the commitment transaction HTLC output has *timed out* AND NOT
	 *     been *resolved*:
	 *     - MUST *resolve* the output, by spending it to a convenient
	 *       address.
	 */
	info->stack_elem = NULL;

	if (!fromwire_onchaind_spend_htlc_expired(info, msg,
						  &out, &out_sats,
						  &htlc_id,
						  &cltv_expiry,
						  &info->u.htlc_expired.remote_per_commitment_point,
						  &info->wscript)) {
		channel_internal_error(channel, "Invalid onchaind_spend_htlc_expired %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* nLocktime: we have to be *after* that block! */
	info->minblock = cltv_expiry + 1;

	/* We have to spend it before we can close incoming */
	info->deadline_block = htlc_outgoing_incoming_deadline(channel, htlc_id);
	create_onchain_tx(channel, &out, out_sats,
			  anchor_outputs ? 1 : 0,
			  cltv_expiry,
			  sign_htlc_expired, info,
			  __func__);
}

static unsigned int onchain_msg(struct subd *sd, const u8 *msg, const int *fds UNUSED)
{
	enum onchaind_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_ONCHAIND_INIT_REPLY:
		handle_onchain_init_reply(sd->channel, msg);
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

	case WIRE_ONCHAIND_SPEND_TO_US:
		handle_onchaind_spend_to_us(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_SPEND_PENALTY:
		handle_onchaind_spend_penalty(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_SPEND_HTLC_SUCCESS:
		handle_onchaind_spend_htlc_success(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_SPEND_HTLC_TIMEOUT:
		handle_onchaind_spend_htlc_timeout(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_SPEND_FULFILL:
		handle_onchaind_spend_fulfill(sd->channel, msg);
		break;

	case WIRE_ONCHAIND_SPEND_HTLC_EXPIRED:
		handle_onchaind_spend_htlc_expired(sd->channel, msg);
		break;

	/* We send these, not receive them */
	case WIRE_ONCHAIND_INIT:
	case WIRE_ONCHAIND_SPENT:
	case WIRE_ONCHAIND_DEPTH:
	case WIRE_ONCHAIND_HTLCS:
	case WIRE_ONCHAIND_KNOWN_PREIMAGE:
	case WIRE_ONCHAIND_SPEND_CREATED:
	case WIRE_ONCHAIND_DEV_MEMLEAK:
	case WIRE_ONCHAIND_DEV_MEMLEAK_REPLY:
		break;
	}

	return 0;
}

/* Only error onchaind can get is if it dies. */
static void onchain_error(struct channel *channel,
			  struct peer_fd *pps UNUSED,
			  const char *desc,
			  const u8 *err_for_them UNUSED,
			  bool disconnect UNUSED,
			  bool warning UNUSED)
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
	enum state_change reason;

	/* use REASON_ONCHAIN or closer's reason, if known */
	reason = REASON_ONCHAIN;
	if (channel->closer != NUM_SIDES)
		reason = REASON_UNKNOWN;  /* will use last cause as reason */

	channel_fail_permanent(channel, reason,
			       "Funding transaction spent");

	/* If we haven't posted the open event yet, post an open */
	if (!channel->scid || !channel->remote_channel_ready) {
		u32 blkh;
		/* Blockheight will be zero if it's not in chain */
		blkh = wallet_transaction_height(channel->peer->ld->wallet,
						 &channel->funding.txid);
		channel_record_open(channel, blkh, true);
	}

	tal_free(channel->close_blockheight);
	channel->close_blockheight = tal_dup(channel, u32, &blockheight);

	/* We could come from almost any state. */
	/* NOTE(mschmoock) above comment is wrong, since we failed above! */
	channel_set_state(channel,
			  channel->state,
			  FUNDING_SPEND_SEEN,
			  reason,
			  tal_fmt(tmpctx, "Onchain funding spend"));

	hsmfd = hsm_get_client_fd(ld, &channel->peer->id,
				  channel->dbid,
				  HSM_PERM_SIGN_ONCHAIN_TX
				  | HSM_PERM_COMMITMENT_POINT);

	channel_set_owner(channel, new_channel_subd(channel, ld,
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

	bip32_pubkey(ld, &final_key, channel->final_key_idx);

	struct ext_key final_wallet_ext_key;
	if (bip32_key_from_parent(
		    ld->bip32_base,
		    channel->final_key_idx,
		    BIP32_FLAG_KEY_PUBLIC,
		    &final_wallet_ext_key) != WALLY_OK) {
		log_broken(channel->log, "Could not derive final_wallet_ext_key %"PRIu64,
			   channel->final_key_idx);
		return KEEP_WATCHING;
	}

	/* This could be a mutual close, but it doesn't matter.
	 * We don't need this for stub channels as well */
	if (!is_stub_scid(channel->scid))
		bitcoin_txid(channel->last_tx, &our_last_txid);
	else
	/* Dummy txid for stub channel to make valgrind happy. */
		bitcoin_txid_from_hex("80cea306607b708a03a1854520729d"
				"a884e4317b7b51f3d4a622f88176f5e034",
				64,
				&our_last_txid);

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
				  channel->our_config.dust_limit,
				  &our_last_txid,
				  channel->shutdown_scriptpubkey[LOCAL],
				  channel->shutdown_scriptpubkey[REMOTE],
				  channel->final_key_idx,
				  &final_wallet_ext_key,
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
				   channel_has(channel, OPT_ANCHORS_ZERO_FEE_HTLC_TX),
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
