#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/asort/asort.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <channeld/channeld_wiregen.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>
#include <lightningd/anchorspend.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/hsm_control.h>
#include <lightningd/htlc_end.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/peer_control.h>
#include <wally_psbt.h>

/* This is attached to each anchor tx retransmission */
struct one_anchor {
	/* We are in adet->anchors */
	struct anchor_details *adet;

	/* Is this for our own commit tx? */
	enum side commit_side;

	/* Where the anchors are */
	struct local_anchor_info info;

	/* If we made an anchor-spend tx, what was its fee? */
	struct amount_sat anchor_spend_fee;
};

/* This is attached to the *commitment* tx retransmission */
struct anchor_details {
	/* Sorted amounts for how much we risk at each blockheight. */
	struct deadline_value *vals;

	/* Witnesscript for anchor */
	const u8 *anchor_wscript;

	/* A callback for each of these */
	struct one_anchor *anchors;
};

struct deadline_value {
	u32 block;
	struct amount_msat msat;
};

static int cmp_deadline_value(const struct deadline_value *a,
			      const struct deadline_value *b,
			      void *unused)
{
	return (int)a->block - (int)b->block;
}

static bool find_anchor_output(struct channel *channel,
			       const struct bitcoin_tx *tx,
			       const u8 *anchor_wscript,
			       struct bitcoin_outpoint *out)
{
	const u8 *scriptpubkey = scriptpubkey_p2wsh(tmpctx, anchor_wscript);

	for (out->n = 0; out->n < tx->wtx->num_outputs; out->n++) {
		if (memeq(scriptpubkey, tal_bytelen(scriptpubkey),
			  tx->wtx->outputs[out->n].script,
			  tx->wtx->outputs[out->n].script_len)) {
			bitcoin_txid(tx, &out->txid);
			return true;
		}
	}
	return false;
}

static bool merge_deadlines(struct channel *channel, struct anchor_details *adet)
{
	size_t dst;

	/* Sort into block-ascending order */
	asort(adet->vals, tal_count(adet->vals), cmp_deadline_value, NULL);

	/* Merge deadlines. */
	dst = 0;
	for (size_t i = 1; i < tal_count(adet->vals); i++) {
		if (adet->vals[i].block != adet->vals[dst].block) {
			dst = i;
			continue;
		}
		if (!amount_msat_add(&adet->vals[dst].msat,
				     adet->vals[dst].msat, adet->vals[i].msat)) {
			log_broken(channel->log,
				   "Cannot add deadlines %s + %s!",
				   fmt_amount_msat(tmpctx, adet->vals[dst].msat),
				   fmt_amount_msat(tmpctx, adet->vals[i].msat));
			return false;
		}
	}
	tal_resize(&adet->vals, dst+1);
	return true;
}

static void add_one_anchor(struct anchor_details *adet,
			   const struct local_anchor_info *info,
			   enum side commit_side)
{
	struct one_anchor one;

	one.info = *info;
	one.adet = adet;
	one.commit_side = commit_side;
	one.anchor_spend_fee = AMOUNT_SAT(0);
	tal_arr_expand(&adet->anchors, one);
}

struct anchor_details *create_anchor_details(const tal_t *ctx,
					     struct channel *channel,
					     const struct bitcoin_tx *tx)
{
	struct lightningd *ld = channel->peer->ld;
	const struct htlc_in *hin;
	struct htlc_in_map_iter ini;
	const struct htlc_out *hout;
	struct htlc_out_map_iter outi;
	struct anchor_details *adet = tal(ctx, struct anchor_details);
	struct local_anchor_info *infos, local_anchor;

	/* If we don't have an anchor, we can't do anything. */
	if (!channel_type_has_anchors(channel->type))
		return tal_free(adet);

	if (!hsm_capable(ld, WIRE_HSMD_SIGN_ANCHORSPEND)) {
		log_broken(ld->log, "hsm not capable of signing anchorspends!");
		return tal_free(adet);
	}

	adet->anchor_wscript
		= bitcoin_wscript_anchor(adet, &channel->local_funding_pubkey);
	adet->anchors = tal_arr(adet, struct one_anchor, 0);

	/* Look for any remote commitment tx anchors we might use */
	infos = wallet_get_local_anchors(tmpctx,
					 channel->peer->ld->wallet,
					 channel->dbid);
	for (size_t i = 0; i < tal_count(infos); i++)
		add_one_anchor(adet, &infos[i], REMOTE);

	/* Now append our own, if we have one. */
	if (find_anchor_output(channel, tx, adet->anchor_wscript,
			       &local_anchor.anchor_point)) {
		local_anchor.commitment_weight = bitcoin_tx_weight(tx);
		local_anchor.commitment_fee = bitcoin_tx_compute_fee(tx);
		add_one_anchor(adet, &local_anchor, LOCAL);
	}

	/* This happens in several cases:
	 * 1. Mutual close tx.
	 * 2. There's no to-us output and no HTLCs */
	if (tal_count(adet->anchors) == 0) {
		return tal_free(adet);
	}

	adet->vals = tal_arr(adet, struct deadline_value, 0);

	/* OK, what's it worth, at each deadline?
	 * We care about incoming HTLCs where we have the preimage, and
	 * outgoing HTLCs. */
	for (hin = htlc_in_map_first(ld->htlcs_in, &ini);
	     hin;
	     hin = htlc_in_map_next(ld->htlcs_in, &ini)) {
		struct deadline_value v;

		if (hin->key.channel != channel)
			continue;

		v.msat = hin->msat;
		v.block = hin->cltv_expiry;
		tal_arr_expand(&adet->vals, v);
	}

	for (hout = htlc_out_map_first(ld->htlcs_out, &outi);
	     hout;
	     hout = htlc_out_map_next(ld->htlcs_out, &outi)) {
		if (hout->key.channel != channel)
			continue;
		struct deadline_value v;

		if (hout->key.channel != channel)
			continue;

		v.msat = hout->msat;
		v.block = hout->cltv_expiry;
		tal_arr_expand(&adet->vals, v);
	}

	/* No htlcs in flight?  No reason to boost. */
	if (tal_count(adet->vals) == 0)
		return tal_free(adet);

	if (!merge_deadlines(channel, adet))
		return tal_free(adet);

	log_debug(channel->log, "We have %zu anchor points to use",
		  tal_count(adet->anchors));
	return adet;
}

/* total_weight includes the commitment tx we're trying to push! */
static struct wally_psbt *anchor_psbt(const tal_t *ctx,
				      struct channel *channel,
				      struct one_anchor *anch,
				      struct utxo **utxos,
				      u32 feerate_target,
				      size_t total_weight)
{
	struct lightningd *ld = channel->peer->ld;
	struct wally_psbt *psbt;
	struct amount_sat change, fee;
	struct pubkey final_key;

	/* PSBT knows how to spend utxos. */
	psbt = psbt_using_utxos(ctx, ld->wallet, utxos,
				default_locktime(ld->topology),
				BITCOIN_TX_RBF_SEQUENCE, NULL);

	/* BOLT #3:
	 * #### `to_local_anchor` and `to_remote_anchor` Output (option_anchors)
	 *...
	 * The amount of the output is fixed at 330 sats, the default
	 * dust limit for P2WSH.
	 */
	psbt_append_input(psbt, &anch->info.anchor_point, BITCOIN_TX_RBF_SEQUENCE,
			  NULL, anch->adet->anchor_wscript, NULL);
	psbt_input_set_wit_utxo(psbt, psbt->num_inputs - 1,
				scriptpubkey_p2wsh(tmpctx, anch->adet->anchor_wscript),
				AMOUNT_SAT(330));
	psbt_input_add_pubkey(psbt, psbt->num_inputs - 1, &channel->local_funding_pubkey, false);

	/* A zero-output tx is invalid: we must have change, even if not really economic */
	change = psbt_compute_fee(psbt);
	/* Assume we add a change output, what would the total fee be? */
	fee = amount_tx_fee(feerate_target, total_weight + change_weight());
	if (!amount_sat_sub(&change, change, fee)
	    || amount_sat_less(change, chainparams->dust_limit)) {
		change = chainparams->dust_limit;
	}

	bip32_pubkey(ld, &final_key, channel->final_key_idx);
	psbt_append_output(psbt,
			   scriptpubkey_p2wpkh(tmpctx, &final_key),
			   change);
	return psbt;
}

/* If it's possible and worth it, return signed tx.  Otherwise NULL. */
static struct bitcoin_tx *spend_anchor(const tal_t *ctx,
				       struct channel *channel,
				       struct one_anchor *anch)
{
	struct lightningd *ld = channel->peer->ld;
	struct utxo **utxos COMPILER_WANTS_INIT("gcc -O3 CI");
	size_t base_weight, weight;
	struct amount_sat fee, diff;
	struct bitcoin_tx *tx;
	struct wally_psbt *psbt;
	struct amount_msat total_value;
	const u8 *msg;

	/* Estimate weight of spend tx plus commitment_tx (not including any UTXO we add) */
	base_weight = bitcoin_tx_core_weight(2, 1)
		+ bitcoin_tx_input_weight(false,
					  bitcoin_tx_input_sig_weight()
					  + 1 + tal_bytelen(anch->adet->anchor_wscript))
		+ bitcoin_tx_output_weight(BITCOIN_SCRIPTPUBKEY_P2WPKH_LEN)
		+ anch->info.commitment_weight;

	total_value = AMOUNT_MSAT(0);
	psbt = NULL;
	for (int i = tal_count(anch->adet->vals) - 1; i >= 0; --i) {
		const struct deadline_value *val = &anch->adet->vals[i];
		u32 feerate, feerate_target;
		struct wally_psbt *candidate_psbt;

		/* Calculate the total value for the current deadline
		 * and all the following */
		if (!amount_msat_add(&total_value, total_value, val->msat))
			return NULL;

		feerate_target = feerate_for_target(ld->topology, val->block);

		/* Ask for some UTXOs which could meet this feerate */
		weight = base_weight;
		utxos = wallet_utxo_boost(tmpctx,
					  ld->wallet,
					  get_block_height(ld->topology),
					  anch->info.commitment_fee,
					  feerate_target,
					  &weight);

		/* Create a new candidate PSBT */
		candidate_psbt = anchor_psbt(tmpctx, channel, anch, utxos, feerate_target, weight);
		if (!candidate_psbt)
			continue;

		fee = psbt_compute_fee(candidate_psbt);

		/* Is it even worth spending this fee to meet the deadline? */
		if (!amount_msat_greater_sat(total_value, fee)) {
			log_debug(channel->log,
				  "Not worth fee %s for %s commit tx to get %s in %u blocks at feerate %uperkw",
				  fmt_amount_sat(tmpctx, fee),
				  anch->commit_side == LOCAL ? "local" : "remote",
				  fmt_amount_msat(tmpctx, val->msat),
				  val->block, feerate_target);
			break;
		}

		/* Add in base commitment fee */
		if (!amount_sat_add(&fee,
				    fee, anch->info.commitment_fee))
			abort();
		if (!amount_feerate(&feerate, fee, weight))
			abort();

		if (feerate < feerate_target) {
			/* We might have had lower feerates which worked: only complain if
			 * we have *nothing* */
			if (tal_count(utxos) == 0 && !psbt) {
				log_unusual(channel->log,
					    "No utxos to bump commit_tx to feerate %uperkw!",
					    feerate_target);
				break;
			}

			log_unusual(channel->log,
				    "We want to bump commit_tx to feerate %uperkw, but can only bump to %uperkw with %zu UTXOs!",
				    feerate_target, feerate, tal_count(utxos));
			psbt = candidate_psbt;
			/* We don't expect to do any better at higher feerates */
			break;
		}

		log_debug(channel->log, "Worth fee %s for %s commit tx to get %s in %u blocks at feerate %uperkw",
			  fmt_amount_sat(tmpctx, fee),
			  anch->commit_side == LOCAL ? "local" : "remote",
			  fmt_amount_msat(tmpctx, val->msat),
			  val->block, feerate);
		psbt = candidate_psbt;
	}

	/* No psbt was worth it? */
	if (!psbt)
		return NULL;

	/* Higher enough than previous to be valid RBF?
	 * We assume 1 sat per vbyte as minrelayfee */
	if (!amount_sat_sub(&diff, fee, anch->anchor_spend_fee)
	    || amount_sat_less(diff, amount_sat(weight / 4)))
		return NULL;

	log_debug(channel->log,
		  "Anchorspend for %s commit tx fee %s (w=%zu), commit_tx fee %s (w=%u):"
		  " package feerate %"PRIu64" perkw",
		  anch->commit_side == LOCAL ? "local" : "remote",
		  fmt_amount_sat(tmpctx, fee),
		  weight - anch->info.commitment_weight,
		  fmt_amount_sat(tmpctx, anch->info.commitment_fee),
		  anch->info.commitment_weight,
		  (fee.satoshis + anch->info.commitment_fee.satoshis) /* Raw: debug log */
		  * 1000 / weight);

	/* OK, HSM, sign it! */
	msg = towire_hsmd_sign_anchorspend(NULL,
					   &channel->peer->id,
					   channel->dbid,
					   cast_const2(const struct utxo **,
						       utxos),
					   psbt);
	msg = hsm_sync_req(tmpctx, ld, take(msg));
	if (!fromwire_hsmd_sign_anchorspend_reply(tmpctx, msg, &psbt))
		fatal("Reading sign_anchorspend_reply: %s", tal_hex(tmpctx, msg));

	if (!psbt_finalize(psbt))
		fatal("Non-final PSBT from hsm: %s",
		      fmt_wally_psbt(tmpctx, psbt));

	/* Update fee so we know for next time */
	anch->anchor_spend_fee = fee;

	tx = tal(ctx, struct bitcoin_tx);
	tx->chainparams = chainparams;
	tx->wtx = psbt_final_tx(tx, psbt);
	assert(tx->wtx);
	tx->psbt = tal_steal(tx, psbt);

	return tx;
}

static bool refresh_anchor_spend(struct channel *channel,
				 const struct bitcoin_tx **tx,
				 struct one_anchor *anch)
{
	struct bitcoin_tx *replace;
	struct amount_sat old_fee = anch->anchor_spend_fee;

	replace = spend_anchor(tal_parent(*tx), channel, anch);
	if (replace) {
		struct bitcoin_txid txid;

		bitcoin_txid(replace, &txid);
		log_info(channel->log, "RBF anchor %s commit tx spend %s: fee was %s now %s",
			 anch->commit_side == LOCAL ? "local" : "remote",
			 fmt_bitcoin_txid(tmpctx, &txid),
			 fmt_amount_sat(tmpctx, old_fee),
			 fmt_amount_sat(tmpctx, anch->anchor_spend_fee));
		log_debug(channel->log, "RBF anchor spend: Old tx %s new %s",
			  fmt_bitcoin_tx(tmpctx, *tx),
			  fmt_bitcoin_tx(tmpctx, replace));
		tal_free(*tx);
		*tx = replace;
	}
	return true;
}

static void create_and_broadcast_anchor(struct channel *channel,
					struct one_anchor *anch)
{
	struct bitcoin_tx *newtx;
	struct bitcoin_txid txid;
	struct lightningd *ld = channel->peer->ld;

	/* Do we want to spend the anchor to boost channel? */
	newtx = spend_anchor(tmpctx, channel, anch);
	if (!newtx) {
		return;
	}

	bitcoin_txid(newtx, &txid);
	log_info(channel->log, "Creating anchor spend for %s commit tx %s: we're paying fee %s",
		 anch->commit_side == LOCAL ? "local" : "remote",
		 fmt_bitcoin_txid(tmpctx, &txid),
		 fmt_amount_sat(tmpctx, anch->anchor_spend_fee));

	/* Send it! */
	broadcast_tx(anch->adet, ld->topology, channel, take(newtx), NULL, true, 0, NULL,
		     refresh_anchor_spend, anch);
}

void commit_tx_boost(struct channel *channel,
		     struct anchor_details *adet,
		     bool success)
{
	enum side side;

	if (!adet)
		return;

	/* If it's in our mempool, we should consider boosting it.
	 * Otherwise, try boosting peers' commitment txs. */
	if (success)
		side = LOCAL;
	else
		side = REMOTE;

	/* Ones we've already launched will use refresh_anchor_spend */
	for (size_t i = 0; i < tal_count(adet->anchors); i++) {
		if (adet->anchors[i].commit_side != side)
			continue;
		if (amount_sat_eq(adet->anchors[i].anchor_spend_fee,
				   AMOUNT_SAT(0))) {
			create_and_broadcast_anchor(channel, &adet->anchors[i]);
		}
	}
}
