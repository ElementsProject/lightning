#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/asort/asort.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
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

struct anchor_details {
	/* Sorted amounts for how much we risk at each blockheight. */
	struct deadline_value *vals;

	/* Witnesscript for anchor */
	const u8 *anchor_wscript;

	/* Where the anchor is */
	struct bitcoin_outpoint anchor_out;

	/* If we made an anchor-spend tx, what was its fee? */
	struct amount_sat anchor_spend_fee;

	/* Weight and fee of the commitment_tx */
	size_t commit_tx_weight;
	struct amount_sat commit_tx_fee;
	u32 commit_tx_feerate;
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

	/* If we don't have an anchor, we can't do anything. */
	if (!channel_type_has_anchors(channel->type))
		return tal_free(adet);

	if (!hsm_capable(ld, WIRE_HSMD_SIGN_ANCHORSPEND)) {
		log_broken(ld->log, "hsm not capable of signing anchorspends!");
		return tal_free(adet);
	}

	adet->commit_tx_weight = bitcoin_tx_weight(tx);
	adet->commit_tx_fee = bitcoin_tx_compute_fee(tx);
	adet->commit_tx_feerate = tx_feerate(tx);
	adet->anchor_wscript
		= bitcoin_wscript_anchor(adet, &channel->local_funding_pubkey);

	/* This happens in several cases:
	 * 1. Mutual close tx.
	 * 2. There's no to-us output and no HTLCs */
	if (!find_anchor_output(channel, tx, adet->anchor_wscript,
				&adet->anchor_out)) {
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

	adet->anchor_spend_fee = AMOUNT_SAT(0);
	return adet;
}

/* If it's possible and worth it, return signed tx.  Otherwise NULL. */
static struct bitcoin_tx *spend_anchor(const tal_t *ctx,
				       struct channel *channel,
				       struct anchor_details *adet)
{
	struct lightningd *ld = channel->peer->ld;
	struct utxo **utxos;
	size_t weight;
	struct amount_sat fee, diff, change;
	struct bitcoin_tx *tx;
	bool worthwhile;
	struct wally_psbt *psbt;
	struct amount_msat total_value;
	struct pubkey final_key;
	const u8 *msg;

	/* Estimate weight of spend tx plus commitment_tx */
	weight = bitcoin_tx_core_weight(2, 1)
		+ bitcoin_tx_input_weight(false, bitcoin_tx_simple_input_witness_weight())
		+ bitcoin_tx_input_weight(false,
					  bitcoin_tx_input_sig_weight()
					  + 1 + tal_bytelen(adet->anchor_wscript))
		+ bitcoin_tx_output_weight(BITCOIN_SCRIPTPUBKEY_P2WPKH_LEN)
		+ adet->commit_tx_weight;

	worthwhile = false;
	total_value = AMOUNT_MSAT(0);
	for (int i = tal_count(adet->vals) - 1; i >= 0 && !worthwhile; --i) {
		const struct deadline_value *val = &adet->vals[i];
		u32 feerate;

		/* Calculate the total value for the current deadline
		 * and all the following */
		if (!amount_msat_add(&total_value, total_value, val->msat))
			return NULL;

		feerate = feerate_for_target(ld->topology, val->block);
		/* Would the commit tx make that feerate by itself? */
		if (adet->commit_tx_feerate >= feerate)
			continue;

		/* Get the fee required to meet the current block */
		fee = amount_tx_fee(feerate, weight);

		/* We already have part of the fee in commitment_tx. */
		if (amount_sat_sub(&fee, fee, adet->commit_tx_fee)
		    && amount_msat_greater_sat(total_value, fee)) {
			worthwhile = true;
		}

		log_debug(channel->log, "%s fee %s to get %s in %u blocks at feerate %uperkw",
			  worthwhile ? "Worth" : "Not worth",
			  fmt_amount_sat(tmpctx, fee),
			  fmt_amount_msat(tmpctx, val->msat),
			  val->block, feerate);
	}

	/* Not worth it? */
	if (!worthwhile)
		return NULL;

	/* Higher enough than previous to be valid RBF?
	 * We assume 1 sat per vbyte as minrelayfee */
	if (!amount_sat_sub(&diff, fee, adet->anchor_spend_fee)
	    || amount_sat_less(diff, amount_sat(weight / 4)))
		return NULL;

	log_debug(channel->log,
		  "Anchorspend fee %s (w=%zu), commit_tx fee %s (w=%zu):"
		  " package feerate %"PRIu64" perkw",
		  fmt_amount_sat(tmpctx, fee),
		  weight - adet->commit_tx_weight,
		  fmt_amount_sat(tmpctx, adet->commit_tx_fee),
		  adet->commit_tx_weight,
		  (fee.satoshis + adet->commit_tx_fee.satoshis) /* Raw: debug log */
		  * 1000 / weight);

	/* FIXME: Use more than one utxo! */
	utxos = tal_arr(tmpctx, struct utxo *, 1);
	utxos[0] = wallet_find_utxo(utxos, ld->wallet,
				    get_block_height(ld->topology),
				    NULL,
				    0, /* FIXME: unused! */
				    0, false, NULL);
	if (!utxos[0]) {
		log_unusual(channel->log,
			    "We want to bump commit_tx fee, but no funds!");
		return NULL;
	}

	/* FIXME: we get a random UTXO.  We should really allow
	 * multiple UTXOs here */
	if (amount_sat_less(utxos[0]->amount, fee)) {
		log_unusual(channel->log,
			    "We want to bump commit_tx with fee %s, but utxo %s is only %s!",
			    fmt_amount_sat(tmpctx, fee),
			    type_to_string(tmpctx, struct bitcoin_outpoint,
					   &utxos[0]->outpoint),
			    fmt_amount_sat(tmpctx, utxos[0]->amount));
		return NULL;
	}

	/* PSBT knows how to spend utxos. */
	psbt = psbt_using_utxos(tmpctx, ld->wallet, utxos,
				default_locktime(ld->topology),
				BITCOIN_TX_RBF_SEQUENCE, NULL);

	/* BOLT #3:
	 * #### `to_local_anchor` and `to_remote_anchor` Output (option_anchors)
	 *...
	 * The amount of the output is fixed at 330 sats, the default
	 * dust limit for P2WSH.
	 */
	psbt_append_input(psbt, &adet->anchor_out, BITCOIN_TX_RBF_SEQUENCE,
			  NULL, adet->anchor_wscript, NULL);
	psbt_input_set_wit_utxo(psbt, 1,
				scriptpubkey_p2wsh(tmpctx, adet->anchor_wscript),
				AMOUNT_SAT(330));
	psbt_input_add_pubkey(psbt, 1, &channel->local_funding_pubkey, false);

	if (!amount_sat_add(&change, utxos[0]->amount, AMOUNT_SAT(330))
	    || !amount_sat_sub(&change, change, fee)) {
		log_broken(channel->log,
			   "Error calculating anchorspend change: utxo %s fee %s",
			   fmt_amount_sat(tmpctx, utxos[0]->amount),
			   fmt_amount_sat(tmpctx, fee));
		return NULL;
	}

	bip32_pubkey(ld, &final_key, channel->final_key_idx);
	psbt_append_output(psbt,
			   scriptpubkey_p2wpkh(tmpctx, &final_key),
			   change);

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
		      type_to_string(tmpctx, struct wally_psbt, psbt));

	/* Update fee so we know for next time */
	adet->anchor_spend_fee = fee;

	tx = tal(ctx, struct bitcoin_tx);
	tx->chainparams = chainparams;
	tx->wtx = psbt_final_tx(tx, psbt);
	assert(tx->wtx);
	tx->psbt = tal_steal(tx, psbt);

	return tx;
}

static bool refresh_anchor_spend(struct channel *channel,
				 const struct bitcoin_tx **tx,
				 struct anchor_details *adet)
{
	struct bitcoin_tx *replace;
	struct amount_sat old_fee = adet->anchor_spend_fee;

	replace = spend_anchor(tal_parent(*tx), channel, adet);
	if (replace) {
		struct bitcoin_txid txid;

		bitcoin_txid(replace, &txid);
		log_info(channel->log, "RBF anchor spend %s: fee was %s now %s",
			 type_to_string(tmpctx, struct bitcoin_txid, &txid),
			 fmt_amount_sat(tmpctx, old_fee),
			 fmt_amount_sat(tmpctx, adet->anchor_spend_fee));
		log_debug(channel->log, "RBF anchor spend: Old tx %s new %s",
			  type_to_string(tmpctx, struct bitcoin_tx, *tx),
			  type_to_string(tmpctx, struct bitcoin_tx, replace));
		tal_free(*tx);
		*tx = replace;
	}
	return true;
}

bool commit_tx_boost(struct channel *channel,
		     const struct bitcoin_tx **tx,
		     struct anchor_details *adet)
{
	struct bitcoin_tx *newtx;
	struct bitcoin_txid txid;
	struct lightningd *ld = channel->peer->ld;

	if (!adet)
		return true;

	/* Have we already spent anchor?  If so, we'll use refresh_anchor_spend! */
	if (!amount_sat_eq(adet->anchor_spend_fee, AMOUNT_SAT(0)))
		return true;

	/* Do we want to spend the anchor to boost channel?
	 * We allocate it off adet, which is tied to lifetime of commit_tx
	 * rexmit. */
	newtx = spend_anchor(adet, channel, adet);
	if (!newtx)
		return true;

	bitcoin_txid(newtx, &txid);
	log_info(channel->log, "Creating anchor spend for CPFP %s: we're paying fee %s",
		 type_to_string(tmpctx, struct bitcoin_txid, &txid),
		 fmt_amount_sat(tmpctx, adet->anchor_spend_fee));

	/* Send it! */
	broadcast_tx(ld->topology, channel, take(newtx), NULL, true, 0, NULL,
		     refresh_anchor_spend, adet);
	return true;
}

