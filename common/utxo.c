#include <assert.h>
#include <bitcoin/privkey.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/ccan/mem/mem.h>
#include <common/key_derive.h>
#include <common/utils.h>
#include <common/utxo.h>
#include <wire/wire.h>

void towire_utxo(u8 **pptr, const struct utxo *utxo)
{
	/* Is this a unilateral close output and needs the
	 * close_info? */
	bool is_unilateral_close = utxo->close_info != NULL;
	towire_bitcoin_txid(pptr, &utxo->txid);
	towire_u32(pptr, utxo->outnum);
	towire_amount_sat(pptr, utxo->amount);
	towire_u32(pptr, utxo->keyindex);
	towire_bool(pptr, utxo->is_p2sh);

	towire_u16(pptr, tal_count(utxo->scriptPubkey));
	towire_u8_array(pptr, utxo->scriptPubkey, tal_count(utxo->scriptPubkey));

	towire_bool(pptr, is_unilateral_close);
	if (is_unilateral_close) {
		towire_u64(pptr, utxo->close_info->channel_id);
		towire_node_id(pptr, &utxo->close_info->peer_id);
		towire_bool(pptr, utxo->close_info->commitment_point != NULL);
		if (utxo->close_info->commitment_point)
			towire_pubkey(pptr, utxo->close_info->commitment_point);
		towire_bool(pptr, utxo->close_info->option_anchor_outputs);
	}
}

struct utxo *fromwire_utxo(const tal_t *ctx, const u8 **ptr, size_t *max)
{
	struct utxo *utxo = tal(ctx, struct utxo);

	fromwire_bitcoin_txid(ptr, max, &utxo->txid);
	utxo->outnum = fromwire_u32(ptr, max);
	utxo->amount = fromwire_amount_sat(ptr, max);
	utxo->keyindex = fromwire_u32(ptr, max);
	utxo->is_p2sh = fromwire_bool(ptr, max);

	utxo->scriptPubkey = fromwire_tal_arrn(utxo, ptr, max, fromwire_u16(ptr, max));

	if (fromwire_bool(ptr, max)) {
		utxo->close_info = tal(utxo, struct unilateral_close_info);
		utxo->close_info->channel_id = fromwire_u64(ptr, max);
		fromwire_node_id(ptr, max, &utxo->close_info->peer_id);
		if (fromwire_bool(ptr, max)) {
			utxo->close_info->commitment_point = tal(utxo,
								 struct pubkey);
			fromwire_pubkey(ptr, max,
					utxo->close_info->commitment_point);
		} else
			utxo->close_info->commitment_point = NULL;
		utxo->close_info->option_anchor_outputs
			= fromwire_bool(ptr, max);
	} else {
		utxo->close_info = NULL;
	}
	return utxo;
}

struct bitcoin_tx *tx_spending_utxos(const tal_t *ctx,
				     const struct chainparams *chainparams,
				     const struct utxo **utxos,
				     const struct ext_key *bip32_base,
				     bool add_change_output,
				     size_t num_output,
				     u32 nlocktime,
				     u32 nsequence)
{
	struct pubkey key;
	u8 *scriptSig, *redeemscript;

	size_t outcount = add_change_output ? 1 + num_output : num_output;
	struct bitcoin_tx *tx = bitcoin_tx(ctx, chainparams, tal_count(utxos),
					   outcount, nlocktime);

	for (size_t i = 0; i < tal_count(utxos); i++) {
		u32 this_nsequence;
		if (utxos[i]->is_p2sh && bip32_base) {
			bip32_pubkey(bip32_base, &key, utxos[i]->keyindex);
			scriptSig =
				bitcoin_scriptsig_p2sh_p2wpkh(tmpctx, &key);
			redeemscript =
				bitcoin_redeem_p2sh_p2wpkh(tmpctx, &key);

		} else {
			scriptSig = NULL;
			redeemscript = NULL;
		}

		/* BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
		 * #### `to_remote` Output
		 * ...
		 * The output is spent by a transaction with `nSequence` field
		 * set to `1` and witness:
		 */
		if (utxos[i]->close_info && utxos[i]->close_info->option_anchor_outputs)
			this_nsequence = 1;
		else
			this_nsequence = nsequence;

		bitcoin_tx_add_input(tx, &utxos[i]->txid,
				     utxos[i]->outnum,
				     this_nsequence,
				     scriptSig, utxos[i]->amount,
				     utxos[i]->scriptPubkey, NULL);

		/* Add redeemscript to the PSBT input */
		if (redeemscript)
			psbt_input_set_redeemscript(tx->psbt, i,
						    redeemscript);

	}

	return tx;
}

size_t utxo_spend_weight(const struct utxo *utxo)
{
	return bitcoin_tx_simple_input_weight(utxo->is_p2sh);
}
