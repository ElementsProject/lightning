#include <bitcoin/script.h>
#include <common/key_derive.h>
#include <common/utxo.h>
#include <wire/wire.h>

void towire_utxo(u8 **pptr, const struct utxo *utxo)
{
	/* Is this a unilateral close output and needs the
	 * close_info? */
	bool is_unilateral_close = utxo->close_info != NULL;
	towire_bitcoin_txid(pptr, &utxo->txid);
	towire_u32(pptr, utxo->outnum);
	towire_u64(pptr, utxo->amount);
	towire_u32(pptr, utxo->keyindex);
	towire_bool(pptr, utxo->is_p2sh);

	towire_bool(pptr, is_unilateral_close);
	if (is_unilateral_close) {
		towire_u64(pptr, utxo->close_info->channel_id);
		towire_pubkey(pptr, &utxo->close_info->peer_id);
		towire_pubkey(pptr, &utxo->close_info->commitment_point);
	}
}

struct utxo *fromwire_utxo(const tal_t *ctx, const u8 **ptr, size_t *max)
{
	struct utxo *utxo = tal(ctx, struct utxo);

	fromwire_bitcoin_txid(ptr, max, &utxo->txid);
	utxo->outnum = fromwire_u32(ptr, max);
	utxo->amount = fromwire_u64(ptr, max);
	utxo->keyindex = fromwire_u32(ptr, max);
	utxo->is_p2sh = fromwire_bool(ptr, max);
	if (fromwire_bool(ptr, max)) {
		utxo->close_info = tal(utxo, struct unilateral_close_info);
		utxo->close_info->channel_id = fromwire_u64(ptr, max);
		fromwire_pubkey(ptr, max, &utxo->close_info->peer_id);
		fromwire_pubkey(ptr, max, &utxo->close_info->commitment_point);
	} else {
		utxo->close_info = NULL;
	}
	return utxo;
}

struct bitcoin_tx *tx_spending_utxos(const tal_t *ctx,
				     const struct utxo **utxos,
				     const struct ext_key *bip32_base,
				     bool add_change_output)
{
	struct bitcoin_tx *tx =
	    bitcoin_tx(ctx, tal_count(utxos), add_change_output ? 2 : 1);

	for (size_t i = 0; i < tal_count(utxos); i++) {
		tx->input[i].txid = utxos[i]->txid;
		tx->input[i].index = utxos[i]->outnum;
		tx->input[i].amount = tal_dup(tx, u64, &utxos[i]->amount);
		if (utxos[i]->is_p2sh && bip32_base) {
			struct pubkey key;
			bip32_pubkey(bip32_base, &key, utxos[i]->keyindex);
			tx->input[i].script =
				bitcoin_scriptsig_p2sh_p2wpkh(tx, &key);
		}
	}

	return tx;
}
