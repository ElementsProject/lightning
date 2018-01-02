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

void fromwire_utxo(const tal_t *ctx, const u8 **ptr, size_t *max, struct utxo *utxo)
{
	fromwire_bitcoin_txid(ptr, max, &utxo->txid);
	utxo->outnum = fromwire_u32(ptr, max);
	utxo->amount = fromwire_u64(ptr, max);
	utxo->keyindex = fromwire_u32(ptr, max);
	utxo->is_p2sh = fromwire_bool(ptr, max);
	if (fromwire_bool(ptr, max)) {
		utxo->close_info = tal(ctx, struct unilateral_close_info);
		utxo->close_info->channel_id = fromwire_u64(ptr, max);
		fromwire_pubkey(ptr, max, &utxo->close_info->peer_id);
		fromwire_pubkey(ptr, max, &utxo->close_info->commitment_point);
	} else {
		utxo->close_info = NULL;
	}
}


struct utxo *from_utxoptr_arr(const tal_t *ctx, const struct utxo **utxos)
{
	size_t i, n = tal_count(utxos);
	struct utxo *utxo = tal_arr(ctx, struct utxo, n);

	for (i = 0; i < n; i++)
		utxo[i] = *utxos[i];
	return utxo;
}

const struct utxo **to_utxoptr_arr(const tal_t *ctx, const struct utxo *utxos)
{
	size_t i, n = tal_count(utxos);
	const struct utxo **utxo = tal_arr(ctx, const struct utxo *, n);

	for (i = 0; i < n; i++)
		utxo[i] = &utxos[i];
	return utxo;
}
