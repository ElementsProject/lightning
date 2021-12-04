#include "config.h"
#include <common/utxo.h>
#include <wire/wire.h>

void towire_utxo(u8 **pptr, const struct utxo *utxo)
{
	/* Is this a unilateral close output and needs the
	 * close_info? */
	bool is_unilateral_close = utxo->close_info != NULL;
	towire_bitcoin_outpoint(pptr, &utxo->outpoint);
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
		towire_u32(pptr, utxo->close_info->csv);
	}
}

struct utxo *fromwire_utxo(const tal_t *ctx, const u8 **ptr, size_t *max)
{
	struct utxo *utxo = tal(ctx, struct utxo);

	fromwire_bitcoin_outpoint(ptr, max, &utxo->outpoint);
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
		utxo->close_info->csv = fromwire_u32(ptr, max);
	} else {
		utxo->close_info = NULL;
	}
	return utxo;
}

size_t utxo_spend_weight(const struct utxo *utxo, size_t min_witness_weight)
{
	size_t wit_weight = bitcoin_tx_simple_input_witness_weight();
	/* If the min is less than what we'd use for a 'normal' tx,
	 * we return the value with the greater added/calculated */
	if (wit_weight < min_witness_weight)
		return bitcoin_tx_input_weight(utxo->is_p2sh,
					       min_witness_weight);

	return bitcoin_tx_input_weight(utxo->is_p2sh, wit_weight);
}
