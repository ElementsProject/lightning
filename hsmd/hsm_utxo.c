#include "config.h"
#include <hsmd/hsm_utxo.h>
#include <wire/wire.h>

static const struct hsm_utxo *to_hsm_utxo(const tal_t *ctx,
					  const struct utxo *utxo)
{
	struct hsm_utxo *hutxo = tal(ctx, struct hsm_utxo);

	hutxo->outpoint = utxo->outpoint;
	hutxo->amount = utxo->amount;
	hutxo->keyindex = utxo->keyindex;

	if (utxo->close_info) {
		hutxo->close_info
			= tal_dup(hutxo, struct unilateral_close_info,
				  utxo->close_info);
		if (hutxo->close_info->commitment_point)
			hutxo->close_info->commitment_point
				= tal_dup(hutxo->close_info,
					  struct pubkey,
					  hutxo->close_info->commitment_point);
	} else
		hutxo->close_info = NULL;

	if (utxo->scriptPubkey)
		hutxo->scriptPubkey = tal_dup_talarr(hutxo, u8, utxo->scriptPubkey);
	else
		hutxo->scriptPubkey = NULL;

	return hutxo;
}

const struct hsm_utxo **utxos_to_hsm_utxos(const tal_t *ctx,
					   struct utxo **utxos)
{
	const struct hsm_utxo **hutxos
		= tal_arr(ctx, const struct hsm_utxo *, tal_count(utxos));

	for (size_t i = 0; i < tal_count(hutxos); i++)
		hutxos[i] = to_hsm_utxo(hutxos, utxos[i]);
	return hutxos;
}

void towire_hsm_utxo(u8 **pptr, const struct hsm_utxo *utxo)
{
	/* Is this a unilateral close output and needs the
	 * close_info? */
	bool is_unilateral_close = utxo->close_info != NULL;
	towire_bitcoin_outpoint(pptr, &utxo->outpoint);
	towire_amount_sat(pptr, utxo->amount);
	towire_u32(pptr, utxo->keyindex);
	/* Used to be ->is_p2sh, but HSM uses scriptpubkey to determine type */
	towire_bool(pptr, false);

	towire_u16(pptr, tal_count(utxo->scriptPubkey));
	towire_u8_array(pptr, utxo->scriptPubkey, tal_count(utxo->scriptPubkey));

	towire_bool(pptr, is_unilateral_close);
	if (is_unilateral_close) {
		towire_u64(pptr, utxo->close_info->channel_id);
		towire_node_id(pptr, &utxo->close_info->peer_id);
		towire_bool(pptr, utxo->close_info->commitment_point != NULL);
		if (utxo->close_info->commitment_point)
			towire_pubkey(pptr, utxo->close_info->commitment_point);
		towire_bool(pptr, utxo->close_info->option_anchors);
		towire_u32(pptr, utxo->close_info->csv);
	}

	/* Used to be ->is_in_coinbase, but HSM doesn't care */
	towire_bool(pptr, false);
}

struct hsm_utxo *fromwire_hsm_utxo(const tal_t *ctx, const u8 **ptr, size_t *max)
{
	struct hsm_utxo *utxo = tal(ctx, struct hsm_utxo);

	fromwire_bitcoin_outpoint(ptr, max, &utxo->outpoint);
	utxo->amount = fromwire_amount_sat(ptr, max);
	utxo->keyindex = fromwire_u32(ptr, max);
	fromwire_bool(ptr, max);

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
		utxo->close_info->option_anchors
			= fromwire_bool(ptr, max);
		utxo->close_info->csv = fromwire_u32(ptr, max);
	} else {
		utxo->close_info = NULL;
	}

	fromwire_bool(ptr, max);
	return utxo;
}
