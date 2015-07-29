#include "bitcoin/pubkey.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/tx.h"
#include "close_tx.h"
#include "permute_tx.h"
#include "pkt.h"
#include "protobuf_convert.h"

struct bitcoin_tx *create_close_tx(const tal_t *ctx,
				   OpenChannel *ours,
				   OpenChannel *theirs,
				   int64_t delta,
				   const struct sha256_double *anchor_txid,
				   uint64_t input_amount,
				   unsigned int anchor_output)
{
	struct bitcoin_tx *tx;
	const u8 *redeemscript;
	struct pubkey ourkey, theirkey;
	struct sha256 redeem;

	/* Now create close tx: one input, two outputs. */
	tx = bitcoin_tx(ctx, 1, 2);

	/* Our input spends the anchor tx output. */
	tx->input[0].txid = *anchor_txid;
	tx->input[0].index = anchor_output;
	tx->input[0].input_amount = input_amount;

	/* Outputs goes to final pubkey */
	if (!proto_to_pubkey(ours->final_key, &ourkey))
		return tal_free(tx);
	if (!proto_to_pubkey(theirs->final_key, &theirkey))
		return tal_free(tx);

	/* delta must make sense. */
	if (delta < 0 && ours->anchor->total - ours->commitment_fee < -delta)
			return tal_free(tx);
	if (delta > 0 && theirs->anchor->total - theirs->commitment_fee < delta)
			return tal_free(tx);

	proto_to_sha256(ours->revocation_hash, &redeem);

	/* One output is to us. */
	tx->output[0].amount = ours->anchor->total - ours->commitment_fee + delta;
	redeemscript = bitcoin_redeem_single(tx, &ourkey);
	tx->output[0].script = scriptpubkey_p2sh(tx, redeemscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Other output is to them. */
	tx->output[1].amount = theirs->anchor->total - theirs->commitment_fee - delta;
	redeemscript = bitcoin_redeem_single(tx, &theirkey);
	tx->output[1].script = scriptpubkey_p2sh(tx, redeemscript);
	tx->output[1].script_length = tal_count(tx->output[1].script);

	tx->fee = ours->commitment_fee + theirs->commitment_fee;
	permute_outputs(tx->output, 2, NULL);
	return tx;
}
