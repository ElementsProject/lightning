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
				   const struct sha256_double *anchor_txid1,
				   unsigned int index1, uint64_t input_amount1,
				   const struct sha256_double *anchor_txid2,
				   unsigned int index2, uint64_t input_amount2,
				   size_t inmap[2])
{
	struct bitcoin_tx *tx;
	const u8 *redeemscript;
	struct pubkey ourkey, theirkey;
	struct sha256 redeem;

	/* Now create close tx: two inputs, two outputs. */
	tx = bitcoin_tx(ctx, 2, 2);

	/* Our inputs spend the anchor tx outputs. */
	tx->input[0].txid = *anchor_txid1;
	tx->input[0].index = index1;
	tx->input[0].input_amount = input_amount1;
	tx->input[1].txid = *anchor_txid2;
	tx->input[1].index = index2;
	tx->input[1].input_amount = input_amount2;

	/* Outputs goes to final pubkey */
	if (!proto_to_pubkey(ours->final, &ourkey))
		return tal_free(tx);
	if (!proto_to_pubkey(theirs->final, &theirkey))
		return tal_free(tx);

	/* delta must make sense. */
	if (delta < 0 && ours->total_input - ours->commitment_fee < -delta)
			return tal_free(tx);
	if (delta > 0 && theirs->total_input - theirs->commitment_fee < delta)
			return tal_free(tx);

	proto_to_sha256(ours->revocation_hash, &redeem);

	/* One output is to us. */
	tx->output[0].amount = ours->total_input - ours->commitment_fee + delta;
	redeemscript = bitcoin_redeem_single(tx, &ourkey);
	tx->output[0].script = scriptpubkey_p2sh(tx, redeemscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Other output is to them. */
	tx->output[1].amount = theirs->total_input - theirs->commitment_fee - delta;
	redeemscript = bitcoin_redeem_single(tx, &theirkey);
	tx->output[1].script = scriptpubkey_p2sh(tx, redeemscript);
	tx->output[1].script_length = tal_count(tx->output[1].script);

	tx->fee = ours->commitment_fee + theirs->commitment_fee;
	permute_inputs(tx->input, 2, inmap);
	permute_outputs(tx->output, 2, NULL);
	return tx;
}
