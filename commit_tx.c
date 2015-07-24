#include "bitcoin/pubkey.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/tx.h"
#include "commit_tx.h"
#include "overflows.h"
#include "permute_tx.h"
#include "pkt.h"
#include "protobuf_convert.h"

struct bitcoin_tx *create_commit_tx(const tal_t *ctx,
				    OpenChannel *ours,
				    OpenChannel *theirs,
				    const struct sha256 *rhash,
				    int64_t delta,
				    const struct sha256_double *anchor_txid1,
				    unsigned int index1, uint64_t input_amount1,
				    const struct sha256_double *anchor_txid2,
				    unsigned int index2, uint64_t input_amount2,
				    size_t inmap[2])
{
	struct bitcoin_tx *tx;
	const u8 *redeemscript;
	struct pubkey ourkey, theirkey, to_me;
	u32 locktime;

	/* Now create commitment tx: two inputs, two outputs. */
	tx = bitcoin_tx(ctx, 2, 2);

	/* Our inputs spend the anchor txs outputs. */
	tx->input[0].txid = *anchor_txid1;
	tx->input[0].index = index1;
	tx->input[0].input_amount = input_amount1;
	tx->input[1].txid = *anchor_txid2;
	tx->input[1].index = index2;
	tx->input[1].input_amount = input_amount2;

	if (add_overflows_u64(tx->input[0].input_amount,
			      tx->input[1].input_amount))
		return tal_free(tx);

	/* Output goes to our final pubkeys */
	if (!proto_to_pubkey(ours->final, &ourkey))
		return tal_free(tx);
	if (!proto_to_pubkey(theirs->final, &theirkey))
		return tal_free(tx);

	if (!proto_to_locktime(theirs, &locktime))
		return tal_free(tx);

	/* First output is a P2SH to a complex redeem script (usu. for me) */
	redeemscript = bitcoin_redeem_secret_or_delay(tx, &ourkey,
						      locktime,
						      &theirkey,
						      rhash);
	tx->output[0].script = scriptpubkey_p2sh(tx, redeemscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);

	if (ours->total_input < ours->commitment_fee)
		return tal_free(tx);
	tx->output[0].amount = ours->total_input - ours->commitment_fee;
	/* Asking for more than we have? */
	if (delta < 0 && -delta > tx->output[0].amount)
		return tal_free(tx);
	tx->output[0].amount += delta;
	
	/* Second output is a P2SH payment to them. */
	if (!proto_to_pubkey(theirs->final, &to_me))
		return tal_free(tx);
	tx->output[1].script = scriptpubkey_p2sh(ctx,
						 bitcoin_redeem_single(ctx,
								       &to_me));
	tx->output[1].script_length = tal_count(tx->output[1].script);

	if (theirs->total_input < theirs->commitment_fee)
		return tal_free(tx);
	tx->output[1].amount = theirs->total_input - theirs->commitment_fee;
	/* Asking for more than they have? */
	if (delta > 0 && delta > tx->output[1].amount)
		return tal_free(tx);
	tx->output[0].amount -= delta;

	/* Calculate fee; difference of inputs and outputs. */
	tx->fee = tx->input[0].input_amount + tx->input[1].input_amount
		- (tx->output[0].amount + tx->output[1].amount);

	permute_inputs(tx->input, 2, inmap);
	permute_outputs(tx->output, 2, NULL);
	return tx;
}
