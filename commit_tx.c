#include "bitcoin/pubkey.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/tx.h"
#include "commit_tx.h"
#include "permute_tx.h"
#include "pkt.h"
#include "protobuf_convert.h"

struct bitcoin_tx *create_commit_tx(const tal_t *ctx,
				    OpenChannel *ours,
				    OpenChannel *theirs,
				    const struct sha256 *rhash,
				    int64_t delta,
				    const struct sha256_double *anchor_txid,
				    unsigned int anchor_output)
{
	struct bitcoin_tx *tx;
	const u8 *redeemscript;
	struct pubkey ourkey, theirkey, to_me;
	u32 locktime;

	/* Now create commitment tx: one input, two outputs. */
	tx = bitcoin_tx(ctx, 1, 2);

	/* Our input spends the anchor tx output. */
	tx->input[0].txid = *anchor_txid;
	tx->input[0].index = anchor_output;

	/* Output goes to our final pubkeys */
	if (!proto_to_pubkey(ours->final, &ourkey))
		return tal_free(tx);
	if (!proto_to_pubkey(theirs->final, &theirkey))
		return tal_free(tx);

	if (!proto_to_locktime(ours, &locktime))
		return tal_free(tx);

	/* First output is a P2SH to a complex redeem script (usu. for me) */
	redeemscript = bitcoin_redeem_revocable(tx, &ourkey,
						locktime,
						&theirkey,
						rhash);
	tx->output[0].script = scriptpubkey_p2sh(tx, redeemscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);

	if (ours->anchor->total < ours->commitment_fee)
		return tal_free(tx);
	tx->output[0].amount = ours->anchor->total - ours->commitment_fee;
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

	if (theirs->anchor->total < theirs->commitment_fee)
		return tal_free(tx);
	tx->output[1].amount = theirs->anchor->total - theirs->commitment_fee;
	/* Asking for more than they have? */
	if (delta > 0 && delta > tx->output[1].amount)
		return tal_free(tx);
	tx->output[0].amount -= delta;

	permute_outputs(ours->seed, theirs->seed, 1, tx->output, 2, NULL);
	return tx;
}
