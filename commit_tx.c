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
				    OpenAnchor *anchor,
				    const struct sha256 *rhash,
				    uint64_t to_us, uint64_t to_them)
{
	struct bitcoin_tx *tx;
	const u8 *redeemscript;
	struct pubkey ourkey, theirkey;
	u32 locktime;

	/* Now create commitment tx: one input, two outputs. */
	tx = bitcoin_tx(ctx, 1, 2);

	/* Our input spends the anchor tx output. */
	proto_to_sha256(anchor->txid, &tx->input[0].txid.sha);
	tx->input[0].index = anchor->output_index;
	tx->input[0].input_amount = anchor->amount;

	/* Output goes to our final pubkeys */
	if (!proto_to_pubkey(ours->final_key, &ourkey))
		return tal_free(tx);
	if (!proto_to_pubkey(theirs->final_key, &theirkey))
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
	tx->output[0].amount = to_us;

	/* Second output is a P2SH payment to them. */
	tx->output[1].script = scriptpubkey_p2sh(ctx,
						 bitcoin_redeem_single(ctx,
							       &theirkey));
	tx->output[1].script_length = tal_count(tx->output[1].script);
	tx->output[1].amount = to_them;

	/* Calculate fee; difference of inputs and outputs. */
	assert(tx->output[0].amount + tx->output[1].amount
	       <= tx->input[0].input_amount);
	tx->fee = tx->input[0].input_amount
		- (tx->output[0].amount + tx->output[1].amount);

	permute_outputs(tx->output, 2, NULL);
	return tx;
}
