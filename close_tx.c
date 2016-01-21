#include "bitcoin/pubkey.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/tx.h"
#include "close_tx.h"
#include "permute_tx.h"
#include "protobuf_convert.h"

struct bitcoin_tx *create_close_tx(secp256k1_context *secpctx,
				   const tal_t *ctx,
				   OpenChannel *ours,
				   OpenChannel *theirs,
				   OpenAnchor *anchor,
				   uint64_t to_us, uint64_t to_them)
{
	struct bitcoin_tx *tx;
	const u8 *redeemscript;
	struct pubkey ourkey, theirkey;
	struct sha256 redeem;

	/* Now create close tx: one input, two outputs. */
	tx = bitcoin_tx(ctx, 1, 2);

	/* Our input spends the anchor tx output. */
	proto_to_sha256(anchor->txid, &tx->input[0].txid.sha);
	tx->input[0].index = anchor->output_index;
	tx->input[0].input_amount = anchor->amount;

	/* Outputs goes to final pubkey */
	if (!proto_to_pubkey(secpctx, ours->final_key, &ourkey))
		return tal_free(tx);
	if (!proto_to_pubkey(secpctx, theirs->final_key, &theirkey))
		return tal_free(tx);


	proto_to_sha256(ours->revocation_hash, &redeem);

	/* One output is to us. */
	tx->output[0].amount = to_us;
	redeemscript = bitcoin_redeem_single(tx, &ourkey);
	tx->output[0].script = scriptpubkey_p2sh(tx, redeemscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Other output is to them. */
	tx->output[1].amount = to_them;
	redeemscript = bitcoin_redeem_single(tx, &theirkey);
	tx->output[1].script = scriptpubkey_p2sh(tx, redeemscript);
	tx->output[1].script_length = tal_count(tx->output[1].script);

	assert(tx->output[0].amount + tx->output[1].amount
	       <= tx->input[0].input_amount);
	tx->fee = tx->input[0].input_amount
		- (tx->output[0].amount + tx->output[1].amount);

	permute_outputs(tx->output, 2, NULL);
	return tx;
}
