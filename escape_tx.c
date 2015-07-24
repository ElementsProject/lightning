#include "bitcoin/pubkey.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/tx.h"
#include "escape_tx.h"
#include "protobuf_convert.h"

static struct bitcoin_tx *escape_tx(const tal_t *ctx,
				    const u8 *redeemscript,
				    const struct sha256_double *anchor_txid,
				    unsigned int anchor_index,
				    uint64_t input_amount,
				    uint64_t escape_fee)
{
	struct bitcoin_tx *tx = bitcoin_tx(ctx, 1, 1);

	/* Our input spends the anchor tx output. */
	tx->input[0].txid = *anchor_txid;
	tx->input[0].index = anchor_index;
	tx->input[0].input_amount = input_amount;

	/* Escape fee must be sane. */
	tx->fee = escape_fee;
	if (tx->fee > input_amount)
		return tal_free(tx);
	tx->output[0].amount = input_amount - tx->fee;
	tx->output[0].script = scriptpubkey_p2sh(tx, redeemscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);

	return tx;
}

struct bitcoin_tx *create_escape_tx(const tal_t *ctx,
				    OpenChannel *ours,
				    OpenChannel *theirs,
				    const struct sha256_double *anchor_txid,
				    unsigned int anchor_index,
				    uint64_t input_amount,
				    uint64_t escape_fee)
{
	struct bitcoin_tx *tx;
	const u8 *redeemscript;
	struct pubkey ourkey, theirkey;
	struct sha256 rhash;
	u32 locktime;

	/* Outputs goes to final pubkey */
	if (!proto_to_pubkey(ours->final, &ourkey))
		return NULL;
	if (!proto_to_pubkey(theirs->final, &theirkey))
		return NULL;;
	if (!proto_to_locktime(theirs, &locktime))
		return NULL;

	/* They can have it if they they present revocation preimage. */
	proto_to_sha256(ours->escape_hash, &rhash);

	redeemscript = bitcoin_redeem_secret_or_delay(ctx, &ourkey, locktime,
						      &theirkey, &rhash);

	tx = escape_tx(ctx, redeemscript, anchor_txid, anchor_index,
		       input_amount, escape_fee);
	tal_free(redeemscript);
	return tx;
}

struct bitcoin_tx *create_fast_escape_tx(const tal_t *ctx,
					 OpenChannel *ours,
					 OpenChannel *theirs,
					 const struct sha256_double *anchor_txid,
					 unsigned int anchor_index,
					 uint64_t input_amount,
					 uint64_t escape_fee)
{
	struct bitcoin_tx *tx;
	const u8 *redeemscript;
	struct pubkey ourkey, theirkey;
	struct sha256 ehash;
	u32 locktime;

	/* Outputs goes to final pubkey */
	if (!proto_to_pubkey(ours->final, &ourkey))
		return NULL;
	if (!proto_to_pubkey(theirs->final, &theirkey))
		return NULL;
	if (!proto_to_locktime(theirs, &locktime))
		return NULL;

	/* We can have it if we present their escape preimage. */
	proto_to_sha256(theirs->escape_hash, &ehash);

	redeemscript = bitcoin_redeem_secret_or_delay(ctx, &theirkey, locktime,
						      &ourkey, &ehash);

	tx = escape_tx(ctx, redeemscript, anchor_txid, anchor_index,
		       input_amount, escape_fee);
	tal_free(redeemscript);
	return tx;
}
