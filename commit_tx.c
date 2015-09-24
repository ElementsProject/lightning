#include "bitcoin/pubkey.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/tx.h"
#include "commit_tx.h"
#include "funding.h"
#include "overflows.h"
#include "permute_tx.h"
#include "pkt.h"
#include "protobuf_convert.h"

static bool add_htlc(struct bitcoin_tx *tx, size_t n,
		     const UpdateAddHtlc *h,
		     const struct pubkey *ourkey,
		     const struct pubkey *theirkey,
		     const struct sha256 *rhash,
		     u32 locktime,
		     u8 *(*scriptpubkeyfn)(const tal_t *,
					   const struct pubkey *,
					   const struct pubkey *,
					   uint32_t,
					   uint32_t,
					   const struct sha256 *,
					   const struct sha256 *))
{
	uint32_t htlc_abstime;
	struct sha256 htlc_rhash;

	assert(!tx->output[n].script);

	/* This shouldn't happen... */
	if (!proto_to_abs_locktime(h->expiry, &htlc_abstime))
		return false;

	proto_to_sha256(h->r_hash, &htlc_rhash);
	tx->output[n].script = scriptpubkey_p2sh(tx,
				 scriptpubkeyfn(tx, ourkey, theirkey,
						htlc_abstime, locktime, rhash,
						&htlc_rhash));
	tx->output[n].script_length = tal_count(tx->output[n].script);
	tx->output[n].amount = h->amount_msat / 1000;
	return true;
}

struct bitcoin_tx *create_commit_tx(const tal_t *ctx,
				    OpenChannel *ours,
				    OpenChannel *theirs,
				    OpenAnchor *anchor,
				    const struct sha256 *rhash,
				    const struct channel_state *cstate)
{
	struct bitcoin_tx *tx;
	const u8 *redeemscript;
	struct pubkey ourkey, theirkey;
	u32 locktime;
	size_t i, num;
	uint64_t total;

	/* Now create commitment tx: one input, two outputs (plus htlcs) */
	tx = bitcoin_tx(ctx, 1, 2 + tal_count(cstate->a.htlcs)
			+ tal_count(cstate->b.htlcs));

	/* Our input spends the anchor tx output. */
	proto_to_sha256(anchor->txid, &tx->input[0].txid.sha);
	tx->input[0].index = anchor->output_index;
	tx->input[0].input_amount = anchor->amount;

	/* Output goes to our final pubkeys */
	if (!proto_to_pubkey(ours->final_key, &ourkey))
		return tal_free(tx);
	if (!proto_to_pubkey(theirs->final_key, &theirkey))
		return tal_free(tx);

	if (!proto_to_rel_locktime(theirs->delay, &locktime))
		return tal_free(tx);

	/* First output is a P2SH to a complex redeem script (usu. for me) */
	redeemscript = bitcoin_redeem_secret_or_delay(tx, &ourkey,
						      locktime,
						      &theirkey,
						      rhash);
	tx->output[0].script = scriptpubkey_p2sh(tx, redeemscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);
	tx->output[0].amount = cstate->a.pay_msat / 1000;

	/* Second output is a P2SH payment to them. */
	tx->output[1].script = scriptpubkey_p2sh(ctx,
						 bitcoin_redeem_single(ctx,
							       &theirkey));
	tx->output[1].script_length = tal_count(tx->output[1].script);
	tx->output[1].amount = cstate->b.pay_msat / 1000;

	/* First two outputs done, now for the HTLCs. */
	total = tx->output[0].amount + tx->output[1].amount;
	num = 2;

	/* HTLCs we've sent. */
	for (i = 0; i < tal_count(cstate->a.htlcs); i++) {
		if (!add_htlc(tx, num, cstate->a.htlcs[i], &ourkey, &theirkey,
			      rhash, locktime, scriptpubkey_htlc_send))
			return tal_free(tx);
		total += tx->output[num++].amount;
	}
	/* HTLCs we've received. */
	for (i = 0; i < tal_count(cstate->b.htlcs); i++) {
		if (!add_htlc(tx, num, cstate->b.htlcs[i], &ourkey, &theirkey,
			      rhash, locktime, scriptpubkey_htlc_recv))
			return tal_free(tx);
		total += tx->output[num++].amount;
	}
	assert(num == tx->output_count);

	/* Calculate fee; difference of inputs and outputs. */
	assert(total <= tx->input[0].input_amount);
	tx->fee = tx->input[0].input_amount - total;

	permute_outputs(tx->output, tx->output_count, NULL);
	return tx;
}
