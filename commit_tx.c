#include "bitcoin/locktime.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/tx.h"
#include "commit_tx.h"
#include "funding.h"
#include "overflows.h"
#include "permute_tx.h"
#include "remove_dust.h"
#include <assert.h>

static bool add_htlc(struct bitcoin_tx *tx, size_t n,
		     const struct channel_htlc *h,
		     const struct pubkey *ourkey,
		     const struct pubkey *theirkey,
		     const struct sha256 *rhash,
		     const struct rel_locktime *locktime,
		     u8 *(*scriptpubkeyfn)(const tal_t *,
					   const struct pubkey *,
					   const struct pubkey *,
					   const struct abs_locktime *,
					   const struct rel_locktime *,
					   const struct sha256 *,
					   const struct sha256 *))
{
	assert(!tx->output[n].script);

	tx->output[n].script = scriptpubkey_p2wsh(tx,
				 scriptpubkeyfn(tx, ourkey, theirkey,
						&h->expiry, locktime, rhash,
						&h->rhash));
	tx->output[n].script_length = tal_count(tx->output[n].script);
	tx->output[n].amount = h->msatoshis / 1000;
	return true;
}

struct bitcoin_tx *create_commit_tx(const tal_t *ctx,
				    const struct pubkey *our_final,
				    const struct pubkey *their_final,
				    const struct rel_locktime *their_locktime,
				    const struct sha256_double *anchor_txid,
				    unsigned int anchor_index,
				    u64 anchor_satoshis,
				    const struct sha256 *rhash,
				    const struct channel_state *cstate,
				    int **map)
{
	struct bitcoin_tx *tx;
	const u8 *redeemscript;
	size_t i, num;
	uint64_t total;

	/* Now create commitment tx: one input, two outputs (plus htlcs) */
	tx = bitcoin_tx(ctx, 1, 2 + tal_count(cstate->a.htlcs)
			+ tal_count(cstate->b.htlcs));

	/* Our input spends the anchor tx output. */
	tx->input[0].txid = *anchor_txid;
	tx->input[0].index = anchor_index;
	tx->input[0].amount = tal_dup(tx->input, u64, &anchor_satoshis);

	/* First output is a P2WSH to a complex redeem script (usu. for me) */
	redeemscript = bitcoin_redeem_secret_or_delay(tx, our_final,
						      their_locktime,
						      their_final,
						      rhash);
	tx->output[0].script = scriptpubkey_p2wsh(tx, redeemscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);
	tx->output[0].amount = cstate->a.pay_msat / 1000;

	/* Second output is a P2WPKH payment to them. */
	tx->output[1].script = scriptpubkey_p2wpkh(tx, their_final);
	tx->output[1].script_length = tal_count(tx->output[1].script);
	tx->output[1].amount = cstate->b.pay_msat / 1000;

	/* First two outputs done, now for the HTLCs. */
	total = tx->output[0].amount + tx->output[1].amount;
	num = 2;

	/* HTLCs we've sent. */
	for (i = 0; i < tal_count(cstate->a.htlcs); i++) {
		if (!add_htlc(tx, num, &cstate->a.htlcs[i],
			      our_final, their_final,
			      rhash, their_locktime, scriptpubkey_htlc_send))
			return tal_free(tx);
		total += tx->output[num++].amount;
	}
	/* HTLCs we've received. */
	for (i = 0; i < tal_count(cstate->b.htlcs); i++) {
		if (!add_htlc(tx, num, &cstate->b.htlcs[i],
			      our_final, their_final,
			      rhash, their_locktime, scriptpubkey_htlc_recv))
			return tal_free(tx);
		total += tx->output[num++].amount;
	}
	assert(num == tx->output_count);
	assert(total <= anchor_satoshis);

	*map = tal_arr(ctx, int, tx->output_count);
	permute_outputs(tx->output, tx->output_count, *map);
	remove_dust(tx, *map);

	return tx;
}
