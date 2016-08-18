#include "bitcoin/locktime.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/tx.h"
#include "channel.h"
#include "commit_tx.h"
#include "htlc.h"
#include "overflows.h"
#include "permute_tx.h"
#include "remove_dust.h"
#include <assert.h>

static bool add_htlc(struct bitcoin_tx *tx, size_t n,
		     secp256k1_context *secpctx,
		     const struct htlc *h,
		     const struct pubkey *ourkey,
		     const struct pubkey *theirkey,
		     const struct sha256 *rhash,
		     const struct rel_locktime *locktime,
		     u8 *(*scriptpubkeyfn)(const tal_t *,
					   secp256k1_context *,
					   const struct pubkey *,
					   const struct pubkey *,
					   const struct abs_locktime *,
					   const struct rel_locktime *,
					   const struct sha256 *,
					   const struct sha256 *))
{
	assert(!tx->output[n].script);

	tx->output[n].script = scriptpubkey_p2wsh(tx,
				 scriptpubkeyfn(tx, secpctx, ourkey, theirkey,
						&h->expiry, locktime, rhash,
						&h->rhash));
	tx->output[n].script_length = tal_count(tx->output[n].script);
	tx->output[n].amount = h->msatoshis / 1000;
	return true;
}

struct bitcoin_tx *create_commit_tx(const tal_t *ctx,
				    secp256k1_context *secpctx,
				    const struct pubkey *our_final,
				    const struct pubkey *their_final,
				    const struct rel_locktime *our_locktime,
				    const struct rel_locktime *their_locktime,
				    const struct sha256_double *anchor_txid,
				    unsigned int anchor_index,
				    u64 anchor_satoshis,
				    const struct sha256 *rhash,
				    const struct channel_state *cstate,
				    enum channel_side side,
				    int **map)
{
	struct bitcoin_tx *tx;
	const u8 *redeemscript;
	size_t i, num;
	uint64_t total;
	const struct pubkey *self, *other;
	const struct rel_locktime *locktime;

	/* Now create commitment tx: one input, two outputs (plus htlcs) */
	tx = bitcoin_tx(ctx, 1, 2 + tal_count(cstate->side[OURS].htlcs)
			+ tal_count(cstate->side[THEIRS].htlcs));

	/* Our input spends the anchor tx output. */
	tx->input[0].txid = *anchor_txid;
	tx->input[0].index = anchor_index;
	tx->input[0].amount = tal_dup(tx->input, u64, &anchor_satoshis);

	/* For our commit tx, our payment is delayed by amount they said */
	if (side == OURS) {
		self = our_final;
		other = their_final;
		locktime = their_locktime;
	} else {
		self = their_final;
		other = our_final;
		locktime = our_locktime;
	}
	
	/* First output is a P2WSH to a complex redeem script
	 * (usu. for this side) */
	redeemscript = bitcoin_redeem_secret_or_delay(tx, secpctx, self,
						      locktime,
						      other,
						      rhash);
	tx->output[0].script = scriptpubkey_p2wsh(tx, redeemscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);
	tx->output[0].amount = cstate->side[side].pay_msat / 1000;

	/* Second output is a P2WPKH payment to other side. */
	tx->output[1].script = scriptpubkey_p2wpkh(tx, secpctx, other);
	tx->output[1].script_length = tal_count(tx->output[1].script);
	tx->output[1].amount = cstate->side[!side].pay_msat / 1000;

	/* First two outputs done, now for the HTLCs. */
	total = tx->output[0].amount + tx->output[1].amount;
	num = 2;

	/* HTLCs this side sent. */
	for (i = 0; i < tal_count(cstate->side[side].htlcs); i++) {
		if (!add_htlc(tx, num, secpctx, cstate->side[side].htlcs[i],
			      self, other, rhash, locktime,
			      bitcoin_redeem_htlc_send))
			return tal_free(tx);
		total += tx->output[num++].amount;
	}
	/* HTLCs this side has received. */
	for (i = 0; i < tal_count(cstate->side[!side].htlcs); i++) {
		if (!add_htlc(tx, num, secpctx, cstate->side[!side].htlcs[i],
			      self, other, rhash, locktime,
			      bitcoin_redeem_htlc_recv))
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
