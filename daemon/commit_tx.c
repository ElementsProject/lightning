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

u8 *wscript_for_htlc(const tal_t *ctx,
		     secp256k1_context *secpctx,
		     const struct htlc *h,
		     const struct pubkey *our_final,
		     const struct pubkey *their_final,
		     const struct rel_locktime *our_locktime,
		     const struct rel_locktime *their_locktime,
		     const struct sha256 *rhash,
		     enum htlc_side side)
{
	u8 *(*fn)(const tal_t *, secp256k1_context *,
		  const struct pubkey *, const struct pubkey *,
		  const struct abs_locktime *, const struct rel_locktime *,
		  const struct sha256 *, const struct sha256 *);

	/* scripts are different for htlcs offered vs accepted */
	if (side == htlc_owner(h))
		fn = bitcoin_redeem_htlc_send;
	else
		fn = bitcoin_redeem_htlc_recv;

	if (side == LOCAL)
		return fn(ctx, secpctx, our_final, their_final,
			  &h->expiry, our_locktime, rhash, &h->rhash);
	else
		return fn(ctx, secpctx, their_final, our_final,
			  &h->expiry, their_locktime, rhash, &h->rhash);
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
	enum htlc_side htlc_side;

	/* Now create commitment tx: one input, two outputs (plus htlcs) */
	tx = bitcoin_tx(ctx, 1, 2 + tal_count(cstate->side[OURS].htlcs)
			+ tal_count(cstate->side[THEIRS].htlcs));

	/* Our input spends the anchor tx output. */
	tx->input[0].txid = *anchor_txid;
	tx->input[0].index = anchor_index;
	tx->input[0].amount = tal_dup(tx->input, u64, &anchor_satoshis);

	/* For our commit tx, our payment is delayed by amount they said */
	if (side == OURS) {
		htlc_side = LOCAL;
		self = our_final;
		other = their_final;
		locktime = their_locktime;
	} else {
		htlc_side = REMOTE;
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

	for (i = 0; i < tal_count(cstate->side[side].htlcs); i++) {
		tx->output[num].script
			= scriptpubkey_p2wsh(tx,
				wscript_for_htlc(tx, secpctx,
						 cstate->side[side].htlcs[i],
						 our_final, their_final,
						 our_locktime, their_locktime,
						 rhash, htlc_side));
		tx->output[num].script_length
			= tal_count(tx->output[num].script);
		tx->output[num].amount
			= cstate->side[side].htlcs[i]->msatoshis / 1000;
		total += tx->output[num++].amount;
	}
	for (i = 0; i < tal_count(cstate->side[!side].htlcs); i++) {
		tx->output[num].script
			= scriptpubkey_p2wsh(tx,
				wscript_for_htlc(tx, secpctx,
						 cstate->side[!side].htlcs[i],
						 our_final, their_final,
						 our_locktime, their_locktime,
						 rhash, htlc_side));
		tx->output[num].script_length
			= tal_count(tx->output[num].script);
		tx->output[num].amount
			= cstate->side[!side].htlcs[i]->msatoshis / 1000;
		total += tx->output[num++].amount;
	}
	assert(num == tx->output_count);
	assert(total <= anchor_satoshis);

	*map = tal_arr(ctx, int, tx->output_count);
	permute_outputs(tx->output, tx->output_count, *map);
	remove_dust(tx, *map);

	return tx;
}
