#include "bitcoin/locktime.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/tx.h"
#include "channel.h"
#include "commit_tx.h"
#include "htlc.h"
#include "lightningd.h"
#include "overflows.h"
#include "peer.h"
#include "permute_tx.h"
#include "remove_dust.h"
#include <assert.h>

u8 *wscript_for_htlc(const tal_t *ctx,
		     const struct peer *peer,
		     const struct htlc *h,
		     const struct sha256 *rhash,
		     enum htlc_side side)
{
	const struct peer_visible_state *this_side, *other_side;
	u8 *(*fn)(const tal_t *, secp256k1_context *,
		  const struct pubkey *, const struct pubkey *,
		  const struct abs_locktime *, const struct rel_locktime *,
		  const struct sha256 *, const struct sha256 *);

	/* scripts are different for htlcs offered vs accepted */
	if (side == htlc_owner(h))
		fn = bitcoin_redeem_htlc_send;
	else
		fn = bitcoin_redeem_htlc_recv;

	if (side == LOCAL) {
		this_side = &peer->local;
		other_side = &peer->remote;
	} else {
		this_side = &peer->remote;
		other_side = &peer->local;
	}

	return fn(ctx, peer->dstate->secpctx,
		  &this_side->finalkey, &other_side->finalkey,
		  &h->expiry, &this_side->locktime, rhash, &h->rhash);
}

static size_t count_htlcs(const struct htlc_map *htlcs, int flag)
{
	struct htlc_map_iter it;
	struct htlc *h;
	size_t n = 0;

	for (h = htlc_map_first(htlcs, &it); h; h = htlc_map_next(htlcs, &it)) {
		if (htlc_has(h, flag))
			n++;
	}
	return n;
}

u8 *commit_output_to_us(const tal_t *ctx,
			const struct peer *peer,
			const struct sha256 *rhash,
			enum htlc_side side,
			u8 **wscript)
{
	u8 *tmp;
	if (!wscript)
		wscript = &tmp;
	
	/* Our output to ourself is encumbered by delay. */
	if (side == LOCAL) {
		*wscript = bitcoin_redeem_secret_or_delay(ctx,
							  peer->dstate->secpctx,
							  &peer->local.finalkey,
							  &peer->remote.locktime,
							  &peer->remote.finalkey,
							  rhash);
		return scriptpubkey_p2wsh(ctx, *wscript);
	} else {
		/* Their output to us is a simple p2wpkh */
		*wscript = NULL;
		return scriptpubkey_p2wpkh(ctx, peer->dstate->secpctx,
					   &peer->local.finalkey);
	}
}

u8 *commit_output_to_them(const tal_t *ctx,
			  const struct peer *peer,
			  const struct sha256 *rhash,
			  enum htlc_side side,
			  u8 **wscript)
{
	u8 *tmp;
	if (!wscript)
		wscript = &tmp;

	/* Their output to themselves is encumbered by delay. */
	if (side == REMOTE) {
		*wscript = bitcoin_redeem_secret_or_delay(ctx,
							  peer->dstate->secpctx,
							  &peer->remote.finalkey,
							  &peer->local.locktime,
							  &peer->local.finalkey,
							  rhash);
		return scriptpubkey_p2wsh(ctx, *wscript);
	} else {
		/* Our output to them is a simple p2wpkh */
		*wscript = NULL;
		return scriptpubkey_p2wpkh(ctx, peer->dstate->secpctx,
					   &peer->remote.finalkey);
	}
}

struct bitcoin_tx *create_commit_tx(const tal_t *ctx,
				    struct peer *peer,
				    const struct sha256 *rhash,
				    const struct channel_state *cstate,
				    enum htlc_side side,
				    int **map)
{
	struct bitcoin_tx *tx;
	size_t num;
	uint64_t total;
	struct htlc_map_iter it;
	struct htlc *h;
	int committed_flag = HTLC_FLAG(side,HTLC_F_COMMITTED);

	/* Now create commitment tx: one input, two outputs (plus htlcs) */
	tx = bitcoin_tx(ctx, 1, 2 + count_htlcs(&peer->htlcs, committed_flag));

	/* Our input spends the anchor tx output. */
	tx->input[0].txid = peer->anchor.txid;
	tx->input[0].index = peer->anchor.index;
	tx->input[0].amount = tal_dup(tx->input, u64, &peer->anchor.satoshis);

	tx->output[0].script = commit_output_to_us(tx, peer, rhash, side, NULL);
	tx->output[0].script_length = tal_count(tx->output[0].script);
	tx->output[0].amount = cstate->side[OURS].pay_msat / 1000;

	tx->output[1].script = commit_output_to_them(tx, peer, rhash, side,NULL);
	tx->output[1].script_length = tal_count(tx->output[1].script);
	tx->output[1].amount = cstate->side[THEIRS].pay_msat / 1000;

	/* First two outputs done, now for the HTLCs. */
	total = tx->output[0].amount + tx->output[1].amount;
	num = 2;

	for (h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		if (!htlc_has(h, committed_flag))
			continue;
		tx->output[num].script
			= scriptpubkey_p2wsh(tx,
					     wscript_for_htlc(tx, peer, h,
							      rhash, side));
		tx->output[num].script_length
			= tal_count(tx->output[num].script);
		tx->output[num].amount = h->msatoshis / 1000;
		total += tx->output[num++].amount;
	}
	assert(num == tx->output_count);
	assert(total <= peer->anchor.satoshis);

	*map = tal_arr(ctx, int, tx->output_count);
	permute_outputs(tx->output, tx->output_count, *map);
	remove_dust(tx, *map);

	return tx;
}
