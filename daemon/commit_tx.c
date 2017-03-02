#include "bitcoin/locktime.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/tx.h"
#include "channel.h"
#include "commit_tx.h"
#include "htlc.h"
#include "lightningd.h"
#include "log.h"
#include "overflows.h"
#include "peer.h"
#include "peer_internal.h"
#include "permute_tx.h"
#include "remove_dust.h"
#include "utils.h"
#include <assert.h>
#include <inttypes.h>

u8 *wscript_for_htlc(const tal_t *ctx,
		     const struct peer *peer,
		     const struct htlc *h,
		     const struct sha256 *rhash,
		     enum side side)
{
	const struct peer_visible_state *this_side, *other_side;
	u8 *(*fn)(const tal_t *,
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

	return fn(ctx,
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
			enum side side,
			u8 **wscript)
{
	u8 *tmp;
	if (!wscript)
		wscript = &tmp;

	/* Our output to ourself is encumbered by delay. */
	if (side == LOCAL) {
		*wscript = bitcoin_redeem_secret_or_delay(ctx,
							  &peer->local.finalkey,
							  &peer->remote.locktime,
							  &peer->remote.finalkey,
							  rhash);
		return scriptpubkey_p2wsh(ctx, *wscript);
	} else {
		/* Their output to us is a simple p2wpkh */
		*wscript = NULL;
		return scriptpubkey_p2wpkh(ctx, &peer->local.finalkey);
	}
}

u8 *commit_output_to_them(const tal_t *ctx,
			  const struct peer *peer,
			  const struct sha256 *rhash,
			  enum side side,
			  u8 **wscript)
{
	u8 *tmp;
	if (!wscript)
		wscript = &tmp;

	/* Their output to themselves is encumbered by delay. */
	if (side == REMOTE) {
		*wscript = bitcoin_redeem_secret_or_delay(ctx,
							  &peer->remote.finalkey,
							  &peer->local.locktime,
							  &peer->local.finalkey,
							  rhash);
		return scriptpubkey_p2wsh(ctx, *wscript);
	} else {
		/* Our output to them is a simple p2wpkh */
		*wscript = NULL;
		return scriptpubkey_p2wpkh(ctx, &peer->remote.finalkey);
	}
}

/* Takes ownership of script. */
static bool add_output(struct bitcoin_tx *tx, u8 *script, u64 amount,
		       size_t *output_count,
		       u64 *total)
{
	assert(*output_count < tal_count(tx->output));
	if (is_dust(amount))
		return false;
	tx->output[*output_count].script = tal_steal(tx, script);
	tx->output[*output_count].amount = amount;
	(*output_count)++;
	(*total) += amount;
	return true;
}

struct bitcoin_tx *create_commit_tx(const tal_t *ctx,
				    struct peer *peer,
				    const struct sha256 *rhash,
				    const struct channel_state *cstate,
				    enum side side,
				    bool *otherside_only)
{
	const tal_t *tmpctx = tal_tmpctx(ctx);
	struct bitcoin_tx *tx;
	uint64_t total = 0;
	struct htlc_map_iter it;
	struct htlc *h;
	size_t output_count;
	bool pays_to[2];
	int committed_flag = HTLC_FLAG(side,HTLC_F_COMMITTED);

	/* Now create commitment tx: one input, two outputs (plus htlcs) */
	tx = bitcoin_tx(ctx, 1, 2 + count_htlcs(&peer->htlcs, committed_flag));

 	log_debug(peer->log, "Creating commitment tx:");
	log_add_struct(peer->log, " rhash = %s", struct sha256, rhash);
	log_add_struct(peer->log, " My finalkey = %s", struct pubkey,
		       &peer->local.finalkey);
	log_add_struct(peer->log, " Their finalkey = %s", struct pubkey,
		       &peer->remote.finalkey);
	log_add_struct(peer->log, " My locktime = %s", struct rel_locktime,
		       &peer->local.locktime);
	log_add_struct(peer->log, " Their locktime = %s", struct rel_locktime,
		       &peer->remote.locktime);

	/* Our input spends the anchor tx output. */
	tx->input[0].txid = peer->anchor.txid;
	tx->input[0].index = peer->anchor.index;
	tx->input[0].amount = tal_dup(tx->input, u64, &peer->anchor.satoshis);

	output_count = 0;
	pays_to[LOCAL] = add_output(tx, commit_output_to_us(tmpctx, peer, rhash,
							    side, NULL),
				    cstate->side[LOCAL].pay_msat / 1000,
				    &output_count,
				    &total);
	if (pays_to[LOCAL])
		log_debug(peer->log, "Pays %u to local: %s",
			  cstate->side[LOCAL].pay_msat / 1000,
			  tal_hex(tmpctx, tx->output[output_count-1].script));
	else
		log_debug(peer->log, "DOES NOT pay %u to local",
			  cstate->side[LOCAL].pay_msat / 1000);
	pays_to[REMOTE] = add_output(tx, commit_output_to_them(tmpctx, peer,
							       rhash, side,
							       NULL),
				     cstate->side[REMOTE].pay_msat / 1000,
				     &output_count,
				     &total);
	if (pays_to[REMOTE])
		log_debug(peer->log, "Pays %u to remote: %s",
			  cstate->side[REMOTE].pay_msat / 1000,
			  tal_hex(tmpctx, tx->output[output_count-1].script));
	else
		log_debug(peer->log, "DOES NOT pay %u to remote",
			  cstate->side[REMOTE].pay_msat / 1000);

	/* If their tx doesn't pay to them, or our tx doesn't pay to us... */
	*otherside_only = !pays_to[side];

	/* First two outputs done, now for the HTLCs. */
	for (h = htlc_map_first(&peer->htlcs, &it);
	     h;
	     h = htlc_map_next(&peer->htlcs, &it)) {
		const u8 *wscript;

		if (!htlc_has(h, committed_flag))
			continue;
		wscript = wscript_for_htlc(tmpctx, peer, h, rhash, side);
		/* If we pay any HTLC, it's txout is not just to other side. */
		if (add_output(tx, scriptpubkey_p2wsh(tmpctx, wscript),
			       h->msatoshi / 1000, &output_count, &total)) {
			*otherside_only = false;
			log_debug(peer->log, "Pays %"PRIu64" to htlc %"PRIu64,
				  h->msatoshi / 1000, h->id);
			log_add_struct(peer->log, " expiry %s",
				       struct abs_locktime, &h->expiry);
			log_add_struct(peer->log, " rhash %s", struct sha256,
				       &h->rhash);
			log_debug(peer->log, "Script: %s",
				  tal_hex(tmpctx, wscript));
		} else
			log_debug(peer->log, "DOES NOT pay %"PRIu64" to htlc %"PRIu64,
				  h->msatoshi / 1000, h->id);
	}
	assert(total <= peer->anchor.satoshis);

	tal_resize(&tx->output, output_count);
	permute_outputs(tx->output, tal_count(tx->output), NULL);
	tal_free(tmpctx);
	return tx;
}
