/* Code to talk to bitcoind to watch for various events.
 *
 * Here's what we want to know:
 *
 * - An anchor tx:
 *   - Reached given depth
 *   - Times out.
 *   - Is unspent after reaching given depth.
 *
 * - Our own commitment tx:
 *   - Reached a given depth.
 *
 * - HTLC spend tx:
 *   - Reached a given depth.
 * 
 * - Anchor tx output:
 *   - Is spent by their current tx.
 *   - Is spent by a revoked tx.
 *
 * - Commitment tx HTLC outputs:
 *   - HTLC timed out
 *   - HTLC spent
 *
 * We do this by adding the P2SH address to the wallet, and then querying
 * that using listtransactions.
 *
 * WE ASSUME NO MALLEABILITY!  This requires segregated witness.
 */
#include "bitcoin/script.h"
#include "bitcoin/tx.h"
#include "bitcoind.h"
#include "lightningd.h"
#include "log.h"
#include "peer.h"
#include "timeout.h"
#include "watch.h"
#include <ccan/hash/hash.h>
#include <ccan/structeq/structeq.h>

const struct txwatch_output *txowatch_keyof(const struct txowatch *w)
{
	return &w->out;
}

size_t txo_hash(const struct txwatch_output *out)
{
	return hash(&out->txid, 1, out->index);
}

bool txowatch_eq(const struct txowatch *w, const struct txwatch_output *out)
{
	return structeq(&w->out.txid, &out->txid)
		&& w->out.index == out->index;
}

static void destroy_txowatch(struct txowatch *w)
{
	txowatch_hash_del(&w->peer->dstate->txowatches, w);
}

/* Watch a txo. */
static void insert_txo_watch(struct peer *peer,
			     const struct sha256_double *txid,
			     unsigned int txout,
			     void (*cb)(struct peer *peer,
					const struct bitcoin_tx *tx,
					void *cbdata),
			     void *cbdata)
{
	struct txowatch *w = tal(peer, struct txowatch);

	w->out.txid = *txid;
	w->out.index = txout;
	w->peer = peer;
	w->cb = cb;
	w->cbdata = cbdata;

	txowatch_hash_add(&w->peer->dstate->txowatches, w);
	tal_add_destructor(w, destroy_txowatch);
}

const struct sha256_double *txwatch_keyof(const struct txwatch *w)
{
	return &w->txid;
}

size_t txid_hash(const struct sha256_double *txid)
{
	return hash(txid->sha.u.u8, sizeof(txid->sha.u.u8), 0);
}

bool txwatch_eq(const struct txwatch *w, const struct sha256_double *txid)
{
	return structeq(&w->txid, txid);
}

static void destroy_txwatch(struct txwatch *w)
{
	txwatch_hash_del(&w->dstate->txwatches, w);
}

static struct txwatch *insert_txwatch(const tal_t *ctx,
				      struct lightningd_state *dstate,
				      struct peer *peer,
				      const struct sha256_double *txid,
				      void (*cb)(struct peer *, int, void *),
				      void *cbdata)
{
	struct txwatch *w;

	/* We could have a null-watch on it because we saw it spend a TXO */
	w = txwatch_hash_get(&dstate->txwatches, txid);
	if (w) {
		assert(!w->cb);
		tal_free(w);
	}

	w = tal(ctx, struct txwatch);
	w->depth = 0;
	w->txid = *txid;
	w->dstate = dstate;
	w->peer = peer;
	w->cb = cb;
	w->cbdata = cbdata;

	txwatch_hash_add(&w->dstate->txwatches, w);
	tal_add_destructor(w, destroy_txwatch);

	return w;
}

void add_anchor_watch_(struct peer *peer,
		       const struct sha256_double *txid,
		       unsigned int out,
		       void (*anchor_cb)(struct peer *peer, int depth, void *),
		       void (*spend_cb)(struct peer *peer,
					const struct bitcoin_tx *, void *),
		       void *cbdata)
{
	struct sha256 h;
	struct ripemd160 redeemhash;
	u8 *redeemscript;

	insert_txwatch(peer, peer->dstate, peer, txid, anchor_cb, cbdata);
	insert_txo_watch(peer, txid, out, spend_cb, cbdata);

	redeemscript = bitcoin_redeem_2of2(peer, &peer->them.commitkey,
					   &peer->us.commitkey);
	sha256(&h, redeemscript, tal_count(redeemscript));
	ripemd160(&redeemhash, h.u.u8, sizeof(h));
	tal_free(redeemscript);

	/* Telling bitcoind to watch the redeemhash address means
	 * it'll tell is about the anchor itself (spend to that
	 * address), and any commit txs (spend from that address).*/
	bitcoind_watch_addr(peer->dstate, &redeemhash);
}

void add_commit_tx_watch_(struct peer *peer,
			  const struct sha256_double *txid,
			  void (*cb)(struct peer *peer, int depth, void *),
			  void *cbdata)
{
	insert_txwatch(peer, peer->dstate, peer, txid, cb, cbdata);

	/* We are already watching the anchor txo, so we don't need to
	 * watch anything else. */
}

static void tx_watched_inputs(struct lightningd_state *dstate,
			      const struct bitcoin_tx *tx, void *unused)
{
	size_t in;

	for (in = 0; in < tx->input_count; in++) {
		struct txwatch_output out;
		struct txowatch *txow;

		out.txid = tx->input[in].txid;
		out.index = tx->input[in].index;

		txow = txowatch_hash_get(&dstate->txowatches, &out);
		if (txow)
			txow->cb(txow->peer, tx, txow->cbdata);
	}
}

static void watched_transaction(struct lightningd_state *dstate,
				const struct sha256_double *txid,
				int confirmations,
				bool is_coinbase)

{
	struct txwatch *txw;

	/* Are we watching this txid directly (or already reported)? */
	txw = txwatch_hash_get(&dstate->txwatches, txid);
	if (txw) {
		if (confirmations != txw->depth) {
			txw->depth = confirmations;
			if (txw->cb)
				txw->cb(txw->peer, txw->depth, txw->cbdata);
		}
		return;
	}

	/* Don't report about this txid twice. */
	insert_txwatch(dstate, dstate, NULL, txid, NULL, NULL);

	/* Maybe it spent an output we're watching? */
	if (!is_coinbase)
		bitcoind_txid_lookup(dstate, txid, tx_watched_inputs, NULL);
}

static struct timeout watch_timeout;

static void start_poll_transactions(struct lightningd_state *dstate)
{
	if (!list_empty(&dstate->bitcoin_req)) {
		log_unusual(dstate->base_log,
			    "Delaying start poll: commands in progress");
	} else
		bitcoind_poll_transactions(dstate, watched_transaction);
	refresh_timeout(dstate, &watch_timeout);
}

void setup_watch_timer(struct lightningd_state *dstate)
{
	init_timeout(&watch_timeout, dstate->config.poll_seconds,
		     start_poll_transactions, dstate);
	/* Run once immediately, in case there are issues. */
	start_poll_transactions(dstate);
}
