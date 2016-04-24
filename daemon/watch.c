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
#include "chaintopology.h"
#include "lightningd.h"
#include "log.h"
#include "peer.h"
#include "timeout.h"
#include "watch.h"
#include <ccan/hash/hash.h>
#include <ccan/ptrint/ptrint.h>
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

struct txwatch *watch_txid_(const tal_t *ctx,
			    struct peer *peer,
			    const struct sha256_double *txid,
			    void (*cb)(struct peer *peer, int depth,
				       const struct sha256_double *txid,
				       void *arg),
			    void *cb_arg)
{
	struct txwatch *w;

	assert(!txwatch_hash_get(&peer->dstate->txwatches, txid));

	w = tal(ctx, struct txwatch);
	w->depth = -1;
	w->txid = *txid;
	w->dstate = peer->dstate;
	w->peer = peer;
	w->cb = cb;
	w->cbdata = cb_arg;

	txwatch_hash_add(&w->dstate->txwatches, w);
	tal_add_destructor(w, destroy_txwatch);

	return w;
}

struct txwatch *watch_tx_(const tal_t *ctx,
			 struct peer *peer,
			 const struct bitcoin_tx *tx,
			 void (*cb)(struct peer *peer, int depth,
				    const struct sha256_double *txid,
				    void *arg),
			  void *cb_arg)
{
	struct sha256_double txid;

	normalized_txid(tx, &txid);
	return watch_txid(ctx, peer, &txid, cb, cb_arg);
}

struct txowatch *watch_txo_(const tal_t *ctx,
			    struct peer *peer,
			    const struct sha256_double *txid,
			    unsigned int output,
			    void (*cb)(struct peer *peer,
				       const struct bitcoin_tx *tx,
				       void *),
			    void *cbdata)
{
	struct txowatch *w = tal(ctx, struct txowatch);

	w->out.txid = *txid;
	w->out.index = output;
	w->peer = peer;
	w->cb = cb;
	w->cbdata = cbdata;

	txowatch_hash_add(&w->peer->dstate->txowatches, w);
	tal_add_destructor(w, destroy_txowatch);

	return w;
}


void txwatch_fire(struct lightningd_state *dstate,
		  struct txwatch *txw,
		  unsigned int depth)
{
	if (depth != txw->depth) {
		log_debug(txw->peer->log,
			  "Got depth change %u for %02x%02x%02x...\n",
			  txw->depth,
			  txw->txid.sha.u.u8[0],
			  txw->txid.sha.u.u8[1],
			  txw->txid.sha.u.u8[2]);
		txw->depth = depth;
		txw->cb(txw->peer, txw->depth, &txw->txid, txw->cbdata);
	}
}

void txowatch_fire(struct lightningd_state *dstate,
		   const struct txowatch *txow,
		   const struct bitcoin_tx *tx)
{
	struct sha256_double txid;

	bitcoin_txid(tx, &txid);
	log_debug(txow->peer->log,
		  "Got UTXO spend for %02x%02x%02x:%u: %02x%02x%02x%02x...\n",
		  txow->out.txid.sha.u.u8[0],
		  txow->out.txid.sha.u.u8[1],
		  txow->out.txid.sha.u.u8[2],
		  txow->out.index,
		  txid.sha.u.u8[0],
		  txid.sha.u.u8[1],
		  txid.sha.u.u8[2],
		  txid.sha.u.u8[3]);
	txow->cb(txow->peer, tx, txow->cbdata);
}

void watch_topology_changed(struct lightningd_state *dstate)
{
	struct txwatch_hash_iter i;
	struct txwatch *w;
	bool needs_rerun;

again:
	/* Iterating a htable during deletes is safe, but might skip entries. */
	needs_rerun = false;
	for (w = txwatch_hash_first(&dstate->txwatches, &i);
	     w;
	     w = txwatch_hash_next(&dstate->txwatches, &i)) {
		size_t depth;

		/* Don't fire if we haven't seen it at all. */
		if (w->depth == -1)
			continue;

		depth = get_tx_depth(dstate, w);
		if (depth != w->depth) {
			w->depth = depth;
			w->cb(w->peer, w->depth, &w->txid, w->cbdata);
			needs_rerun = true;
		}
	}
	if (needs_rerun)
		goto again;
}
