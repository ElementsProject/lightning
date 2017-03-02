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
#include "pseudorand.h"
#include "timeout.h"
#include "watch.h"
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/structeq/structeq.h>

const struct txwatch_output *txowatch_keyof(const struct txowatch *w)
{
	return &w->out;
}

size_t txo_hash(const struct txwatch_output *out)
{
	/* This hash-in-one-go trick only works if they're consecutive. */
	BUILD_ASSERT(offsetof(struct txwatch_output, index)
		     == sizeof(((struct txwatch_output *)NULL)->txid));
	return siphash24(siphash_seed(), &out->txid,
			 sizeof(out->txid) + sizeof(out->index));
}

bool txowatch_eq(const struct txowatch *w, const struct txwatch_output *out)
{
	return structeq(&w->out.txid, &out->txid)
		&& w->out.index == out->index;
}

static void destroy_txowatch(struct txowatch *w)
{
	txowatch_hash_del(&w->topo->txowatches, w);
}

const struct sha256_double *txwatch_keyof(const struct txwatch *w)
{
	return &w->txid;
}

size_t txid_hash(const struct sha256_double *txid)
{
	return siphash24(siphash_seed(), txid->sha.u.u8, sizeof(txid->sha.u.u8));
}

bool txwatch_eq(const struct txwatch *w, const struct sha256_double *txid)
{
	return structeq(&w->txid, txid);
}

static void destroy_txwatch(struct txwatch *w)
{
	txwatch_hash_del(&w->topo->txwatches, w);
}

struct txwatch *watch_txid_(const tal_t *ctx,
			    struct chain_topology *topo,
			    struct peer *peer,
			    const struct sha256_double *txid,
			    enum watch_result (*cb)(struct peer *peer,
						    unsigned int depth,
						    const struct sha256_double *,
						    void *arg),
			    void *cb_arg)
{
	struct txwatch *w;

	w = tal(ctx, struct txwatch);
	w->topo = topo;
	w->depth = 0;
	w->txid = *txid;
	w->peer = peer;
	w->cb = cb;
	w->cbdata = cb_arg;

	txwatch_hash_add(&w->topo->txwatches, w);
	tal_add_destructor(w, destroy_txwatch);

	return w;
}

bool watching_txid(const struct chain_topology *topo,
		   const struct sha256_double *txid)
{
	return txwatch_hash_get(&topo->txwatches, txid) != NULL;
}

struct txwatch *watch_tx_(const tal_t *ctx,
			  struct chain_topology *topo,
			  struct peer *peer,
			  const struct bitcoin_tx *tx,
			  enum watch_result (*cb)(struct peer *peer,
						  unsigned int depth,
						  const struct sha256_double *,
						  void *arg),
			  void *cb_arg)
{
	struct sha256_double txid;

	bitcoin_txid(tx, &txid);
	return watch_txid(ctx, topo, peer, &txid, cb, cb_arg);
}

struct txowatch *watch_txo_(const tal_t *ctx,
			    struct chain_topology *topo,
			    struct peer *peer,
			    const struct sha256_double *txid,
			    unsigned int output,
			    enum watch_result (*cb)(struct peer *peer,
						    const struct bitcoin_tx *tx,
						    size_t input_num,
						    void *),
			    void *cbdata)
{
	struct txowatch *w = tal(ctx, struct txowatch);

	w->topo = topo;
	w->out.txid = *txid;
	w->out.index = output;
	w->peer = peer;
	w->cb = cb;
	w->cbdata = cbdata;

	txowatch_hash_add(&w->topo->txowatches, w);
	tal_add_destructor(w, destroy_txowatch);

	return w;
}

void txwatch_fire(struct chain_topology *topo,
		  const struct sha256_double *txid,
		  unsigned int depth)
{
	struct txwatch *txw = txwatch_hash_get(&topo->txwatches, txid);

	if (txw && depth != txw->depth) {
		enum watch_result r;
		peer_debug(txw->peer,
			  "Got depth change %u for %02x%02x%02x...\n",
			  txw->depth,
			  txw->txid.sha.u.u8[0],
			  txw->txid.sha.u.u8[1],
			  txw->txid.sha.u.u8[2]);
		txw->depth = depth;
		r = txw->cb(txw->peer, txw->depth, &txw->txid, txw->cbdata);
		switch (r) {
		case DELETE_WATCH:
			tal_free(txw);
			return;
		case KEEP_WATCHING:
			return;
		}
		fatal("txwatch callback %p returned %i\n", txw->cb, r);
	}
}

void txowatch_fire(struct chain_topology *topo,
		   const struct txowatch *txow,
		   const struct bitcoin_tx *tx,
		   size_t input_num)
{
	struct sha256_double txid;
	enum watch_result r;

	bitcoin_txid(tx, &txid);
	peer_debug(txow->peer,
		  "Got UTXO spend for %02x%02x%02x:%u: %02x%02x%02x%02x...\n",
		  txow->out.txid.sha.u.u8[0],
		  txow->out.txid.sha.u.u8[1],
		  txow->out.txid.sha.u.u8[2],
		  txow->out.index,
		  txid.sha.u.u8[0],
		  txid.sha.u.u8[1],
		  txid.sha.u.u8[2],
		  txid.sha.u.u8[3]);
	r = txow->cb(txow->peer, tx, input_num, txow->cbdata);
	switch (r) {
	case DELETE_WATCH:
		tal_free(txow);
		return;
	case KEEP_WATCHING:
		return;
	}
	fatal("txowatch callback %p returned %i\n", txow->cb, r);
}

void watch_topology_changed(struct chain_topology *topo)
{
	struct txwatch_hash_iter i;
	struct txwatch *w;
	bool needs_rerun;

again:
	/* Iterating a htable during deletes is safe, but might skip entries. */
	needs_rerun = false;
	for (w = txwatch_hash_first(&topo->txwatches, &i);
	     w;
	     w = txwatch_hash_next(&topo->txwatches, &i)) {
		size_t depth;

		depth = get_tx_depth(topo, &w->txid);
		if (depth != w->depth) {
			enum watch_result r;
			w->depth = depth;
			needs_rerun = true;
			r = w->cb(w->peer, w->depth, &w->txid, w->cbdata);
			switch (r) {
			case DELETE_WATCH:
				tal_free(w);
				continue;
			case KEEP_WATCHING:
				continue;
			}
			fatal("txwatch callback %p returned %i\n", w->cb, r);
		}
	}
	if (needs_rerun)
		goto again;
}
