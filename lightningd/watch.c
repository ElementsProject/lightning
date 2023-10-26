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
 * - Payments to invoice fallback addresses:
 *   - Reached a given depth.
 *
 * We do this by adding the P2SH address to the wallet, and then querying
 * that using listtransactions.
 *
 * WE ASSUME NO MALLEABILITY!  This requires segregated witness.
 */
#include "config.h"
#include <common/type_to_string.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/lightningd.h>
#include <lightningd/watch.h>

/* Watching an output */
struct txowatch {
	struct chain_topology *topo;

	/* Channel who owns us. */
	struct channel *channel;

	/* Output to watch. */
	struct bitcoin_outpoint out;

	/* A new tx. */
	enum watch_result (*cb)(struct channel *channel,
				const struct bitcoin_tx *tx,
				size_t input_num,
				const struct block *block);
};

struct txwatch {
	struct chain_topology *topo;

	/* Transaction to watch. */
	struct bitcoin_txid txid;

	/* May be NULL if we haven't seen it yet. */
	const struct bitcoin_tx *tx;

	int depth;

	/* A new depth (0 if kicked out, otherwise 1 = tip, etc.) */
	enum watch_result (*cb)(struct lightningd *ld,
				const struct bitcoin_txid *txid,
				const struct bitcoin_tx *tx,
				unsigned int depth,
				void *arg);
	void *cbarg;
};

const struct bitcoin_outpoint *txowatch_keyof(const struct txowatch *w)
{
	return &w->out;
}

size_t txo_hash(const struct bitcoin_outpoint *out)
{
	/* This hash-in-one-go trick only works if they're consecutive. */
	BUILD_ASSERT(offsetof(struct bitcoin_outpoint, n)
		     == sizeof(((struct bitcoin_outpoint *)NULL)->txid));
	return siphash24(siphash_seed(), out,
			 sizeof(out->txid) + sizeof(out->n));
}

bool txowatch_eq(const struct txowatch *w, const struct bitcoin_outpoint *out)
{
	return bitcoin_txid_eq(&w->out.txid, &out->txid)
		&& w->out.n == out->n;
}

static void destroy_txowatch(struct txowatch *w)
{
	txowatch_hash_del(w->topo->txowatches, w);
}

const struct bitcoin_txid *txwatch_keyof(const struct txwatch *w)
{
	return &w->txid;
}

size_t txid_hash(const struct bitcoin_txid *txid)
{
	return siphash24(siphash_seed(),
			 txid->shad.sha.u.u8, sizeof(txid->shad.sha.u.u8));
}

bool txwatch_eq(const struct txwatch *w, const struct bitcoin_txid *txid)
{
	return bitcoin_txid_eq(&w->txid, txid);
}

static void destroy_txwatch(struct txwatch *w)
{
	txwatch_hash_del(w->topo->txwatches, w);
}

struct txwatch *watch_txid_(const tal_t *ctx,
			    struct chain_topology *topo,
			    const struct bitcoin_txid *txid,
			    enum watch_result (*cb)(struct lightningd *ld,
						    const struct bitcoin_txid *,
						    const struct bitcoin_tx *,
						    unsigned int depth,
						    void *arg),
			    void *arg)
{
	struct txwatch *w;

	w = tal(ctx, struct txwatch);
	w->topo = topo;
	w->depth = -1;
	w->txid = *txid;
	w->tx = NULL;
	w->cb = cb;
	w->cbarg = arg;

	txwatch_hash_add(w->topo->txwatches, w);
	tal_add_destructor(w, destroy_txwatch);

	return w;
}

struct txwatch *find_txwatch_(struct chain_topology *topo,
			      const struct bitcoin_txid *txid,
			      enum watch_result (*cb)(struct lightningd *ld,
						      const struct bitcoin_txid *,
						      const struct bitcoin_tx *,
						      unsigned int depth,
						      void *arg),
			    void *arg)
{
	struct txwatch_hash_iter i;
	struct txwatch *w;

	/* We could have more than one channel watching same txid, though we
	 * don't for onchaind. */
	for (w = txwatch_hash_getfirst(topo->txwatches, txid, &i);
	     w;
	     w = txwatch_hash_getnext(topo->txwatches, txid, &i)) {
		if (w->cb == cb && w->cbarg == arg)
			break;
	}
	return w;
}

bool watching_txid(const struct chain_topology *topo,
		   const struct bitcoin_txid *txid)
{
	return txwatch_hash_get(topo->txwatches, txid) != NULL;
}

struct txowatch *watch_txo(const tal_t *ctx,
			   struct chain_topology *topo,
			   struct channel *channel,
			   const struct bitcoin_outpoint *outpoint,
			   enum watch_result (*cb)(struct channel *channel_,
						   const struct bitcoin_tx *tx,
						   size_t input_num,
						   const struct block *block))
{
	struct txowatch *w = tal(ctx, struct txowatch);

	w->topo = topo;
	w->out = *outpoint;
	w->channel = channel;
	w->cb = cb;

	txowatch_hash_add(w->topo->txowatches, w);
	tal_add_destructor(w, destroy_txowatch);

	return w;
}

/* Returns true if we fired a callback */
static bool txw_fire(struct txwatch *txw,
		     const struct bitcoin_txid *txid,
		     unsigned int depth)
{
	enum watch_result r;

	if (depth == txw->depth)
		return false;

	if (txw->depth == -1) {
		log_debug(txw->topo->log,
			  "Got first depth change ->%u for %s",
			  txw->depth,
			  type_to_string(tmpctx, struct bitcoin_txid, &txw->txid));
	} else {
		/* zero depth signals a reorganization */
		log_debug(txw->topo->log,
			  "Got depth change %u->%u for %s%s",
			  txw->depth, depth,
			  type_to_string(tmpctx, struct bitcoin_txid, &txw->txid),
			  depth ? "" : " REORG");
	}
	txw->depth = depth;
	r = txw->cb(txw->topo->bitcoind->ld, txid, txw->tx, txw->depth,
		    txw->cbarg);
	switch (r) {
	case DELETE_WATCH:
		tal_free(txw);
		return true;
	case KEEP_WATCHING:
		return true;
	}
	fatal("txwatch callback %p returned %i\n", txw->cb, r);
}

void txwatch_fire(struct chain_topology *topo,
		  const struct bitcoin_txid *txid,
		  unsigned int depth)
{
	struct txwatch *txw;

	txw = txwatch_hash_get(topo->txwatches, txid);

	if (txw)
		txw_fire(txw, txid, depth);
}

void txowatch_fire(const struct txowatch *txow,
		   const struct bitcoin_tx *tx,
		   size_t input_num,
		   const struct block *block)
{
	struct bitcoin_txid txid;
	enum watch_result r;

	bitcoin_txid(tx, &txid);
	log_debug(txow->channel->log,
		  "Got UTXO spend for %s:%u: %s",
		  type_to_string(tmpctx, struct bitcoin_txid, &txow->out.txid),
		  txow->out.n,
		  type_to_string(tmpctx, struct bitcoin_txid, &txid));

	r = txow->cb(txow->channel, tx, input_num, block);
	switch (r) {
	case DELETE_WATCH:
		tal_free(txow);
		return;
	case KEEP_WATCHING:
		return;
	}
	fatal("txowatch callback %p returned %i", txow->cb, r);
}

void watch_topology_changed(struct chain_topology *topo)
{
	struct txwatch_hash_iter i;
	struct txwatch *w;
	bool needs_rerun;
	do {
		/* Iterating a htable during deletes is safe, but might skip entries. */
		needs_rerun = false;
		for (w = txwatch_hash_first(topo->txwatches, &i);
		     w;
		     w = txwatch_hash_next(topo->txwatches, &i)) {
			u32 depth;

			depth = get_tx_depth(topo, &w->txid);
			if (depth) {
				if (!w->tx)
					w->tx = wallet_transaction_get(w, topo->ld->wallet,
								       &w->txid);
				needs_rerun |= txw_fire(w, &w->txid, depth);
			}
		}
	} while (needs_rerun);
}

void txwatch_inform(const struct chain_topology *topo,
		    const struct bitcoin_txid *txid,
		    const struct bitcoin_tx *tx_may_steal)
{
	struct txwatch *txw;

	txw = txwatch_hash_get(topo->txwatches, txid);

	if (txw && !txw->tx)
		txw->tx = tal_steal(txw, tx_may_steal);
}
