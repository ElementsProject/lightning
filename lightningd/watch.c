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
#include <bitcoin/script.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/ptrint/ptrint.h>
#include <common/pseudorand.h>
#include <common/timeout.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/peer_control.h>
#include <lightningd/watch.h>

/* Watching an output */
struct txowatch {
	struct chain_topology *topo;

	/* Channel who owns us. */
	struct channel *channel;

	/* Output to watch. */
	struct txwatch_output out;

	/* A new tx. */
	enum watch_result (*cb)(struct channel *channel,
				const struct bitcoin_tx *tx,
				size_t input_num,
				const struct block *block);
};

struct txwatch {
	struct chain_topology *topo;

	/* Channel who owns us. */
	struct channel *channel;

	/* Transaction to watch. */
	struct bitcoin_txid txid;
	unsigned int depth;

	/* A new depth (0 if kicked out, otherwise 1 = tip, etc.) */
	enum watch_result (*cb)(struct channel *channel,
				const struct bitcoin_txid *txid,
				unsigned int depth);
};

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
	return bitcoin_txid_eq(&w->out.txid, &out->txid)
		&& w->out.index == out->index;
}

static void destroy_txowatch(struct txowatch *w)
{
	txowatch_hash_del(&w->topo->txowatches, w);
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
	txwatch_hash_del(&w->topo->txwatches, w);
}

struct txwatch *watch_txid(const tal_t *ctx,
			   struct chain_topology *topo,
			   struct channel *channel,
			   const struct bitcoin_txid *txid,
			   enum watch_result (*cb)(struct channel *channel,
						    const struct bitcoin_txid *,
						    unsigned int depth))
{
	struct txwatch *w;

	w = tal(ctx, struct txwatch);
	w->topo = topo;
	w->depth = 0;
	w->txid = *txid;
	w->channel = channel;
	w->cb = cb;

	txwatch_hash_add(&w->topo->txwatches, w);
	tal_add_destructor(w, destroy_txwatch);

	return w;
}

struct txwatch *find_txwatch(struct chain_topology *topo,
			     const struct bitcoin_txid *txid,
			     const struct channel *channel)
{
	struct txwatch_hash_iter i;
	struct txwatch *w;

	/* We could have more than one channel watching same txid, though we
	 * don't for onchaind. */
	for (w = txwatch_hash_getfirst(&topo->txwatches, txid, &i);
	     w;
	     w = txwatch_hash_getnext(&topo->txwatches, txid, &i)) {
		if (w->channel == channel)
			break;
	}
	return w;
}

bool watching_txid(const struct chain_topology *topo,
		   const struct bitcoin_txid *txid)
{
	return txwatch_hash_get(&topo->txwatches, txid) != NULL;
}

struct txwatch *watch_tx(const tal_t *ctx,
			 struct chain_topology *topo,
			 struct channel *channel,
			 const struct bitcoin_tx *tx,
			 enum watch_result (*cb)(struct channel *channel,
						  const struct bitcoin_txid *,
						  unsigned int depth))
{
	struct bitcoin_txid txid;

	bitcoin_txid(tx, &txid);
	return watch_txid(ctx, topo, channel, &txid, cb);
}

struct txowatch *watch_txo(const tal_t *ctx,
			   struct chain_topology *topo,
			   struct channel *channel,
			   const struct bitcoin_txid *txid,
			   unsigned int output,
			   enum watch_result (*cb)(struct channel *channel,
						   const struct bitcoin_tx *tx,
						   size_t input_num,
						   const struct block *block))
{
	struct txowatch *w = tal(ctx, struct txowatch);

	w->topo = topo;
	w->out.txid = *txid;
	w->out.index = output;
	w->channel = channel;
	w->cb = cb;

	txowatch_hash_add(&w->topo->txowatches, w);
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
	log_debug(txw->channel->log,
		  "Got depth change %u->%u for %s",
		  txw->depth, depth,
		  type_to_string(tmpctx, struct bitcoin_txid, &txw->txid));
	txw->depth = depth;
	r = txw->cb(txw->channel, txid, txw->depth);
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

	txw = txwatch_hash_get(&topo->txwatches, txid);

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
		  txow->out.index,
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
		for (w = txwatch_hash_first(&topo->txwatches, &i);
		     w;
		     w = txwatch_hash_next(&topo->txwatches, &i)) {
			u32 depth;

			depth = get_tx_depth(topo, &w->txid);
			if (depth)
				needs_rerun |= txw_fire(w, &w->txid, depth);
		}
	} while (needs_rerun);
}
