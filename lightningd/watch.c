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
#include <bitcoin/psbt.h>
#include <ccan/tal/str/str.h>
#include <common/addr.h>
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
	return txwatch_hash_exists(topo->txwatches, txid);
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
			  "Got first depth change 0->%u for %s",
			  depth,
			  fmt_bitcoin_txid(tmpctx, &txw->txid));
	} else {
		/* zero depth signals a reorganization */
		log_debug(txw->topo->log,
			  "Got depth change %u->%u for %s%s",
			  txw->depth, depth,
			  fmt_bitcoin_txid(tmpctx, &txw->txid),
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
	struct txwatch_hash_iter it;

	for (struct txwatch *txw = txwatch_hash_getfirst(topo->txwatches, txid, &it);
	     txw;
	     txw = txwatch_hash_getnext(topo->txwatches, txid, &it)) {
		txw_fire(txw, txid, depth);
	}
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
		  fmt_bitcoin_txid(tmpctx, &txow->out.txid),
		  txow->out.n,
		  fmt_bitcoin_txid(tmpctx, &txid));

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

	/* Iterating a htable during deletes is safe and consistent.
	 * Adding is forbidden. */
	txwatch_hash_lock(topo->txwatches);
	for (w = txwatch_hash_first(topo->txwatches, &i);
	     w;
	     w = txwatch_hash_next(topo->txwatches, &i)) {
		u32 depth;

		depth = get_tx_depth(topo, &w->txid);
		if (depth) {
			if (!w->tx)
				w->tx = wallet_transaction_get(w, topo->ld->wallet,
								       &w->txid);
			txw_fire(w, &w->txid, depth);
		}
	}
	txwatch_hash_unlock(topo->txwatches);
}

void txwatch_inform(const struct chain_topology *topo,
		    const struct bitcoin_txid *txid,
		    struct bitcoin_tx *tx TAKES)
{
	struct txwatch_hash_iter it;

	for (struct txwatch *txw = txwatch_hash_getfirst(topo->txwatches, txid, &it);
	     txw;
	     txw = txwatch_hash_getnext(topo->txwatches, txid, &it)) {
		if (txw->tx)
			continue;
		/* FIXME: YUCK!  These don't have PSBTs attached */
		if (!tx->psbt)
			tx->psbt = new_psbt(tx, tx->wtx);
		txw->tx = clone_bitcoin_tx(txw, tx);
	}

	/* If we don't clone above, handle take() now */
	tal_free_if_taken(tx);
}

struct scriptpubkeywatch {
	struct script_with_len swl;
	struct bitcoin_outpoint expected_outpoint;
	struct amount_sat expected_amount;
	void (*cb)(struct lightningd *ld,
		   const struct bitcoin_tx *tx,
		   u32 outnum,
		   const struct txlocator *loc,
		   void *);
	void *arg;
};

const struct script_with_len *scriptpubkeywatch_keyof(const struct scriptpubkeywatch *w)
{
	return &w->swl;
}

bool scriptpubkeywatch_eq(const struct scriptpubkeywatch *w, const struct script_with_len *swl)
{
	return script_with_len_eq(&w->swl, swl);
}

static void destroy_scriptpubkeywatch(struct scriptpubkeywatch *w, struct chain_topology *topo)
{
	scriptpubkeywatch_hash_del(topo->scriptpubkeywatches, w);
}

static struct scriptpubkeywatch *find_watchscriptpubkey(const struct scriptpubkeywatch_hash *scriptpubkeywatches,
							const u8 *scriptpubkey,
							const struct bitcoin_outpoint *expected_outpoint,
							struct amount_sat expected_amount,
							void (*cb)(struct lightningd *ld,
								   const struct bitcoin_tx *tx,
								   u32 outnum,
								   const struct txlocator *loc,
								   void *),
							void *arg)
{
	struct scriptpubkeywatch_hash_iter it;
	const struct script_with_len swl = { scriptpubkey, tal_bytelen(scriptpubkey) };

	for (struct scriptpubkeywatch *w = scriptpubkeywatch_hash_getfirst(scriptpubkeywatches, &swl, &it);
	     w;
	     w = scriptpubkeywatch_hash_getnext(scriptpubkeywatches, &swl, &it)) {
		if (bitcoin_outpoint_eq(&w->expected_outpoint, expected_outpoint)
		    && amount_sat_eq(w->expected_amount, expected_amount)
		    && w->cb == cb
		    && w->arg == arg) {
			return w;
		}
	}
	return NULL;
}

bool watch_scriptpubkey_(const tal_t *ctx,
			 struct chain_topology *topo,
			 const u8 *scriptpubkey TAKES,
			 const struct bitcoin_outpoint *expected_outpoint,
			 struct amount_sat expected_amount,
			 void (*cb)(struct lightningd *ld,
				    const struct bitcoin_tx *tx,
				    u32 outnum,
				    const struct txlocator *loc,
				    void *),
			 void *arg)
{
	struct scriptpubkeywatch *w;

	if (find_watchscriptpubkey(topo->scriptpubkeywatches,
				   scriptpubkey,
				   expected_outpoint,
				   expected_amount,
				   cb, arg)) {
		if (taken(scriptpubkey))
			tal_free(scriptpubkey);
		return false;
	}

	w = tal(ctx, struct scriptpubkeywatch);
	w->swl.script = tal_dup_talarr(w, u8, scriptpubkey);
	w->swl.len = tal_bytelen(w->swl.script);
	w->expected_outpoint = *expected_outpoint;
	w->expected_amount = expected_amount;
	w->cb = cb;
	w->arg = arg;
	scriptpubkeywatch_hash_add(topo->scriptpubkeywatches, w);
	tal_add_destructor2(w, destroy_scriptpubkeywatch, topo);
	return true;
}

bool unwatch_scriptpubkey_(const tal_t *ctx,
			   struct chain_topology *topo,
			   const u8 *scriptpubkey,
			   const struct bitcoin_outpoint *expected_outpoint,
			   struct amount_sat expected_amount,
			   void (*cb)(struct lightningd *ld,
				      const struct bitcoin_tx *tx,
				      u32 outnum,
				      const struct txlocator *loc,
				      void *),
			   void *arg)
{
	struct scriptpubkeywatch *w = find_watchscriptpubkey(topo->scriptpubkeywatches,
							     scriptpubkey,
							     expected_outpoint,
							     expected_amount,
							     cb, arg);
	if (w) {
		tal_free(w);
		return true;
	}
	return false;
}

bool watch_check_tx_outputs(const struct chain_topology *topo,
			    const struct txlocator *loc,
			    const struct bitcoin_tx *tx,
			    const struct bitcoin_txid *txid)
{
	bool tx_interesting = false;

	for (size_t outnum = 0; outnum < tx->wtx->num_outputs; outnum++) {
		const struct wally_tx_output *txout = &tx->wtx->outputs[outnum];
		const struct script_with_len swl = { txout->script, txout->script_len };
		struct scriptpubkeywatch_hash_iter it;
		bool output_matched = false, bad_txid = false, bad_amount = false, bad_outnum = false;
		struct amount_asset outasset = bitcoin_tx_output_get_amount(tx, outnum);

		/* Ensure callbacks don't do an insert during iteration! */
		scriptpubkeywatch_hash_lock(topo->scriptpubkeywatches);
		for (struct scriptpubkeywatch *w = scriptpubkeywatch_hash_getfirst(topo->scriptpubkeywatches, &swl, &it);
		     w;
		     w = scriptpubkeywatch_hash_getnext(topo->scriptpubkeywatches, &swl, &it)) {
			if (!bitcoin_txid_eq(&w->expected_outpoint.txid, txid)) {
				bad_txid = true;
				continue;
			}
			if (outnum != w->expected_outpoint.n) {
				bad_outnum = true;
				continue;
			}
			if (!amount_asset_is_main(&outasset)
			    || !amount_sat_eq(amount_asset_to_sat(&outasset), w->expected_amount)) {
				bad_amount = true;
				continue;
			}

			w->cb(topo->ld, tx, outnum, loc, w->arg);
			output_matched = true;
			tx_interesting = true;
		}
		scriptpubkeywatch_hash_unlock(topo->scriptpubkeywatches);

		/* Only complain about mismatch if we missed all of them.
		 * This helps diagnose mistakes like wrong txid, see
		 * https://github.com/ElementsProject/lightning/issues/8892 */
		if (!output_matched && (bad_txid || bad_amount || bad_outnum)) {
			const char *addr = encode_scriptpubkey_to_addr(tmpctx, chainparams,
								       txout->script, txout->script_len);
			if (!addr)
				addr = tal_fmt(tmpctx, "Scriptpubkey %s", tal_hexstr(tmpctx, txout->script, txout->script_len));
			if (bad_txid) {
				log_unusual(topo->ld->log,
					    "Unexpected spend to %s by unexpected txid %s:%zu",
					    addr, fmt_bitcoin_txid(tmpctx, txid), outnum);
			}
			if (bad_amount) {
				log_unusual(topo->ld->log,
					    "Unexpected amount %s to %s by txid %s:%zu",
					    amount_asset_is_main(&outasset)
					    ? fmt_amount_sat(tmpctx, amount_asset_to_sat(&outasset))
					    : "fee output",
					    addr, fmt_bitcoin_txid(tmpctx, txid), outnum);
			}
			if (bad_outnum) {
				log_unusual(topo->ld->log,
					    "Unexpected output number %zu paying to %s in txid %s",
					    outnum, addr, fmt_bitcoin_txid(tmpctx, txid));
			}
		}
	}

	return tx_interesting;
}

struct blockdepthwatch {
	u32 height;
	enum watch_result (*depthcb)(struct lightningd *ld,
				     u32 depth,
				     void *);
	enum watch_result (*reorgcb)(struct lightningd *ld,
				     void *);
	void *arg;
};

u32 blockdepthwatch_keyof(const struct blockdepthwatch *w)
{
	return w->height;
}

size_t u32_hash(u32 val)
{
	return siphash24(siphash_seed(), &val, sizeof(val));
}

bool blockdepthwatch_eq(const struct blockdepthwatch *w, u32 height)
{
	return w->height == height;
}

static void destroy_blockdepthwatch(struct blockdepthwatch *w, struct chain_topology *topo)
{
	blockdepthwatch_hash_del(topo->blockdepthwatches, w);
}

static struct blockdepthwatch *find_blockdepthwatch(const struct blockdepthwatch_hash *blockdepthwatches,
						    u32 blockheight,
						    enum watch_result (*depthcb)(struct lightningd *ld, u32 depth, void *),
						    enum watch_result (*reorgcb)(struct lightningd *ld, void *),
						    void *arg)
{
	struct blockdepthwatch_hash_iter it;

	for (struct blockdepthwatch *w = blockdepthwatch_hash_first(blockdepthwatches, &it);
	     w;
	     w = blockdepthwatch_hash_next(blockdepthwatches, &it)) {
		if (w->height == blockheight
		    && w->depthcb == depthcb
		    && w->reorgcb == reorgcb
		    && w->arg == arg) {
			return w;
		}
	}
	return NULL;
}

bool watch_blockdepth_(const tal_t *ctx,
		       struct chain_topology *topo,
		       u32 blockheight,
		       enum watch_result (*depthcb)(struct lightningd *ld, u32 depth, void *),
		       enum watch_result (*reorgcb)(struct lightningd *ld, void *),
		       void *arg)
{
	struct blockdepthwatch *w;

	if (find_blockdepthwatch(topo->blockdepthwatches, blockheight, depthcb, reorgcb, arg))
		return false;

	w = tal(ctx, struct blockdepthwatch);
	w->height = blockheight;
	w->depthcb = depthcb;
	w->reorgcb = reorgcb;
	w->arg = arg;
	blockdepthwatch_hash_add(topo->blockdepthwatches, w);
	tal_add_destructor2(w, destroy_blockdepthwatch, topo);
	return true;
}

void watch_check_block_added(const struct chain_topology *topo, u32 blockheight)
{
	struct blockdepthwatch_hash_iter it;

	/* With ccan/htable, deleting during iteration is safe: adding isn't! */
	blockdepthwatch_hash_lock(topo->blockdepthwatches);
	for (struct blockdepthwatch *w = blockdepthwatch_hash_first(topo->blockdepthwatches, &it);
	     w;
	     w = blockdepthwatch_hash_next(topo->blockdepthwatches, &it)) {
		/* You are not supposed to watch future blocks! */
		assert(blockheight >= w->height);

		u32 depth = blockheight - w->height + 1;
		enum watch_result r = w->depthcb(topo->ld, depth, w->arg);

		switch (r) {
		case DELETE_WATCH:
			tal_free(w);
			continue;
		case KEEP_WATCHING:
			continue;
		}
		fatal("blockdepthwatch depth callback %p returned %i", w->depthcb, r);
	}
	blockdepthwatch_hash_unlock(topo->blockdepthwatches);
}

void watch_check_block_removed(const struct chain_topology *topo, u32 blockheight)
{
	struct blockdepthwatch_hash_iter it;

	/* With ccan/htable, deleting during iteration is safe. */
	blockdepthwatch_hash_lock(topo->blockdepthwatches);
	for (struct blockdepthwatch *w = blockdepthwatch_hash_getfirst(topo->blockdepthwatches, blockheight, &it);
	     w;
	     w = blockdepthwatch_hash_getnext(topo->blockdepthwatches, blockheight, &it)) {
		enum watch_result r = w->reorgcb(topo->ld, w->arg);
		assert(r == DELETE_WATCH);
		tal_free(w);
	}
	blockdepthwatch_hash_unlock(topo->blockdepthwatches);
}
