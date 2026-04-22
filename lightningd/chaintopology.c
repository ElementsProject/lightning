#include "config.h"
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/io/io.h>
#include <ccan/tal/str/str.h>
#include <common/htlc_tx.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/trace.h>
#include <db/exec.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/gossip_control.h>
#include <lightningd/invoice.h>
#include <lightningd/io_loop_with_timers.h>
#include <lightningd/notification.h>
#include <math.h>
#include <wallet/txfilter.h>

/* Mutual recursion via timer. */
static void try_extend_tip(struct chain_topology *topo);

static bool first_update_complete = false;

static void next_topology_timer(struct chain_topology *topo)
{
	assert(!topo->extend_timer);
	topo->extend_timer = new_reltimer(topo->ld->timers, topo,
					  time_from_sec(topo->poll_seconds),
					  try_extend_tip, topo);
}

static void filter_block_txs(struct chain_topology *topo, struct block *b)
{
	/* Now we see if any of those txs are interesting. */
	const size_t num_txs = tal_count(b->full_txs);
	for (size_t i = 0; i < num_txs; i++) {
		struct bitcoin_tx *tx = b->full_txs[i];
		struct bitcoin_txid txid;
		const struct txlocator loc = { b->height, i };
		bool is_coinbase = i == 0;
		size_t *our_outnums;

		/* Tell them if it spends a txo we care about. */
		for (size_t j = 0; j < tx->wtx->num_inputs; j++) {
			struct bitcoin_outpoint out;
			struct txowatch_hash_iter it;

			bitcoin_tx_input_get_txid(tx, j, &out.txid);
			out.n = tx->wtx->inputs[j].index;

			for (struct txowatch *txo = txowatch_hash_getfirst(topo->txowatches, &out, &it);
			     txo;
			     txo = txowatch_hash_getnext(topo->txowatches, &out, &it)) {
				wallet_transaction_add(topo->ld->wallet,
						       tx->wtx, b->height, i);
				txowatch_fire(txo, tx, j, b);
			}
		}

		txid = b->txids[i];
		our_outnums = tal_arr(tmpctx, size_t, 0);
		if (wallet_extract_owned_outputs(topo->ld->wallet,
						 tx->wtx, is_coinbase, &b->height, &our_outnums)) {
			wallet_transaction_add(topo->ld->wallet, tx->wtx,
					       b->height, i);
			for (size_t k = 0; k < tal_count(our_outnums); k++) {
				const struct wally_tx_output *txout;
				struct amount_sat amount;
				struct bitcoin_outpoint outpoint;

				txout = &tx->wtx->outputs[our_outnums[k]];
				outpoint.txid = txid;
				outpoint.n = our_outnums[k];
				amount = bitcoin_tx_output_get_amount_sat(tx, our_outnums[k]);
				invoice_check_onchain_payment(topo->ld, txout->script, amount, &outpoint);
			}

		}

		/* We did spends first, in case that tells us to watch tx. */

		/* Make sure we preserve any transaction we are interested in */
		if (watch_check_tx_outputs(topo, &loc, tx, &txid)
		    || watching_txid(topo, &txid)
		    || we_broadcast(topo->ld, &txid)) {
			wallet_transaction_add(topo->ld->wallet,
					       tx->wtx, b->height, i);
		}

		txwatch_inform(topo, &txid, take(tx));
	}
	b->full_txs = tal_free(b->full_txs);
	b->txids = tal_free(b->txids);
}

size_t get_tx_depth(const struct chain_topology *topo,
		    const struct bitcoin_txid *txid)
{
	u32 blockheight = wallet_transaction_height(topo->ld->wallet, txid);

	if (blockheight == 0)
		return 0;
	return topo->tip->height - blockheight + 1;
}

static enum watch_result closeinfo_txid_confirmed(struct lightningd *ld,
						  const struct bitcoin_txid *txid,
						  const struct bitcoin_tx *tx,
						  unsigned int depth,
						  void *unused)
{
	/* Sanity check. */
	if (tx != NULL) {
		struct bitcoin_txid txid2;

		bitcoin_txid(tx, &txid2);
		if (!bitcoin_txid_eq(txid, &txid2)) {
			fatal("Txid for %s is not %s",
			      fmt_bitcoin_tx(tmpctx, tx),
			      fmt_bitcoin_txid(tmpctx, txid));
		}
	}

	/* We delete ourselves first time, so should not be reorged out!! */
	assert(depth > 0);
	/* Subtle: depth 1 == current block. */
	wallet_confirm_tx(ld->wallet, txid,
			  get_block_height(ld->topology) + 1 - depth);
	return DELETE_WATCH;
}

/* We need to know if close_info UTXOs (which the wallet doesn't natively know
 * how to spend, so is not in the normal path) get reconfirmed.
 *
 * This can happen on startup (where we manually unwind 100 blocks) or on a
 * reorg.  The db NULLs out the confirmation_height, so we can't easily figure
 * out just the new ones (and removing the ON DELETE SET NULL clause is
 * non-trivial).
 *
 * So every time, we just set a notification for every tx in this class we're
 * not already watching: there are not usually many, nor many reorgs, so the
 * redundancy is OK.
 */
static void watch_for_utxo_reconfirmation(struct chain_topology *topo,
					  struct wallet *wallet)
{
	struct utxo **unconfirmed;

	unconfirmed = wallet_get_unconfirmed_closeinfo_utxos(tmpctx, wallet);
	const size_t num_unconfirmed = tal_count(unconfirmed);
	for (size_t i = 0; i < num_unconfirmed; i++) {
		assert(unconfirmed[i]->close_info != NULL);
		assert(unconfirmed[i]->blockheight == NULL);

		if (find_txwatch(topo, &unconfirmed[i]->outpoint.txid,
				 closeinfo_txid_confirmed, NULL))
			continue;

		watch_txid(topo, topo,
			   &unconfirmed[i]->outpoint.txid,
			   closeinfo_txid_confirmed, NULL);
	}
}

static enum watch_result tx_confirmed(struct lightningd *ld,
				      const struct bitcoin_txid *txid,
				      const struct bitcoin_tx *tx,
				      unsigned int depth,
				      void *unused)
{
	/* We don't actually need to do anything here: the fact that we were
	 * watching the tx made chaintopology.c update the transaction depth */
	if (depth != 0)
		return DELETE_WATCH;
	return KEEP_WATCHING;
}

void watch_unconfirmed_txid(struct lightningd *ld,
			    struct chain_topology *topo,
			    const struct bitcoin_txid *txid)
{
	watch_txid(ld->wallet, topo, txid, tx_confirmed, NULL);
}

static void watch_for_unconfirmed_txs(struct lightningd *ld,
				      struct chain_topology *topo)
{
	struct bitcoin_txid *txids;

	txids = wallet_transactions_by_height(tmpctx, ld->wallet, 0);
	log_debug(ld->log, "Got %zu unconfirmed transactions", tal_count(txids));
	for (size_t i = 0; i < tal_count(txids); i++)
		watch_unconfirmed_txid(ld, topo, &txids[i]);
}

struct sync_waiter {
	/* Linked from chain_topology->sync_waiters */
	struct list_node list;
	void (*cb)(struct chain_topology *topo, void *arg);
	void *arg;
};

static void destroy_sync_waiter(struct sync_waiter *waiter)
{
	list_del(&waiter->list);
}

void topology_add_sync_waiter_(const tal_t *ctx,
			       struct chain_topology *topo,
			       void (*cb)(struct chain_topology *topo,
					  void *arg),
			       void *arg)
{
	struct sync_waiter *w = tal(ctx, struct sync_waiter);
	w->cb = cb;
	w->arg = arg;
	list_add_tail(topo->sync_waiters, &w->list);
	tal_add_destructor(w, destroy_sync_waiter);
}

/* Once we're run out of new blocks to add, call this. */
static void updates_complete(struct chain_topology *topo)
{
	if (!bitcoin_blkid_eq(&topo->tip->blkid, &topo->prev_tip)) {
		/* Tell lightningd about new block. */
		notify_new_block(topo->ld);

		/* Tell blockdepth watchers */
		watch_check_block_added(topo, topo->tip->height);

		/* Tell watch code to re-evaluate all txs. */
		watch_topology_changed(topo);

		/* Maybe need to rebroadcast. */
		rebroadcast_txs(topo->ld);

		/* We've processed these UTXOs */
		db_set_intvar(topo->ld->wallet->db,
			      "last_processed_block", topo->tip->height);

		topo->prev_tip = topo->tip->blkid;

		/* Send out an account balance snapshot */
		if (!first_update_complete) {
			send_account_balance_snapshot(topo->ld);
			first_update_complete = true;
		}
	}

	/* If bitcoind is synced, we're now synced. */
	if (topo->ld->bitcoind->synced && !topology_synced(topo)) {
		struct sync_waiter *w;
		struct list_head *list = topo->sync_waiters;

		/* Mark topology_synced() before callbacks. */
		topo->sync_waiters = NULL;

		while ((w = list_pop(list, struct sync_waiter, list))) {
			/* In case it doesn't free itself. */
			tal_del_destructor(w, destroy_sync_waiter);
			tal_steal(list, w);
			w->cb(topo, w->arg);
		}
		tal_free(list);
	}

	/* Try again soon. */
	next_topology_timer(topo);
}

static void record_wallet_spend(struct lightningd *ld,
				const struct bitcoin_outpoint *outpoint,
				const struct bitcoin_txid *txid,
				u32 tx_blockheight)
{
	struct utxo *utxo;

	/* Find the amount this was for */
	utxo = wallet_utxo_get(tmpctx, ld->wallet, outpoint);
	if (!utxo) {
		log_broken(ld->log, "No record of utxo %s",
			   fmt_bitcoin_outpoint(tmpctx,
					  outpoint));
		return;
	}

	wallet_save_chain_mvt(ld, new_coin_wallet_withdraw(tmpctx, txid, outpoint,
						      tx_blockheight,
						      utxo->amount, mk_mvt_tags(MVT_WITHDRAWAL)));
}

/**
 * topo_update_spends -- Tell the wallet about all spent outpoints
 */
static void topo_update_spends(struct chain_topology *topo,
			       struct bitcoin_tx **txs,
			       const struct bitcoin_txid *txids,
			       u32 blockheight)
{
	const struct short_channel_id *spent_scids;
	const size_t num_txs = tal_count(txs);
	for (size_t i = 0; i < num_txs; i++) {
		const struct bitcoin_tx *tx = txs[i];

		for (size_t j = 0; j < tx->wtx->num_inputs; j++) {
			struct bitcoin_outpoint outpoint;

			bitcoin_tx_input_get_outpoint(tx, j, &outpoint);

			if (wallet_outpoint_spend(tmpctx, topo->ld->wallet,
						  blockheight, &outpoint))
				record_wallet_spend(topo->ld, &outpoint,
						    &txids[i], blockheight);

		}
	}

	/* Retrieve all potential channel closes from the UTXO set and
	 * tell gossipd about them. */
	spent_scids =
	    wallet_utxoset_get_spent(tmpctx, topo->ld->wallet, blockheight);
	gossipd_notify_spends(topo->ld, blockheight, spent_scids);
}

static void topo_add_utxos(struct chain_topology *topo, struct block *b)
{
	/* Coinbase and pegin UTXOs can be ignored */
	const uint32_t skip_features = WALLY_TX_IS_COINBASE | WALLY_TX_IS_PEGIN;
	const size_t num_txs = tal_count(b->full_txs);
	for (size_t i = 0; i < num_txs; i++) {
		const struct bitcoin_tx *tx = b->full_txs[i];
		for (size_t n = 0; n < tx->wtx->num_outputs; n++) {
			const struct wally_tx_output *output;
			output = &tx->wtx->outputs[n];
			if (output->features & skip_features)
				continue;
			if (!is_p2wsh(output->script, output->script_len, NULL))
				continue; /* We only care about p2wsh utxos */

			struct amount_asset amt = bitcoin_tx_output_get_amount(tx, n);
			if (!amount_asset_is_main(&amt))
				continue; /* Ignore non-policy asset outputs */

			struct bitcoin_outpoint outpoint = { b->txids[i], n };
			wallet_utxoset_add(topo->ld->wallet, &outpoint,
					   b->height, i,
					   output->script, output->script_len,
					   amount_asset_to_sat(&amt));
		}
	}
}

static void add_tip(struct chain_topology *topo, struct block *b)
{
	/* Attach to tip; b is now the tip. */
	assert(b->height == topo->tip->height + 1);
	b->prev = topo->tip;
	topo->tip->next = b;	/* FIXME this doesn't seem to be used anywhere */
	topo->tip = b;
	trace_span_start("wallet_block_add", b);
	wallet_block_add(topo->ld->wallet, b);
	trace_span_end(b);

	trace_span_start("topo_add_utxo", b);
	topo_add_utxos(topo, b);
	trace_span_end(b);

	trace_span_start("topo_update_spends", b);
	topo_update_spends(topo, b->full_txs, b->txids, b->height);
	trace_span_end(b);

	/* Only keep the transactions we care about. */
	trace_span_start("filter_block_txs", b);
	filter_block_txs(topo, b);
	trace_span_end(b);

	block_map_add(topo->block_map, b);
}

static struct block *new_block(struct chain_topology *topo,
			       struct bitcoin_block *blk,
			       unsigned int height)
{
	struct block *b = tal(topo, struct block);

	bitcoin_block_blkid(blk, &b->blkid);
	log_debug(topo->log, "Adding block %u: %s",
		  height,
		  fmt_bitcoin_blkid(tmpctx, &b->blkid));
	assert(!block_map_get(topo->block_map, &b->blkid));
	b->next = NULL;
	b->prev = NULL;

	b->height = height;

	b->hdr = blk->hdr;

	b->full_txs = tal_steal(b, blk->tx);
	b->txids = tal_steal(b, blk->txids);

	return b;
}

static void remove_tip(struct chain_topology *topo)
{
	struct block *b = topo->tip;
	struct bitcoin_txid *txs;
	size_t n;
	const struct short_channel_id *removed_scids;

	log_debug(topo->log, "Removing stale block %u: %s",
			  topo->tip->height,
			  fmt_bitcoin_blkid(tmpctx, &b->blkid));

	/* Move tip back one. */
	topo->tip = b->prev;

	if (!topo->tip)
		fatal("Initial block %u (%s) reorganized out!",
		      b->height,
		      fmt_bitcoin_blkid(tmpctx, &b->blkid));

	txs = wallet_transactions_by_height(b, topo->ld->wallet, b->height);
	n = tal_count(txs);

	/* Notify that txs are kicked out (their height will be set NULL in db) */
	for (size_t i = 0; i < n; i++)
		txwatch_fire(topo, &txs[i], 0);

	/* Grab these before we delete block from db */
	removed_scids = wallet_utxoset_get_created(tmpctx, topo->ld->wallet,
						   b->height);
	wallet_block_remove(topo->ld->wallet, b);

	/* This may have unconfirmed txs: reconfirm as we add blocks. */
	watch_for_utxo_reconfirmation(topo, topo->ld->wallet);

	/* Anyone watching for block removes */
	watch_check_block_removed(topo, b->height);

	block_map_del(topo->block_map, b);

	/* These no longer exist, so gossipd drops any reference to them just
	 * as if they were spent. */
	gossipd_notify_spends(topo->ld, b->height, removed_scids);
	tal_free(b);
}

static void get_new_block(struct bitcoind *bitcoind,
			  u32 height,
			  struct bitcoin_blkid *blkid,
			  struct bitcoin_block *blk,
			  struct chain_topology *topo)
{
	if (!blkid && !blk) {
		/* No such block, we're done. */
		updates_complete(topo);
		trace_span_end(topo);
		return;
	}
	assert(blkid && blk);

	/* Annotate all transactions with the chainparams */
	for (size_t i = 0; i < tal_count(blk->tx); i++)
		blk->tx[i]->chainparams = chainparams;

	/* Unexpected predecessor?  Free predecessor, refetch it. */
	if (!bitcoin_blkid_eq(&topo->tip->blkid, &blk->hdr.prev_hash))
		remove_tip(topo);
	else {
		add_tip(topo, new_block(topo, blk, height));

		/* tell plugins a new block was processed */
		notify_block_added(topo->ld, topo->tip);
	}

	/* Try for next one. */
	trace_span_end(topo);
	try_extend_tip(topo);
}

static void try_extend_tip(struct chain_topology *topo)
{
	topo->extend_timer = NULL;
	trace_span_start("extend_tip", topo);
	bitcoind_getrawblockbyheight(topo->request_ctx, topo->ld->bitcoind, topo->tip->height + 1,
				     get_new_block, topo);
}

u32 get_block_height(const struct chain_topology *topo)
{
	return topo->tip->height;
}

u32 get_network_blockheight(const struct chain_topology *topo)
{
	if (topo->tip->height > topo->headercount)
		return topo->tip->height;
	else
		return topo->headercount;
}

/* On shutdown, channels get deleted last.  That frees from our list, so
 * do it now instead. */
static void destroy_chain_topology(struct chain_topology *topo)
{
	broadcast_shutdown(topo->ld);
}

struct chain_topology *new_topology(struct lightningd *ld, struct logger *log)
{
	struct chain_topology *topo = tal(ld, struct chain_topology);

	topo->ld = ld;
	topo->block_map = new_htable(topo, block_map);
	topo->txwatches = new_htable(topo, txwatch_hash);
	topo->txowatches = new_htable(topo, txowatch_hash);
	topo->scriptpubkeywatches = new_htable(topo, scriptpubkeywatch_hash);
	topo->blockdepthwatches = new_htable(topo, blockdepthwatch_hash);
	topo->log = log;
	topo->poll_seconds = 30;
	topo->root = NULL;
	topo->sync_waiters = tal(topo, struct list_head);
	topo->extend_timer = NULL;
	topo->updatefee_timer = NULL;
	topo->checkchain_timer = NULL;
	topo->request_ctx = tal(topo, char);
	list_head_init(topo->sync_waiters);

	return topo;
}

static bool check_sync(struct bitcoind *bitcoind,
		       const u32 headercount, const u32 blockcount, const bool ibd,
		       struct chain_topology *topo, bool first_call)
{
	topo->headercount = headercount;

	if (ibd) {
		if (first_call)
			log_unusual(bitcoind->log,
				    "Waiting for initial block download (this can take"
				    " a while!)");
		else
			log_debug(bitcoind->log,
				  "Still waiting for initial block download");
	} else if (headercount != blockcount) {
		if (first_call)
			log_unusual(bitcoind->log,
				    "Waiting for bitcoind to catch up"
				    " (%u blocks of %u)",
				    blockcount, headercount);
		else
			log_debug(bitcoind->log,
				  "Waiting for bitcoind to catch up"
				  " (%u blocks of %u)",
				  blockcount, headercount);
	} else {
		bitcoind->synced = true;
		return true;
	}
	return false;
}

/* Loop to see if bitcoind is synced */
static void retry_sync(struct chain_topology *topo);
static void retry_sync_getchaininfo_done(struct bitcoind *bitcoind, const char *chain,
					 const u32 headercount, const u32 blockcount, const bool ibd,
					 struct chain_topology *topo)
{
	if (check_sync(bitcoind, headercount, blockcount, ibd, topo, false)) {
		log_unusual(bitcoind->log, "Bitcoin backend now synced.");
		return;
	}

	topo->checkchain_timer = new_reltimer(bitcoind->ld->timers, topo,
					      /* Be 4x more aggressive in this case. */
					      time_divide(time_from_sec(bitcoind->ld->topology
									->poll_seconds), 4),
					      retry_sync, topo);
}

static void retry_sync(struct chain_topology *topo)
{
	topo->checkchain_timer = NULL;
	bitcoind_getchaininfo(topo->request_ctx, topo->ld->bitcoind, get_block_height(topo),
			      retry_sync_getchaininfo_done, topo);
}

struct chaininfo_once {
	const char *chain;
	u32 headercount, blockcount;
	bool ibd;
};

static void get_chaininfo_once(struct bitcoind *bitcoind, const char *chain,
			       const u32 headercount, const u32 blockcount, const bool ibd,
			       struct chaininfo_once *once)
{
	once->chain = tal_strdup(once, chain);
	once->headercount = headercount;
	once->blockcount = blockcount;
	once->ibd = ibd;
	io_break(bitcoind->ld->topology);
}

struct feerates_once {
	u32 feerate_floor;
	struct feerate_est *rates;
};

static void get_feerates_once(struct lightningd *ld,
			      u32 feerate_floor,
			      const struct feerate_est *rates TAKES,
			      struct feerates_once *once)
{
	once->feerate_floor = feerate_floor;
	once->rates = tal_dup_talarr(once, struct feerate_est, rates);
	io_break(ld->topology);
}

static void get_block_once(struct bitcoind *bitcoind,
			   u32 height,
			   struct bitcoin_blkid *blkid UNUSED,
			   struct bitcoin_block *blk,
			   struct bitcoin_block **blkp)
{
	*blkp = tal_steal(NULL, blk);
	io_break(bitcoind->ld->topology);
}

/* We want to loop and poll until bitcoind has this height */
struct wait_for_height {
	struct bitcoind *bitcoind;
	u32 minheight;
};

/* Timer recursion */
static void retry_height_reached(struct wait_for_height *wh);

static void wait_until_height_reached(struct bitcoind *bitcoind, const char *chain,
				      const u32 headercount, const u32 blockcount, const bool ibd,
				      struct wait_for_height *wh)
{
	if (blockcount >= wh->minheight) {
		io_break(wh);
		return;
	}

	log_debug(bitcoind->ld->log, "bitcoind now at %u of %u blocks, waiting...",
		  blockcount, wh->minheight);
	new_reltimer(bitcoind->ld->timers, bitcoind, time_from_sec(5),
		     retry_height_reached, wh);
}

static void retry_height_reached(struct wait_for_height *wh)
{
	bitcoind_getchaininfo(wh, wh->bitcoind, wh->minheight,
			      wait_until_height_reached, wh);
}

/* Subtract, but floored at 0 */
static u32 blocknum_reduce(u32 blockheight, s32 sub)
{
	if ((u32)sub > blockheight)
		return 0;
	return blockheight - sub;
}

void setup_topology(struct chain_topology *topo)
{
	void *ret;
	/* Since we loop below, we free tmpctx, so we need a local */
	const tal_t *local_ctx = tal(NULL, char);
	struct chaininfo_once *chaininfo = tal(local_ctx, struct chaininfo_once);
	struct feerates_once *feerates = tal(local_ctx, struct feerates_once);
	struct bitcoin_block *blk;
	bool blockscan_start_set;
	u32 blockscan_start;
	s64 fixup;

	/* This waits for bitcoind. */
	bitcoind_check_commands(topo->ld->bitcoind);

	/* For testing.. */
	log_debug(topo->ld->log, "All Bitcoin plugin commands registered");

	db_begin_transaction(topo->ld->wallet->db);

	/*~ If we were asked to rescan from an absolute height (--rescan < 0)
	 * then just go there. Otherwise compute the diff to our current height,
	 * lowerbounded by 0. */
	if (topo->ld->config.rescan < 0) {
		blockscan_start = -topo->ld->config.rescan;
		blockscan_start_set = true;
	} else {
		/* Get the blockheight we are currently at, or 0 */
		blockscan_start = wallet_blocks_maxheight(topo->ld->wallet);
		blockscan_start_set = (blockscan_start != 0);

		/* If we don't know blockscan_start, can't do this yet */
		if (blockscan_start_set)
			blockscan_start = blocknum_reduce(blockscan_start, topo->ld->config.rescan);
	}

	fixup = db_get_intvar(topo->ld->wallet->db, "fixup_block_scan", -1);
	if (fixup == -1) {
		/* Never done fixup: this is set to non-zero if we have blocks. */
		topo->old_block_scan = wallet_blocks_contig_minheight(topo->ld->wallet);
		db_set_intvar(topo->ld->wallet->db, "fixup_block_scan",
			      topo->old_block_scan);
	} else {
		topo->old_block_scan = fixup;
	}
	db_commit_transaction(topo->ld->wallet->db);

	/* Sanity checks, then topology initialization. */
	chaininfo->chain = NULL;
	feerates->rates = NULL;
	bitcoind_getchaininfo(chaininfo, topo->ld->bitcoind, blockscan_start,
			      get_chaininfo_once, chaininfo);
	bitcoind_estimate_fees(feerates, topo->ld->bitcoind, get_feerates_once, feerates);

	/* Each one will break, but they might only exit once! */
	ret = io_loop_with_timers(topo->ld);
	assert(ret == topo);
	if (chaininfo->chain == NULL || feerates->rates == NULL) {
		ret = io_loop_with_timers(topo->ld);
		assert(ret == topo);
	}

	topo->headercount = chaininfo->headercount;
	if (!streq(chaininfo->chain, chainparams->bip70_name))
		fatal("Wrong network! Our Bitcoin backend is running on '%s',"
		      " but we expect '%s'.", chaininfo->chain, chainparams->bip70_name);

	if (!blockscan_start_set) {
		blockscan_start = blocknum_reduce(chaininfo->blockcount, topo->ld->config.rescan);
	} else {
		/* If bitcoind's current blockheight is below the requested
		 * height, wait, as long as header count is greater.  You can
		 * always explicitly request a reindex from that block number
		 * using --rescan=. */
		if (chaininfo->headercount < blockscan_start) {
			fatal("bitcoind has gone backwards from %u to %u blocks!",
			      blockscan_start, chaininfo->blockcount);
		} else if (chaininfo->blockcount < blockscan_start) {
			struct wait_for_height *wh = tal(local_ctx, struct wait_for_height);
			wh->bitcoind = topo->ld->bitcoind;
			wh->minheight = blockscan_start;

			/* We're not happy, but we'll wait... */
			log_broken(topo->ld->log,
				   "bitcoind has gone backwards from %u to %u blocks, waiting...",
				   blockscan_start, chaininfo->blockcount);
			bitcoind_getchaininfo(wh, topo->ld->bitcoind, blockscan_start,
					      wait_until_height_reached, wh);
			ret = io_loop_with_timers(topo->ld);
			assert(ret == wh);

			/* Might have been a while, so re-ask for fee estimates */
			bitcoind_estimate_fees(feerates, topo->ld->bitcoind, get_feerates_once, feerates);
			ret = io_loop_with_timers(topo->ld);
			assert(ret == topo);
		}
	}

	/* Sets bitcoin->synced or logs warnings */
	check_sync(topo->ld->bitcoind, chaininfo->headercount, chaininfo->blockcount,
		   chaininfo->ibd, topo, true);

	/* It's very useful to have feerates early */
	update_feerates(topo->ld, feerates->feerate_floor, feerates->rates, NULL);

	/* Get the first block, so we can initialize topography. */
	bitcoind_getrawblockbyheight(topo, topo->ld->bitcoind, blockscan_start,
				     get_block_once, &blk);
	ret = io_loop_with_timers(topo->ld);
	assert(ret == topo);

	tal_steal(local_ctx, blk);
	topo->root = new_block(topo, blk, blockscan_start);
	block_map_add(topo->block_map, topo->root);
	topo->tip = topo->root;
	topo->prev_tip = topo->tip->blkid;

	db_begin_transaction(topo->ld->wallet->db);

	/* In case we don't get all the way to updates_complete */
	db_set_intvar(topo->ld->wallet->db,
		      "last_processed_block", topo->tip->height);

	/* Rollback to the given blockheight, so we start track
	 * correctly again */
	wallet_blocks_rollback(topo->ld->wallet, blockscan_start);

	/* May have unconfirmed txs: reconfirm as we add blocks. */
	watch_for_utxo_reconfirmation(topo, topo->ld->wallet);

	/* We usually watch txs because we have outputs coming to us, or they're
	 * related to a channel.  But not if they're created by sendpsbt without any
	 * outputs to us. */
	watch_for_unconfirmed_txs(topo->ld, topo);
	db_commit_transaction(topo->ld->wallet->db);

	tal_free(local_ctx);

	tal_add_destructor(topo, destroy_chain_topology);
}

static void fixup_scan_block(struct bitcoind *bitcoind,
			     u32 height,
			     struct bitcoin_blkid *blkid,
			     struct bitcoin_block *blk,
			     struct chain_topology *topo)
{
	/* Can't scan the block?  We will try again next restart */
	if (!blk) {
		log_unusual(topo->ld->log,
			    "fixup_scan: could not load block %u, will retry next restart",
			    height);
		return;
	}

	log_debug(topo->ld->log, "fixup_scan: block %u with %zu txs", height, tal_count(blk->tx));
	topo_update_spends(topo, blk->tx, blk->txids, height);

	/* Caught up. */
	if (height == get_block_height(topo)) {
		log_info(topo->ld->log, "Scanning for missed UTXOs finished");
		db_set_intvar(topo->ld->wallet->db, "fixup_block_scan", 0);
		return;
	}

	db_set_intvar(topo->ld->wallet->db, "fixup_block_scan", ++topo->old_block_scan);
	bitcoind_getrawblockbyheight(topo, topo->ld->bitcoind,
				     topo->old_block_scan,
				     fixup_scan_block, topo);
}

static void fixup_scan(struct chain_topology *topo)
{
	log_info(topo->ld->log, "Scanning for missed UTXOs from block %u", topo->old_block_scan);
	bitcoind_getrawblockbyheight(topo, topo->ld->bitcoind,
				     topo->old_block_scan,
				     fixup_scan_block, topo);
}

void begin_topology(struct chain_topology *topo)
{
	/* If we were not synced, start looping to check */
	if (!topo->ld->bitcoind->synced)
		retry_sync(topo);
	/* Regular feerate updates */
	start_fee_polling(topo->ld);
	/* Regular block updates */
	try_extend_tip(topo);

	if (topo->old_block_scan)
		fixup_scan(topo);
}

void stop_topology(struct chain_topology *topo)
{
	/* Remove timers while we're cleaning up plugins. */
	tal_free(topo->checkchain_timer);
	tal_free(topo->extend_timer);
	tal_free(topo->updatefee_timer);

	/* Don't handle responses to any existing requests. */
	tal_free(topo->request_ctx);
}
