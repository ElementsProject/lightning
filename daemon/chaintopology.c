#include "bitcoin/block.h"
#include "bitcoin/tx.h"
#include "bitcoind.h"
#include "chaintopology.h"
#include "lightningd.h"
#include "log.h"
#include "peer.h"
#include "timeout.h"
#include "utils.h"
#include "watch.h"
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/structeq/structeq.h>

static struct timeout topology_timeout;

struct tx_in_block {
	struct list_node list;
	struct txwatch *w;
	struct block *block;
};

struct block {
	int height;

	/* Actual header. */
	struct bitcoin_block_hdr hdr;

	/* Previous block (if any). */
	struct block *prev;

	/* Next block (if any). */
	struct block *next;

	/* Key for hash table */
	struct sha256_double blkid;

	/* 0 if not enough predecessors. */
	u32 mediantime;

	/* Transactions in this block we care about */
	struct list_head txs;

	/* Full copy of txs (trimmed to txs list in connect_blocks) */
	struct bitcoin_tx **full_txs;
};

/* Hash blocks by sha */
static const struct sha256_double *keyof_block_map(const struct block *b)
{
	return &b->blkid;
}

static size_t hash_sha(const struct sha256_double *key)
{
	size_t ret;

	memcpy(&ret, key, sizeof(ret));
	return ret;
}

static bool block_eq(const struct block *b, const struct sha256_double *key)
{
	return structeq(&b->blkid, key);
}
HTABLE_DEFINE_TYPE(struct block, keyof_block_map, hash_sha, block_eq, block_map);

struct topology {
	struct block *root;
	struct block *tip;
	struct block_map block_map;
};

static int cmp_times(const u32 *a, const u32 *b, void *unused)
{
	if (*a > *b)
		return -1;
	else if (*b > * a)
		return 1;
	return 0;
}

/* Mediantime is median of this and previous 10 blocks. */
static u32 get_mediantime(const struct topology *topo, const struct block *b)
{
	unsigned int i;
	u32 times[11];

	for (i = 0; i < ARRAY_SIZE(times); i++) {
		if (!b)
			return 0;
		times[i] = le32_to_cpu(b->hdr.timestamp);
		b = b->prev;
	}
	asort(times, ARRAY_SIZE(times), cmp_times, NULL);
	return times[ARRAY_SIZE(times) / 2];
}

static void remove_tx(struct tx_in_block *t)
{
	list_del_from(&t->block->txs, &t->list);
}

static void add_tx_to_block(struct block *b, struct txwatch *w)
{
	/* We attach this to watch, so removed when that is */
	struct tx_in_block *t = tal(w, struct tx_in_block);

	t->block = b;
	t->w = w;
	list_add_tail(&b->txs, &t->list);
	tal_add_destructor(t, remove_tx);
}

/* Fills in prev, height, mediantime. */
static void connect_block(struct lightningd_state *dstate,
			  struct block *prev,
			  struct block *b)
{
	struct topology *topo = dstate->topology;
	size_t i;

	assert(b->height == -1);
	assert(b->mediantime == 0);
	assert(b->prev == NULL);
	assert(prev->next == b);

	b->prev = prev;
	b->height = b->prev->height + 1;
	b->mediantime = get_mediantime(topo, b);

	block_map_add(&topo->block_map, b);
	
	/* Now we see if any of those txs are interesting. */
	for (i = 0; i < tal_count(b->full_txs); i++) {
		struct bitcoin_tx *tx = b->full_txs[i];
		struct txwatch *w;
		struct sha256_double txid;
		struct txwatch_hash_iter iter;
		size_t j;

		/* Tell them if it spends a txo we care about. */
		for (j = 0; j < tx->input_count; j++) {
			struct txwatch_output out;
			struct txowatch *txo;
			out.txid = tx->input[j].txid;
			out.index = tx->input[j].index;

			txo = txowatch_hash_get(&dstate->txowatches, &out);
			if (txo)
				txowatch_fire(dstate, txo, tx, j);
		}

		/* We do spends first, in case that tells us to watch tx. */
		bitcoin_txid(tx, &txid);
		for (w = txwatch_hash_getfirst(&dstate->txwatches, &txid, &iter);
		     w;
		     w = txwatch_hash_getnext(&dstate->txwatches, &txid, &iter)){
			add_tx_to_block(b, w);
			/* Fire if it's the first we've seen it: this might
			 * set up txo watches, which could fire in this block */
			txwatch_fire(dstate, w, 0);
		}
	}
	b->full_txs = tal_free(b->full_txs);
}

static bool tx_in_block(const struct block *b,
			const struct sha256_double *txid)
{
	struct tx_in_block *tx;

	list_for_each(&b->txs, tx, list) {
		if (structeq(&tx->w->txid, txid))
			return true;
	}
	return false;
}

/* FIXME: put block pointer in txwatch. */
static struct block *block_for_tx(struct topology *topo,
				  const struct sha256_double *txid)
{
	struct block *b;

	for (b = topo->tip; b; b = b->prev) {
		if (tx_in_block(b, txid))
			return b;
	}
	return NULL;
}

size_t get_tx_depth(struct lightningd_state *dstate, const struct txwatch *w)
{
	struct topology *topo = dstate->topology;
	const struct block *b;

	b = block_for_tx(topo, &w->txid);
	if (!b)
		return 0;
	return topo->tip->height - b->height + 1;
}

static void try_broadcast(struct lightningd_state *dstate,
			  const char *msg, char **txs)
{
	size_t num_txs = tal_count(txs);
	const char *this_tx;

	/* These are expected. */
	if (strstr(msg, "txn-mempool-conflict")
	    || strstr(msg, "transaction already in block chain"))
		log_debug(dstate->base_log,
			  "Expected error broadcasting tx %s: %s",
			  txs[num_txs-1], msg);
	else
		log_unusual(dstate->base_log, "Broadcasting tx %s: %s",
			    txs[num_txs-1], msg);

	if (num_txs == 1) {
		tal_free(txs);
		return;
	}

	/* Strip off last one. */
	this_tx = txs[num_txs-1];
	tal_resize(&txs, num_txs-1);

	bitcoind_sendrawtx(dstate, this_tx, try_broadcast, txs);
}

/* FIXME: This is dumb.  We can group txs and avoid bothering bitcoind
 * if any one tx is in the main chain. */
static void rebroadcast_txs(struct lightningd_state *dstate)
{
	/* Copy txs now (peers may go away, and they own txs). */
	size_t num_txs = 0;
	char **txs = tal_arr(dstate, char *, 0);
	struct peer *peer;

	list_for_each(&dstate->peers, peer, list) {
		struct outgoing_tx *otx;

		list_for_each(&peer->outgoing_txs, otx, list) {
			u8 *rawtx;

			if (block_for_tx(dstate->topology, &otx->txid))
				continue;

			tal_resize(&txs, num_txs+1);
			rawtx = linearize_tx(txs, otx->tx);
			txs[num_txs] = tal_hexstr(txs, rawtx, tal_count(rawtx));
			num_txs++;
		}
	}

	if (num_txs)
		bitcoind_sendrawtx(dstate, txs[num_txs-1], try_broadcast, txs);
	else
		tal_free(txs);
}

static void destroy_outgoing_tx(struct outgoing_tx *otx)
{
	list_del(&otx->list);
}

void broadcast_tx(struct peer *peer, const struct bitcoin_tx *tx)
{
	struct outgoing_tx *otx = tal(peer, struct outgoing_tx);
	char **txs = tal_arr(peer->dstate, char *, 1);
	u8 *rawtx;

	otx->tx = tal_steal(otx, tx);
	bitcoin_txid(otx->tx, &otx->txid);
	list_add_tail(&peer->outgoing_txs, &otx->list);
	tal_add_destructor(otx, destroy_outgoing_tx);

	/* FIXME: log_struct */
	log_add(peer->log, " (tx %02x%02x%02x%02x...)",
		otx->txid.sha.u.u8[0], otx->txid.sha.u.u8[1],
		otx->txid.sha.u.u8[2], otx->txid.sha.u.u8[3]);

	rawtx = linearize_tx(txs, otx->tx);
	txs[0] = tal_hexstr(txs, rawtx, tal_count(rawtx));
	bitcoind_sendrawtx(peer->dstate, txs[0], try_broadcast, txs);
}

static void free_blocks(struct lightningd_state *dstate, struct block *b)
{
	struct block *next;

	while (b) {
		struct tx_in_block *tx, *n;

		/* Notify that txs are kicked out. */
		list_for_each_safe(&b->txs, tx, n, list)
			txwatch_fire(dstate, tx->w, 0);

		next = b->next;
		tal_free(b);
		b = next;
	}
}

/* B is the new chain (linked by ->next); update topology */
static void topology_changed(struct lightningd_state *dstate,
			     struct block *prev,
			     struct block *b)
{
	/* Eliminate any old chain. */
	if (prev->next)
		free_blocks(dstate, prev->next);

	prev->next = b;
	do {
		connect_block(dstate, prev, b);
		dstate->topology->tip = prev = b;
		b = b->next;
	} while (b);

	/* Tell watch code to re-evaluate all txs. */
	watch_topology_changed(dstate);

	/* Maybe need to rebroadcast. */
	rebroadcast_txs(dstate);
}

static struct block *new_block(struct lightningd_state *dstate,
			       struct bitcoin_block *blk,
			       struct block *next)
{
	struct topology *topo = dstate->topology;
	struct block *b = tal(topo, struct block);

	sha256_double(&b->blkid, &blk->hdr, sizeof(blk->hdr));
	log_debug(dstate->base_log, "Adding block %02x%02x%02x%02x...\n",
			  b->blkid.sha.u.u8[0],
			  b->blkid.sha.u.u8[1],
			  b->blkid.sha.u.u8[2],
			  b->blkid.sha.u.u8[3]);
	assert(!block_map_get(&topo->block_map, &b->blkid));
	b->next = next;

	/* We fill these out in topology_changed */
	b->height = -1;
	b->mediantime = 0;
	b->prev = NULL;

	b->hdr = blk->hdr;

	list_head_init(&b->txs);
	b->full_txs = tal_steal(b, blk->tx);

	return b;
}

static void gather_blocks(struct lightningd_state *dstate,
			  struct bitcoin_block *blk,
			  struct block *next)
{
	struct topology *topo = dstate->topology;
	struct block *b, *prev;

	b = new_block(dstate, blk, next);

	/* Recurse if we need prev. */
	prev = block_map_get(&topo->block_map, &blk->hdr.prev_hash);
	if (!prev) {
		bitcoind_getrawblock(dstate, &blk->hdr.prev_hash,
				     gather_blocks, b);
		return;
	}

	/* All done. */
	topology_changed(dstate, prev, b);
	refresh_timeout(dstate, &topology_timeout);
}

static void check_chaintips(struct lightningd_state *dstate,
			    struct sha256_double *blockids,
			    void *arg)
{
	struct topology *topo = dstate->topology;

	/* 0 is the main tip. */
	if (!topo->tip || !structeq(&blockids[0], &topo->tip->blkid))
		bitcoind_getrawblock(dstate, &blockids[0], gather_blocks,
				     (struct block *)NULL);
	else
		refresh_timeout(dstate, &topology_timeout);
}

static void start_poll_chaintips(struct lightningd_state *dstate)
{
	if (!list_empty(&dstate->bitcoin_req)) {
		log_unusual(dstate->base_log,
			    "Delaying start poll: commands in progress");
		refresh_timeout(dstate, &topology_timeout);
	} else
		bitcoind_get_chaintips(dstate, check_chaintips, NULL);
}

static void init_topo(struct lightningd_state *dstate,
		      struct bitcoin_block *blk,
		      ptrint_t *p)
{
	struct topology *topo = dstate->topology;

	topo->root = new_block(dstate, blk, NULL);
	topo->root->height = ptr2int(p);
	block_map_add(&topo->block_map, topo->root);

	/* Now grab chaintips immediately. */
	bitcoind_get_chaintips(dstate, check_chaintips, NULL);
}

static void get_init_block(struct lightningd_state *dstate,
			   const struct sha256_double *blkid,
			   ptrint_t *blknum)
{
	bitcoind_getrawblock(dstate, blkid, init_topo, blknum);
}

static void get_init_blockhash(struct lightningd_state *dstate, u32 blockcount,
			       void *unused)
{
	u32 start;

	if (blockcount < 100)
		start = 0;
	else
		start = blockcount - 100;

	/* Start topology from 100 blocks back. */
	bitcoind_getblockhash(dstate, start, get_init_block, int2ptr(start));
}

u32 get_tx_mediantime(struct lightningd_state *dstate,
		      const struct sha256_double *txid)
{
	struct block *b;

	b = block_for_tx(dstate->topology, txid);
	if (b)
		return b->mediantime;

	fatal("Tx %s not found for get_tx_mediantime",
	      tal_hexstr(dstate, txid, sizeof(*txid)));
}

u32 get_tip_mediantime(struct lightningd_state *dstate)
{
	return dstate->topology->tip->mediantime;
}

void setup_topology(struct lightningd_state *dstate)
{
	dstate->topology = tal(dstate, struct topology);
	dstate->topology->tip = NULL;
	block_map_init(&dstate->topology->block_map);

	init_timeout(&topology_timeout, dstate->config.poll_seconds,
		     start_poll_chaintips, dstate);
	bitcoind_getblockcount(dstate, get_init_blockhash, NULL);
}
