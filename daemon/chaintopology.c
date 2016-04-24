#include "bitcoin/block.h"
#include "bitcoin/tx.h"
#include "bitcoind.h"
#include "chaintopology.h"
#include "lightningd.h"
#include "log.h"
#include "timeout.h"
#include "watch.h"
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/ptrint/ptrint.h>
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

	/* We can have multiple children. */
	struct block **nexts;

	/* Key for hash table */
	struct sha256_double blkid;

	/* 0 if not enough predecessors. */
	u32 mediantime;

	/* Transactions in this block we care about */
	struct list_head txs;
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
	struct block **tips;
	struct sha256_double *newtips;
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

/* Mediantime is median of previous 11 blocks. */
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

/* Fills in prev, height, mediantime. */
static void connect_blocks(struct topology *topo, struct block *b)
{
	size_t n;

	/* Hooked in already? */
	if (b->height != -1)
		return;

	b->prev = block_map_get(&topo->block_map, &b->hdr.prev_hash);
	connect_blocks(topo, b->prev);

	b->height = b->prev->height + 1;
	n = tal_count(b->prev->nexts);
	tal_resize(&b->prev->nexts, n+1);
	b->prev->nexts[n] = b;

	b->mediantime = get_mediantime(topo, b->prev);
}

/* This is expensive, but reorgs are usually short and txs are few.
 *
 * B                TX
 *  o--------o-------o
 *   \
 *    \      TX
 *     ------o-------o-------o
 *
 *
 * This counts as depth 1, not 2, since the top fork may be extended.
 *
 * B            
 *  o--------o-------o
 *   \
 *    \      TX
 *     ------o-------o-------o
 *
 * This TX counts as depth 0 by our algorithm, which treats "not in chain"
 * as "next in chain".
 *
 * B            
 *  o--------o-------o-------o
 *   \
 *    \      TX
 *     ------o-------o-------o
 *
 * This counts as -1.
 *
 * We calculate the "height" of a tx (subtraction from best tips gives us the 
 * the depth).
 *
 * 1) The height of a tx in a particular branch is the height of the block it
 *    appears in, or the max height + 1 (assuming it's pending).
 * 2) The overall height of a tx is the maximum height on any branch.
 */

static bool tx_in_block(const struct block *b, const struct txwatch *w)
{
	struct tx_in_block *tx;

	list_for_each(&b->txs, tx, list) {
		if (tx->w == w)
			return true;
	}
	return false;
}

/* FIXME: Cache this on the tips. */
static size_t get_tx_branch_height(const struct topology *topo,
				   const struct block *tip,
				   const struct txwatch *w,
				   struct sha256_double *blkid,
				   size_t max)
{
	const struct block *b;

	for (b = tip; b; b = b->prev) {
		if (tx_in_block(b, w)) {
			*blkid = b->blkid;
			return b->height;
		}
		/* Don't bother returning less than max */
		if (b->height < max)
			return max;
	}

	return tip->height + 1;
}

size_t get_tx_depth(struct lightningd_state *dstate, const struct txwatch *w,
		    struct sha256_double *blkid)
{
	const struct topology *topo = dstate->topology;
	size_t i, max = 0, longest = 0;

	/* Calculate tx height. */
	for (i = 0; i < tal_count(topo->tips); i++) {
		size_t h = get_tx_branch_height(topo, topo->tips[i], w, blkid,
						max);
		if (h > max)
			max = h;

		/* Grab longest tip while we're here. */
		if (topo->tips[i]->height > longest)
			longest = topo->tips[i]->height;
	}

	return longest + 1 - max;
}

#if 0
static void reevaluate_txs_from(struct lightningd_state *dstate,
				struct block *common,
				struct block *b)
{
	struct topology *topo = dstate->topology;
	size_t i;
	struct tx_in_block *tx;

	/* Careful!  Callbacks could cause arbitrary txs to be deleted. */
again:
	b->tx_deleted = false;

	list_for_each(&b->txs, tx, list) {
		size_t dist = get_tx_distance(common, tx->w);
		int depth;

		/* Worst case, distance is one past tips. */
		depth = topo->tips[0]->height - (b->height + dist);
		assert(depth >= -1);

#if 0 /* When we replace notifications */
		if (tx->w->depth != depth) {
			tx->w->depth = depth;
			tx->w->cb(tx->w->peer, depth, tx->w->cbdata);
			if (b->tx_deleted)
				goto again;
		}
#endif
	}

	for (i = 0; i < tal_count(b->nexts); i++)
		reevaluate_txs_from(dstate, common, b->nexts[i]);
}

static struct block *find_common(struct topology *topo,
				 struct block *a, struct block *b)
{
	/* Special case for first time, when we have no previous tips */
	if (!a)
		return b;
	    
	/* Get to same height to start. */ 
	while (a->height > b->height)
		a = block_map_get(&topo->block_map, &a->prevblkid);
	while (b->height > a->height)
		b = block_map_get(&topo->block_map, &b->prevblkid);

	while (a != b) {
		a = block_map_get(&topo->block_map, &a->prevblkid);
		b = block_map_get(&topo->block_map, &b->prevblkid);
	}
	return a;
}
#endif

static void topology_changed(struct lightningd_state *dstate)
{
	struct topology *topo = dstate->topology;
	size_t i;

#if 0
	struct block *common = NULL;

	/* topo->tips is NULL for very first time. */
	if (topo->tips) {
		for (i = 0; i < tal_count(topo->tips); i++)
			common = find_common(topo, common, topo->tips[i]);
	}
#endif

	tal_free(topo->tips);
	topo->tips = tal_arr(topo, struct block *, tal_count(topo->newtips));
	for (i = 0; i < tal_count(topo->newtips); i++) {
		topo->tips[i] = block_map_get(&topo->block_map,
					      &topo->newtips[i]);
		connect_blocks(topo, topo->tips[i]);
	}

	/* FIXME: Tell watch code to re-evaluate all txs. */
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

static struct block *add_block(struct lightningd_state *dstate,
			       struct bitcoin_block *blk)
{
	size_t i;
	struct topology *topo = dstate->topology;
	struct block *b = tal(topo, struct block);

	sha256_double(&b->blkid, &blk->hdr, sizeof(blk->hdr));
	log_debug(dstate->base_log, "Adding block %02x%02x%02x%02x...\n",
			  b->blkid.sha.u.u8[0],
			  b->blkid.sha.u.u8[1],
			  b->blkid.sha.u.u8[2],
			  b->blkid.sha.u.u8[3]);
	assert(!block_map_get(&topo->block_map, &b->blkid));

	/* We fill these out in topology_changed */
	b->height = -1;
	b->nexts = tal_arr(b, struct block *, 0);
	b->mediantime = 0;
	b->prev = NULL;

	b->hdr = blk->hdr;

	/* See if any of those txs are interesting. */
	list_head_init(&b->txs);
	for (i = 0; i < tal_count(blk->tx); i++) {
		struct txwatch *w;
		struct sha256_double txid;

		bitcoin_txid(blk->tx[i], &txid);
		w = txwatch_hash_get(&dstate->txwatches, &txid);
		if (w)
			add_tx_to_block(b, w);
	}

	block_map_add(&topo->block_map, b);
	return b;
}

static void gather_blocks(struct lightningd_state *dstate,
			  struct bitcoin_block *blk,
			  ptrint_t *p)
{
	struct topology *topo = dstate->topology;
	ptrdiff_t i;

	add_block(dstate, blk);

	/* Recurse if we need prev. */
	if (!block_map_get(&topo->block_map, &blk->hdr.prev_hash)) {
		bitcoind_getrawblock(dstate, &blk->hdr.prev_hash,
				     gather_blocks, p);
		return;
	}

	/* Recurse if more tips to map. */
	for (i = ptr2int(p) + 1; i < tal_count(topo->newtips); i++) {
		if (!block_map_get(&topo->block_map, &topo->newtips[i])) {
			bitcoind_getrawblock(dstate, &topo->newtips[i],
					     gather_blocks, int2ptr(i));
			return;
		}
	}

	/* All done. */
	topology_changed(dstate);

	refresh_timeout(dstate, &topology_timeout);
}

static bool tips_changed(struct sha256_double *blockids, struct block **tips)
{
	size_t i;

	/* First time */
	if (!tips)
		return true;

	if (tal_count(blockids) != tal_count(tips))
		return true;

	for (i = 0; i < tal_count(tips); i++)
		if (!structeq(&blockids[i], &tips[i]->blkid))
			return true;
	return false;
}
	
static void check_chaintips(struct lightningd_state *dstate,
			    struct sha256_double *blockids,
			    void *arg)
{
	size_t i;
	struct topology *topo = dstate->topology;

	/* We assume chaintip ordering: if we're wrong, it's just slow */
	if (!tips_changed(blockids, topo->tips))
		goto out;

	/* Start iterating on first unknown tip. */
	topo->newtips = tal_steal(topo, blockids);
	for (i = 0; i < tal_count(topo->newtips); i++) {
		if (block_map_get(&topo->block_map, &topo->newtips[i]))
			continue;
		bitcoind_getrawblock(dstate, &topo->newtips[i], gather_blocks,
				     int2ptr(i));
		return;
	}

	log_unusual(dstate->base_log, "Chaintips changed but all blocks known?");
	topology_changed(dstate);

out:
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
	struct block *b;

	b = add_block(dstate, blk);
	b->height = ptr2int(p);

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

void setup_topology(struct lightningd_state *dstate)
{
	dstate->topology = tal(dstate, struct topology);
	dstate->topology->tips = NULL;
	dstate->topology->newtips = NULL;
	block_map_init(&dstate->topology->block_map);

	init_timeout(&topology_timeout, dstate->config.poll_seconds,
		     start_poll_chaintips, dstate);
	bitcoind_getblockcount(dstate, get_init_blockhash, NULL);
}
