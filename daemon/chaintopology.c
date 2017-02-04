#include "bitcoin/block.h"
#include "bitcoin/tx.h"
#include "bitcoind.h"
#include "chaintopology.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "peer.h"
#include "timeout.h"
#include "utils.h"
#include "watch.h"
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/io/io.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <inttypes.h>

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
	struct sha256_double *txids;

	/* And their associated index in the block */
	u32 *txnums;

	/* Full copy of txs (trimmed to txs list in connect_block) */
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
	u64 feerate;
	bool startup;
};

static void start_poll_chaintip(struct lightningd_state *dstate);

static void next_topology_timer(struct lightningd_state *dstate)
{
	if (dstate->topology->startup) {
		dstate->topology->startup = false;
		io_break(dstate);
	}
	new_reltimer(&dstate->timers, dstate, dstate->config.poll_time,
		     start_poll_chaintip, dstate);
}

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

/* FIXME: Remove tx from block when peer done. */
static void add_tx_to_block(struct block *b, const struct sha256_double *txid, const u32 txnum)
{
	size_t n = tal_count(b->txids);

	tal_resize(&b->txids, n+1);
	tal_resize(&b->txnums, n+1);
	b->txids[n] = *txid;
	b->txnums[n] = txnum;
}

static bool we_broadcast(struct lightningd_state *dstate,
			 const struct sha256_double *txid)
{
	struct peer *peer;

	list_for_each(&dstate->peers, peer, list) {
		struct outgoing_tx *otx;

		list_for_each(&peer->outgoing_txs, otx, list) {
			if (structeq(&otx->txid, txid))
				return true;
		}
	}
	return false;
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
		struct sha256_double txid;
		size_t j;

		/* Tell them if it spends a txo we care about. */
		for (j = 0; j < tal_count(tx->input); j++) {
			struct txwatch_output out;
			struct txowatch *txo;
			out.txid = tx->input[j].txid;
			out.index = tx->input[j].index;

			txo = txowatch_hash_get(&dstate->txowatches, &out);
			if (txo)
				txowatch_fire(dstate, txo, tx, j);
		}

		/* We did spends first, in case that tells us to watch tx. */
		bitcoin_txid(tx, &txid);
		if (watching_txid(dstate, &txid) || we_broadcast(dstate, &txid))
			add_tx_to_block(b, &txid, i);
	}
	b->full_txs = tal_free(b->full_txs);

	/* Tell peers about new block. */
	peers_new_block(dstate, b->height);
}

static bool tx_in_block(const struct block *b,
			const struct sha256_double *txid)
{
	size_t i, n = tal_count(b->txids);

	for (i = 0; i < n; i++) {
		if (structeq(&b->txids[i], txid))
			return true;
	}
	return false;
}

/* FIXME: Use hash table. */
static struct block *block_for_tx(struct lightningd_state *dstate,
				  const struct sha256_double *txid)
{
	struct topology *topo = dstate->topology;
	struct block *b;

	for (b = topo->tip; b; b = b->prev) {
		if (tx_in_block(b, txid))
			return b;
	}
	return NULL;
}

size_t get_tx_depth(struct lightningd_state *dstate,
		    const struct sha256_double *txid)
{
	struct topology *topo = dstate->topology;
	const struct block *b;

	b = block_for_tx(dstate, txid);
	if (!b)
		return 0;
	return topo->tip->height - b->height + 1;
}

struct txs_to_broadcast {
	/* We just sent txs[cursor] */
	size_t cursor;
	/* These are hex encoded already, for bitcoind_sendrawtx */
	const char **txs;

	/* Command to complete when we're done, iff dev-broadcast triggered */
	struct command *cmd;
};

/* We just sent the last entry in txs[].  Shrink and send the next last. */
static void broadcast_remainder(struct lightningd_state *dstate,
				int exitstatus, const char *msg,
				struct txs_to_broadcast *txs)
{
	/* These are expected. */
	if (strstr(msg, "txn-mempool-conflict")
	    || strstr(msg, "transaction already in block chain"))
		log_debug(dstate->base_log,
			  "Expected error broadcasting tx %s: %s",
			  txs->txs[txs->cursor], msg);
	else if (exitstatus)
		log_unusual(dstate->base_log, "Broadcasting tx %s: %i %s",
			    txs->txs[txs->cursor], exitstatus, msg);

	txs->cursor++;
	if (txs->cursor == tal_count(txs->txs)) {
		if (txs->cmd)
			command_success(txs->cmd, null_response(txs->cmd));
		tal_free(txs);
		return;
	}

	/* Broadcast next one. */
	bitcoind_sendrawtx(NULL, dstate, txs->txs[txs->cursor],
			   broadcast_remainder, txs);
}

/* FIXME: This is dumb.  We can group txs and avoid bothering bitcoind
 * if any one tx is in the main chain. */
static void rebroadcast_txs(struct lightningd_state *dstate,
			    struct command *cmd)
{
	/* Copy txs now (peers may go away, and they own txs). */
	size_t num_txs = 0;
	struct txs_to_broadcast *txs;
	struct peer *peer;

	if (dstate->dev_no_broadcast)
		return;

	txs = tal(dstate, struct txs_to_broadcast);
	txs->cmd = cmd;

	/* Put any txs we want to broadcast in ->txs. */
	txs->txs = tal_arr(txs, const char *, 0);
	list_for_each(&dstate->peers, peer, list) {
		struct outgoing_tx *otx;

		list_for_each(&peer->outgoing_txs, otx, list) {
			if (block_for_tx(dstate, &otx->txid))
				continue;

			tal_resize(&txs->txs, num_txs+1);
			txs->txs[num_txs] = tal_strdup(txs, otx->hextx);
			num_txs++;
		}
	}

	/* Let this do the dirty work. */
	txs->cursor = (size_t)-1;
	broadcast_remainder(dstate, 0, "", txs);
}

static void destroy_outgoing_tx(struct outgoing_tx *otx)
{
	list_del_from(&otx->peer->outgoing_txs, &otx->list);
}

static void broadcast_done(struct lightningd_state *dstate,
			   int exitstatus, const char *msg,
			   struct outgoing_tx *otx)
{
	if (otx->failed && exitstatus != 0) {
		otx->failed(otx->peer, exitstatus, msg);
		tal_free(otx);
	} else {
		/* For continual rebroadcasting */
		list_add_tail(&otx->peer->outgoing_txs, &otx->list);
		tal_add_destructor(otx, destroy_outgoing_tx);
	}
}

void broadcast_tx(struct peer *peer, const struct bitcoin_tx *tx,
		  void (*failed)(struct peer *peer,
				 int exitstatus, const char *err))
{
	struct outgoing_tx *otx = tal(peer, struct outgoing_tx);
	const u8 *rawtx = linearize_tx(otx, tx);

	otx->peer = peer;
	bitcoin_txid(tx, &otx->txid);
	otx->hextx = tal_hex(otx, rawtx);
	otx->failed = failed;
	tal_free(rawtx);

	log_add_struct(peer->log, " (tx %s)", struct sha256_double, &otx->txid);

	if (peer->dstate->dev_no_broadcast)
		broadcast_done(peer->dstate, 0, "dev_no_broadcast", otx);
	else
		bitcoind_sendrawtx(peer, peer->dstate, otx->hextx,
				   broadcast_done, otx);
}

static void free_blocks(struct lightningd_state *dstate, struct block *b)
{
	struct block *next;

	while (b) {
		size_t i, n = tal_count(b->txids);

		/* Notify that txs are kicked out. */
		for (i = 0; i < n; i++)
			txwatch_fire(dstate, &b->txids[i], 0);

		next = b->next;
		tal_free(b);
		b = next;
	}
}

static void update_fee(struct lightningd_state *dstate, u64 rate, u64 *feerate)
{
	log_debug(dstate->base_log, "Feerate %"PRIu64" -> %"PRIu64,
		  rate, *feerate);
	*feerate = rate;
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
	rebroadcast_txs(dstate, NULL);

	/* Once per new block head, update fee estimate. */
	bitcoind_estimate_fee(dstate, update_fee, &dstate->topology->feerate);
}

static struct block *new_block(struct lightningd_state *dstate,
			       struct bitcoin_block *blk,
			       struct block *next)
{
	struct topology *topo = dstate->topology;
	struct block *b = tal(topo, struct block);

	sha256_double(&b->blkid, &blk->hdr, sizeof(blk->hdr));
	log_debug_struct(dstate->base_log, "Adding block %s",
			 struct sha256_double, &b->blkid);
	assert(!block_map_get(&topo->block_map, &b->blkid));
	b->next = next;

	/* We fill these out in topology_changed */
	b->height = -1;
	b->mediantime = 0;
	b->prev = NULL;

	b->hdr = blk->hdr;

	b->txids = tal_arr(b, struct sha256_double, 0);
	b->txnums = tal_arr(b, u32, 0);
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
	next_topology_timer(dstate);
}

static void check_chaintip(struct lightningd_state *dstate,
			   const struct sha256_double *tipid,
			   void *arg)
{
	struct topology *topo = dstate->topology;

	/* 0 is the main tip. */
	if (!structeq(tipid, &topo->tip->blkid))
		bitcoind_getrawblock(dstate, tipid, gather_blocks,
				     (struct block *)NULL);
	else
		/* Next! */
		next_topology_timer(dstate);
}

static void start_poll_chaintip(struct lightningd_state *dstate)
{
	if (!list_empty(&dstate->bitcoin_req)) {
		log_unusual(dstate->base_log,
			    "Delaying start poll: commands in progress");
		next_topology_timer(dstate);
	} else
		bitcoind_get_chaintip(dstate, check_chaintip, NULL);
}

static void init_topo(struct lightningd_state *dstate,
		      struct bitcoin_block *blk,
		      ptrint_t *p)
{
	struct topology *topo = dstate->topology;

	topo->root = new_block(dstate, blk, NULL);
	topo->root->height = ptr2int(p);
	block_map_add(&topo->block_map, topo->root);
	topo->tip = topo->root;

	/* Now grab chaintip immediately. */
	bitcoind_get_chaintip(dstate, check_chaintip, NULL);
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
	struct peer *peer;

	/* Start back before any reasonable forks. */
	if (blockcount < dstate->config.forever_confirms)
		start = 0;
	else
		start = blockcount - dstate->config.forever_confirms;

	/* If loaded from database, go back to earliest possible peer anchor. */
	list_for_each(&dstate->peers, peer, list) {
		if (peer->anchor.min_depth && peer->anchor.min_depth < start)
			start = peer->anchor.min_depth;
	}

	/* Start topology from 100 blocks back. */
	bitcoind_getblockhash(dstate, start, get_init_block, int2ptr(start));
}

u32 get_tx_mediantime(struct lightningd_state *dstate,
		      const struct sha256_double *txid)
{
	struct block *b;

	b = block_for_tx(dstate, txid);
	if (b)
		return b->mediantime;

	fatal("Tx %s not found for get_tx_mediantime",
	      tal_hexstr(dstate, txid, sizeof(*txid)));
}

u32 get_tip_mediantime(struct lightningd_state *dstate)
{
	return dstate->topology->tip->mediantime;
}

u32 get_block_height(struct lightningd_state *dstate)
{
	return dstate->topology->tip->height;
}

u64 get_feerate(struct lightningd_state *dstate)
{
	if (dstate->config.override_fee_rate) {
		log_debug(dstate->base_log,
			"Forcing fee rate, ignoring estimate");
		return dstate->config.override_fee_rate;
	}
	else if (dstate->topology->feerate == 0) {
		log_info(dstate->base_log,
			 "No fee estimate: using default fee rate");
		return dstate->config.default_fee_rate;
	}
	return dstate->topology->feerate;
}

struct txlocator *locate_tx(const void *ctx, struct lightningd_state *dstate,
			    const struct sha256_double *txid)
{
	struct block *block = block_for_tx(dstate, txid);
	if (block == NULL) {
		return NULL;
	}

	struct txlocator *loc = talz(ctx, struct txlocator);
	loc->blkheight = block->height;
	size_t i, n = tal_count(block->txids);
	for (i = 0; i < n; i++) {
		if (structeq(&block->txids[i], txid)){
			loc->index = block->txnums[i];
			return loc;
		}
	}
	return tal_free(loc);
}

static void json_dev_broadcast(struct command *cmd,
			       const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *enabletok;
	bool enable;

	if (!json_get_params(buffer, params,
			     "enable", &enabletok,
			     NULL)) {
		command_fail(cmd, "Need enable");
		return;
	}

	if (!json_tok_bool(buffer, enabletok, &enable)) {
		command_fail(cmd, "enable must be true or false");
		return;
	}

	log_debug(cmd->dstate->base_log, "dev-broadcast: broadcast %s",
		  enable ? "enabled" : "disabled");
	cmd->dstate->dev_no_broadcast = !enable;

	/* If enabling, flush and wait. */
	if (enable)
		rebroadcast_txs(cmd->dstate, cmd);
	else
		command_success(cmd, null_response(cmd));
}

static const struct json_command dev_broadcast_command = {
	"dev-broadcast",
	json_dev_broadcast,
	"Pretend we broadcast txs, but don't send to bitcoind",
	"Returns an empty result on success (waits for flush if enabled)"
};
AUTODATA(json_command, &dev_broadcast_command);

void setup_topology(struct lightningd_state *dstate)
{
	dstate->topology = tal(dstate, struct topology);
	block_map_init(&dstate->topology->block_map);

	dstate->topology->startup = true;
	dstate->topology->feerate = 0;
	bitcoind_getblockcount(dstate, get_init_blockhash, NULL);

	/* Once it gets topology, it calls io_break() and we return. */
	io_loop(NULL, NULL);
	assert(!dstate->topology->startup);
}
