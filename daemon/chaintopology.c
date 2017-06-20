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

static void start_poll_chaintip(struct chain_topology *topo);

static void next_topology_timer(struct chain_topology *topo)
{
	if (topo->startup) {
		topo->startup = false;
		io_break(topo);
	}
	new_reltimer(topo->timers, topo, topo->poll_time,
		     start_poll_chaintip, topo);
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
static u32 get_mediantime(const struct chain_topology *topo, const struct block *b)
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

static bool we_broadcast(const struct chain_topology *topo,
			 const struct sha256_double *txid)
{
	const struct outgoing_tx *otx;

	list_for_each(&topo->outgoing_txs, otx, list) {
		if (structeq(&otx->txid, txid))
			return true;
	}
	return false;
}

/* Fills in prev, height, mediantime. */
static void connect_block(struct chain_topology *topo,
			  struct block *prev,
			  struct block *b)
{
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

			txo = txowatch_hash_get(&topo->txowatches, &out);
			if (txo)
				txowatch_fire(topo, txo, tx, j);
		}

		/* We did spends first, in case that tells us to watch tx. */
		bitcoin_txid(tx, &txid);
		if (watching_txid(topo, &txid) || we_broadcast(topo, &txid))
			add_tx_to_block(b, &txid, i);
	}
	b->full_txs = tal_free(b->full_txs);

	/* Tell peers about new block. */
	notify_new_block(topo, b->height);
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
static struct block *block_for_tx(const struct chain_topology *topo,
				  const struct sha256_double *txid)
{
	struct block *b;

	for (b = topo->tip; b; b = b->prev) {
		if (tx_in_block(b, txid))
			return b;
	}
	return NULL;
}

size_t get_tx_depth(const struct chain_topology *topo,
		    const struct sha256_double *txid)
{
	const struct block *b;

	b = block_for_tx(topo, txid);
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
static void broadcast_remainder(struct bitcoind *bitcoind,
				int exitstatus, const char *msg,
				struct txs_to_broadcast *txs)
{
	/* These are expected. */
	if (strstr(msg, "txn-mempool-conflict")
	    || strstr(msg, "transaction already in block chain"))
		log_debug(bitcoind->log,
			  "Expected error broadcasting tx %s: %s",
			  txs->txs[txs->cursor], msg);
	else if (exitstatus)
		log_unusual(bitcoind->log, "Broadcasting tx %s: %i %s",
			    txs->txs[txs->cursor], exitstatus, msg);

	txs->cursor++;
	if (txs->cursor == tal_count(txs->txs)) {
		if (txs->cmd)
			command_success(txs->cmd, null_response(txs->cmd));
		tal_free(txs);
		return;
	}

	/* Broadcast next one. */
	bitcoind_sendrawtx(bitcoind, txs->txs[txs->cursor],
			   broadcast_remainder, txs);
}

/* FIXME: This is dumb.  We can group txs and avoid bothering bitcoind
 * if any one tx is in the main chain. */
static void rebroadcast_txs(struct chain_topology *topo, struct command *cmd)
{
	/* Copy txs now (peers may go away, and they own txs). */
	size_t num_txs = 0;
	struct txs_to_broadcast *txs;
	struct outgoing_tx *otx;

	if (topo->dev_no_broadcast)
		return;

	txs = tal(topo, struct txs_to_broadcast);
	txs->cmd = cmd;

	/* Put any txs we want to broadcast in ->txs. */
	txs->txs = tal_arr(txs, const char *, 0);
	list_for_each(&topo->outgoing_txs, otx, list) {
		if (block_for_tx(topo, &otx->txid))
			continue;

		tal_resize(&txs->txs, num_txs+1);
		txs->txs[num_txs] = tal_strdup(txs, otx->hextx);
		num_txs++;
	}

	/* Let this do the dirty work. */
	txs->cursor = (size_t)-1;
	broadcast_remainder(topo->bitcoind, 0, "", txs);
}

static void destroy_outgoing_tx(struct outgoing_tx *otx)
{
	list_del(&otx->list);
}

static void clear_otx_peer(struct peer *peer, struct outgoing_tx *otx)
{
	assert(otx->peer == peer);
	otx->peer = NULL;
}

static void broadcast_done(struct bitcoind *bitcoind,
			   int exitstatus, const char *msg,
			   struct outgoing_tx *otx)
{
	/* Peer gone?  Stop. */
	if (!otx->peer) {
		tal_free(otx);
		return;
	}

	if (otx->failed && exitstatus != 0) {
		otx->failed(otx->peer, exitstatus, msg);
		tal_free(otx);
	} else {
		/* For continual rebroadcasting, until peer freed. */
		tal_steal(otx->peer, otx);
		tal_del_destructor2(otx->peer, clear_otx_peer, otx);
		list_add_tail(&otx->topo->outgoing_txs, &otx->list);
		tal_add_destructor(otx, destroy_outgoing_tx);
	}
}

void broadcast_tx(struct chain_topology *topo,
		  struct peer *peer, const struct bitcoin_tx *tx,
		  void (*failed)(struct peer *peer,
				 int exitstatus, const char *err))
{
	/* Peer might vanish: topo owns it to start with. */
	struct outgoing_tx *otx = tal(topo, struct outgoing_tx);
	const u8 *rawtx = linearize_tx(otx, tx);

	otx->peer = peer;
	bitcoin_txid(tx, &otx->txid);
	otx->hextx = tal_hex(otx, rawtx);
	otx->failed = failed;
	otx->topo = topo;
	tal_free(rawtx);
	tal_add_destructor2(peer, clear_otx_peer, otx);

	log_add_struct(topo->log,
		       " (tx %s)", struct sha256_double, &otx->txid);

	if (topo->dev_no_broadcast)
		broadcast_done(topo->bitcoind, 0, "dev_no_broadcast", otx);
	else
		bitcoind_sendrawtx(topo->bitcoind, otx->hextx,
				   broadcast_done, otx);
}

static void free_blocks(struct chain_topology *topo, struct block *b)
{
	struct block *next;

	while (b) {
		size_t i, n = tal_count(b->txids);

		/* Notify that txs are kicked out. */
		for (i = 0; i < n; i++)
			txwatch_fire(topo, &b->txids[i], 0);

		next = b->next;
		tal_free(b);
		b = next;
	}
}

static void update_fee(struct bitcoind *bitcoind, u64 rate,
		       struct chain_topology *topo)
{
	log_debug(topo->log, "Feerate %"PRIu64" (was %"PRIu64")",
		  rate, topo->feerate);
	topo->feerate = rate;
}

/* B is the new chain (linked by ->next); update topology */
static void topology_changed(struct chain_topology *topo,
			     struct block *prev,
			     struct block *b)
{
	/* Eliminate any old chain. */
	if (prev->next)
		free_blocks(topo, prev->next);

	prev->next = b;
	do {
		connect_block(topo, prev, b);
		topo->tip = prev = b;
		b = b->next;
	} while (b);

	/* Tell watch code to re-evaluate all txs. */
	watch_topology_changed(topo);

	/* Maybe need to rebroadcast. */
	rebroadcast_txs(topo, NULL);

	/* Once per new block head, update fee estimate. */
	bitcoind_estimate_fee(topo->bitcoind, update_fee, topo);
}

static struct block *new_block(struct chain_topology *topo,
			       struct bitcoin_block *blk,
			       struct block *next)
{
	struct block *b = tal(topo, struct block);

	sha256_double(&b->blkid, &blk->hdr, sizeof(blk->hdr));
	log_debug_struct(topo->log, "Adding block %s",
			 struct sha256_double, &b->blkid);
	assert(!block_map_get(&topo->block_map, &b->blkid));
	b->next = next;
	b->topo = topo;

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

static void add_block(struct bitcoind *bitcoind,
		      struct chain_topology *topo,
		      struct bitcoin_block *blk,
		      struct block *next);

static void gather_previous_blocks(struct bitcoind *bitcoind,
				   struct bitcoin_block *blk,
				   struct block *next)
{
	add_block(bitcoind, next->topo, blk, next);
}

static void add_block(struct bitcoind *bitcoind,
		      struct chain_topology *topo,
		      struct bitcoin_block *blk,
		      struct block *next)
{
	struct block *b, *prev;

	b = new_block(topo, blk, next);

	/* Recurse if we need prev. */
	prev = block_map_get(&topo->block_map, &blk->hdr.prev_hash);
	if (!prev) {
		bitcoind_getrawblock(bitcoind, &blk->hdr.prev_hash,
				     gather_previous_blocks, b);
		return;
	}

	/* All done. */
	topology_changed(topo, prev, b);
	next_topology_timer(topo);
}

static void rawblock_tip(struct bitcoind *bitcoind,
			 struct bitcoin_block *blk,
			 struct chain_topology *topo)
{
	add_block(bitcoind, topo, blk, NULL);
}

static void check_chaintip(struct bitcoind *bitcoind,
			   const struct sha256_double *tipid,
			   struct chain_topology *topo)
{
	/* 0 is the main tip. */
	if (!structeq(tipid, &topo->tip->blkid))
		bitcoind_getrawblock(bitcoind, tipid, rawblock_tip, topo);
	else
		/* Next! */
		next_topology_timer(topo);
}

static void start_poll_chaintip(struct chain_topology *topo)
{
	if (!list_empty(&topo->bitcoind->pending)) {
		log_unusual(topo->log,
			    "Delaying start poll: commands in progress");
		next_topology_timer(topo);
	} else
		bitcoind_get_chaintip(topo->bitcoind, check_chaintip, topo);
}

static void init_topo(struct bitcoind *bitcoind,
		      struct bitcoin_block *blk,
		      struct chain_topology *topo)
{
	topo->root = new_block(topo, blk, NULL);
	topo->root->height = topo->first_blocknum;
	block_map_add(&topo->block_map, topo->root);
	topo->tip = topo->root;

	/* Now grab chaintip immediately. */
	bitcoind_get_chaintip(bitcoind, check_chaintip, topo);
}

static void get_init_block(struct bitcoind *bitcoind,
			   const struct sha256_double *blkid,
			   struct chain_topology *topo)
{
	bitcoind_getrawblock(bitcoind, blkid, init_topo, topo);
}

static void get_init_blockhash(struct bitcoind *bitcoind, u32 blockcount,
			       struct chain_topology *topo)
{
	/* Start back before any reasonable forks. */
	if (blockcount < 100)
		topo->first_blocknum = 0;
	else if (!topo->first_blocknum || blockcount - 100 < topo->first_blocknum)
		topo->first_blocknum = blockcount - 100;

	/* Start topology from 100 blocks back. */
	bitcoind_getblockhash(bitcoind, topo->first_blocknum,
			      get_init_block, topo);
}

u32 get_tx_mediantime(const struct chain_topology *topo,
		      const struct sha256_double *txid)
{
	struct block *b;

	b = block_for_tx(topo, txid);
	if (b)
		return b->mediantime;

	fatal("Tx %s not found for get_tx_mediantime",
	      tal_hexstr(topo, txid, sizeof(*txid)));
}

u32 get_tip_mediantime(const struct chain_topology *topo)
{
	return topo->tip->mediantime;
}

u32 get_block_height(const struct chain_topology *topo)
{
	return topo->tip->height;
}

u64 get_feerate(const struct chain_topology *topo)
{
	if (topo->override_fee_rate) {
		log_debug(topo->log, "Forcing fee rate, ignoring estimate");
		return topo->override_fee_rate;
	}
	else if (topo->feerate == 0) {
		log_info(topo->log, "No fee estimate: using default fee rate");
		return topo->default_fee_rate;
	}
	return topo->feerate;
}

struct txlocator *locate_tx(const void *ctx, const struct chain_topology *topo,
			    const struct sha256_double *txid)
{
	struct block *block = block_for_tx(topo, txid);
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

void json_dev_broadcast(struct command *cmd,
			struct chain_topology *topo,
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
	cmd->dstate->topology->dev_no_broadcast = !enable;

	/* If enabling, flush and wait. */
	if (enable)
		rebroadcast_txs(cmd->dstate->topology, cmd);
	else
		command_success(cmd, null_response(cmd));
}

static void json_dev_blockheight(struct command *cmd,
				 const char *buffer, const jsmntok_t *params)
{
	struct chain_topology *topo = cmd->dstate->topology;
	struct json_result *response;

	response = new_json_result(cmd);
	json_object_start(response, NULL);
	json_add_num(response, "blockheight", get_block_height(topo));
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command dev_blockheight = {
	"dev-blockheight",
	json_dev_blockheight,
	"Find out what block height we have",
	"Returns { blockheight: u32 } on success"
};
AUTODATA(json_command, &dev_blockheight);

/* On shutdown, peers get deleted last.  That frees from our list, so
 * do it now instead. */
static void destroy_outgoing_txs(struct chain_topology *topo)
{
	struct outgoing_tx *otx;

	while ((otx = list_pop(&topo->outgoing_txs, struct outgoing_tx, list)))
		tal_free(otx);
}

struct chain_topology *new_topology(const tal_t *ctx, struct log *log)
{
	struct chain_topology *topo = tal(ctx, struct chain_topology);

	block_map_init(&topo->block_map);
	list_head_init(&topo->outgoing_txs);
	txwatch_hash_init(&topo->txwatches);
	txowatch_hash_init(&topo->txowatches);
	topo->log = log;
	topo->default_fee_rate = 40000;
	topo->override_fee_rate = 0;
	topo->dev_no_broadcast = false;

	return topo;
}

void setup_topology(struct chain_topology *topo, struct bitcoind *bitcoind,
		    struct timers *timers,
		    struct timerel poll_time, u32 first_peer_block)
{
	topo->startup = true;
	topo->feerate = 0;
	topo->timers = timers;
	topo->bitcoind = bitcoind;
	topo->poll_time = poll_time;
	topo->first_blocknum = first_peer_block;

	bitcoind_getblockcount(bitcoind, get_init_blockhash, topo);

	tal_add_destructor(topo, destroy_outgoing_txs);

	/* Once it gets topology, it calls io_break() and we return. */
	io_loop(NULL, NULL);
	assert(!topo->startup);
}
