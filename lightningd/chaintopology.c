#include "bitcoin/block.h"
#include "bitcoin/tx.h"
#include "bitcoind.h"
#include "chaintopology.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "watch.h"
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/io/io.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <common/timeout.h>
#include <common/utils.h>
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

/* FIXME: Remove tx from block when peer done. */
static void add_tx_to_block(struct block *b,
			    const struct bitcoin_tx *tx, const u32 txnum)
{
	size_t n = tal_count(b->txs);

	tal_resize(&b->txs, n+1);
	tal_resize(&b->txnums, n+1);
	b->txs[n] = tal_steal(b->txs, tx);
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
	u64 satoshi_owned;

	assert(b->height == -1);
	assert(b->prev == NULL);
	assert(prev->next == b);

	b->prev = prev;
	b->height = b->prev->height + 1;

	block_map_add(&topo->block_map, b);

	/* Now we see if any of those txs are interesting. */
	for (i = 0; i < tal_count(b->full_txs); i++) {
		const struct bitcoin_tx *tx = b->full_txs[i];
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
				txowatch_fire(topo, txo, tx, j, b);
		}

		satoshi_owned = 0;
		if (txfilter_match(topo->bitcoind->ld->owned_txfilter, tx)) {
			wallet_extract_owned_outputs(topo->bitcoind->ld->wallet,
						     tx, &satoshi_owned);
		}

		/* We did spends first, in case that tells us to watch tx. */
		bitcoin_txid(tx, &txid);
		if (watching_txid(topo, &txid) || we_broadcast(topo, &txid) ||
		    satoshi_owned != 0)
			add_tx_to_block(b, tx, i);
	}
	b->full_txs = tal_free(b->full_txs);

	/* Tell lightningd about new block. */
	notify_new_block(topo->bitcoind->ld, b->height);
}

static const struct bitcoin_tx *tx_in_block(const struct block *b,
					    const struct sha256_double *txid)
{
	size_t i, n = tal_count(b->txs);

	for (i = 0; i < n; i++) {
		struct sha256_double this_txid;
		bitcoin_txid(b->txs[i], &this_txid);
		if (structeq(&this_txid, txid))
			return b->txs[i];
	}
	return NULL;
}

/* FIXME: Use hash table. */
static struct block *block_for_tx(const struct chain_topology *topo,
				  const struct sha256_double *txid,
				  const struct bitcoin_tx **tx)
{
	struct block *b;
	const struct bitcoin_tx *dummy_tx;

	if (!tx)
		tx = &dummy_tx;

	for (b = topo->tip; b; b = b->prev) {
		*tx = tx_in_block(b, txid);
		if (*tx)
			return b;
	}
	return NULL;
}

size_t get_tx_depth(const struct chain_topology *topo,
		    const struct sha256_double *txid,
		    const struct bitcoin_tx **tx)
{
	const struct block *b;

	b = block_for_tx(topo, txid, tx);
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

#if DEVELOPER
	if (topo->dev_no_broadcast)
		return;
#endif /* DEVELOPER */

	txs = tal(topo, struct txs_to_broadcast);
	txs->cmd = cmd;

	/* Put any txs we want to broadcast in ->txs. */
	txs->txs = tal_arr(txs, const char *, 0);
	list_for_each(&topo->outgoing_txs, otx, list) {
		if (block_for_tx(topo, &otx->txid, NULL))
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

	log_add(topo->log, " (tx %s)",
		type_to_string(ltmp, struct sha256_double, &otx->txid));

#if DEVELOPER
	if (topo->dev_no_broadcast) {
		broadcast_done(topo->bitcoind, 0, "dev_no_broadcast", otx);
		return;
	}
#endif
	bitcoind_sendrawtx(topo->bitcoind, otx->hextx, broadcast_done, otx);
}

static void free_blocks(struct chain_topology *topo, struct block *b)
{
	struct block *next;

	while (b) {
		size_t i, n = tal_count(b->txs);

		/* Notify that txs are kicked out. */
		for (i = 0; i < n; i++)
			txwatch_fire(topo, b->txs[i], 0);

		next = b->next;
		tal_free(b);
		b = next;
	}
}

static const char *feerate_name(enum feerate feerate)
{
	return feerate == FEERATE_IMMEDIATE ? "Immediate"
		: feerate == FEERATE_NORMAL ? "Normal" : "Slow";
}

/* We sanitize feerates if necessary to put them in descending order. */
static void update_feerates(struct bitcoind *bitcoind,
			    const u32 *satoshi_per_kw,
			    struct chain_topology *topo)
{
	u32 old_feerates[NUM_FEERATES];
	bool changed = false;

	for (size_t i = 0; i < NUM_FEERATES; i++) {
		log_debug(topo->log, "%s feerate %u (was %u)",
			  feerate_name(i),
			  satoshi_per_kw[i], topo->feerate[i]);
		old_feerates[i] = topo->feerate[i];
		topo->feerate[i] = satoshi_per_kw[i];
	}

	for (size_t i = 0; i < NUM_FEERATES; i++) {
		for (size_t j = 0; j < i; j++) {
			if (topo->feerate[j] < topo->feerate[i]) {
				log_unusual(topo->log,
					    "Feerate %s (%u) above %s (%u)",
					    feerate_name(i), topo->feerate[i],
					    feerate_name(j), topo->feerate[j]);
				topo->feerate[j] = topo->feerate[i];
			}
		}
		if (topo->feerate[i] != old_feerates[i])
			changed = true;
	}

	if (changed)
		notify_feerate_change(bitcoind->ld);
}

/* B is the new chain (linked by ->next); update topology */
static void topology_changed(struct chain_topology *topo,
			     struct block *prev,
			     struct block *b)
{
	/* FEERATE_IMMEDIATE, FEERATE_NORMAL, FEERATE_SLOW */
	const char *estmodes[] = { "CONSERVATIVE", "ECONOMICAL", "ECONOMICAL" };
	const u32 blocks[] = { 2, 4, 100 };

	BUILD_ASSERT(ARRAY_SIZE(blocks) == NUM_FEERATES);

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

	/* Once per new block head, update fee estimates. */
	bitcoind_estimate_fees(topo->bitcoind, blocks, estmodes, NUM_FEERATES,
			       update_feerates, topo);
}

static struct block *new_block(struct chain_topology *topo,
			       struct bitcoin_block *blk,
			       struct block *next)
{
	struct block *b = tal(topo, struct block);

	sha256_double(&b->blkid, &blk->hdr, sizeof(blk->hdr));
	log_debug(topo->log, "Adding block %s",
		  type_to_string(ltmp, struct sha256_double, &b->blkid));
	assert(!block_map_get(&topo->block_map, &b->blkid));
	b->next = next;
	b->topo = topo;

	/* We fill these out in topology_changed */
	b->height = -1;
	b->prev = NULL;

	b->hdr = blk->hdr;

	b->txs = tal_arr(b, const struct bitcoin_tx *, 0);
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

u32 get_block_height(const struct chain_topology *topo)
{
	return topo->tip->height;
}

/* We may only have estimate for 2 blocks, for example.  Extrapolate. */
static u32 guess_feerate(const struct chain_topology *topo, enum feerate feerate)
{
	size_t i = 0;
	u32 rate = 0;

	/* We assume each one is half the previous. */
	for (i = 0; i < feerate; i++) {
		if (topo->feerate[i]) {
			log_info(topo->log,
				 "No fee estimate for %s: basing on %s rate",
				 feerate_name(feerate),
				 feerate_name(i));
			rate = topo->feerate[i];
		}
		rate /= 2;
	}

	if (rate == 0) {
		rate = topo->default_fee_rate >> feerate;
		log_info(topo->log,
			 "No fee estimate for %s: basing on default fee rate",
			 feerate_name(feerate));
	}

	return rate;
}

u32 get_feerate(const struct chain_topology *topo, enum feerate feerate)
{
	if (topo->override_fee_rate) {
		log_debug(topo->log, "Forcing fee rate, ignoring estimate");
		return topo->override_fee_rate[feerate];
	} else if (topo->feerate[feerate] == 0) {
		return guess_feerate(topo, feerate);
	}
	return topo->feerate[feerate];
}

struct txlocator *locate_tx(const void *ctx, const struct chain_topology *topo,
			    const struct sha256_double *txid)
{
	struct block *block = block_for_tx(topo, txid, NULL);
	if (block == NULL) {
		return NULL;
	}

	struct txlocator *loc = talz(ctx, struct txlocator);
	loc->blkheight = block->height;
	size_t i, n = tal_count(block->txs);
	for (i = 0; i < n; i++) {
		struct sha256_double this_txid;
		bitcoin_txid(block->txs[i], &this_txid);
		if (structeq(&this_txid, txid)){
			loc->index = block->txnums[i];
			return loc;
		}
	}
	return tal_free(loc);
}

#if DEVELOPER
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

	log_debug(cmd->ld->log, "dev-broadcast: broadcast %s",
		  enable ? "enabled" : "disabled");
	cmd->ld->topology->dev_no_broadcast = !enable;

	/* If enabling, flush and wait. */
	if (enable)
		rebroadcast_txs(cmd->ld->topology, cmd);
	else
		command_success(cmd, null_response(cmd));
}

static void json_dev_blockheight(struct command *cmd,
				 const char *buffer, const jsmntok_t *params)
{
	struct chain_topology *topo = cmd->ld->topology;
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

static void json_dev_setfees(struct command *cmd,
			     const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *ratetok[NUM_FEERATES];
	struct chain_topology *topo = cmd->ld->topology;
	struct json_result *response;

	if (!json_get_params(buffer, params,
			     "?immediate", &ratetok[FEERATE_IMMEDIATE],
			     "?normal", &ratetok[FEERATE_NORMAL],
			     "?slow", &ratetok[FEERATE_SLOW],
			     NULL)) {
		command_fail(cmd, "Bad parameters");
		return;
	}

	if (!topo->override_fee_rate) {
		u32 fees[NUM_FEERATES];
		for (size_t i = 0; i < ARRAY_SIZE(fees); i++)
			fees[i] = get_feerate(topo, i);
		topo->override_fee_rate = tal_dup_arr(topo, u32, fees,
						      ARRAY_SIZE(fees), 0);
	}
	for (size_t i = 0; i < NUM_FEERATES; i++) {
		if (!ratetok[i])
			continue;
		if (!json_tok_number(buffer, ratetok[i],
				     &topo->override_fee_rate[i])) {
			command_fail(cmd, "invalid feerate %.*s",
				     (int)(ratetok[i]->end - ratetok[i]->start),
				     buffer + ratetok[i]->start);
			return;
		}
	}
	log_debug(topo->log,
		  "dev-setfees: fees now %u/%u/%u",
		  topo->override_fee_rate[FEERATE_IMMEDIATE],
		  topo->override_fee_rate[FEERATE_NORMAL],
		  topo->override_fee_rate[FEERATE_SLOW]);

	notify_feerate_change(cmd->ld);

	response = new_json_result(cmd);
	json_object_start(response, NULL);
	json_add_num(response, "immediate",
		     topo->override_fee_rate[FEERATE_IMMEDIATE]);
	json_add_num(response, "normal",
		     topo->override_fee_rate[FEERATE_NORMAL]);
	json_add_num(response, "slow",
		     topo->override_fee_rate[FEERATE_SLOW]);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command dev_setfees_command = {
	"dev-setfees",
	json_dev_setfees,
	"Set feerate in satoshi-per-kw for {immediate}, {normal} and {slow} (each optional).  Returns the value of those three feerates.",
	"Allows testing of feerate changes"
};
AUTODATA(json_command, &dev_setfees_command);
#endif /* DEVELOPER */

/* On shutdown, peers get deleted last.  That frees from our list, so
 * do it now instead. */
static void destroy_outgoing_txs(struct chain_topology *topo)
{
	struct outgoing_tx *otx;

	while ((otx = list_pop(&topo->outgoing_txs, struct outgoing_tx, list)))
		tal_free(otx);
}

struct chain_topology *new_topology(struct lightningd *ld, struct log *log)
{
	struct chain_topology *topo = tal(ld, struct chain_topology);

	block_map_init(&topo->block_map);
	list_head_init(&topo->outgoing_txs);
	txwatch_hash_init(&topo->txwatches);
	txowatch_hash_init(&topo->txowatches);
	topo->log = log;
	topo->default_fee_rate = 40000;
	topo->override_fee_rate = NULL;
	topo->bitcoind = new_bitcoind(topo, ld, log);
#if DEVELOPER
	topo->dev_no_broadcast = false;
#endif

	return topo;
}

void setup_topology(struct chain_topology *topo,
		    struct timers *timers,
		    struct timerel poll_time, u32 first_peer_block)
{
	topo->startup = true;
	memset(&topo->feerate, 0, sizeof(topo->feerate));
	topo->timers = timers;
	topo->poll_time = poll_time;
	topo->first_blocknum = first_peer_block;

	/* Make sure bitcoind is started, and ready */
	wait_for_bitcoind(topo->bitcoind);

	bitcoind_getblockcount(topo->bitcoind, get_init_blockhash, topo);

	tal_add_destructor(topo, destroy_outgoing_txs);

	/* Once it gets topology, it calls io_break() and we return. */
	io_loop(NULL, NULL);
	assert(!topo->startup);
}
