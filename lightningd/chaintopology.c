#include "bitcoin/block.h"
#include "bitcoin/script.h"
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
#include <ccan/tal/str/str.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <inttypes.h>
#include <lightningd/gossip_control.h>

/* Mutual recursion via timer. */
static void try_extend_tip(struct chain_topology *topo);

static void next_topology_timer(struct chain_topology *topo)
{
	/* This takes care of its own lifetime. */
	notleak(new_reltimer(topo->timers, topo, topo->poll_time,
			     try_extend_tip, topo));
}

static bool we_broadcast(const struct chain_topology *topo,
			 const struct bitcoin_txid *txid)
{
	const struct outgoing_tx *otx;

	list_for_each(&topo->outgoing_txs, otx, list) {
		if (structeq(&otx->txid, txid))
			return true;
	}
	return false;
}

static void filter_block_txs(struct chain_topology *topo, struct block *b)
{
	size_t i;
	u64 satoshi_owned;

	/* Now we see if any of those txs are interesting. */
	for (i = 0; i < tal_count(b->full_txs); i++) {
		const struct bitcoin_tx *tx = b->full_txs[i];
		struct bitcoin_txid txid;
		size_t j;

		/* Tell them if it spends a txo we care about. */
		for (j = 0; j < tal_count(tx->input); j++) {
			struct txwatch_output out;
			struct txowatch *txo;
			out.txid = tx->input[j].txid;
			out.index = tx->input[j].index;

			txo = txowatch_hash_get(&topo->txowatches, &out);
			if (txo) {
				wallet_transaction_add(topo->wallet, tx, b->height, i);
				txowatch_fire(txo, tx, j, b);
			}
		}

		satoshi_owned = 0;
		if (txfilter_match(topo->bitcoind->ld->owned_txfilter, tx)) {
			wallet_extract_owned_outputs(topo->bitcoind->ld->wallet,
						     tx, &b->height,
						     &satoshi_owned);
		}

		/* We did spends first, in case that tells us to watch tx. */
		bitcoin_txid(tx, &txid);
		if (watching_txid(topo, &txid) || we_broadcast(topo, &txid) ||
		    satoshi_owned != 0) {
			wallet_transaction_add(topo->wallet, tx, b->height, i);
		}
	}
	b->full_txs = tal_free(b->full_txs);
}

size_t get_tx_depth(const struct chain_topology *topo,
		    const struct bitcoin_txid *txid)
{
	u32 blockheight = wallet_transaction_height(topo->wallet, txid);

	if (blockheight == 0)
		return 0;
	return topo->tip->height - blockheight + 1;
}

struct txs_to_broadcast {
	/* We just sent txs[cursor] */
	size_t cursor;
	/* These are hex encoded already, for bitcoind_sendrawtx */
	const char **txs;

	/* Command to complete when we're done, if and only if dev-broadcast triggered */
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

	txs = tal(topo, struct txs_to_broadcast);
	txs->cmd = cmd;

	/* Put any txs we want to broadcast in ->txs. */
	txs->txs = tal_arr(txs, const char *, 0);
	list_for_each(&topo->outgoing_txs, otx, list) {
		if (wallet_transaction_height(topo->wallet, &otx->txid))
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

static void clear_otx_channel(struct channel *channel, struct outgoing_tx *otx)
{
	if (otx->channel != channel)
		fatal("channel %p, otx %p has channel %p", channel, otx, otx->channel);
	otx->channel = NULL;
}

static void broadcast_done(struct bitcoind *bitcoind,
			   int exitstatus, const char *msg,
			   struct outgoing_tx *otx)
{
	/* Channel gone?  Stop. */
	if (!otx->channel) {
		tal_free(otx);
		return;
	}

	/* No longer needs to be disconnected if channel dies. */
	tal_del_destructor2(otx->channel, clear_otx_channel, otx);

	if (otx->failed && exitstatus != 0) {
		otx->failed(otx->channel, exitstatus, msg);
		tal_free(otx);
	} else {
		/* For continual rebroadcasting, until channel freed. */
		tal_steal(otx->channel, otx);
		list_add_tail(&bitcoind->ld->topology->outgoing_txs, &otx->list);
		tal_add_destructor(otx, destroy_outgoing_tx);
	}
}

void broadcast_tx(struct chain_topology *topo,
		  struct channel *channel, const struct bitcoin_tx *tx,
		  void (*failed)(struct channel *channel,
				 int exitstatus, const char *err))
{
	/* Channel might vanish: topo owns it to start with. */
	struct outgoing_tx *otx = tal(topo, struct outgoing_tx);
	const u8 *rawtx = linearize_tx(otx, tx);

	otx->channel = channel;
	bitcoin_txid(tx, &otx->txid);
	otx->hextx = tal_hex(otx, rawtx);
	otx->failed = failed;
	tal_free(rawtx);
	tal_add_destructor2(channel, clear_otx_channel, otx);

	log_add(topo->log, " (tx %s)",
		type_to_string(tmpctx, struct bitcoin_txid, &otx->txid));

	wallet_transaction_add(topo->wallet, tx, 0, 0);
	bitcoind_sendrawtx(topo->bitcoind, otx->hextx, broadcast_done, otx);
}

static const char *feerate_name(enum feerate feerate)
{
	return feerate == FEERATE_IMMEDIATE ? "Immediate"
		: feerate == FEERATE_NORMAL ? "Normal" : "Slow";
}

/* Mutual recursion via timer. */
static void next_updatefee_timer(struct chain_topology *topo);

/* bitcoind considers 250 satoshi per kw to be the minimum acceptable fee:
 * less than this won't even relay.
 */
#define BITCOIND_MINRELAYTXFEE_PER_KW 250
/*
 * But bitcoind uses vbytes (ie. (weight + 3) / 4) for this
 * calculation, rather than weight, meaning we can disagree since we do
 * it sanely (as specified in BOLT #3).
 */
#define FEERATE_BITCOIND_SEES(feerate, weight) \
	(((feerate) * (weight)) / 1000 * 1000 / ((weight) + 3))
/* ie. fee = (feerate * weight) // 1000
 * bitcoind needs (worst-case): fee * 1000 / (weight + 3) >= 4000
 *
 * (feerate * weight) // 1000 * 1000 // (weight + 3) >= 4000
 *
 * The feerate needs to be higher for lower weight, and our minimum tx weight
 * is 464 (version (4) + count_tx_in (1) + tx_in (32 + 4 + 1 + 4) +
 * count_tx_out (1) + amount (8) + P2WSH (1 + 1 + 32) + witness 1 + 1 + <sig>
 * + 1 + <key>).  Assume it's 400 to give a significant safety margin (it
 * only makes 1 difference in the result anyway).
 */
#define MINIMUM_TX_WEIGHT 400
/*
 * This formula is satisfied by a feerate of 4030 (hand-search).
 */
#define FEERATE_FLOOR 253
static u32 feerate_floor(void)
{
	/* Assert that bitcoind will see this as above minRelayTxFee */
	BUILD_ASSERT(FEERATE_BITCOIND_SEES(FEERATE_FLOOR, MINIMUM_TX_WEIGHT)
		     >= BITCOIND_MINRELAYTXFEE_PER_KW);
	/* And a lesser value won't do */
	BUILD_ASSERT(FEERATE_BITCOIND_SEES(FEERATE_FLOOR-1, MINIMUM_TX_WEIGHT)
		     < BITCOIND_MINRELAYTXFEE_PER_KW);
	/* And I'm right about it being OK for larger txs, too */
	BUILD_ASSERT(FEERATE_BITCOIND_SEES(FEERATE_FLOOR, (MINIMUM_TX_WEIGHT*2))
		     >= BITCOIND_MINRELAYTXFEE_PER_KW);

	return FEERATE_FLOOR;
}

/* We sanitize feerates if necessary to put them in descending order. */
static void update_feerates(struct bitcoind *bitcoind,
			    const u32 *satoshi_per_kw,
			    struct chain_topology *topo)
{
	u32 old_feerates[NUM_FEERATES];
	bool changed = false;

	for (size_t i = 0; i < NUM_FEERATES; i++) {
		u32 feerate = satoshi_per_kw[i];

		if (feerate < feerate_floor())
			feerate = feerate_floor();

		if (feerate != topo->feerate[i]) {
			log_debug(topo->log, "%s feerate %u (was %u)",
				  feerate_name(i),
				  feerate, topo->feerate[i]);
			if (feerate != satoshi_per_kw[i])
				log_debug(topo->log,
					  "...feerate %u hit floor %u",
					  satoshi_per_kw[i], feerate);
		}
		old_feerates[i] = topo->feerate[i];
		topo->feerate[i] = feerate;
	}

	for (size_t i = 0; i < NUM_FEERATES; i++) {
		for (size_t j = 0; j < i; j++) {
			if (topo->feerate[j] < topo->feerate[i]) {
				log_debug(topo->log,
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

	next_updatefee_timer(topo);
}

static void start_fee_estimate(struct chain_topology *topo)
{
	/* FEERATE_IMMEDIATE, FEERATE_NORMAL, FEERATE_SLOW */
	const char *estmodes[] = { "CONSERVATIVE", "ECONOMICAL", "ECONOMICAL" };
	const u32 blocks[] = { 2, 4, 100 };

	BUILD_ASSERT(ARRAY_SIZE(blocks) == NUM_FEERATES);

	/* Once per new block head, update fee estimates. */
	bitcoind_estimate_fees(topo->bitcoind, blocks, estmodes, NUM_FEERATES,
			       update_feerates, topo);
}

static void next_updatefee_timer(struct chain_topology *topo)
{
	/* This takes care of its own lifetime. */
	notleak(new_reltimer(topo->timers, topo, topo->poll_time,
			     start_fee_estimate, topo));
}

/* Once we're run out of new blocks to add, call this. */
static void updates_complete(struct chain_topology *topo)
{
	if (topo->tip != topo->prev_tip) {
		/* Tell lightningd about new block. */
		notify_new_block(topo->bitcoind->ld, topo->tip->height);

		/* Tell watch code to re-evaluate all txs. */
		watch_topology_changed(topo);

		/* Maybe need to rebroadcast. */
		rebroadcast_txs(topo, NULL);

		/* We've processed these UTXOs */
		db_set_intvar(topo->bitcoind->ld->wallet->db,
			      "last_processed_block", topo->tip->height);

		topo->prev_tip = topo->tip;
	}

	/* Try again soon. */
	next_topology_timer(topo);
}

/**
 * topo_update_spends -- Tell the wallet about all spent outpoints
 */
static void topo_update_spends(struct chain_topology *topo, struct block *b)
{
	const struct short_channel_id *scid;
	for (size_t i = 0; i < tal_count(b->full_txs); i++) {
		const struct bitcoin_tx *tx = b->full_txs[i];
		for (size_t j = 0; j < tal_count(tx->input); j++) {
			const struct bitcoin_tx_input *input = &tx->input[j];
			scid = wallet_outpoint_spend(topo->wallet, tmpctx,
						     b->height, &input->txid,
						     input->index);
			if (scid) {
				gossipd_notify_spend(topo->bitcoind->ld, scid);
				tal_free(scid);
			}
		}
	}
}

static void topo_add_utxos(struct chain_topology *topo, struct block *b)
{
	for (size_t i = 0; i < tal_count(b->full_txs); i++) {
		const struct bitcoin_tx *tx = b->full_txs[i];
		for (size_t j = 0; j < tal_count(tx->output); j++) {
			const struct bitcoin_tx_output *output = &tx->output[j];
			if (is_p2wsh(output->script, NULL)) {
				wallet_utxoset_add(topo->wallet, tx, j,
						   b->height, i, output->script,
						   output->amount);
			}
		}
	}
}

static void add_tip(struct chain_topology *topo, struct block *b)
{
	/* Attach to tip; b is now the tip. */
	assert(b->height == topo->tip->height + 1);
	b->prev = topo->tip;
	topo->tip->next = b;
	topo->tip = b;
	wallet_block_add(topo->wallet, b);

	topo_add_utxos(topo, b);
	topo_update_spends(topo, b);

	/* Only keep the transactions we care about. */
	filter_block_txs(topo, b);

	block_map_add(&topo->block_map, b);
}

static struct block *new_block(struct chain_topology *topo,
			       struct bitcoin_block *blk,
			       unsigned int height)
{
	struct block *b = tal(topo, struct block);

	sha256_double(&b->blkid.shad, &blk->hdr, sizeof(blk->hdr));
	log_debug(topo->log, "Adding block %u: %s",
		  height,
		  type_to_string(tmpctx, struct bitcoin_blkid, &b->blkid));
	assert(!block_map_get(&topo->block_map, &b->blkid));
	b->next = NULL;
	b->prev = NULL;

	b->height = height;

	b->hdr = blk->hdr;

	b->txnums = tal_arr(b, u32, 0);
	b->full_txs = tal_steal(b, blk->tx);

	return b;
}

static void remove_tip(struct chain_topology *topo)
{
	struct block *b = topo->tip;
	struct bitcoin_txid *txs;
	size_t i, n;

	/* Move tip back one. */
	topo->tip = b->prev;
	if (!topo->tip)
		fatal("Initial block %u (%s) reorganized out!",
		      b->height,
		      type_to_string(tmpctx, struct bitcoin_blkid, &b->blkid));

	txs = wallet_transactions_by_height(b, topo->wallet, b->height);
	n = tal_count(txs);

	/* Notify that txs are kicked out. */
	for (i = 0; i < n; i++)
		txwatch_fire(topo, &txs[i], 0);

	wallet_block_remove(topo->wallet, b);
	block_map_del(&topo->block_map, b);
	tal_free(b);
}

static void have_new_block(struct bitcoind *bitcoind UNUSED,
			   struct bitcoin_block *blk,
			   struct chain_topology *topo)
{
	/* Unexpected predecessor?  Free predecessor, refetch it. */
	if (!structeq(&topo->tip->blkid, &blk->hdr.prev_hash))
		remove_tip(topo);
	else
		add_tip(topo, new_block(topo, blk, topo->tip->height + 1));

	/* Try for next one. */
	try_extend_tip(topo);
}

static void get_new_block(struct bitcoind *bitcoind,
			  const struct bitcoin_blkid *blkid,
			  struct chain_topology *topo)
{
	if (!blkid) {
		/* No such block, we're done. */
		updates_complete(topo);
		return;
	}
	bitcoind_getrawblock(bitcoind, blkid, have_new_block, topo);
}

static void try_extend_tip(struct chain_topology *topo)
{
	bitcoind_getblockhash(topo->bitcoind, topo->tip->height + 1,
			      get_new_block, topo);
}

static void init_topo(struct bitcoind *bitcoind UNUSED,
		      struct bitcoin_block *blk,
		      struct chain_topology *topo)
{
	topo->root = new_block(topo, blk, topo->first_blocknum);
	block_map_add(&topo->block_map, topo->root);
	topo->tip = topo->prev_tip = topo->root;

	/* In case we don't get all the way to updates_complete */
	db_set_intvar(topo->bitcoind->ld->wallet->db,
		      "last_processed_block", topo->tip->height);

	io_break(topo);
}

static void get_init_block(struct bitcoind *bitcoind,
			   const struct bitcoin_blkid *blkid,
			   struct chain_topology *topo)
{
	bitcoind_getrawblock(bitcoind, blkid, init_topo, topo);
}

static void get_init_blockhash(struct bitcoind *bitcoind, u32 blockcount,
			       struct chain_topology *topo)
{
	/* This can happen if bitcoind still syncing, or first_blocknum is MAX */
	if (blockcount < topo->first_blocknum)
		topo->first_blocknum = blockcount;

	/* For fork protection (esp. because we don't handle our own first
	 * block getting reorged out), we always go 100 blocks further back
	 * than we need. */
	if (topo->first_blocknum < 100)
		topo->first_blocknum = 0;
	else
		topo->first_blocknum -= 100;

	/* Rollback to the given blockheight, so we start track
	 * correctly again */
	wallet_blocks_rollback(topo->wallet, topo->first_blocknum);

	/* Get up to speed with topology. */
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

#if DEVELOPER
static void json_dev_blockheight(struct command *cmd,
				 const char *buffer UNUSED, const jsmntok_t *params UNUSED)
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
	"Show current block height"
};
AUTODATA(json_command, &dev_blockheight);

static void json_dev_setfees(struct command *cmd,
			     const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *ratetok[NUM_FEERATES];
	struct chain_topology *topo = cmd->ld->topology;
	struct json_result *response;

	if (!json_get_params(cmd, buffer, params,
			     "?immediate", &ratetok[FEERATE_IMMEDIATE],
			     "?normal", &ratetok[FEERATE_NORMAL],
			     "?slow", &ratetok[FEERATE_SLOW],
			     NULL)) {
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
			command_fail(cmd, "Invalid feerate %.*s",
				     ratetok[i]->end - ratetok[i]->start,
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
	"Set feerate in satoshi-per-kw for {immediate}, {normal} and {slow} (each is optional, when set, separate by spaces) and show the value of those three feerates"
};
AUTODATA(json_command, &dev_setfees_command);

void chaintopology_mark_pointers_used(struct htable *memtable,
				      const struct chain_topology *topo)
{
	struct txwatch_hash_iter wit;
	struct txwatch *w;
	struct txowatch_hash_iter owit;
	struct txowatch *ow;

	/* memleak can't see inside hash tables, so do them manually */
	for (w = txwatch_hash_first(&topo->txwatches, &wit);
	     w;
	     w = txwatch_hash_next(&topo->txwatches, &wit))
		memleak_scan_region(memtable, w);

	for (ow = txowatch_hash_first(&topo->txowatches, &owit);
	     ow;
	     ow = txowatch_hash_next(&topo->txowatches, &owit))
		memleak_scan_region(memtable, ow);
}
#endif /* DEVELOPER */

/* On shutdown, channels get deleted last.  That frees from our list, so
 * do it now instead. */
static void destroy_chain_topology(struct chain_topology *topo)
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
	topo->wallet = ld->wallet;
	return topo;
}

void setup_topology(struct chain_topology *topo,
		    struct timers *timers,
		    struct timerel poll_time, u32 first_blocknum)
{
	memset(&topo->feerate, 0, sizeof(topo->feerate));
	topo->timers = timers;
	topo->poll_time = poll_time;

	topo->first_blocknum = first_blocknum;

	/* Make sure bitcoind is started, and ready */
	wait_for_bitcoind(topo->bitcoind);

	bitcoind_getblockcount(topo->bitcoind, get_init_blockhash, topo);

	tal_add_destructor(topo, destroy_chain_topology);

	/* Once it gets initial block, it calls io_break() and we return. */
	io_loop(NULL, NULL);
}

void begin_topology(struct chain_topology *topo)
{
	/* Begin fee estimation. */
	start_fee_estimate(topo);

	try_extend_tip(topo);
}
