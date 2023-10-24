#include "config.h"
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/io/io.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/htlc_tx.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/timeout.h>
#include <common/trace.h>
#include <common/type_to_string.h>
#include <db/exec.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/gossip_control.h>
#include <lightningd/io_loop_with_timers.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/notification.h>
#include <math.h>
#include <wallet/txfilter.h>

/* Mutual recursion via timer. */
static void try_extend_tip(struct chain_topology *topo);

static bool first_update_complete = false;

/* init_topo sets topo->root, start_fee_estimate clears
 * feerate_uninitialized (even if unsuccessful) */
static void maybe_completed_init(struct chain_topology *topo)
{
	if (topo->feerate_uninitialized)
		return;
	if (!topo->root)
		return;
	log_debug(topo->ld->log, "io_break: %s", __func__);
	io_break(topo);
}

static void next_topology_timer(struct chain_topology *topo)
{
	assert(!topo->extend_timer);
	topo->extend_timer = new_reltimer(topo->ld->timers, topo,
					  time_from_sec(topo->poll_seconds),
					  try_extend_tip, topo);
}

static bool we_broadcast(const struct chain_topology *topo,
			 const struct bitcoin_txid *txid)
{
	return outgoing_tx_map_get(topo->outgoing_txs, txid) != NULL;
}

static void filter_block_txs(struct chain_topology *topo, struct block *b)
{
	size_t i;
	struct amount_sat owned;

	/* Now we see if any of those txs are interesting. */
	for (i = 0; i < tal_count(b->full_txs); i++) {
		const struct bitcoin_tx *tx = b->full_txs[i];
		struct bitcoin_txid txid;
		size_t j;
		bool is_coinbase = i == 0;

		/* Tell them if it spends a txo we care about. */
		for (j = 0; j < tx->wtx->num_inputs; j++) {
			struct bitcoin_outpoint out;
			struct txowatch *txo;
			bitcoin_tx_input_get_txid(tx, j, &out.txid);
			out.n = tx->wtx->inputs[j].index;

			txo = txowatch_hash_get(topo->txowatches, &out);
			if (txo) {
				wallet_transaction_add(topo->ld->wallet,
						       tx->wtx, b->height, i);
				txowatch_fire(txo, tx, j, b);
			}
		}

		owned = AMOUNT_SAT(0);
		txid = b->txids[i];
		if (txfilter_match(topo->bitcoind->ld->owned_txfilter, tx)) {
			wallet_extract_owned_outputs(topo->bitcoind->ld->wallet,
						     tx->wtx, is_coinbase, &b->height, &owned);
			wallet_transaction_add(topo->ld->wallet, tx->wtx,
					       b->height, i);
		}

		/* We did spends first, in case that tells us to watch tx. */
		if (watching_txid(topo, &txid) || we_broadcast(topo, &txid)) {
			wallet_transaction_add(topo->ld->wallet,
					       tx->wtx, b->height, i);
		}

		txwatch_inform(topo, &txid, tx);
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

struct txs_to_broadcast {
	/* We just sent txs[cursor] */
	size_t cursor;
	/* These are hex encoded already, for bitcoind_sendrawtx */
	const char **txs;

	/* IDs to attach to each tx (could be NULL!) */
	const char **cmd_id;

	/* allowhighfees flags for each tx */
	bool *allowhighfees;
};

/* We just sent the last entry in txs[].  Shrink and send the next last. */
static void broadcast_remainder(struct bitcoind *bitcoind,
				bool success, const char *msg,
				struct txs_to_broadcast *txs)
{
	if (!success)
		log_debug(bitcoind->log,
			  "Expected error broadcasting tx %s: %s",
			  txs->txs[txs->cursor], msg);

	txs->cursor++;
	if (txs->cursor == tal_count(txs->txs)) {
		tal_free(txs);
		return;
	}

	/* Broadcast next one. */
	bitcoind_sendrawtx(bitcoind, bitcoind,
			   txs->cmd_id[txs->cursor], txs->txs[txs->cursor],
			   txs->allowhighfees[txs->cursor],
			   broadcast_remainder, txs);
}

/* FIXME: This is dumb.  We can group txs and avoid bothering bitcoind
 * if any one tx is in the main chain. */
static void rebroadcast_txs(struct chain_topology *topo)
{
	/* Copy txs now (peers may go away, and they own txs). */
	struct txs_to_broadcast *txs;
	struct outgoing_tx *otx;
	struct outgoing_tx_map_iter it;
	tal_t *cleanup_ctx = tal(NULL, char);

	txs = tal(topo, struct txs_to_broadcast);
	txs->cmd_id = tal_arr(txs, const char *, 0);

	/* Put any txs we want to broadcast in ->txs. */
	txs->txs = tal_arr(txs, const char *, 0);
	txs->allowhighfees = tal_arr(txs, bool, 0);

	for (otx = outgoing_tx_map_first(topo->outgoing_txs, &it); otx;
	     otx = outgoing_tx_map_next(topo->outgoing_txs, &it)) {
		if (wallet_transaction_height(topo->ld->wallet, &otx->txid))
			continue;

		/* Don't send ones which aren't ready yet.  Note that if the
		 * minimum block is N, we broadcast it when we have block N-1! */
		if (get_block_height(topo) + 1 < otx->minblock)
			continue;

		/* Don't free from txmap inside loop! */
		if (otx->refresh
		    && !otx->refresh(otx->channel, &otx->tx, otx->cbarg)) {
			tal_steal(cleanup_ctx, otx);
			continue;
		}

		tal_arr_expand(&txs->txs, fmt_bitcoin_tx(txs->txs, otx->tx));
		tal_arr_expand(&txs->allowhighfees, otx->allowhighfees);
		tal_arr_expand(&txs->cmd_id, tal_strdup_or_null(txs, otx->cmd_id));
	}
	tal_free(cleanup_ctx);

	/* Free explicitly in case we were called because a block came in.
	 * Then set a new timer 30-60 seconds away */
	tal_free(topo->rebroadcast_timer);
	topo->rebroadcast_timer = new_reltimer(topo->ld->timers, topo,
					       time_from_sec(30 + pseudorand(30)),
					       rebroadcast_txs, topo);

	/* Let this do the dirty work. */
	txs->cursor = (size_t)-1;
	broadcast_remainder(topo->bitcoind, true, "", txs);
}

static void destroy_outgoing_tx(struct outgoing_tx *otx, struct chain_topology *topo)
{
	outgoing_tx_map_del(topo->outgoing_txs, otx);
}

static void clear_otx_channel(struct channel *channel, struct outgoing_tx *otx)
{
	if (otx->channel != channel)
		fatal("channel %p, otx %p has channel %p", channel, otx, otx->channel);
	otx->channel = NULL;
}

static void broadcast_done(struct bitcoind *bitcoind,
			   bool success, const char *msg,
			   struct outgoing_tx *otx)
{
	/* Channel gone?  Stop. */
	if (!otx->channel) {
		tal_free(otx);
		return;
	}

	/* No longer needs to be disconnected if channel dies. */
	tal_del_destructor2(otx->channel, clear_otx_channel, otx);

	if (otx->finished) {
		if (otx->finished(otx->channel, otx->tx, success, msg, otx->cbarg)) {
			tal_free(otx);
			return;
		}
	}

	if (we_broadcast(bitcoind->ld->topology, &otx->txid)) {
		log_debug(
		    bitcoind->ld->topology->log,
		    "Not adding %s to list of outgoing transactions, already "
		    "present",
		    type_to_string(tmpctx, struct bitcoin_txid, &otx->txid));
		tal_free(otx);
		return;
	}

	/* For continual rebroadcasting, until channel freed. */
	tal_steal(otx->channel, otx);
	outgoing_tx_map_add(bitcoind->ld->topology->outgoing_txs, otx);
	tal_add_destructor2(otx, destroy_outgoing_tx, bitcoind->ld->topology);
}

void broadcast_tx_(struct chain_topology *topo,
		   struct channel *channel, const struct bitcoin_tx *tx,
		   const char *cmd_id, bool allowhighfees, u32 minblock,
		   bool (*finished)(struct channel *channel,
				    const struct bitcoin_tx *tx,
				    bool success,
				    const char *err,
				    void *cbarg),
		   bool (*refresh)(struct channel *channel,
				   const struct bitcoin_tx **tx,
				   void *cbarg),
		   void *cbarg)
{
	/* Channel might vanish: topo owns it to start with. */
	struct outgoing_tx *otx = tal(topo, struct outgoing_tx);

	otx->channel = channel;
	bitcoin_txid(tx, &otx->txid);
	otx->tx = clone_bitcoin_tx(otx, tx);
	otx->minblock = minblock;
	otx->allowhighfees = allowhighfees;
	otx->finished = finished;
	otx->refresh = refresh;
	otx->cbarg = cbarg;
	if (taken(otx->cbarg))
		tal_steal(otx, otx->cbarg);
	otx->cmd_id = tal_strdup_or_null(otx, cmd_id);

	/* Note that if the minimum block is N, we broadcast it when
	 * we have block N-1! */
	if (get_block_height(topo) + 1 < otx->minblock) {
		log_debug(topo->log, "Deferring broadcast of txid %s until block %u",
			  type_to_string(tmpctx, struct bitcoin_txid, &otx->txid),
			  otx->minblock - 1);

		/* For continual rebroadcasting, until channel freed. */
		tal_steal(otx->channel, otx);
		outgoing_tx_map_add(topo->outgoing_txs, otx);
		tal_add_destructor2(otx, destroy_outgoing_tx, topo);
		return;
	}

	tal_add_destructor2(channel, clear_otx_channel, otx);
	log_debug(topo->log, "Broadcasting txid %s%s%s",
		  type_to_string(tmpctx, struct bitcoin_txid, &otx->txid),
		  cmd_id ? " for " : "", cmd_id ? cmd_id : "");

	wallet_transaction_add(topo->ld->wallet, tx->wtx, 0, 0);
	bitcoind_sendrawtx(topo->bitcoind, topo->bitcoind, otx->cmd_id,
			   fmt_bitcoin_tx(tmpctx, otx->tx),
			   allowhighfees,
			   broadcast_done, otx);
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
			      type_to_string(tmpctx,
					     struct bitcoin_tx,
					     tx),
			      type_to_string(tmpctx,
					     struct bitcoin_txid,
					     txid));
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
	for (size_t i = 0; i < tal_count(unconfirmed); i++) {
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

/* Mutual recursion via timer. */
static void next_updatefee_timer(struct chain_topology *topo);

static u32 interp_feerate(const struct feerate_est *rates, u32 blockcount)
{
	const struct feerate_est *before = NULL, *after = NULL;

	/* Find before and after. */
	for (size_t i = 0; i < tal_count(rates); i++) {
		if (rates[i].blockcount <= blockcount) {
			before = &rates[i];
		} else if (rates[i].blockcount > blockcount && !after) {
			after = &rates[i];
		}
	}
	/* No estimates at all? */
	if (!before && !after)
		return 0;
	/* We don't extrapolate. */
	if (!before && after)
		return after->rate;
	if (before && !after)
		return before->rate;

	/* Interpolate, eg. blockcount 10, rate 15000, blockcount 20, rate 5000.
	 * At 15, rate should be 10000.
	 * 15000 + (15 - 10) / (20 - 10) * (15000 - 5000)
	 * 15000 + 5 / 10 * 10000
	 * => 10000
	 */
	/* Don't go backwards though! */
	if (before->rate < after->rate)
		return before->rate;

	return before->rate
		- ((u64)(blockcount - before->blockcount)
		   * (before->rate - after->rate)
		   / (after->blockcount - before->blockcount));

}

u32 feerate_for_deadline(const struct chain_topology *topo, u32 blockcount)
{
	u32 rate = interp_feerate(topo->feerates[0], blockcount);

	/* 0 is a special value, meaning "don't know" */
	if (rate && rate < topo->feerate_floor)
		rate = topo->feerate_floor;
	return rate;
}

u32 smoothed_feerate_for_deadline(const struct chain_topology *topo,
				  u32 blockcount)
{
	/* Note: we cap it at feerate_floor when we smooth */
	return interp_feerate(topo->smoothed_feerates, blockcount);
}

/* feerate_for_deadline, but really lowball for distant targets */
u32 feerate_for_target(const struct chain_topology *topo, u64 deadline)
{
	u64 blocks, blockheight;

	blockheight = get_block_height(topo);

	/* Past deadline?  Want it now. */
	if (blockheight > deadline)
		return feerate_for_deadline(topo, 1);

	blocks = deadline - blockheight;

	/* Over 200 blocks, we *always* use min fee! */
	if (blocks > 200)
		return FEERATE_FLOOR;
	/* Over 100 blocks, use min fee bitcoind will accept */
	if (blocks > 100)
		return get_feerate_floor(topo);

	return feerate_for_deadline(topo, blocks);
}

/* Mixes in fresh feerate rate into old smoothed values, modifies rate */
static void smooth_one_feerate(const struct chain_topology *topo,
			       struct feerate_est *rate)
{
	/* Smoothing factor alpha for simple exponential smoothing. The goal is to
	 * have the feerate account for 90 percent of the values polled in the last
	 * 2 minutes. The following will do that in a polling interval
	 * independent manner. */
	double alpha = 1 - pow(0.1,(double)topo->poll_seconds / 120);
	u32 old_feerate, feerate_smooth;

	/* We don't call this unless we had a previous feerate */
	old_feerate = smoothed_feerate_for_deadline(topo, rate->blockcount);
	assert(old_feerate);

	feerate_smooth = rate->rate * alpha + old_feerate * (1 - alpha);

	/* But to avoid updating forever, only apply smoothing when its
	 * effect is more then 10 percent */
	if (abs((int)rate->rate - (int)feerate_smooth) > (0.1 * rate->rate))
		rate->rate = feerate_smooth;

	if (rate->rate < get_feerate_floor(topo))
		rate->rate = get_feerate_floor(topo);

	if (rate->rate != feerate_smooth)
		log_debug(topo->log,
			  "Feerate estimate for %u blocks set to %u (was %u)",
			  rate->blockcount, rate->rate, feerate_smooth);
}

static bool feerates_differ(const struct feerate_est *a,
			    const struct feerate_est *b)
{
	if (tal_count(a) != tal_count(b))
		return true;
	for (size_t i = 0; i < tal_count(a); i++) {
		if (a[i].blockcount != b[i].blockcount)
			return true;
		if (a[i].rate != b[i].rate)
			return true;
	}
	return false;
}

/* In case the plugin does weird stuff! */
static bool different_blockcounts(struct chain_topology *topo,
				  const struct feerate_est *old,
				  const struct feerate_est *new)
{
	if (tal_count(old) != tal_count(new)) {
		log_unusual(topo->log, "Presented with %zu feerates this time (was %zu!)",
			    tal_count(new), tal_count(old));
		return true;
	}
	for (size_t i = 0; i < tal_count(old); i++) {
		if (old[i].blockcount != new[i].blockcount) {
			log_unusual(topo->log, "Presented with feerates"
				    " for blockcount %u, previously %u",
				    new[i].blockcount, old[i].blockcount);
			return true;
		}
	}
	return false;
}

static void update_feerates(struct lightningd *ld,
			    u32 feerate_floor,
			    const struct feerate_est *rates TAKES)
{
	struct feerate_est *new_smoothed;
	bool changed;
	struct chain_topology *topo = ld->topology;

	topo->feerate_floor = feerate_floor;

	/* Don't bother updating if we got no feerates; we'd rather have
	 * historical ones, if any. */
	if (tal_count(rates) == 0)
		goto rearm;

	/* If the feerate blockcounts differ, don't average, just override */
	if (topo->feerates[0] && different_blockcounts(topo, topo->feerates[0], rates)) {
		for (size_t i = 0; i < ARRAY_SIZE(topo->feerates); i++)
			topo->feerates[i] = tal_free(topo->feerates[i]);
		topo->smoothed_feerates = tal_free(topo->smoothed_feerates);
	}

	/* Move down historical rates, insert these */
	tal_free(topo->feerates[FEE_HISTORY_NUM-1]);
	memmove(topo->feerates + 1, topo->feerates,
		sizeof(topo->feerates[0]) * (FEE_HISTORY_NUM-1));
	topo->feerates[0] = tal_dup_talarr(topo, struct feerate_est, rates);
	changed = feerates_differ(topo->feerates[0], topo->feerates[1]);

	/* Use this as basis of new smoothed ones. */
	new_smoothed = tal_dup_talarr(topo, struct feerate_est, topo->feerates[0]);

	/* If there were old smoothed feerates, incorporate those */
	if (tal_count(topo->smoothed_feerates) != 0) {
		for (size_t i = 0; i < tal_count(new_smoothed); i++)
			smooth_one_feerate(topo, &new_smoothed[i]);
	}
	changed |= feerates_differ(topo->smoothed_feerates, new_smoothed);
	tal_free(topo->smoothed_feerates);
	topo->smoothed_feerates = new_smoothed;

	if (changed)
		notify_feerate_change(topo->ld);

rearm:
	if (topo->feerate_uninitialized) {
		/* This doesn't mean we *have* a fee estimate, but it does
		 * mean we tried. */
		topo->feerate_uninitialized = false;
		maybe_completed_init(topo);
	}

	next_updatefee_timer(topo);
}

static void start_fee_estimate(struct chain_topology *topo)
{
	topo->updatefee_timer = NULL;
	if (topo->stopping)
		return;
	/* Once per new block head, update fee estimates. */
	bitcoind_estimate_fees(topo->bitcoind, update_feerates);
}

struct rate_conversion {
	u32 blockcount;
};

static struct rate_conversion conversions[] = {
	[FEERATE_OPENING] = { 12 },
	[FEERATE_MUTUAL_CLOSE] = { 100 },
	[FEERATE_UNILATERAL_CLOSE] = { 6 },
	[FEERATE_DELAYED_TO_US] = { 12 },
	[FEERATE_HTLC_RESOLUTION] = { 6 },
	[FEERATE_PENALTY] = { 12 },
};

u32 opening_feerate(struct chain_topology *topo)
{
	if (topo->ld->force_feerates)
		return topo->ld->force_feerates[FEERATE_OPENING];
	return feerate_for_deadline(topo,
				    conversions[FEERATE_OPENING].blockcount);
}

u32 mutual_close_feerate(struct chain_topology *topo)
{
	if (topo->ld->force_feerates)
		return topo->ld->force_feerates[FEERATE_MUTUAL_CLOSE];
	return smoothed_feerate_for_deadline(topo,
					     conversions[FEERATE_MUTUAL_CLOSE].blockcount);
}

u32 unilateral_feerate(struct chain_topology *topo, bool option_anchors)
{
	if (topo->ld->force_feerates)
		return topo->ld->force_feerates[FEERATE_UNILATERAL_CLOSE];

	if (option_anchors) {
		/* We can lowball fee, since we can CPFP with anchors */
		u32 feerate = feerate_for_deadline(topo, 100);
		if (!feerate)
			return 0; /* Don't know */
		/* We still need to get into the mempool, so use 5 sat/byte */
		if (feerate < 1250)
			return 1250;
		return feerate;
	}

	return smoothed_feerate_for_deadline(topo,
					     conversions[FEERATE_UNILATERAL_CLOSE].blockcount)
		* topo->ld->config.commit_fee_percent / 100;
}

u32 delayed_to_us_feerate(struct chain_topology *topo)
{
	if (topo->ld->force_feerates)
		return topo->ld->force_feerates[FEERATE_DELAYED_TO_US];
	return smoothed_feerate_for_deadline(topo,
					     conversions[FEERATE_DELAYED_TO_US].blockcount);
}

u32 htlc_resolution_feerate(struct chain_topology *topo)
{
	if (topo->ld->force_feerates)
		return topo->ld->force_feerates[FEERATE_HTLC_RESOLUTION];
	return smoothed_feerate_for_deadline(topo,
					     conversions[FEERATE_HTLC_RESOLUTION].blockcount);
}

u32 penalty_feerate(struct chain_topology *topo)
{
	if (topo->ld->force_feerates)
		return topo->ld->force_feerates[FEERATE_PENALTY];
	return smoothed_feerate_for_deadline(topo,
					     conversions[FEERATE_PENALTY].blockcount);
}

u32 get_feerate_floor(const struct chain_topology *topo)
{
	return topo->feerate_floor;
}

static struct command_result *json_feerates(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct chain_topology *topo = cmd->ld->topology;
	struct json_stream *response;
	bool missing;
	enum feerate_style *style;
	u32 rate;

	if (!param(cmd, buffer, params,
		   p_req("style", param_feerate_style, &style),
		   NULL))
		return command_param_failed();

	missing = (tal_count(topo->feerates[0]) == 0);

	response = json_stream_success(cmd);
	if (missing)
		json_add_string(response, "warning_missing_feerates",
				"Some fee estimates unavailable: bitcoind startup?");

	json_object_start(response, feerate_style_name(*style));
	rate = opening_feerate(topo);
	if (rate)
		json_add_num(response, "opening", feerate_to_style(rate, *style));
	rate = mutual_close_feerate(topo);
	if (rate)
		json_add_num(response, "mutual_close",
			     feerate_to_style(rate, *style));
	rate = unilateral_feerate(topo, false);
	if (rate)
		json_add_num(response, "unilateral_close",
			     feerate_to_style(rate, *style));
	rate = unilateral_feerate(topo, true);
	if (rate)
		json_add_num(response, "unilateral_anchor_close",
			     feerate_to_style(rate, *style));
	rate = penalty_feerate(topo);
	if (rate)
		json_add_num(response, "penalty",
			     feerate_to_style(rate, *style));
	if (cmd->ld->deprecated_apis) {
		rate = delayed_to_us_feerate(topo);
		if (rate)
			json_add_num(response, "delayed_to_us",
				     feerate_to_style(rate, *style));
		rate = htlc_resolution_feerate(topo);
		if (rate)
			json_add_num(response, "htlc_resolution",
				     feerate_to_style(rate, *style));
	}

	json_add_u64(response, "min_acceptable",
		     feerate_to_style(feerate_min(cmd->ld, NULL), *style));
	json_add_u64(response, "max_acceptable",
		     feerate_to_style(feerate_max(cmd->ld, NULL), *style));
	json_add_u64(response, "floor",
		     feerate_to_style(get_feerate_floor(cmd->ld->topology),
				      *style));

	json_array_start(response, "estimates");
	assert(tal_count(topo->smoothed_feerates) == tal_count(topo->feerates[0]));
	for (size_t i = 0; i < tal_count(topo->feerates[0]); i++) {
		json_object_start(response, NULL);
		json_add_num(response, "blockcount",
			     topo->feerates[0][i].blockcount);
		json_add_u64(response, "feerate",
			     feerate_to_style(topo->feerates[0][i].rate, *style));
		json_add_u64(response, "smoothed_feerate",
			     feerate_to_style(topo->smoothed_feerates[i].rate,
					      *style));
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);

	if (!missing) {
		/* It actually is negotiated per-channel... */
		bool anchor_outputs
			= feature_offered(cmd->ld->our_features->bits[INIT_FEATURE],
					  OPT_ANCHOR_OUTPUTS)
			|| feature_offered(cmd->ld->our_features->bits[INIT_FEATURE],
					   OPT_ANCHORS_ZERO_FEE_HTLC_TX);

		json_object_start(response, "onchain_fee_estimates");
		/* eg 020000000001016f51de645a47baa49a636b8ec974c28bdff0ac9151c0f4eda2dbe3b41dbe711d000000001716001401fad90abcd66697e2592164722de4a95ebee165ffffffff0240420f00000000002200205b8cd3b914cf67cdd8fa6273c930353dd36476734fbd962102c2df53b90880cdb73f890000000000160014c2ccab171c2a5be9dab52ec41b825863024c54660248304502210088f65e054dbc2d8f679de3e40150069854863efa4a45103b2bb63d060322f94702200d3ae8923924a458cffb0b7360179790830027bb6b29715ba03e12fc22365de1012103d745445c9362665f22e0d96e9e766f273f3260dea39c8a76bfa05dd2684ddccf00000000 == weight 702 */
		json_add_num(response, "opening_channel_satoshis",
			     opening_feerate(cmd->ld->topology) * 702 / 1000);
		/* eg. 02000000000101afcfac637d44d4e0df52031dba55b18d3f1bd79ad4b7ebbee964f124c5163dc30100000000ffffffff02400d03000000000016001427213e2217b4f56bd19b6c8393dc9f61be691233ca1f0c0000000000160014071c49cad2f420f3c805f9f6b98a57269cb1415004004830450221009a12b4d5ae1d41781f79bedecfa3e65542b1799a46c272287ba41f009d2e27ff0220382630c899207487eba28062f3989c4b656c697c23a8c89c1d115c98d82ff261014730440220191ddf13834aa08ea06dca8191422e85d217b065462d1b405b665eefa0684ed70220252409bf033eeab3aae89ae27596d7e0491bcc7ae759c5644bced71ef3cccef30147522102324266de8403b3ab157a09f1f784d587af61831c998c151bcc21bb74c2b2314b2102e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e5752ae00000000 == weight 673 */
		json_add_u64(response, "mutual_close_satoshis",
			     mutual_close_feerate(cmd->ld->topology) * 673 / 1000);
		/* eg. 02000000000101c4fecaae1ea940c15ec502de732c4c386d51f981317605bbe5ad2c59165690ab00000000009db0e280010a2d0f00000000002200208d290003cedb0dd00cd5004c2d565d55fc70227bf5711186f4fa9392f8f32b4a0400483045022100952fcf8c730c91cf66bcb742cd52f046c0db3694dc461e7599be330a22466d790220740738a6f9d9e1ae5c86452fa07b0d8dddc90f8bee4ded24a88fe4b7400089eb01483045022100db3002a93390fc15c193da57d6ce1020e82705e760a3aa935ebe864bd66dd8e8022062ee9c6aa7b88ff4580e2671900a339754116371d8f40eba15b798136a76cd150147522102324266de8403b3ab157a09f1f784d587af61831c998c151bcc21bb74c2b2314b2102e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e5752ae9a3ed620 == weight 598 */
		/* Or, with anchors:
		 * 02000000000101dc824e8e880f90f397a74f89022b4d58f8c36ebc4fffc238bd525bd11f5002a501000000009db0e280044a010000000000002200200e1a08b3da3bea6a7a77315f95afcd589fe799af46cf9bfb89523172814050e44a01000000000000220020be7935a77ca9ab70a4b8b1906825637767fed3c00824aa90c988983587d6848878e001000000000022002009fa3082e61ca0bd627915b53b0cb8afa467248fa4dc95141f78b96e9c98a8ed245a0d000000000022002091fb9e7843a03e66b4b1173482a0eb394f03a35aae4c28e8b4b1f575696bd793040047304402205c2ea9cf6f670e2f454c054f9aaca2d248763e258e44c71675c06135fd8f36cb02201b564f0e1b3f1ea19342f26e978a4981675da23042b4d392737636738c3514da0147304402205fcd2af5b724cbbf71dfa07bd14e8018ce22c08a019976dc03d0f545f848d0a702203652200350cadb464a70a09829d09227ed3da8c6b8ef5e3a59b5eefd056deaae0147522102324266de8403b3ab157a09f1f784d587af61831c998c151bcc21bb74c2b2314b2102e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e5752ae9b3ed620 1112 */
		if (anchor_outputs)
			json_add_u64(response, "unilateral_close_satoshis",
				     unilateral_feerate(cmd->ld->topology, true) * 1112 / 1000);
		else
			json_add_u64(response, "unilateral_close_satoshis",
				     unilateral_feerate(cmd->ld->topology, false) * 598 / 1000);
		json_add_u64(response, "unilateral_close_nonanchor_satoshis",
			     unilateral_feerate(cmd->ld->topology, false) * 598 / 1000);

		json_add_u64(response, "htlc_timeout_satoshis",
			     htlc_timeout_fee(htlc_resolution_feerate(cmd->ld->topology),
					      false, false).satoshis /* Raw: estimate */);
		json_add_u64(response, "htlc_success_satoshis",
			     htlc_success_fee(htlc_resolution_feerate(cmd->ld->topology),
					      false, false).satoshis /* Raw: estimate */);
		json_object_end(response);
	}

	return command_success(cmd, response);
}

static const struct json_command feerates_command = {
	"feerates",
	"bitcoin",
	json_feerates,
	"Return feerate estimates, either satoshi-per-kw ({style} perkw) or satoshi-per-kb ({style} perkb)."
};
AUTODATA(json_command, &feerates_command);

static struct command_result *json_parse_feerate(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	struct json_stream *response;
	u32 *feerate;

	if (!param(cmd, buffer, params,
		   p_req("feerate", param_feerate, &feerate),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	json_add_num(response, feerate_style_name(FEERATE_PER_KSIPA),
		     feerate_to_style(*feerate, FEERATE_PER_KSIPA));
	return command_success(cmd, response);
}

static const struct json_command parse_feerate_command = {
	"parsefeerate",
	"bitcoin",
	json_parse_feerate,
	"Return current feerate in perkw + perkb for given feerate string."
};
AUTODATA(json_command, &parse_feerate_command);

static void next_updatefee_timer(struct chain_topology *topo)
{
	assert(!topo->updatefee_timer);
	topo->updatefee_timer = new_reltimer(topo->ld->timers, topo,
					     time_from_sec(topo->poll_seconds),
					     start_fee_estimate, topo);
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
		/* Tell watch code to re-evaluate all txs. */
		watch_topology_changed(topo);

		/* Tell lightningd about new block. */
		notify_new_block(topo->bitcoind->ld, topo->tip->height);

		/* Maybe need to rebroadcast. */
		rebroadcast_txs(topo);

		/* We've processed these UTXOs */
		db_set_intvar(topo->bitcoind->ld->wallet->db,
			      "last_processed_block", topo->tip->height);

		topo->prev_tip = topo->tip->blkid;

		/* Send out an account balance snapshot */
		if (!first_update_complete) {
			send_account_balance_snapshot(topo->ld, topo->tip->height);
			first_update_complete = true;
		}
	}

	/* If bitcoind is synced, we're now synced. */
	if (topo->bitcoind->synced && !topology_synced(topo)) {
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
				struct bitcoin_outpoint *outpoint,
				struct bitcoin_txid *txid,
				u32 tx_blockheight)
{
	struct utxo *utxo;

	/* Find the amount this was for */
	utxo = wallet_utxo_get(tmpctx, ld->wallet, outpoint);
	if (!utxo) {
		log_broken(ld->log, "No record of utxo %s",
			   type_to_string(tmpctx, struct bitcoin_outpoint,
					  outpoint));
		return;
	}

	notify_chain_mvt(ld, new_coin_wallet_withdraw(tmpctx, txid, outpoint,
						      tx_blockheight,
						      utxo->amount, WITHDRAWAL));
}

/**
 * topo_update_spends -- Tell the wallet about all spent outpoints
 */
static void topo_update_spends(struct chain_topology *topo, struct block *b)
{
	const struct short_channel_id *spent_scids;
	for (size_t i = 0; i < tal_count(b->full_txs); i++) {
		const struct bitcoin_tx *tx = b->full_txs[i];

		for (size_t j = 0; j < tx->wtx->num_inputs; j++) {
			struct bitcoin_outpoint outpoint;

			bitcoin_tx_input_get_outpoint(tx, j, &outpoint);

			if (wallet_outpoint_spend(topo->ld->wallet, tmpctx,
						  b->height, &outpoint))
				record_wallet_spend(topo->ld, &outpoint,
						    &b->txids[i], b->height);

		}
	}

	/* Retrieve all potential channel closes from the UTXO set and
	 * tell gossipd about them. */
	spent_scids =
	    wallet_utxoset_get_spent(tmpctx, topo->ld->wallet, b->height);
	gossipd_notify_spends(topo->bitcoind->ld, b->height, spent_scids);
}

static void topo_add_utxos(struct chain_topology *topo, struct block *b)
{
	for (size_t i = 0; i < tal_count(b->full_txs); i++) {
		const struct bitcoin_tx *tx = b->full_txs[i];
		struct bitcoin_outpoint outpoint;

		bitcoin_txid(tx, &outpoint.txid);
		for (outpoint.n = 0;
		     outpoint.n < tx->wtx->num_outputs;
		     outpoint.n++) {
			if (tx->wtx->outputs[outpoint.n].features
			    & WALLY_TX_IS_COINBASE)
				continue;

			const u8 *script = bitcoin_tx_output_get_script(tmpctx, tx, outpoint.n);
			struct amount_asset amt = bitcoin_tx_output_get_amount(tx, outpoint.n);

			if (amount_asset_is_main(&amt) && is_p2wsh(script, NULL)) {
				wallet_utxoset_add(topo->ld->wallet, &outpoint,
						   b->height, i, script,
						   amount_asset_to_sat(&amt));
			}
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
	topo_update_spends(topo, b);
	trace_span_end(b);

	/* Only keep the transactions we care about. */
	trace_span_start("filter_block_txs", b);
	filter_block_txs(topo, b);
	trace_span_end(b);

	block_map_add(topo->block_map, b);
	topo->max_blockheight = b->height;
}

static struct block *new_block(struct chain_topology *topo,
			       struct bitcoin_block *blk,
			       unsigned int height)
{
	struct block *b = tal(topo, struct block);

	bitcoin_block_blkid(blk, &b->blkid);
	log_debug(topo->log, "Adding block %u: %s",
		  height,
		  type_to_string(tmpctx, struct bitcoin_blkid, &b->blkid));
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
			  type_to_string(tmpctx, struct bitcoin_blkid, &b->blkid));

	/* Move tip back one. */
	topo->tip = b->prev;

	if (!topo->tip)
		fatal("Initial block %u (%s) reorganized out!",
		      b->height,
		      type_to_string(tmpctx, struct bitcoin_blkid, &b->blkid));

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
	block_map_del(topo->block_map, b);

	/* These no longer exist, so gossipd drops any reference to them just
	 * as if they were spent. */
	gossipd_notify_spends(topo->bitcoind->ld, b->height, removed_scids);
	tal_free(b);
}

static void get_new_block(struct bitcoind *bitcoind,
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
		add_tip(topo, new_block(topo, blk, topo->tip->height + 1));

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
	if (topo->stopping)
		return;
	trace_span_start("extend_tip", topo);
	bitcoind_getrawblockbyheight(topo->bitcoind, topo->tip->height + 1,
				     get_new_block, topo);
}

static void init_topo(struct bitcoind *bitcoind UNUSED,
		      struct bitcoin_blkid *blkid UNUSED,
		      struct bitcoin_block *blk,
		      struct chain_topology *topo)
{
	topo->root = new_block(topo, blk, topo->max_blockheight);
	block_map_add(topo->block_map, topo->root);
	topo->tip = topo->root;
	topo->prev_tip = topo->tip->blkid;

	/* In case we don't get all the way to updates_complete */
	db_set_intvar(topo->bitcoind->ld->wallet->db,
		      "last_processed_block", topo->tip->height);

	maybe_completed_init(topo);
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

u32 feerate_min(struct lightningd *ld, bool *unknown)
{
	const struct chain_topology *topo = ld->topology;
	u32 min;

	if (unknown)
		*unknown = false;

        /* We allow the user to ignore the fee limits,
	 * although this comes with inherent risks.
	 *
	 * By enabling this option, users are explicitly
	 * made aware of the potential dangers.
	 * There are situations, such as the one described in [1],
	 * where it becomes necessary to bypass the fee limits to resolve
	 * issues like a stuck channel.
	 *
	 * BTW experimental-anchors feature provides a solution to this problem.
	 *
	 * [1] https://github.com/ElementsProject/lightning/issues/6362
	 * */
	min = 0xFFFFFFFF;
	for (size_t i = 0; i < ARRAY_SIZE(topo->feerates); i++) {
		for (size_t j = 0; j < tal_count(topo->feerates[i]); j++) {
			if (topo->feerates[i][j].rate < min)
				min = topo->feerates[i][j].rate;
		}
	}
	if (min == 0xFFFFFFFF) {
		if (unknown)
			*unknown = true;
		min = 0;
	}

	/* FIXME: This is what bcli used to do: halve the slow feerate! */
	min /= 2;

	/* We can't allow less than feerate_floor, since that won't relay */
	if (min < get_feerate_floor(topo))
		return get_feerate_floor(topo);
	return min;
}

u32 feerate_max(struct lightningd *ld, bool *unknown)
{
	const struct chain_topology *topo = ld->topology;
	u32 max = 0;

	if (unknown)
		*unknown = false;

	for (size_t i = 0; i < ARRAY_SIZE(topo->feerates); i++) {
		for (size_t j = 0; j < tal_count(topo->feerates[i]); j++) {
			if (topo->feerates[i][j].rate > max)
				max = topo->feerates[i][j].rate;
		}
	}
	if (!max) {
		if (unknown)
			*unknown = true;
		return UINT_MAX;
	}
	return max * topo->ld->config.max_fee_multiplier;
}

u32 default_locktime(const struct chain_topology *topo)
{
	u32 locktime, current_height = get_block_height(topo);

	/* Setting the locktime to the next block to be mined has multiple
	 * benefits:
	 * - anti fee-snipping (even if not yet likely)
	 * - less distinguishable transactions (with this we create
	 *   general-purpose transactions which looks like bitcoind:
	 *   native segwit, nlocktime set to tip, and sequence set to
	 *   0xFFFFFFFD by default. Other wallets are likely to implement
	 *   this too).
	 */
	locktime = current_height;

	/* Eventually fuzz it too. */
	if (locktime > 100 && pseudorand(10) == 0)
		locktime -= pseudorand(100);

	return locktime;
}

/* On shutdown, channels get deleted last.  That frees from our list, so
 * do it now instead. */
static void destroy_chain_topology(struct chain_topology *topo)
{
	struct outgoing_tx *otx;
	struct outgoing_tx_map_iter it;
	for (otx = outgoing_tx_map_first(topo->outgoing_txs, &it); otx;
	     otx = outgoing_tx_map_next(topo->outgoing_txs, &it)) {
		tal_del_destructor2(otx, destroy_outgoing_tx, topo);
		tal_free(otx);
	}
}

struct chain_topology *new_topology(struct lightningd *ld, struct logger *log)
{
	struct chain_topology *topo = tal(ld, struct chain_topology);

	topo->ld = ld;
	topo->block_map = tal(topo, struct block_map);
	block_map_init(topo->block_map);
	topo->outgoing_txs = tal(topo, struct outgoing_tx_map);
	outgoing_tx_map_init(topo->outgoing_txs);
	topo->txwatches = tal(topo, struct txwatch_hash);
	txwatch_hash_init(topo->txwatches);
	topo->txowatches = tal(topo, struct txowatch_hash);
	txowatch_hash_init(topo->txowatches);
	topo->log = log;
	topo->bitcoind = new_bitcoind(topo, ld, log);
	topo->poll_seconds = 30;
	topo->feerate_uninitialized = true;
	memset(topo->feerates, 0, sizeof(topo->feerates));
	topo->smoothed_feerates = NULL;
	topo->root = NULL;
	topo->sync_waiters = tal(topo, struct list_head);
	topo->extend_timer = NULL;
	topo->rebroadcast_timer = NULL;
	topo->stopping = false;
	list_head_init(topo->sync_waiters);

	return topo;
}

static void check_blockcount(struct chain_topology *topo, u32 blockcount)
{
	/* If bitcoind's current blockheight is below the requested
	 * height, refuse.  You can always explicitly request a reindex from
	 * that block number using --rescan=. */
	if (blockcount < topo->max_blockheight) {
		/* UINT32_MAX == no blocks in database */
		if (topo->max_blockheight == UINT32_MAX) {
			/* Relative rescan, but we didn't know the blockheight */
			/* Protect against underflow in subtraction.
			 * Possible in regtest mode. */
			if (blockcount < topo->bitcoind->ld->config.rescan)
				topo->max_blockheight = 0;
			else
				topo->max_blockheight = blockcount - topo->bitcoind->ld->config.rescan;
		} else
			fatal("bitcoind has gone backwards from %u to %u blocks!",
			      topo->max_blockheight, blockcount);
	}

	/* Rollback to the given blockheight, so we start track
	 * correctly again */
	wallet_blocks_rollback(topo->ld->wallet, topo->max_blockheight);
	/* This may have unconfirmed txs: reconfirm as we add blocks. */
	watch_for_utxo_reconfirmation(topo, topo->ld->wallet);
}

static void retry_check_chain(struct chain_topology *topo);

static void
check_chain(struct bitcoind *bitcoind, const char *chain,
	    const u32 headercount, const u32 blockcount, const bool ibd,
	    const bool first_call, struct chain_topology *topo)
{
	if (!streq(chain, chainparams->bip70_name))
		fatal("Wrong network! Our Bitcoin backend is running on '%s',"
		      " but we expect '%s'.", chain, chainparams->bip70_name);

	topo->headercount = headercount;

	if (first_call) {
		/* Has the Bitcoin backend gone backward ? */
		check_blockcount(topo, blockcount);
		/* Get up to speed with topology. */
		bitcoind_getrawblockbyheight(topo->bitcoind, topo->max_blockheight,
					     init_topo, topo);
	}

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
		if (!first_call)
			log_unusual(bitcoind->log,
				    "Bitcoin backend now synced.");
		bitcoind->synced = true;
		return;
	}

	assert(!bitcoind->checkchain_timer);
	bitcoind->checkchain_timer
		= new_reltimer(bitcoind->ld->timers, bitcoind,
			       /* Be 4x more aggressive in this case. */
			       time_divide(time_from_sec(bitcoind->ld->topology
							 ->poll_seconds), 4),
			       retry_check_chain, bitcoind->ld->topology);
}

static void retry_check_chain(struct chain_topology *topo)
{
	topo->bitcoind->checkchain_timer = NULL;
	if (topo->stopping)
		return;
	bitcoind_getchaininfo(topo->bitcoind, false, topo->max_blockheight, check_chain, topo);
}

void setup_topology(struct chain_topology *topo,
		    u32 min_blockheight, u32 max_blockheight)
{
	void *ret;

	topo->min_blockheight = min_blockheight;
	topo->max_blockheight = max_blockheight;

	/* This waits for bitcoind. */
	bitcoind_check_commands(topo->bitcoind);

	/* For testing.. */
	log_debug(topo->ld->log, "All Bitcoin plugin commands registered");

	/* Sanity checks, then topology initialization. */
	topo->bitcoind->checkchain_timer = NULL;
	bitcoind_getchaininfo(topo->bitcoind, true, topo->max_blockheight, check_chain, topo);

	tal_add_destructor(topo, destroy_chain_topology);

	start_fee_estimate(topo);

	/* Once it gets initial block, it calls io_break() and we return. */
	ret = io_loop_with_timers(topo->ld);
	assert(ret == topo);
	log_debug(topo->ld->log, "io_loop_with_timers: %s", __func__);
}

void begin_topology(struct chain_topology *topo)
{
	try_extend_tip(topo);
}

void stop_topology(struct chain_topology *topo)
{
	/* Stop timers from re-arming. */
	topo->stopping = true;

	/* Remove timers while we're cleaning up plugins. */
	tal_free(topo->bitcoind->checkchain_timer);
	tal_free(topo->extend_timer);
	tal_free(topo->updatefee_timer);
}
