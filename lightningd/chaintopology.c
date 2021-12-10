#include "config.h"
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/io/io.h>
#include <ccan/tal/str/str.h>
#include <common/htlc_tx.h>
#include <common/json_command.h>
#include <common/memleak.h>
#include <common/param.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/gossip_control.h>
#include <lightningd/io_loop_with_timers.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
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
	const struct outgoing_tx *otx;

	list_for_each(&topo->outgoing_txs, otx, list) {
		if (bitcoin_txid_eq(&otx->txid, txid))
			return true;
	}
	return false;
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

		/* Tell them if it spends a txo we care about. */
		for (j = 0; j < tx->wtx->num_inputs; j++) {
			struct bitcoin_outpoint out;
			struct txowatch *txo;
			bitcoin_tx_input_get_txid(tx, j, &out.txid);
			out.n = tx->wtx->inputs[j].index;

			txo = txowatch_hash_get(&topo->txowatches, &out);
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
						     tx->wtx, &b->height, &owned);
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

	/* Command to complete when we're done, if and only if dev-broadcast triggered */
	struct command *cmd;
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
		if (txs->cmd)
			was_pending(command_success(txs->cmd,
						    json_stream_success(txs->cmd)));
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
	struct txs_to_broadcast *txs;
	struct outgoing_tx *otx;

	txs = tal(topo, struct txs_to_broadcast);
	txs->cmd = cmd;

	/* Put any txs we want to broadcast in ->txs. */
	txs->txs = tal_arr(txs, const char *, 0);
	list_for_each(&topo->outgoing_txs, otx, list) {
		if (wallet_transaction_height(topo->ld->wallet, &otx->txid))
			continue;

		tal_arr_expand(&txs->txs, tal_strdup(txs, otx->hextx));
	}

	/* Let this do the dirty work. */
	txs->cursor = (size_t)-1;
	broadcast_remainder(topo->bitcoind, true, "", txs);
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

	if (otx->failed_or_success) {
		otx->failed_or_success(otx->channel, success, msg);
		tal_free(otx);
	} else {
		/* For continual rebroadcasting, until channel freed. */
		tal_steal(otx->channel, otx);
		list_add_tail(&bitcoind->ld->topology->outgoing_txs, &otx->list);
		tal_add_destructor(otx, destroy_outgoing_tx);
	}
}

void broadcast_tx_ahf(struct chain_topology *topo,
		      struct channel *channel, const struct bitcoin_tx *tx,
		      bool allowhighfees,
		      void (*failed)(struct channel *channel,
				     bool success,
				     const char *err))
{
	/* Channel might vanish: topo owns it to start with. */
	struct outgoing_tx *otx = tal(topo, struct outgoing_tx);
	const u8 *rawtx = linearize_tx(otx, tx);

	otx->channel = channel;
	bitcoin_txid(tx, &otx->txid);
	otx->hextx = tal_hex(otx, rawtx);
	otx->failed_or_success = failed;
	tal_free(rawtx);
	tal_add_destructor2(channel, clear_otx_channel, otx);

	log_debug(topo->log, "Broadcasting txid %s",
		  type_to_string(tmpctx, struct bitcoin_txid, &otx->txid));

	wallet_transaction_add(topo->ld->wallet, tx->wtx, 0, 0);
	bitcoind_sendrawtx_ahf(topo->bitcoind, otx->hextx, allowhighfees,
			       broadcast_done, otx);
}
void broadcast_tx(struct chain_topology *topo,
		  struct channel *channel, const struct bitcoin_tx *tx,
		  void (*failed)(struct channel *channel,
				 bool success,
				 const char *err))
{
	return broadcast_tx_ahf(topo, channel, tx, false, failed);
}


static enum watch_result closeinfo_txid_confirmed(struct lightningd *ld,
						  struct channel *channel,
						  const struct bitcoin_txid *txid,
						  const struct bitcoin_tx *tx,
						  unsigned int depth)
{
	/* Sanity check. */
	if (tx != NULL) {
		struct bitcoin_txid txid2;

		bitcoin_txid(tx, &txid2);
		if (!bitcoin_txid_eq(txid, &txid2)) {
			channel_internal_error(channel, "Txid for %s is not %s",
					       type_to_string(tmpctx,
							      struct bitcoin_tx,
							      tx),
					       type_to_string(tmpctx,
							      struct bitcoin_txid,
							      txid));
			return DELETE_WATCH;
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

		if (find_txwatch(topo, &unconfirmed[i]->outpoint.txid, NULL))
			continue;

		notleak(watch_txid(topo, topo, NULL,
				   &unconfirmed[i]->outpoint.txid,
				   closeinfo_txid_confirmed));
	}
}

const char *feerate_name(enum feerate feerate)
{
	switch (feerate) {
	case FEERATE_OPENING: return "opening";
	case FEERATE_MUTUAL_CLOSE: return "mutual_close";
	case FEERATE_UNILATERAL_CLOSE: return "unilateral_close";
	case FEERATE_DELAYED_TO_US: return "delayed_to_us";
	case FEERATE_HTLC_RESOLUTION: return "htlc_resolution";
	case FEERATE_PENALTY: return "penalty";
	case FEERATE_MIN: return "min_acceptable";
	case FEERATE_MAX: return "max_acceptable";
	}
	abort();
}

struct command_result *param_feerate_estimate(struct command *cmd,
					      u32 **feerate_per_kw,
					      enum feerate feerate)
{
	*feerate_per_kw = tal(cmd, u32);
	**feerate_per_kw = try_get_feerate(cmd->ld->topology, feerate);
	if (!**feerate_per_kw)
		return command_fail(cmd, LIGHTNINGD, "Cannot estimate fees");

	return NULL;
}

/* Mutual recursion via timer. */
static void next_updatefee_timer(struct chain_topology *topo);

static void init_feerate_history(struct chain_topology *topo,
				 enum feerate feerate, u32 val)
{
	for (size_t i = 0; i < FEE_HISTORY_NUM; i++)
		topo->feehistory[feerate][i] = val;
}

static void add_feerate_history(struct chain_topology *topo,
				enum feerate feerate, u32 val)
{
	memmove(&topo->feehistory[feerate][1], &topo->feehistory[feerate][0],
		(FEE_HISTORY_NUM - 1) * sizeof(u32));
	topo->feehistory[feerate][0] = val;
}

/* We sanitize feerates if necessary to put them in descending order. */
static void update_feerates(struct bitcoind *bitcoind,
			    const u32 *satoshi_per_kw,
			    struct chain_topology *topo)
{
	u32 old_feerates[NUM_FEERATES];
	/* Smoothing factor alpha for simple exponential smoothing. The goal is to
	 * have the feerate account for 90 percent of the values polled in the last
	 * 2 minutes. The following will do that in a polling interval
	 * independent manner. */
	double alpha = 1 - pow(0.1,(double)topo->poll_seconds / 120);
	bool feerate_changed = false;

	for (size_t i = 0; i < NUM_FEERATES; i++) {
		u32 feerate = satoshi_per_kw[i];

		/* Takes into account override_fee_rate */
		old_feerates[i] = try_get_feerate(topo, i);

		/* If estimatefee failed, don't do anything. */
		if (!feerate)
			continue;

		/* Initial smoothed feerate is the polled feerate */
		if (!old_feerates[i]) {
			feerate_changed = true;
			old_feerates[i] = feerate;
			init_feerate_history(topo, i, feerate);

			log_debug(topo->log,
					  "Smoothed feerate estimate for %s initialized to polled estimate %u",
					  feerate_name(i), feerate);
		} else {
			if (feerate != old_feerates[i])
				feerate_changed = true;
			add_feerate_history(topo, i, feerate);
		}

		/* Smooth the feerate to avoid spikes. */
		u32 feerate_smooth = feerate * alpha + old_feerates[i] * (1 - alpha);
		/* But to avoid updating forever, only apply smoothing when its
		 * effect is more then 10 percent */
		if (abs((int)feerate - (int)feerate_smooth) > (0.1 * feerate)) {
			feerate = feerate_smooth;
			log_debug(topo->log,
					  "... polled feerate estimate for %s (%u) smoothed to %u (alpha=%.2f)",
					  feerate_name(i), satoshi_per_kw[i],
					  feerate, alpha);
		}

		if (feerate < feerate_floor()) {
			feerate = feerate_floor();
			log_debug(topo->log,
					  "... feerate estimate for %s hit floor %u",
					  feerate_name(i), feerate);
		}

		if (feerate != topo->feerate[i]) {
			log_debug(topo->log, "Feerate estimate for %s set to %u (was %u)",
				  feerate_name(i),
				  feerate, topo->feerate[i]);
		}
		topo->feerate[i] = feerate;
	}

	if (topo->feerate_uninitialized) {
		/* This doesn't mean we *have* a fee estimate, but it does
		 * mean we tried. */
		topo->feerate_uninitialized = false;
		maybe_completed_init(topo);
	}

	if (feerate_changed)
		notify_feerate_change(bitcoind->ld);

	next_updatefee_timer(topo);
}

static void start_fee_estimate(struct chain_topology *topo)
{
	topo->updatefee_timer = NULL;
	if (topo->stopping)
		return;
	/* Once per new block head, update fee estimates. */
	bitcoind_estimate_fees(topo->bitcoind, NUM_FEERATES, update_feerates,
			       topo);
}

u32 opening_feerate(struct chain_topology *topo)
{
	return try_get_feerate(topo, FEERATE_OPENING);
}

u32 mutual_close_feerate(struct chain_topology *topo)
{
	return try_get_feerate(topo, FEERATE_MUTUAL_CLOSE);
}

u32 unilateral_feerate(struct chain_topology *topo)
{
	return try_get_feerate(topo, FEERATE_UNILATERAL_CLOSE);
}

u32 delayed_to_us_feerate(struct chain_topology *topo)
{
	return try_get_feerate(topo, FEERATE_DELAYED_TO_US);
}

u32 htlc_resolution_feerate(struct chain_topology *topo)
{
	return try_get_feerate(topo, FEERATE_HTLC_RESOLUTION);
}

u32 penalty_feerate(struct chain_topology *topo)
{
	return try_get_feerate(topo, FEERATE_PENALTY);
}

static struct command_result *json_feerates(struct command *cmd,
					    const char *buffer,
					    const jsmntok_t *obj UNNEEDED,
					    const jsmntok_t *params)
{
	struct chain_topology *topo = cmd->ld->topology;
	struct json_stream *response;
	u32 feerates[NUM_FEERATES];
	bool missing;
	enum feerate_style *style;

	if (!param(cmd, buffer, params,
		   p_req("style", param_feerate_style, &style),
		   NULL))
		return command_param_failed();

	missing = false;
	for (size_t i = 0; i < ARRAY_SIZE(feerates); i++) {
		feerates[i] = try_get_feerate(topo, i);
		if (!feerates[i])
			missing = true;
	}

	response = json_stream_success(cmd);

	if (missing)
		json_add_string(response, "warning_missing_feerates",
				"Some fee estimates unavailable: bitcoind startup?");

	json_object_start(response, feerate_style_name(*style));
	for (size_t i = 0; i < ARRAY_SIZE(feerates); i++) {
		if (!feerates[i] || i == FEERATE_MIN || i == FEERATE_MAX)
			continue;
		json_add_num(response, feerate_name(i),
			     feerate_to_style(feerates[i], *style));
	}
	json_add_u64(response, "min_acceptable",
		     feerate_to_style(feerate_min(cmd->ld, NULL), *style));
	json_add_u64(response, "max_acceptable",
		     feerate_to_style(feerate_max(cmd->ld, NULL), *style));
	json_object_end(response);

	if (!missing) {
		/* It actually is negotiated per-channel... */
		bool anchor_outputs
			= feature_offered(cmd->ld->our_features->bits[INIT_FEATURE],
					  OPT_ANCHOR_OUTPUTS);

		json_object_start(response, "onchain_fee_estimates");
		/* eg 020000000001016f51de645a47baa49a636b8ec974c28bdff0ac9151c0f4eda2dbe3b41dbe711d000000001716001401fad90abcd66697e2592164722de4a95ebee165ffffffff0240420f00000000002200205b8cd3b914cf67cdd8fa6273c930353dd36476734fbd962102c2df53b90880cdb73f890000000000160014c2ccab171c2a5be9dab52ec41b825863024c54660248304502210088f65e054dbc2d8f679de3e40150069854863efa4a45103b2bb63d060322f94702200d3ae8923924a458cffb0b7360179790830027bb6b29715ba03e12fc22365de1012103d745445c9362665f22e0d96e9e766f273f3260dea39c8a76bfa05dd2684ddccf00000000 == weight 702 */
		json_add_num(response, "opening_channel_satoshis",
			     opening_feerate(cmd->ld->topology) * 702 / 1000);
		/* eg. 02000000000101afcfac637d44d4e0df52031dba55b18d3f1bd79ad4b7ebbee964f124c5163dc30100000000ffffffff02400d03000000000016001427213e2217b4f56bd19b6c8393dc9f61be691233ca1f0c0000000000160014071c49cad2f420f3c805f9f6b98a57269cb1415004004830450221009a12b4d5ae1d41781f79bedecfa3e65542b1799a46c272287ba41f009d2e27ff0220382630c899207487eba28062f3989c4b656c697c23a8c89c1d115c98d82ff261014730440220191ddf13834aa08ea06dca8191422e85d217b065462d1b405b665eefa0684ed70220252409bf033eeab3aae89ae27596d7e0491bcc7ae759c5644bced71ef3cccef30147522102324266de8403b3ab157a09f1f784d587af61831c998c151bcc21bb74c2b2314b2102e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e5752ae00000000 == weight 673 */
		json_add_u64(response, "mutual_close_satoshis",
			     mutual_close_feerate(cmd->ld->topology) * 673 / 1000);
		/* eg. 02000000000101c4fecaae1ea940c15ec502de732c4c386d51f981317605bbe5ad2c59165690ab00000000009db0e280010a2d0f00000000002200208d290003cedb0dd00cd5004c2d565d55fc70227bf5711186f4fa9392f8f32b4a0400483045022100952fcf8c730c91cf66bcb742cd52f046c0db3694dc461e7599be330a22466d790220740738a6f9d9e1ae5c86452fa07b0d8dddc90f8bee4ded24a88fe4b7400089eb01483045022100db3002a93390fc15c193da57d6ce1020e82705e760a3aa935ebe864bd66dd8e8022062ee9c6aa7b88ff4580e2671900a339754116371d8f40eba15b798136a76cd150147522102324266de8403b3ab157a09f1f784d587af61831c998c151bcc21bb74c2b2314b2102e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e5752ae9a3ed620 == weight 598 */
		json_add_u64(response, "unilateral_close_satoshis",
			     unilateral_feerate(cmd->ld->topology) * 598 / 1000);

		/* This really depends on whether we *negotiated*
		 * option_anchor_outputs for a particular channel! */
		json_add_u64(response, "htlc_timeout_satoshis",
			     htlc_timeout_fee(htlc_resolution_feerate(cmd->ld->topology),
					      anchor_outputs).satoshis /* Raw: estimate */);
		json_add_u64(response, "htlc_success_satoshis",
			     htlc_success_fee(htlc_resolution_feerate(cmd->ld->topology),
					      anchor_outputs).satoshis /* Raw: estimate */);
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
		/* Tell lightningd about new block. */
		notify_new_block(topo->bitcoind->ld, topo->tip->height);

		/* Tell watch code to re-evaluate all txs. */
		watch_topology_changed(topo);

		/* Maybe need to rebroadcast. */
		rebroadcast_txs(topo, NULL);

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

	for (size_t i=0; i<tal_count(spent_scids); i++) {
		gossipd_notify_spend(topo->bitcoind->ld, &spent_scids[i]);
	}
	tal_free(spent_scids);
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
	wallet_block_add(topo->ld->wallet, b);

	topo_add_utxos(topo, b);
	topo_update_spends(topo, b);

	/* Only keep the transactions we care about. */
	filter_block_txs(topo, b);

	block_map_add(&topo->block_map, b);
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
	assert(!block_map_get(&topo->block_map, &b->blkid));
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
	size_t i, n;
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
	for (i = 0; i < n; i++)
		txwatch_fire(topo, &txs[i], 0);

	/* Grab these before we delete block from db */
	removed_scids = wallet_utxoset_get_created(tmpctx, topo->ld->wallet,
						   b->height);
	wallet_block_remove(topo->ld->wallet, b);

	/* This may have unconfirmed txs: reconfirm as we add blocks. */
	watch_for_utxo_reconfirmation(topo, topo->ld->wallet);
	block_map_del(&topo->block_map, b);
	tal_free(b);

	/* These no longer exist, so gossipd drops any reference to them just
	 * as if they were spent. */
	for (size_t i=0; i<tal_count(removed_scids); i++)
		gossipd_notify_spend(topo->bitcoind->ld, &removed_scids[i]);
}

static void get_new_block(struct bitcoind *bitcoind,
			  struct bitcoin_blkid *blkid,
			  struct bitcoin_block *blk,
			  struct chain_topology *topo)
{
	if (!blkid && !blk) {
		/* No such block, we're done. */
		updates_complete(topo);
		return;
	}
	assert(blkid && blk);

	/* Annotate all transactions with the chainparams */
	for (size_t i = 0; i < tal_count(blk->tx); i++)
		blk->tx[i]->chainparams = chainparams;

	/* Unexpected predecessor?  Free predecessor, refetch it. */
	if (!bitcoin_blkid_eq(&topo->tip->blkid, &blk->hdr.prev_hash))
		remove_tip(topo);
	else
		add_tip(topo, new_block(topo, blk, topo->tip->height + 1));

	/* Try for next one. */
	try_extend_tip(topo);
}

static void try_extend_tip(struct chain_topology *topo)
{
	topo->extend_timer = NULL;
	if (topo->stopping)
		return;
	bitcoind_getrawblockbyheight(topo->bitcoind, topo->tip->height + 1,
				     get_new_block, topo);
}

static void init_topo(struct bitcoind *bitcoind UNUSED,
		      struct bitcoin_blkid *blkid UNUSED,
		      struct bitcoin_block *blk,
		      struct chain_topology *topo)
{
	topo->root = new_block(topo, blk, topo->max_blockheight);
	block_map_add(&topo->block_map, topo->root);
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


u32 try_get_feerate(const struct chain_topology *topo, enum feerate feerate)
{
	return topo->feerate[feerate];
}

u32 feerate_min(struct lightningd *ld, bool *unknown)
{
	u32 min;

	if (unknown)
		*unknown = false;

	/* We can't allow less than feerate_floor, since that won't relay */
	if (ld->config.ignore_fee_limits)
		min = 1;
	else {
		min = try_get_feerate(ld->topology, FEERATE_MIN);
		if (!min) {
			if (unknown)
				*unknown = true;
		} else {
			const u32 *hist = ld->topology->feehistory[FEERATE_MIN];

			/* If one of last three was an outlier, use that. */
			for (size_t i = 0; i < FEE_HISTORY_NUM; i++) {
				if (hist[i] < min)
					min = hist[i];
			}
		}
	}

	if (min < feerate_floor())
		return feerate_floor();
	return min;
}

u32 feerate_max(struct lightningd *ld, bool *unknown)
{
	u32 feerate;
	const u32 *feehistory = ld->topology->feehistory[FEERATE_MAX];

	if (unknown)
		*unknown = false;

	if (ld->config.ignore_fee_limits)
		return UINT_MAX;

	/* If we don't know feerate, don't limit other side. */
	feerate = try_get_feerate(ld->topology, FEERATE_MAX);
	if (!feerate) {
		if (unknown)
			*unknown = true;
		return UINT_MAX;
	}

	/* If one of last three was an outlier, use that. */
	for (size_t i = 0; i < FEE_HISTORY_NUM; i++) {
		if (feehistory[i] > feerate)
			feerate = feehistory[i];
	}
	return feerate;
}

/* On shutdown, channels get deleted last.  That frees from our list, so
 * do it now instead. */
static void destroy_chain_topology(struct chain_topology *topo)
{
	struct outgoing_tx *otx;

	while ((otx = list_pop(&topo->outgoing_txs, struct outgoing_tx, list)))
		tal_free(otx);

	/* htable uses malloc, so it would leak here */
	txwatch_hash_clear(&topo->txwatches);
	txowatch_hash_clear(&topo->txowatches);
	block_map_clear(&topo->block_map);
}

struct chain_topology *new_topology(struct lightningd *ld, struct log *log)
{
	struct chain_topology *topo = tal(ld, struct chain_topology);

	topo->ld = ld;
	block_map_init(&topo->block_map);
	list_head_init(&topo->outgoing_txs);
	txwatch_hash_init(&topo->txwatches);
	txowatch_hash_init(&topo->txowatches);
	topo->log = log;
	memset(topo->feerate, 0, sizeof(topo->feerate));
	topo->bitcoind = new_bitcoind(topo, ld, log);
	topo->poll_seconds = 30;
	topo->feerate_uninitialized = true;
	topo->root = NULL;
	topo->sync_waiters = tal(topo, struct list_head);
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
	bitcoind_getchaininfo(topo->bitcoind, false, check_chain, topo);
}

void setup_topology(struct chain_topology *topo,
		    u32 min_blockheight, u32 max_blockheight)
{
	memset(&topo->feerate, 0, sizeof(topo->feerate));

	topo->min_blockheight = min_blockheight;
	topo->max_blockheight = max_blockheight;

	/* This waits for bitcoind. */
	bitcoind_check_commands(topo->bitcoind);

	/* For testing.. */
	log_debug(topo->ld->log, "All Bitcoin plugin commands registered");

	/* Sanity checks, then topology initialization. */
	topo->bitcoind->checkchain_timer = NULL;
	bitcoind_getchaininfo(topo->bitcoind, true, check_chain, topo);

	tal_add_destructor(topo, destroy_chain_topology);

	start_fee_estimate(topo);

	/* Once it gets initial block, it calls io_break() and we return. */
	io_loop_with_timers(topo->ld);
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
