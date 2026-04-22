#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/str/str.h>
#include <common/autodata.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_parse.h>
#include <common/json_stream.h>
#include <common/mkdatastorekey.h>
#include <db/exec.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/gossip_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/onchain_control.h>
#include <lightningd/peer_control.h>
#include <lightningd/plugin.h>
#include <lightningd/watchman.h>
#include <wallet/wallet.h>

/*
 * Watchman is the interface between lightningd and the bwatch plugin.
 * It manages a pending operation queue to ensure reliable delivery of
 * watch add/delete requests to bwatch, even across crashes.
 *
 * Architecture:
 * - Subsystems (channel, onchaind, wallet) call watchman_add/watchman_del
 * - Watchman queues operations and sends them to bwatch via RPC
 * - Operations stay in queue until bwatch acknowledges them
 * - On crash/restart, pending ops are replayed from datastore
 * - Bwatch handles duplicate operations idempotently
 */

/* A pending operation - method and params to send to bwatch */
struct pending_op {
	/* "{method}:{owner}", e.g. "addscriptpubkeywatch:wallet/p2wpkh/42".
	 * Method and owner are recoverable from this without a separate field. */
	const char *op_id;
	const char *json_params; /* JSON params to send to bwatch */
};


/*
 * Datastore persistence helpers
 * Pending operations are stored at ["watchman", "pending", op_id]
 */

/* Generate datastore key for a pending operation */
static const char **make_key(const tal_t *ctx, const char *op_id TAKES)
{
	return mkdatastorekey(ctx, "watchman", "pending", op_id);
}


/* Persist a pending operation to the datastore for crash recovery.
 * The method is encoded in op_id (see struct pending_op), so we store
 * only json_params as the value. */
static void db_save(struct watchman *wm, const struct pending_op *op)
{
	const char **key = make_key(tmpctx, op->op_id);
	const u8 *data = (const u8 *)op->json_params;
	if (wallet_datastore_get(tmpctx, wm->ld->wallet, key, NULL))
		wallet_datastore_update(wm->ld->wallet, key, data);
	else
		wallet_datastore_create(wm->ld->wallet, key, data);
}

/* Remove a pending operation from the datastore */
static void db_remove(struct watchman *wm, const char *op_id)
{
	const char **key = make_key(tmpctx, op_id);
	wallet_datastore_remove(wm->ld->wallet, key);
}

static void save_tip(struct watchman *wm)
{
	struct db *db = wm->ld->wallet->db;
	db_set_intvar(db, "last_watchman_block_height", wm->last_processed_height);
	db_set_blobvar(db, "last_watchman_block_hash",
		       (const u8 *)&wm->last_processed_hash,
		       sizeof(wm->last_processed_hash));
}

static void load_tip(struct watchman *wm)
{
	struct db *db = wm->ld->wallet->db;
	const u8 *blob;

	wm->last_processed_height = db_get_intvar(db, "last_watchman_block_height", 0);

	blob = db_get_blobvar(tmpctx, db, "last_watchman_block_hash");
	if (blob) {
		assert(tal_bytelen(blob) == sizeof(struct bitcoin_blkid));
		memcpy(&wm->last_processed_hash, blob, sizeof(wm->last_processed_hash));
	}
}

/* Load all pending operations from datastore on startup */
static void load_pending_ops(struct watchman *wm)
{
	const char **startkey = mkdatastorekey(tmpctx, "watchman", "pending");
	const char **key;
	const u8 *data;
	u64 generation;
	struct db_stmt *stmt;

	for (stmt = wallet_datastore_first(tmpctx, wm->ld->wallet, startkey,
					   &key, &data, &generation);
	     stmt;
	     stmt = wallet_datastore_next(tmpctx, startkey, stmt,
					  &key, &data, &generation)) {
		if (tal_count(key) != 3)
			continue;

		/* op_id is the datastore key; method is the prefix before ':'.
		 * Malformed keys (no ':') are skipped — they can't be replayed. */
		if (!strchr(key[2], ':')) {
			log_broken(wm->ld->log,
				   "Skipping malformed pending op key '%s' (no ':' separator)",
				   key[2]);
			continue;
		}

		struct pending_op *op = tal(wm, struct pending_op);
		op->op_id       = tal_strdup(op, key[2]);
		op->json_params = tal_strdup(op, (const char *)data);
		tal_arr_expand(&wm->pending_ops, op);

		log_debug(wm->ld->log, "Loaded pending op: %s", op->op_id);
	}
}

static void watchman_on_plugin_ready(struct lightningd *ld, struct plugin *plugin);

/* Apply --rescan: negative means absolute height (only go back),
 * positive means relative (go back N blocks from stored tip). */
static void apply_rescan(struct watchman *wm, struct lightningd *ld)
{
	u32 stored = wm->last_processed_height;
	u32 target;

	if (ld->config.rescan < 0)
		target = (u32)(-ld->config.rescan);  /* absolute height */
	else if (stored > (u32)ld->config.rescan)
		target = stored - (u32)ld->config.rescan;  /* go back N blocks */
	else
		target = 0;  /* rescan exceeds stored height, start from genesis */

	/* Only adjust downward; upward targets are validated later in chaininfo */
	if (target < stored) {
		log_debug(ld->log,
			 "Rescanning: adjusting watchman height from %u to %u",
			 stored, target);
		wm->last_processed_height = target;
	}
}

struct watchman *watchman_new(const tal_t *ctx, struct lightningd *ld)
{
	struct watchman *wm = talz(ctx, struct watchman);

	wm->ld = ld;
	wm->pending_ops = tal_arr(wm, struct pending_op *, 0);
	wm->feerate_floor = 0;
	memset(wm->feerates, 0, sizeof(wm->feerates));
	wm->smoothed_feerates = NULL;

	load_pending_ops(wm);
	load_tip(wm);
	apply_rescan(wm, ld);

	log_info(ld->log, "Watchman: height=%u, %zu pending ops",
		 wm->last_processed_height, tal_count(wm->pending_ops));

	/* Replay pending ops exactly when bwatch transitions to INIT_COMPLETE. */
	ld->plugins->on_plugin_ready = watchman_on_plugin_ready;

	return wm;
}

/* Per-request context for bwatch_ack_response. Carries the bare op_id so the
 * callback never needs to parse the JSON-RPC response id. */
struct bwatch_ack_arg {
	struct watchman *wm;
	const char *op_id; /* "{method}:{owner}", e.g. "addscriptpubkeywatch:wallet/p2wpkh/42" */
};

/* Response callback for bwatch RPC requests; handles both success and error. */
static void bwatch_ack_response(const char *buffer,
				const jsmntok_t *toks,
				const jsmntok_t *idtok UNUSED,
				struct bwatch_ack_arg *arg)
{
	const jsmntok_t *err = json_get_member(buffer, toks, "error");

	if (err) {
		log_unusual(arg->wm->ld->log, "bwatch operation %s failed: %.*s",
			    arg->op_id, json_tok_full_len(err), json_tok_full(buffer, err));
	} else {
		log_debug(arg->wm->ld->log, "Acknowledged pending op: %s", arg->op_id);
	}

	watchman_ack(arg->wm->ld, arg->op_id);
}

/* op_id is "{method}:{owner}"; return the owner suffix. */
static const char *owner_from_op_id(const char *op_id)
{
	const char *colon = strchr(op_id, ':');
	return colon ? colon + 1 : "";
}

/* op_id is "{method}:{owner}"; return the method prefix. */
static const char *method_from_op_id(const tal_t *ctx, const char *op_id)
{
	const char *colon = strchr(op_id, ':');
	assert(colon); /* op_id must always be "{method}:{owner}" */
	return tal_strndup(ctx, op_id, colon - op_id);
}

/* Send an RPC request to the bwatch plugin.
 * op_id must be "{method}:{owner}", e.g. "addscriptpubkeywatch:wallet/p2wpkh/42". */
static void send_to_bwatch(struct watchman *wm, const char *method,
			   const char *op_id, const char *json_params)
{
	struct plugin *bwatch;
	struct jsonrpc_request *req;
	const char *owner;
	size_t len;

	/* Find bwatch plugin by the command it registers */
	bwatch = find_plugin_for_command(wm->ld, method);
	if (!bwatch) {
		log_broken(wm->ld->log, "bwatch plugin not found, cannot send %s", method);
		return;
	}

	if (bwatch->plugin_state != INIT_COMPLETE) {
		log_debug(wm->ld->log, "bwatch plugin not ready (state %d), queuing %s %s",
			  bwatch->plugin_state, method, op_id);
		return;
	}

	struct bwatch_ack_arg *arg = tal(tmpctx, struct bwatch_ack_arg);
	arg->wm = wm;
	arg->op_id = tal_strdup(arg, op_id);

	req = jsonrpc_request_start(wm, method, op_id, bwatch->log,
				     NULL, bwatch_ack_response, arg);

	/* Parent arg to req so it's freed when the request is freed,
	 * regardless of whether the callback fires. */
	tal_steal(req, arg);

	owner = owner_from_op_id(op_id);
	if (!streq(owner, ""))
		json_add_string(req->stream, "owner", owner);

	/* json_params is a JSON object string like {"type":"...","scriptpubkey":"...","start_block":N}.
	 * Append the rest (skip outer braces) so we get type, scriptpubkey, start_block, etc. */
	len = strlen(json_params);
	if (len >= 2 && json_params[0] == '{' && json_params[len-1] == '}') {
		json_stream_append(req->stream, ",", 1);
		json_stream_append(req->stream, json_params + 1, len - 2);
	} else {
		json_stream_append(req->stream, ",", 1);
		json_stream_append(req->stream, json_params, len);
	}

	jsonrpc_request_end(req);
	plugin_request_send(bwatch, req);
}

/* Queue an operation, persist it for crash recovery, and send to bwatch. */
static void enqueue_op(struct watchman *wm, const char *method,
		       const char *op_id, const char *json_params)
{
	struct pending_op *op = tal(wm, struct pending_op);
	op->op_id       = tal_strdup(op, op_id);
	op->json_params = tal_strdup(op, json_params);
	tal_arr_expand(&wm->pending_ops, op);
	db_save(wm, op);
	send_to_bwatch(wm, method, op_id, json_params);
}

/* Internal: queue an add for a specific per-type bwatch command. */
static void watchman_add(struct lightningd *ld, const char *method,
			 const char *owner, const char *json_params)
{
	struct watchman *wm = ld->watchman;
	char *op_id = tal_fmt(tmpctx, "%s:%s", method, owner);

	/* Remove any existing add for this owner */
	watchman_ack(ld, op_id);
	enqueue_op(wm, method, op_id, json_params);
}

/**
 * watchman_del - Queue a delete watch operation
 *
 * Simply queues the operation and sends to bwatch.
 * Bwatch handles duplicate deletes idempotently.
 * Cancels any pending add for this owner.
 */
static void watchman_del(struct lightningd *ld, const char *method,
			 const char *owner, const char *json_params)
{
	struct watchman *wm = ld->watchman;
	char *op_id = tal_fmt(tmpctx, "%s:%s", method, owner);

	/* Cancel any pending add for this owner — the add method is different
	 * from the del method, so scan by owner rather than constructing the
	 * add op_id directly. */
	for (size_t i = 0; i < tal_count(wm->pending_ops); i++) {
		if (strstarts(wm->pending_ops[i]->op_id, "add") &&
		    streq(owner_from_op_id(wm->pending_ops[i]->op_id), owner)) {
			watchman_ack(ld, wm->pending_ops[i]->op_id);
			break;
		}
	}
	enqueue_op(wm, method, op_id, json_params);
}

/**
 * watchman_ack - Acknowledge a completed watch operation
 *
 * Called when bwatch confirms it has processed an add/del operation.
 * Removes the operation from the pending queue and datastore.
 * op_id must be the bare stored id (e.g. "add:wallet/p2wpkh/0"), not the
 * full JSON-RPC response id.
 */
void watchman_ack(struct lightningd *ld, const char *op_id)
{
	struct watchman *wm = ld->watchman;

	for (size_t i = 0; i < tal_count(wm->pending_ops); i++) {
		if (streq(wm->pending_ops[i]->op_id, op_id)) {
			db_remove(wm, op_id);
			tal_free(wm->pending_ops[i]);
			tal_arr_remove(&wm->pending_ops, i);
			return;
		}
	}
}

/**
 * watchman_replay_pending - Resend all pending operations to bwatch
 *
 * Called on startup after bwatch is ready, to ensure any operations
 * that were pending before a crash are sent to bwatch.
 */
void watchman_replay_pending(struct lightningd *ld)
{
	struct watchman *wm = ld->watchman;

	for (size_t i = 0; i < tal_count(wm->pending_ops); i++) {
		struct pending_op *op = wm->pending_ops[i];
		send_to_bwatch(wm, method_from_op_id(tmpctx, op->op_id),
			       op->op_id, op->json_params);
	}
}

/* Replay pending ops when bwatch is ready.  On a fresh node current_height
 * is still 0, so we defer to json_block_processed where it's guaranteed > 0. */
static void watchman_on_plugin_ready(struct lightningd *ld, struct plugin *plugin)
{
	struct watchman *wm = ld->watchman;

	if (!wm)
		return;
	/* Check if this is bwatch by seeing if it owns the "addscriptpubkeywatch" method. */
	if (find_plugin_for_command(ld, "addscriptpubkeywatch") != plugin)
		return;

	if (wm->last_processed_height > 0) {
		log_debug(ld->log, "bwatch reached INIT_COMPLETE, replaying pending ops (height=%u)",
			  wm->last_processed_height);
		watchman_replay_pending(ld);
		/* TODO: notify_block_added(ld, height, &hash) once that helper's
		 * signature is migrated in Group H (chaintopology removal). */
	}
}

void watchman_watch_scriptpubkey(struct lightningd *ld,
				 const char *owner,
				 const u8 *scriptpubkey,
				 size_t script_len,
				 u32 start_block)
{
	watchman_add(ld, "addscriptpubkeywatch", owner,
		     tal_fmt(tmpctx, "{\"scriptpubkey\":\"%s\",\"start_block\":%u}",
			     tal_hexstr(tmpctx, scriptpubkey, script_len),
			     start_block));
}

void watchman_unwatch_scriptpubkey(struct lightningd *ld,
				   const char *owner,
				   const u8 *scriptpubkey,
				   size_t script_len)
{
	watchman_del(ld, "delscriptpubkeywatch", owner,
		     tal_fmt(tmpctx, "{\"scriptpubkey\":\"%s\"}",
			     tal_hexstr(tmpctx, scriptpubkey, script_len)));
}

void watchman_watch_outpoint(struct lightningd *ld,
			     const char *owner,
			     const struct bitcoin_outpoint *outpoint,
			     u32 start_block)
{
	watchman_add(ld, "addoutpointwatch", owner,
		     tal_fmt(tmpctx, "{\"outpoint\":\"%s:%u\",\"start_block\":%u}",
			     fmt_bitcoin_txid(tmpctx, &outpoint->txid),
			     outpoint->n, start_block));
}

void watchman_unwatch_outpoint(struct lightningd *ld,
			       const char *owner,
			       const struct bitcoin_outpoint *outpoint)
{
	watchman_del(ld, "deloutpointwatch", owner,
		     tal_fmt(tmpctx, "{\"outpoint\":\"%s:%u\"}",
			     fmt_bitcoin_txid(tmpctx, &outpoint->txid),
			     outpoint->n));
}

void watchman_watch_scid(struct lightningd *ld,
			 const char *owner,
			 const struct short_channel_id *scid,
			 u32 start_block)
{
	watchman_add(ld, "addscidwatch", owner,
		     tal_fmt(tmpctx, "{\"scid\":\"%s\",\"start_block\":%u}",
			     fmt_short_channel_id(tmpctx, *scid), start_block));
}

void watchman_unwatch_scid(struct lightningd *ld,
			   const char *owner,
			   const struct short_channel_id *scid)
{
	watchman_del(ld, "delscidwatch", owner,
		     tal_fmt(tmpctx, "{\"scid\":\"%s\"}",
			     fmt_short_channel_id(tmpctx, *scid)));
}

void watchman_watch_blockdepth(struct lightningd *ld,
			       const char *owner,
			       u32 confirm_height)
{
	watchman_add(ld, "addblockdepthwatch", owner,
		     tal_fmt(tmpctx, "{\"start_block\":%u}", confirm_height));
}

void watchman_unwatch_blockdepth(struct lightningd *ld,
				 const char *owner,
				 u32 confirm_height)
{
	watchman_del(ld, "delblockdepthwatch", owner,
		     tal_fmt(tmpctx, "{\"start_block\":%u}", confirm_height));
}

/* Dispatch table - add new watch types here */
static const struct depth_dispatch {
	const char *prefix;
	depth_found_fn handler;
	watch_revert_fn revert;
} depth_handlers[] = {
	/* channel/funding_depth/<dbid>: WATCH_BLOCKDEPTH, fires once per new block
	 * while the funding tx accumulates confirmations. */
	{ "channel/funding_depth/", channel_funding_depth_found, channel_funding_depth_revert },
	/* onchaind/channel_close/<dbid>:<txid>: WATCH_BLOCKDEPTH, persistent restart
	 * marker for a closing channel.  Normally a no-op; on crash recovery
	 * (channel->owner == NULL) the handler relaunches onchaind. */
	{ "onchaind/channel_close/", onchaind_channel_close_depth_found, onchaind_channel_close_depth_revert },
	/* onchaind/depth/<dbid>/<txid>: WATCH_BLOCKDEPTH, per-tx depth ticks that
	 * drive CSV and HTLC maturity checks inside onchaind. */
	{ "onchaind/depth/", onchaind_depth_found, onchaind_depth_revert },
	{ NULL, NULL, NULL },
};

static const struct watch_dispatch {
	const char *prefix;
	watch_found_fn handler;
	watch_revert_fn revert;
} watch_handlers[] = {
	/* wallet/utxo/<txid>:<outnum>: WATCH_OUTPOINT, fires when a wallet UTXO is spent */
	{ "wallet/utxo/", wallet_utxo_spent_watch_found, wallet_utxo_spent_watch_revert },
	/* wallet/p2wpkh/<keyidx>: WATCH_SCRIPTPUBKEY, fires when a p2wpkh wallet address receives funds */
	{ "wallet/p2wpkh/", wallet_watch_p2wpkh, wallet_scriptpubkey_watch_revert },
	/* wallet/p2tr/<keyidx>: WATCH_SCRIPTPUBKEY, fires when a p2tr wallet address receives funds */
	{ "wallet/p2tr/", wallet_watch_p2tr, wallet_scriptpubkey_watch_revert },
	/* wallet/p2sh_p2wpkh/<keyidx>: WATCH_SCRIPTPUBKEY, fires when a p2sh-wrapped p2wpkh address receives funds */
	{ "wallet/p2sh_p2wpkh/", wallet_watch_p2sh_p2wpkh, wallet_scriptpubkey_watch_revert },
	/* gossip/funding_spent/<scid>: WATCH_OUTPOINT, fires when the confirmed funding output is spent.
	 * Must precede "gossip/" so the longer prefix wins the strstarts() match. */
	{ "gossip/funding_spent/", gossip_funding_spent_watch_found, gossip_funding_spent_watch_revert },
	/* gossip/<scid>: WATCH_SCID, fires when the channel announcement UTXO is confirmed.
	 * tx==NULL signals the SCID's expected position was absent from the block ("not found"). */
	{ "gossip/", gossip_scid_watch_found, gossip_scid_watch_revert },
	/* channel/funding_spent/<dbid>: WATCH_OUTPOINT, fires when the funding outpoint is spent.
	 * Must precede "channel/funding/" so the longer prefix wins the strstarts() match. */
	{ "channel/funding_spent/", channel_funding_spent_watch_found, channel_funding_spent_watch_revert },
	/* channel/wrong_funding_spent/<dbid>: WATCH_OUTPOINT, fires when shutdown_wrong_funding outpoint is spent. */
	{ "channel/wrong_funding_spent/", channel_wrong_funding_spent_watch_found, channel_wrong_funding_spent_watch_revert },
	/* channel/funding/<dbid>: WATCH_SCRIPTPUBKEY, fires when the funding output script
	 * appears in a tx (i.e. the channel's funding transaction has been confirmed). */
	{ "channel/funding/", channel_funding_watch_found, channel_funding_watch_revert },
	/* onchaind/outpoint/<dbid>/<txid>: WATCH_OUTPOINT, fires when an output
	 * onchaind asked us to track is spent (HTLC sweep, second-stage tx, ...). */
	{ "onchaind/outpoint/", onchaind_output_watch_found, onchaind_output_watch_revert },
	{ NULL, NULL, NULL },
};

/* dispatch_watch_found: search depth_handlers then watch_handlers for owner.
 * depth is NULL for tx-based notifications, set for blockdepth notifications. */
static void dispatch_watch_found(struct lightningd *ld,
				 const char *owner,
				 const struct bitcoin_tx *tx,
				 size_t outnum,
				 u32 blockheight,
				 u32 txindex,
				 const u32 *depth)
{
	for (size_t i = 0; i < ARRAY_SIZE(depth_handlers); i++) {
		if (!depth_handlers[i].prefix)
			continue;
		if (strstarts(owner, depth_handlers[i].prefix)) {
			const char *suffix = owner + strlen(depth_handlers[i].prefix);
			depth_handlers[i].handler(ld, suffix, *depth, blockheight);
			return;
		}
	}
	for (size_t i = 0; i < ARRAY_SIZE(watch_handlers); i++) {
		if (!watch_handlers[i].prefix)
			continue;
		if (strstarts(owner, watch_handlers[i].prefix)) {
			const char *suffix = owner + strlen(watch_handlers[i].prefix);
			watch_handlers[i].handler(ld, suffix, tx, outnum, blockheight, txindex);
			return;
		}
	}
	log_debug(ld->log, "No handler for watch owner: %s", owner);
}

static void dispatch_watch_revert(struct lightningd *ld,
				  const char *owner,
				  u32 blockheight)
{
	for (size_t i = 0; i < ARRAY_SIZE(depth_handlers); i++) {
		if (!depth_handlers[i].prefix)
			continue;
		if (strstarts(owner, depth_handlers[i].prefix)) {
			const char *suffix = owner + strlen(depth_handlers[i].prefix);
			depth_handlers[i].revert(ld, suffix, blockheight);
			return;
		}
	}
	for (size_t i = 0; i < ARRAY_SIZE(watch_handlers); i++) {
		if (!watch_handlers[i].prefix)
			continue;
		if (strstarts(owner, watch_handlers[i].prefix)) {
			const char *suffix = owner + strlen(watch_handlers[i].prefix);
			watch_handlers[i].revert(ld, suffix, blockheight);
			return;
		}
	}
	log_debug(ld->log, "No revert handler for watch owner: %s", owner);
}

static struct command_result *param_bitcoin_tx(struct command *cmd,
					       const char *name,
					       const char *buffer,
					       const jsmntok_t *tok,
					       struct bitcoin_tx **tx)
{
	*tx = bitcoin_tx_from_hex(cmd, buffer + tok->start, tok->end - tok->start);
	if (!*tx)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Expected a hex-encoded transaction");
	return NULL;
}

static struct command_result *param_bitcoin_blkid_cmd(struct command *cmd,
						      const char *name,
						      const char *buffer,
						      const jsmntok_t *tok,
						      struct bitcoin_blkid **blkid)
{
	*blkid = tal(cmd, struct bitcoin_blkid);
	if (!json_to_bitcoin_blkid(buffer, tok, *blkid))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Expected a blockhash");
	return NULL;
}

/**
 * json_watch_found - RPC handler for watch_found notifications from bwatch
 *
 * Handles both tx-based watches (scriptpubkey, outpoint, txid, scid) and
 * blockdepth watches.  Dispatches by owner prefix.
 *
 * For WATCH_SCID, bwatch may omit "tx" and "txindex" to signal that the
 * SCID's expected tx/output was absent from the encoded block ("not found").
 * The handler (gossip_scid_watch_found) detects this via tx==NULL.
 */
static struct command_result *json_watch_found(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNUSED,
					       const jsmntok_t *params)
{
	struct watchman *wm = cmd->ld->watchman;
	const char **owners;
	u32 *blockheight, *txindex, *index, *depth;
	struct bitcoin_tx *tx;

	if (!param_check(cmd, buffer, params,
			 p_req("blockheight", param_number, &blockheight),
			 p_req("owners", param_string_array, &owners),
			 p_opt("tx", param_bitcoin_tx, &tx),
			 p_opt("txindex", param_number, &txindex),
			 p_opt("index", param_number, &index),
			 p_opt("depth", param_number, &depth),
		   NULL))
		return command_param_failed();

	/* For normal tx-based watches tx+txindex are required.
	 * Exception: WATCH_SCID owners send watch_found with tx==NULL to
	 * signal "not found"; their handler checks for this explicitly. */
	if (!depth && !tx && txindex)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "txindex provided without tx in watch_found");
	if (!depth && tx && !txindex)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "tx provided without txindex in watch_found");

	assert(wm);
	if (command_check_only(cmd))
		return command_check_done(cmd);

	log_debug(cmd->ld->log, "watch_found at block %u%s", *blockheight,
		  depth ? " (blockdepth)" : "");
	for (size_t i = 0; i < tal_count(owners); i++)
		dispatch_watch_found(cmd->ld, owners[i], tx,
				     index ? *index : 0,
				     *blockheight,
				     txindex ? *txindex : 0,
				     depth);

	struct json_stream *response = json_stream_success(cmd);
	json_add_u32(response, "blockheight", *blockheight);
	return command_success(cmd, response);
}

static const struct json_command watch_found_command = {
	"watch_found",
	json_watch_found,
};
AUTODATA(json_command, &watch_found_command);

/**
 * json_watch_revert - RPC handler for watch_revert notifications from bwatch
 *
 * Called when a watched item's confirming block is reorged away.  Dispatches
 * to the appropriate revert handler (depth or tx) based on owner prefix.
 */
static struct command_result *json_watch_revert(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNUSED,
						const jsmntok_t *params)
{
	const char *owner;
	u32 *blockheight;

	if (!param(cmd, buffer, params,
		   p_req("owner", param_string, &owner),
		   p_req("blockheight", param_number, &blockheight),
		   NULL))
		return command_param_failed();

	dispatch_watch_revert(cmd->ld, owner, *blockheight);
	struct json_stream *response = json_stream_success(cmd);
	json_add_u32(response, "blockheight", *blockheight);
	return command_success(cmd, response);
}

static const struct json_command watch_revert_command = {
	"watch_revert",
	json_watch_revert,
};
AUTODATA(json_command, &watch_revert_command);

static struct command_result *json_revert_block_processed(struct command *cmd,
							  const char *buffer,
							  const jsmntok_t *obj UNUSED,
							  const jsmntok_t *params)
{
	struct watchman *wm = cmd->ld->watchman;
	u32 *blockheight;
	struct bitcoin_blkid *blockhash;

	if (!param(cmd, buffer, params,
		   p_req("blockheight", param_number, &blockheight),
		   p_req("blockhash", param_bitcoin_blkid_cmd, &blockhash),
		   NULL))
		return command_param_failed();

	if (!wm)
		return command_fail(cmd, LIGHTNINGD, "Watchman not initialized");

	log_debug(wm->ld->log, "block_reverted: %u -> %u",
		  wm->last_processed_height, *blockheight);
	wm->last_processed_height = *blockheight;
	wm->last_processed_hash = *blockhash;
	save_tip(wm);

	struct json_stream *response = json_stream_success(cmd);
	json_add_u32(response, "blockheight", *blockheight);
	return command_success(cmd, response);
}

static const struct json_command revert_block_processed_command = {
	"revert_block_processed",
	json_revert_block_processed,
};
AUTODATA(json_command, &revert_block_processed_command);

/**
 * json_block_processed - RPC handler for block_processed notifications from bwatch
 *
 * Called by bwatch after it finishes processing all watches in a block.
 * We track this height to know where bwatch is in the chain, which helps
 * during startup/reorg scenarios.
 */
static struct command_result *json_block_processed(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *obj UNUSED,
						   const jsmntok_t *params)
{
	struct watchman *wm = cmd->ld->watchman;
	u32 *blockheight;
	struct bitcoin_blkid *blockhash;

	if (!param(cmd, buffer, params,
		   p_req("blockheight", param_number, &blockheight),
		   p_req("blockhash", param_bitcoin_blkid_cmd, &blockhash),
		   NULL))
		return command_param_failed();

	if (!wm)
		return command_fail(cmd, LIGHTNINGD, "Watchman not initialized");

	if (*blockheight != wm->last_processed_height) {
		log_info(wm->ld->log, "block_processed: %u -> %u",
			 wm->last_processed_height, *blockheight);

		/* Fresh node: replay wallet watches now that bwatch->current_height > 0,
		 * so add_watch_and_maybe_rescan will trigger historical rescans. */
		if (wm->last_processed_height == 0) {
			log_debug(wm->ld->log,
				  "First block_processed on fresh node, replaying pending ops");
			watchman_replay_pending(wm->ld);
		}

		wm->last_processed_height = *blockheight;
		wm->last_processed_hash = *blockhash;
		save_tip(wm);
		/* TODO: notify_block_added(wm->ld, *blockheight, blockhash) once
		 * its signature is migrated in Group H (chaintopology removal). */
		send_account_balance_snapshot(wm->ld);
	}

	channel_block_processed(wm->ld, *blockheight);
	notify_new_block(wm->ld);

	struct json_stream *response = json_stream_success(cmd);
	json_add_u32(response, "blockheight", *blockheight);
	if (wm->last_processed_height > 0)
		json_add_string(response, "blockhash",
				fmt_bitcoin_blkid(response, &wm->last_processed_hash));
	return command_success(cmd, response);
}

static const struct json_command block_processed_command = {
	"block_processed",
	json_block_processed,
};
AUTODATA(json_command, &block_processed_command);

/**
 * json_getwatchmanheight - RPC handler to return watchman's last processed height
 *
 * Called by bwatch on startup to determine what height to rescan from.
 */
static struct command_result *json_getwatchmanheight(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *obj UNUSED,
						     const jsmntok_t *params)
{
	struct watchman *wm = cmd->ld->watchman;
	struct json_stream *response;
	u32 height;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	height = wm ? wm->last_processed_height : 0;
	log_debug(cmd->ld->log, "getwatchmanheight: returning height=%u (wm=%s)",
		  height, wm ? "ok" : "NULL");
	response = json_stream_success(cmd);
	json_add_u32(response, "height", height);
	if (wm && wm->last_processed_height > 0)
		json_add_string(response, "blockhash",
				fmt_bitcoin_blkid(response, &wm->last_processed_hash));
	return command_success(cmd, response);
}

static const struct json_command getwatchmanheight_command = {
	"getwatchmanheight",
	json_getwatchmanheight,
};
AUTODATA(json_command, &getwatchmanheight_command);

/**
 * json_chaininfo - RPC handler for chaininfo from bwatch
 *
 * Called by bwatch on startup to inform watchman about the chain name,
 * IBD status, and sync state. Validates we're on the right network and
 * sets bitcoind->synced accordingly.
 */
static struct command_result *json_chaininfo(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNUSED,
					     const jsmntok_t *params)
{
	const char *chain;
	u32 *headercount, *blockcount;
	bool *ibd;

	if (!param(cmd, buffer, params,
		   p_req("chain", param_string, &chain),
		   p_req("headercount", param_number, &headercount),
		   p_req("blockcount", param_number, &blockcount),
		   p_req("ibd", param_bool, &ibd),
		   NULL))
		return command_param_failed();

	if (!streq(chain, chainparams->bip70_name))
		fatal("Wrong network! Our Bitcoin backend is running on '%s',"
		      " but we expect '%s'.", chain, chainparams->bip70_name);
	if (*ibd) {
		log_unusual(cmd->ld->log,
			    "Waiting for initial block download"
			    " (this can take a while!)");
		cmd->ld->bitcoind->synced = false;
	} else if (*headercount != *blockcount) {
		log_unusual(cmd->ld->log,
			    "Waiting for bitcoind to catch up"
			    " (%u blocks of %u)",
			    *blockcount, *headercount);
		cmd->ld->bitcoind->synced = false;
	} else {
		if (!cmd->ld->bitcoind->synced)
			log_info(cmd->ld->log, "Bitcoin backend now synced");
		cmd->ld->bitcoind->synced = true;
		notify_new_block(cmd->ld);
	}

	cmd->ld->watchman->bitcoind_blockcount = *blockcount;

	struct json_stream *response = json_stream_success(cmd);
	json_add_string(response, "chain", chain);
	json_add_bool(response, "synced", cmd->ld->bitcoind->synced);
	return command_success(cmd, response);
}

static const struct json_command chaininfo_command = {
	"chaininfo",
	json_chaininfo,
};
AUTODATA(json_command, &chaininfo_command);
