#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <common/autodata.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/jsonrpc_errors.h>
#include <common/jsonrpc_io.h>
#include <db/exec.h>
#include <lightningd/gossip_control.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
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

/* A pending operation - just the raw JSON params to send to bwatch */
struct pending_op {
	const char *op_id;       /* "add:{owner}" or "del:{owner}" */
	const char *json_params; /* The JSON params to send to bwatch */
};

struct watchman {
	struct lightningd *ld;
	u32 last_processed_height;
	struct pending_op **pending_ops;  /* Array of pending operations */
};

/*
 * Datastore persistence helpers
 * Pending operations are stored at ["watchman", "pending", op_id]
 */

/* Generate datastore key for a pending operation */
static const char **make_key(const tal_t *ctx, const char *op_id)
{
	const char **key = tal_arr(ctx, const char *, 3);
	key[0] = "watchman";
	key[1] = "pending";
	key[2] = op_id;
	return key;
}

/* Persist a pending operation to the datastore for crash recovery */
static void db_save(struct watchman *wm, const struct pending_op *op)
{
	const char **key = make_key(tmpctx, op->op_id);
	u8 *data = tal_dup_arr(tmpctx, u8, (u8 *)op->json_params,
			       strlen(op->json_params) + 1, 0);
	wallet_datastore_create(wm->ld->wallet, key, data);
}

/* Remove a pending operation from the datastore */
static void db_remove(struct watchman *wm, const char *op_id)
{
	const char **key = make_key(tmpctx, op_id);
	wallet_datastore_remove(wm->ld->wallet, key);
}

/* Load all pending operations from datastore on startup */
static void load_pending_ops(struct watchman *wm)
{
	const char **startkey = tal_arr(tmpctx, const char *, 2);
	const char **key;
	const u8 *data;
	u64 generation;
	struct db_stmt *stmt;

	startkey[0] = "watchman";
	startkey[1] = "pending";

	for (stmt = wallet_datastore_first(tmpctx, wm->ld->wallet, startkey,
					   &key, &data, &generation);
	     stmt;
	     stmt = wallet_datastore_next(tmpctx, startkey, stmt,
					  &key, &data, &generation)) {
		if (tal_count(key) != 3)
			continue;

		struct pending_op *op = tal(wm, struct pending_op);
		op->op_id = tal_strdup(op, key[2]);
		op->json_params = tal_strdup(op, (const char *)data);
		tal_arr_expand(&wm->pending_ops, op);

		log_debug(wm->ld->log, "Loaded pending op: %s", op->op_id);
	}
}

struct watchman *watchman_new(const tal_t *ctx, struct lightningd *ld)
{
	struct watchman *wm = tal(ctx, struct watchman);

	wm->ld = ld;
	wm->last_processed_height = db_get_intvar(ld->wallet->db,
						  "last_watchman_block_height", 0);
	wm->pending_ops = tal_arr(wm, struct pending_op *, 0);

	load_pending_ops(wm);

	log_info(ld->log, "Watchman: height=%u, %zu pending ops",
		 wm->last_processed_height, tal_count(wm->pending_ops));

	return wm;
}

/* Callback when bwatch acknowledges a watch operation (success) */
static void bwatch_ack_success(const char *buffer,
				const jsmntok_t *idtok,
				const jsmntok_t *methodtok,
				const jsmntok_t *paramtoks,
				struct watchman *wm)
{
	const char *op_id;
	
	/* Extract op_id from the response id */
	if (!idtok) {
		log_broken(wm->ld->log, "bwatch response missing id, cannot acknowledge operation");
		return;
	}
	
	op_id = json_strdup(tmpctx, buffer, idtok);
	watchman_ack(wm->ld, op_id);
	log_debug(wm->ld->log, "Acknowledged pending op: %s", op_id);
}

/* Callback when bwatch operation fails */
static void bwatch_ack_error(const char *buffer,
			      const jsmntok_t *toks,
			      const jsmntok_t *idtok,
			      struct watchman *wm)
{
	const char *op_id;
	const jsmntok_t *err;
	
	/* Extract op_id from the response id */
	if (!idtok) {
		log_broken(wm->ld->log, "bwatch error response missing id, cannot acknowledge operation");
		return;
	}
	
	op_id = json_strdup(tmpctx, buffer, idtok);
	err = json_get_member(buffer, toks, "error");
	if (err) {
		log_unusual(wm->ld->log, "bwatch operation %s failed: %.*s",
			    op_id, json_tok_full_len(err), json_tok_full(buffer, err));
	} else {
		log_unusual(wm->ld->log, "bwatch operation %s failed: unknown error", op_id);
	}
	
	/* Still remove from queue - bwatch will handle it properly on replay */
	watchman_ack(wm->ld, op_id);
}

/* Send an RPC request to the bwatch plugin */
static void send_to_bwatch(struct watchman *wm, const char *method,
			   const char *op_id, const char *json_params)
{
	struct plugin *bwatch;
	struct jsonrpc_request *req;
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
		/* Operation is already queued, will be sent when plugin is ready */
		return;
	}

	req = jsonrpc_request_start(wm, method, op_id, bwatch->log,
				     bwatch_ack_success, bwatch_ack_error, wm);

	/* json_params is a JSON object string like {"key":"value"}.
	 * jsonrpc_request_start already opened "params":{, so skip outer braces */
	len = strlen(json_params);
	if (len >= 2 && json_params[0] == '{' && json_params[len-1] == '}')
		json_stream_append(req->stream, json_params + 1, len - 2);
	else
		json_stream_append(req->stream, json_params, len);

	jsonrpc_request_end(req);
	plugin_request_send(bwatch, req);
}

/**
 * watchman_add - Queue an add watch operation
 *
 * Simply queues the operation and sends to bwatch.
 * Bwatch handles duplicate adds idempotently.
 */
void watchman_add(struct lightningd *ld, const char *owner, const char *json_params)
{
	struct watchman *wm = ld->watchman;
	char *op_id = tal_fmt(tmpctx, "add:%s", owner);
	struct pending_op *op = tal(wm, struct pending_op);

	/* Remove any existing add for this owner to avoid UNIQUE constraint
	 * when BIP32 and BIP86 both register the same key (e.g. wallet/p2wpkh/0) */
	watchman_ack(ld, op_id);

	op->op_id = tal_strdup(op, op_id);
	op->json_params = tal_strdup(op, json_params);

	tal_arr_expand(&wm->pending_ops, op);
	db_save(wm, op);
	send_to_bwatch(wm, "addwatch", op_id, json_params);
}

/**
 * watchman_del - Queue a delete watch operation
 *
 * Simply queues the operation and sends to bwatch.
 * Bwatch handles duplicate deletes idempotently.
 * Cancels any pending add for this owner.
 */
void watchman_del(struct lightningd *ld, const char *owner, const char *json_params)
{
	struct watchman *wm = ld->watchman;
	char *op_id = tal_fmt(tmpctx, "del:%s", owner);
	struct pending_op *op = tal(wm, struct pending_op);

	/* Cancel any pending add for this owner; we're replacing it with a del */
	watchman_ack(ld, tal_fmt(tmpctx, "add:%s", owner));

	op->op_id = tal_strdup(op, op_id);
	op->json_params = tal_strdup(op, json_params);

	tal_arr_expand(&wm->pending_ops, op);
	db_save(wm, op);
	send_to_bwatch(wm, "delwatch", op_id, json_params);
}

/**
 * watchman_ack - Acknowledge a completed watch operation
 *
 * Called when bwatch confirms it has processed an add/del operation.
 * Removes the operation from the pending queue and datastore.
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
		const char *method = strstarts(op->op_id, "add:") ? "addwatch" : "delwatch";
		send_to_bwatch(wm, method, op->op_id, op->json_params);
	}
}

/**
 * watchman_get_height - Get watchman's last processed block height
 *
 * Returns the last block height that bwatch has processed.
 * This should be used as the start_block when adding new watches
 * to avoid rescanning from genesis.
 */
u32 watchman_get_height(struct lightningd *ld)
{
	struct watchman *wm = ld->watchman;
	if (!wm)
		return 0;
	return wm->last_processed_height;
}

/* Dispatch table - add new watch types here */
static const struct watch_dispatch {
	const char *prefix;
	watch_found_fn handler;
} watch_handlers[] = {
	{ "wallet/p2wpkh/",      wallet_watch_p2wpkh },
	{ "wallet/p2tr/",        wallet_watch_p2tr },
	{ "wallet/p2sh_p2wpkh/", wallet_watch_p2sh_p2wpkh },
	/* Future:
	{ "channel/funding/",    channel_watch_funding },
	{ "onchaind/penalty/",   onchaind_watch_penalty },
	*/
};

/**
 * parse_watch_id - Extract numeric ID from owner suffix
 *
 * Parses the numeric ID from the owner string suffix.
 * This is used for keyindex (wallet), channel_dbid (channel watches),
 * etc. Returns true on success, false on parse error.
 */
static bool parse_watch_id(const char *suffix, u32 *id)
{
	char *endp;
	
	*id = strtol(suffix, &endp, 10);
	return (*endp == '\0');
}

/**
 * dispatch_watch_found - Find and call the appropriate handler for an owner
 *
 * Matches the owner string against registered prefixes, parses the ID,
 * and dispatches to the appropriate handler.
 */
static void dispatch_watch_found(struct lightningd *ld,
				 const char *owner,
				 const struct bitcoin_tx *tx,
				 size_t outnum,
				 u32 blockheight,
				 u32 txindex)
{
	const struct watch_dispatch *handler = NULL;
	const char *suffix = NULL;
	u32 id;
	
	/* Find matching handler by prefix */
	for (size_t i = 0; i < ARRAY_SIZE(watch_handlers); i++) {
		if (strstarts(owner, watch_handlers[i].prefix)) {
			handler = &watch_handlers[i];
			/* Extract suffix by skipping past the prefix
			 * E.g., owner="wallet/p2wpkh/42", prefix="wallet/p2wpkh/"
			 *       -> suffix="42" */
			suffix = owner + strlen(handler->prefix);
			break;
		}
	}
	
	if (!handler) {
		/* No handler found - this is ok, might be a watch type we don't handle yet */
		log_debug(ld->log, "No handler for watch owner: %s", owner);
		return;
	}
	
	/* Parse the ID from the suffix (keyindex, channel_dbid, etc.) */
	if (!parse_watch_id(suffix, &id)) {
		log_broken(ld->log, "Invalid ID in watch owner: %s", owner);
		return;
	}
	
	/* Dispatch to handler */
	handler->handler(ld, id, tx, outnum, blockheight, txindex);
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

/**
 * json_watch_found - RPC handler for watch_found notifications from bwatch
 *
 * Called by bwatch when a watched transaction appears in a block.
 * The notification includes the tx, blockheight, txindex, list of owners, and
 * optionally outnum (for scriptpubkey watches) or innum (for outpoint watches).
 *
 * Dispatches to subsystem handlers based on owner prefix.
 */
static struct command_result *json_watch_found(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	struct watchman *wm = cmd->ld->watchman;
	const char *type, **owners;
	u32 *blockheight, *txindex, *outnum, *innum;
	struct bitcoin_tx *tx;
	void *unused;

	if (!param_check(cmd, buffer, params,
		   p_req("tx", param_bitcoin_tx, &tx),
		   p_req("blockheight", param_number, &blockheight),
		   p_req("txindex", param_number, &txindex),
		   p_req("type", param_string, &type),
		   p_req("owners", param_string_array, &owners),
		   p_opt("outnum", param_number, &outnum),
		   p_opt("innum", param_number, &innum),
		   p_opt("txid", param_ignore, &unused),
		   p_opt("scriptpubkey", param_ignore, &unused),
		   p_opt("outpoint", param_ignore, &unused),
		   NULL))
		return command_param_failed();

	if (outnum && innum)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can only set one of outnum or innum");

	assert(wm);
	if (command_check_only(cmd))
		return command_check_done(cmd);

	/* Log the watch_found notification */
	log_info(cmd->ld->log, "watch_found: %s at block %u", type, *blockheight);

	/* Bwatch now tells us exactly which output/input matched.
	 * outnum = output index for scriptpubkey watches
	 * innum = input index for outpoint watches
	 * For txid watches, neither is set so index defaults to 0
	 * (which those handlers ignore anyway). */
	for (size_t i = 0; i < tal_count(owners); i++) {
		size_t index;
		
		if (outnum)
			index = *outnum;
		else if (innum)
			index = *innum;
		else
			index = 0;
		
		dispatch_watch_found(cmd->ld, owners[i], tx, index, *blockheight, *txindex);
	}

	struct json_stream *response = json_stream_success(cmd);
	json_add_u32(response, "blockheight", *blockheight);
	return command_success(cmd, response);
}

/**
 * json_block_processed - RPC handler for block_processed notifications from bwatch
 *
 * Called by bwatch after it finishes processing all watches in a block.
 * We track this height to know where bwatch is in the chain, which helps
 * during startup/reorg scenarios.
 */
static struct command_result *json_block_processed(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *obj UNNEEDED,
						   const jsmntok_t *params)
{
	struct watchman *wm = cmd->ld->watchman;
	u32 *blockheight;

	if (!param_check(cmd, buffer, params,
			 p_req("blockheight", param_number, &blockheight),
			 NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	if (!wm)
		return command_fail(cmd, LIGHTNINGD, "Watchman not initialized");

	/* Accept any height - handles both forward progress and reorgs */
	if (*blockheight != wm->last_processed_height) {
		log_debug(wm->ld->log, "block_processed: %u -> %u",
			  wm->last_processed_height, *blockheight);
		wm->last_processed_height = *blockheight;
		db_set_intvar(wm->ld->wallet->db, "last_watchman_block_height",
			      *blockheight);
	}

	/* Notify gossipd of the authoritative block height (from bwatch) */
	gossip_notify_blockheight(wm->ld, *blockheight);

	struct json_stream *response = json_stream_success(cmd);
	json_add_u32(response, "blockheight", *blockheight);
	return command_success(cmd, response);
}

/**
 * json_getwatchmanheight - RPC handler to return watchman's last processed height
 *
 * Called by bwatch on startup to determine what height to rescan from.
 */
static struct command_result *json_getwatchmanheight(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *obj UNNEEDED,
						     const jsmntok_t *params)
{
	/* FIXME: REMOVE */
	struct watchman *wm = cmd->ld->watchman;
	struct json_stream *response;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	if (command_check_only(cmd))
		return command_check_done(cmd);

	response = json_stream_success(cmd);
	json_add_u32(response, "height", wm ? wm->last_processed_height : 0);
	return command_success(cmd, response);
}

static const struct json_command watch_found_command = {
	"watch_found",
	json_watch_found,
};
AUTODATA(json_command, &watch_found_command);

static const struct json_command block_processed_command = {
	"block_processed",
	json_block_processed,
};
AUTODATA(json_command, &block_processed_command);

static const struct json_command getwatchmanheight_command = {
	"getwatchmanheight",
	json_getwatchmanheight,
};
AUTODATA(json_command, &getwatchmanheight_command);
