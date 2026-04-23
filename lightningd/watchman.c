#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <common/autodata.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_parse_simple.h>
#include <common/json_stream.h>
#include <common/mkdatastorekey.h>
#include <db/exec.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
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

__attribute__((unused))
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
__attribute__((unused))
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
__attribute__((unused))
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
		cmd->ld->topology->bitcoind->synced = false;
	} else if (*headercount != *blockcount) {
		log_unusual(cmd->ld->log,
			    "Waiting for bitcoind to catch up"
			    " (%u blocks of %u)",
			    *blockcount, *headercount);
		cmd->ld->topology->bitcoind->synced = false;
	} else {
		if (!cmd->ld->topology->bitcoind->synced)
			log_info(cmd->ld->log, "Bitcoin backend now synced");
		cmd->ld->topology->bitcoind->synced = true;
		notify_new_block(cmd->ld);
	}

	cmd->ld->watchman->bitcoind_blockcount = *blockcount;

	struct json_stream *response = json_stream_success(cmd);
	json_add_string(response, "chain", chain);
	json_add_bool(response, "synced", cmd->ld->topology->bitcoind->synced);
	return command_success(cmd, response);
}

static const struct json_command chaininfo_command = {
	"chaininfo",
	json_chaininfo,
};
AUTODATA(json_command, &chaininfo_command);
