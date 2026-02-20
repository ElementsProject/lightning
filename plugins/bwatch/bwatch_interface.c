#include "config.h"
#include "bwatch.h"
#include "bwatch_interface.h"
#include "bwatch_store.h"
#include <bitcoin/tx.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <plugins/libplugin.h>

/*
 * ============================================================================
 * SENDING WATCH_FOUND NOTIFICATIONS	
 * ============================================================================
 */

/* Callback for watch_found RPC - we don't care about the response */
static struct command_result *watch_found_done(struct command *cmd UNUSED,
					       const char *method UNUSED,
					       const char *buf UNUSED,
					       const jsmntok_t *result UNUSED,
					       void *arg UNUSED)
{
	return NULL;
}

/* Send watch_found notification to lightningd
 * @txindex: position of tx in the block (0 = coinbase)
 * @outnum: for scriptpubkey watches, which output matched
 * @innum: for outpoint watches, which input matched
 */
void bwatch_send_watch_found(struct command *cmd,
			     const struct bitcoin_tx *tx,
			     u32 blockheight,
			     const struct watch *w,
			     u32 txindex,
			     u32 outnum,
			     u32 innum)
{
	struct out_req *req;

	req = jsonrpc_request_start(cmd, "watch_found",
				    watch_found_done, watch_found_done, NULL);
	json_add_tx(req->js, "tx", tx);
	json_add_u32(req->js, "blockheight", blockheight);
	json_add_u32(req->js, "txindex", txindex);

	/* Add type and corresponding field */
	switch (w->type) {
	case WATCH_TXID:
		json_add_string(req->js, "type", "txid");
		json_add_txid(req->js, "txid", &w->key.txid);
		assert(outnum == UINT32_MAX);
		assert(innum == UINT32_MAX);
		break;
	case WATCH_SCRIPTPUBKEY:
		json_add_string(req->js, "type", "scriptpubkey");
		json_add_hex(req->js, "scriptpubkey", w->key.scriptpubkey.script,
			     w->key.scriptpubkey.len);
		assert(outnum != UINT32_MAX);
		assert(innum == UINT32_MAX);
		json_add_u32(req->js, "outnum", outnum);
		break;
	case WATCH_OUTPOINT:
		json_add_string(req->js, "type", "outpoint");
		json_add_outpoint(req->js, "outpoint", &w->key.outpoint);
		assert(outnum == UINT32_MAX);
		assert(innum != UINT32_MAX);
		json_add_u32(req->js, "innum", innum);
		break;
	}

	/* Add owners array */
	json_array_start(req->js, "owners");
	for (size_t i = 0; i < tal_count(w->owners); i++)
		json_add_string(req->js, NULL, w->owners[i]);
	json_array_end(req->js);

	send_outreq(req);
}

/*
 * ============================================================================
 * SENDING BLOCK_PROCESSED NOTIFICATION
 * ============================================================================
 */

/* Callback for block_processed acknowledgement from watchman */
static struct command_result *block_processed_ack(struct command *cmd,
						  const char *method UNUSED,
						  const char *buf,
						  const jsmntok_t *result,
						  void *unused UNUSED)
{
	u32 acked_height;
	const char *err;

	/* Parse the acknowledged height */
	err = json_scan(tmpctx, buf, result,
			"{blockheight:%}",
			JSON_SCAN(json_to_number, &acked_height));
	if (err)
		plugin_err(cmd->plugin, "block_processed ack '%.*s': %s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result), err);

	plugin_log(cmd->plugin, LOG_DBG,
		   "Received block_processed ack for height %u", acked_height);
	return command_success(cmd, json_out_obj(cmd, NULL, NULL));
}

/* Non-fatal error handler for block_processed — watchman may not be ready */
static struct command_result *block_processed_err(struct command *cmd,
						  const char *method UNUSED,
						  const char *buf,
						  const jsmntok_t *result,
						  void *unused UNUSED)
{
	plugin_log(cmd->plugin, LOG_DBG,
		   "block_processed RPC failed (watchman not ready?): %.*s",
		   json_tok_full_len(result), json_tok_full(buf, result));
	return command_success(cmd, json_out_obj(cmd, NULL, NULL));
}

/* Send block_processed notification to watchman */
void bwatch_send_block_processed(struct command *cmd, u32 blockheight)
{
	struct out_req *req;

	req = jsonrpc_request_start(cmd, "block_processed",
				    block_processed_ack, block_processed_err, NULL);
	json_add_u32(req->js, "blockheight", blockheight);
	send_outreq(req);
}

/*
 * ============================================================================
 * RPC COMMAND HANDLERS
 * ============================================================================
 */

static struct command_result *param_watch_type(struct command *cmd, const char *name,
					       const char *buffer, const jsmntok_t *tok,
					       enum watch_type *type)
{
	if (json_tok_streq(buffer, tok, "scriptpubkey"))
		*type = WATCH_SCRIPTPUBKEY;
	else if (json_tok_streq(buffer, tok, "outpoint"))
		*type = WATCH_OUTPOINT;
	else if (json_tok_streq(buffer, tok, "txid"))
		*type = WATCH_TXID;
	else {
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be scriptpubkey, outpoint or txid");
	}
	return NULL;
}

static struct command_result *check_type_params(struct command *cmd,
						enum watch_type type,
						const struct bitcoin_outpoint *outpoint,
						const u8 *scriptpubkey,
						const struct bitcoin_txid *txid)
{
	switch (type) {
	case WATCH_SCRIPTPUBKEY:
		if (!scriptpubkey)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "scriptpubkey required for type 'scriptpubkey'");
		if (outpoint || txid)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "no outpoint or txid for type 'scriptpubkey'");
		return NULL;
	case WATCH_OUTPOINT:
		if (!outpoint)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "outpoint required for type 'outpoint'");
		if (scriptpubkey || txid)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "no scriptpubkey or txid for type 'outpoint'");
		return NULL;
	case WATCH_TXID:
		if (!txid)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "txid required for type 'txid'");
		if (outpoint || scriptpubkey)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "no outpoint or scriptpubkey for type 'txid'");
		return NULL;
	}
	abort();
}

/* RPC command: addwatch */
struct command_result *json_bwatch_add(struct command *cmd,
				       const char *buffer,
				       const jsmntok_t *params)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	const char *owner;
	u32 *start_block;
	u8 *scriptpubkey;
	struct bitcoin_outpoint *outpoint;
	struct bitcoin_txid *txid;
	struct watch *w;
	enum watch_type type;
	struct command_result *res;

	if (!param_check(cmd, buffer, params,
			 p_req("owner", param_string, &owner),
			 p_req("type", param_watch_type, &type),
			 p_req("start_block", param_u32, &start_block),
			 p_opt("outpoint", param_outpoint, &outpoint),
			 p_opt("scriptpubkey", param_bin_from_hex, &scriptpubkey),
			 p_opt("txid", param_txid, &txid),
			 NULL))
		return command_param_failed();

	res = check_type_params(cmd, type, outpoint, scriptpubkey, txid);
	if (res)
		return res;

	if (command_check_only(cmd))
		return command_check_done(cmd);

	w = bwatch_add_watch(cmd, bwatch,
			     type,
			     outpoint,
			     scriptpubkey,
			     txid,
			     *start_block,
			     owner);

	if (w && bwatch->current_height > 0 && *start_block <= bwatch->current_height) {
		/* Rescan needed - command completes when rescan finishes */
		bwatch_start_rescan(cmd, w, *start_block, bwatch->current_height);
		return command_still_pending(cmd);
	}

	/* Datastore operation completed synchronously */
	return command_success(cmd, json_out_obj(cmd, NULL, NULL));
}

/* RPC command: delwatch */
struct command_result *json_bwatch_del(struct command *cmd,
				       const char *buffer,
				       const jsmntok_t *params)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	const char *owner;
	u8 *scriptpubkey;
	struct bitcoin_outpoint *outpoint;
	struct bitcoin_txid *txid;
	enum watch_type type;
	struct command_result *res;

	if (!param_check(cmd, buffer, params,
			 p_req("owner", param_string, &owner),
			 p_req("type", param_watch_type, &type),
			 p_opt("outpoint", param_outpoint, &outpoint),
			 p_opt("scriptpubkey", param_bin_from_hex, &scriptpubkey),
			 p_opt("txid", param_txid, &txid),
			 NULL))
		return command_param_failed();

	res = check_type_params(cmd, type, outpoint, scriptpubkey, txid);
	if (res)
		return res;

	if (command_check_only(cmd))
		return command_check_done(cmd);

	bwatch_del_watch(cmd, bwatch, type, outpoint, scriptpubkey, txid, owner);
	
	/* Datastore operation completed synchronously */
	return command_success(cmd, json_out_obj(cmd, "removed", "true"));
}

/* Helper to output common watch fields */
static void json_out_watch_common(struct json_out *jout,
				  enum watch_type type,
				  u32 start_block,
				  wirestring **owners)
{
	json_out_addstr(jout, "type", bwatch_get_watch_type_name(type));
	json_out_add(jout, "start_block", false, "%u", start_block);
	json_out_start(jout, "owners", '[');
	for (size_t i = 0; i < tal_count(owners); i++)
		json_out_addstr(jout, NULL, owners[i]);
	json_out_end(jout, ']');
}

/* RPC command: listwatch */
struct command_result *json_bwatch_list(struct command *cmd,
					const char *buffer,
					const jsmntok_t *params)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	struct json_out *jout;
	struct watch *w;
	struct scriptpubkey_watches_iter sit;
	struct outpoint_watches_iter oit;
	struct txid_watches_iter tit;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	jout = json_out_new(cmd);
	json_out_start(jout, NULL, '{');
	json_out_start(jout, "watches", '[');

	w = scriptpubkey_watches_first(bwatch->scriptpubkey_watches, &sit);
	while (w) {
		json_out_start(jout, NULL, '{');
		json_out_addstr(jout, "scriptpubkey",
				tal_hexstr(tmpctx, w->key.scriptpubkey.script, w->key.scriptpubkey.len));
		json_out_watch_common(jout, w->type, w->start_block, w->owners);
		json_out_end(jout, '}');
		w = scriptpubkey_watches_next(bwatch->scriptpubkey_watches, &sit);
	}

	w = outpoint_watches_first(bwatch->outpoint_watches, &oit);
	while (w) {
		json_out_start(jout, NULL, '{');
		json_out_addstr(jout, "outpoint", fmt_bitcoin_outpoint(tmpctx, &w->key.outpoint));
		json_out_watch_common(jout, w->type, w->start_block, w->owners);
		json_out_end(jout, '}');
		w = outpoint_watches_next(bwatch->outpoint_watches, &oit);
	}

	w = txid_watches_first(bwatch->txid_watches, &tit);
	while (w) {
		json_out_start(jout, NULL, '{');
		json_out_addstr(jout, "txid", fmt_bitcoin_txid(tmpctx, &w->key.txid));
		json_out_watch_common(jout, w->type, w->start_block, w->owners);
		json_out_end(jout, '}');
		w = txid_watches_next(bwatch->txid_watches, &tit);
	}

	json_out_end(jout, ']');
	json_out_end(jout, '}');
	return command_success(cmd, jout);
}

/*
 * ============================================================================
 * WATCHMAN SYNCHRONIZATION
 * ============================================================================
 */

/* Called when getwatchmanheight fails (watchman not ready, method missing, etc.).
 * Retry until watchman is up — bwatch must not start polling before watchman is ready,
 * otherwise block_processed notifications will arrive before watchman can handle them. */
static struct command_result *getwatchmanheight_failed(struct command *cmd,
						       const char *method UNUSED,
						       const char *buf UNUSED,
						       const jsmntok_t *result UNUSED,
						       void *unused UNUSED)
{
	plugin_log(cmd->plugin, LOG_DBG,
		   "getwatchmanheight failed (watchman not ready?), retrying in 500ms");
	global_timer(cmd->plugin, time_from_msec(500), bwatch_sync_with_watchman, NULL);
	return timer_complete(cmd);
}

/* Handle getwatchmanheight response - sync with watchman's last processed height */
static struct command_result *getwatchmanheight_done(struct command *cmd,
						     const char *method UNUSED,
						     const char *buf,
						     const jsmntok_t *result,
						     void *unused UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	u32 watchman_height;
	const jsmntok_t *height_tok;

	/* Parse the response */
	height_tok = json_get_member(buf, result, "height");
	if (!height_tok || !json_to_u32(buf, height_tok, &watchman_height)) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "Could not parse getwatchmanheight response, starting poll from height %u",
			   bwatch->current_height);
		watchman_height = bwatch->current_height;
	}

	plugin_log(cmd->plugin, LOG_DBG,
		   "Watchman reports height %u, bwatch has height %u",
		   watchman_height, bwatch->current_height);

	/* Roll back to watchman's height if we're ahead */
	if (bwatch->current_height > watchman_height) {
		plugin_log(cmd->plugin, LOG_INFORM,
			   "Rolling back from %u to watchman height %u",
			   bwatch->current_height, watchman_height);
		while (bwatch->current_height > watchman_height)
			bwatch_remove_tip(cmd, bwatch);
	}

	plugin_log(cmd->plugin, LOG_INFORM,
		   "bwatch initialized at height %u with %zu blocks, polling every %u ms",
		   bwatch->current_height, tal_count(bwatch->block_history),
		   bwatch->poll_interval_ms);

	/* Schedule poll timer so poll_chain runs with its own command lifecycle */
	bwatch->poll_timer = global_timer(cmd->plugin, time_from_sec(0), bwatch_poll_chain, NULL);
	return timer_complete(cmd);
}

/* Timer callback to sync with watchman before starting normal polling */
struct command_result *bwatch_sync_with_watchman(struct command *cmd, void *unused UNUSED)
{
	struct out_req *req = jsonrpc_request_start(cmd, "getwatchmanheight",
						    getwatchmanheight_done,
						    getwatchmanheight_failed,
						    NULL);
	return send_outreq(req);
}
