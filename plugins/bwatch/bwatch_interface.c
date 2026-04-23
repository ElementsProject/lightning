#include "config.h"
#include <common/json_param.h>
#include <common/json_parse.h>
#include <common/json_stream.h>
#include <plugins/bwatch/bwatch_interface.h>

/*
 * ============================================================================
 * SENDING WATCH_FOUND NOTIFICATIONS
 * ============================================================================
 */

/* Callback for watch_found RPC.
 * watch_found notifications are sent on an aux command so they cannot
 * interfere with the poll command lifetime. */
static struct command_result *notify_ack(struct command *cmd,
				      const char *method UNUSED,
				      const char *buf UNUSED,
				      const jsmntok_t *result UNUSED,
				      void *arg UNUSED)
{
	return aux_command_done(cmd);
}

/* Send watch_found notification to lightningd. */
void bwatch_send_watch_found(struct command *cmd,
			     const struct bitcoin_tx *tx,
			     u32 blockheight,
			     const struct watch *w,
			     u32 txindex,
			     u32 index)
{
	struct command *aux = aux_command(cmd);
	struct out_req *req;

	req = jsonrpc_request_start(aux, "watch_found",
				    notify_ack, notify_ack, NULL);
	/* tx==NULL signals "not found" for WATCH_SCID; omit tx+txindex so
	 * json_watch_found passes tx=NULL down to the handler. */
	if (tx) {
		json_add_tx(req->js, "tx", tx);
		json_add_u32(req->js, "txindex", txindex);
		if (index != UINT32_MAX)
			json_add_u32(req->js, "index", index);
	}
	json_add_u32(req->js, "blockheight", blockheight);

	/* Add owners array */
	json_array_start(req->js, "owners");
	for (size_t i = 0; i < tal_count(w->owners); i++)
		json_add_string(req->js, NULL, w->owners[i]);
	json_array_end(req->js);

	/* Tests (and operators) key off this line; keep wording stable. */
	plugin_log(cmd->plugin, LOG_DBG,
		   "watch_found at block %u", blockheight);

	send_outreq(req);
}

/* Send a blockdepth depth notification to lightningd: same watch_found
 * RPC shape but with depth + blockheight only (no tx). */
void bwatch_send_blockdepth_found(struct command *cmd,
				  const struct watch *w,
				  u32 depth,
				  u32 blockheight)
{
	struct command *aux = aux_command(cmd);
	struct out_req *req;

	req = jsonrpc_request_start(aux, "watch_found",
				    notify_ack, notify_ack, NULL);
	json_add_u32(req->js, "blockheight", blockheight);
	json_add_u32(req->js, "depth", depth);

	json_array_start(req->js, "owners");
	for (size_t i = 0; i < tal_count(w->owners); i++)
		json_add_string(req->js, NULL, w->owners[i]);
	json_array_end(req->js);

	send_outreq(req);
}

/* Tell one owner that a previously-reported watch_found was rolled back. */
void bwatch_send_watch_revert(struct command *cmd,
			      const char *owner,
			      u32 blockheight)
{
	struct command *aux = aux_command(cmd);
	struct out_req *req;

	req = jsonrpc_request_start(aux, "watch_revert",
				    notify_ack, notify_ack, NULL);
	json_add_string(req->js, "owner", owner);
	json_add_u32(req->js, "blockheight", blockheight);
	send_outreq(req);
}

/*
 * ============================================================================
 * SENDING BLOCK_PROCESSED NOTIFICATION
 *
 * After bwatch has persisted a new tip, it tells watchman by sending the
 * block_processed RPC.  The next poll is scheduled from the ack callback,
 * which guarantees watchman's persisted height is updated before bwatch
 * looks for another block — important for crash safety: on restart we
 * trust watchman's height as the floor and re-fetch anything above it.
 * ============================================================================
 */

/* Watchman acked block_processed: safe to poll for the next block. */
static struct command_result *block_processed_ack(struct command *cmd,
						  const char *method UNUSED,
						  const char *buf,
						  const jsmntok_t *result,
						  void *unused UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	u32 acked_height;
	const char *err;

	err = json_scan(tmpctx, buf, result,
			"{blockheight:%}",
			JSON_SCAN(json_to_number, &acked_height));
	if (err)
		plugin_err(cmd->plugin, "block_processed ack '%.*s': %s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result), err);

	plugin_log(cmd->plugin, LOG_DBG,
		   "Received block_processed ack for height %u", acked_height);

	bwatch->poll_timer = global_timer(cmd->plugin, time_from_sec(0),
					  bwatch_poll_chain, NULL);
	return timer_complete(cmd);
}

/* Non-fatal: watchman may not be ready yet (e.g. lightningd still booting).
 * Reschedule the poll anyway so we keep retrying without busy-looping. */
static struct command_result *block_processed_err(struct command *cmd,
						  const char *method UNUSED,
						  const char *buf,
						  const jsmntok_t *result,
						  void *unused UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);

	plugin_log(cmd->plugin, LOG_BROKEN,
		   "block_processed RPC failed (watchman not ready?): %.*s",
		   json_tok_full_len(result), json_tok_full(buf, result));

	bwatch->poll_timer = global_timer(cmd->plugin, time_from_sec(0),
					  bwatch_poll_chain, NULL);
	return timer_complete(cmd);
}

struct command_result *bwatch_send_block_processed(struct command *cmd)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	struct out_req *req;

	req = jsonrpc_request_start(cmd, "block_processed",
				    block_processed_ack, block_processed_err,
				    NULL);
	json_add_u32(req->js, "blockheight", bwatch->current_height);
	json_add_string(req->js, "blockhash",
			fmt_bitcoin_blkid(tmpctx, &bwatch->current_blockhash));
	return send_outreq(req);
}

/*
 * ============================================================================
 * REVERT BLOCK NOTIFICATION
 * ============================================================================
 */

/* Notify watchman that a block was rolled back so it can update and persist
 * its tip. Fire-and-forget via aux_command — the poll timer doesn't depend
 * on the ack. Crash safety: if we crash before the ack, watchman's stale
 * height will be higher than bwatch's on restart, retriggering rollback. */
void bwatch_send_revert_block_processed(struct command *cmd, u32 new_height,
					const struct bitcoin_blkid *new_hash)
{
	struct command *aux = aux_command(cmd);
	struct out_req *req;

	req = jsonrpc_request_start(aux, "revert_block_processed",
				    notify_ack, notify_ack, NULL);
	json_add_u32(req->js, "blockheight", new_height);
	json_add_string(req->js, "blockhash",
			fmt_bitcoin_blkid(tmpctx, new_hash));
	send_outreq(req);
}
