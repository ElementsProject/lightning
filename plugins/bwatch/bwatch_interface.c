#include "config.h"
#include <common/json_param.h>
#include <common/json_parse.h>
#include <common/json_stream.h>
#include <plugins/bwatch/bwatch_interface.h>

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

/* Generic fire-and-forget ack: aux notifications don't gate the poll, so
 * we just close the aux command on either success or error. */
static struct command_result *notify_ack(struct command *cmd,
					 const char *method UNUSED,
					 const char *buf UNUSED,
					 const jsmntok_t *result UNUSED,
					 void *arg UNUSED)
{
	return aux_command_done(cmd);
}

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
