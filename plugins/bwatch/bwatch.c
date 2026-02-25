#include "config.h"
#include "bwatch.h"
#include "bwatch_store.h"
#include "bwatch_scanner.h"
#include "bwatch_interface.h"
#include <bitcoin/block.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_parse.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <plugins/bwatch/bwatch_wiregen.h>
#include <plugins/libplugin.h>

struct bwatch *bwatch_of(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct bwatch);
}
/*
 * ============================================================================
 * BLOCK PROCESSING: Polling
 * ============================================================================
 */

/* Forward declarations */
static struct command_result *getchaininfo_done(struct command *cmd,
						const char *method,
						const char *buf,
						const jsmntok_t *result,
						void *unused);

/* Parse block from RPC response */
static struct bitcoin_block *block_from_response(const char *buf,
						 const jsmntok_t *result,
						 struct bitcoin_blkid *blockhash_out)
{
	const jsmntok_t *blocktok = json_get_member(buf, result, "block");
	struct bitcoin_block *block;

	if (!blocktok)
		return NULL;

	block = bitcoin_block_from_hex(tmpctx, chainparams,
				       buf + blocktok->start,
				       blocktok->end - blocktok->start);
	if (block && blockhash_out)
		bitcoin_block_blkid(block, blockhash_out);

	return block;
}

/* Fetch a block by height for rescan */
static struct command_result *fetch_block_rescan(struct command *cmd,
						 u32 height,
						 struct command_result *(*cb)(struct command *,
									      const char *,
									      const char *,
									      const jsmntok_t *,
									      struct rescan_state *),
						 struct rescan_state *rescan)
{
	struct out_req *req = jsonrpc_request_start(cmd, "getrawblockbyheight",
						    cb, cb, rescan);
	json_add_u32(req->js, "height", height);
	return send_outreq(req);
}

/* Fetch a block by height for normal processing */
static struct command_result *fetch_block_handle(struct command *cmd,
						 u32 height,
						 struct command_result *(*cb)(struct command *,
									      const char *,
									      const char *,
									      const jsmntok_t *,
									      u32 *),
						 u32 *block_height)
{
	struct out_req *req = jsonrpc_request_start(cmd, "getrawblockbyheight",
						    cb, cb, block_height);
	json_add_u32(req->js, "height", height);
	return send_outreq(req);
}

/* Reschedule the timer and complete */
static struct command_result *poll_finished(struct command *cmd)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);

	plugin_log(cmd->plugin, LOG_DBG, "Rescheduling poll timer (current_height=%u)",
		   bwatch->current_height);
	bwatch->poll_timer = global_timer(cmd->plugin, time_from_msec(bwatch->poll_interval_ms),
					   bwatch_poll_chain, NULL);
	return timer_complete(cmd);
}

/* Remove tip block on reorg (exposed for bwatch_interface.c) */
void bwatch_remove_tip(struct command *cmd, struct bwatch *bwatch)
{
	size_t count = tal_count(bwatch->block_history);

	if (count == 0) {
		plugin_log(bwatch->plugin, LOG_BROKEN,
			   "remove_tip called with no block history!");
		return;
	}

	plugin_log(bwatch->plugin, LOG_DBG, "Removing stale block %u: %s",
		   bwatch->current_height,
		   fmt_bitcoin_blkid(tmpctx, &bwatch->current_blockhash));

	/* Delete block from datastore */
	bwatch_delete_block_from_datastore(cmd, bwatch->current_height);

	/* Remove last block from history */
	tal_free(bwatch->block_history[count - 1]);
	tal_resize(&bwatch->block_history, count - 1);

	/* Move tip back one */
	size_t newcount = count - 1;
	if (newcount > 0) {
		struct block_record_wire *newtip = bwatch->block_history[newcount - 1];
		bwatch->current_height = newtip->height;
		bwatch->current_blockhash = newtip->hash;
		assert(newtip->height == bwatch->current_height);
	} else {
		/* Back to genesis */
		bwatch->current_height = 0;
		memset(&bwatch->current_blockhash, 0, sizeof(bwatch->current_blockhash));
	}
}

/* Process or initialize from a block */
static struct command_result *handle_block(struct command *cmd,
					   const char *method,
					   const char *buf,
					   const jsmntok_t *result,
					   u32 *block_height)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	struct bitcoin_blkid blockhash;
	struct bitcoin_block *block;
	bool is_init = (bwatch->current_height == 0);

	block = block_from_response(buf, result, &blockhash);
	if (!block) {
		plugin_log(cmd->plugin, LOG_BROKEN, "Failed to get/parse block %u: '%.*s'",
			   *block_height,
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
		return poll_finished(cmd);
	}

	/* If not initializing, validate block continuity */
	if (!is_init) {
		/* Unexpected predecessor? Remove tip and use the new chain's hash */
		if (!bitcoin_blkid_eq(&block->hdr.prev_hash, &bwatch->current_blockhash)) {
			plugin_log(cmd->plugin, LOG_INFORM,
				   "Reorg detected at block %u: expected parent %s, got %s (fetched block hash: %s)",
				   *block_height,
				   fmt_bitcoin_blkid(tmpctx, &bwatch->current_blockhash),
				   fmt_bitcoin_blkid(tmpctx, &block->hdr.prev_hash),
				   fmt_bitcoin_blkid(tmpctx, &blockhash));
			/* Remove tip and retry from new height */
			bwatch_remove_tip(cmd, bwatch);
			/* Retry from new current height + 1 */
			*block_height = bwatch->current_height + 1;
			return fetch_block_handle(cmd, *block_height, handle_block, block_height);
		}

		/* Good block, process watches */
		bwatch_process_block_txs(cmd, bwatch, block, *block_height, &blockhash, NULL);
	}

	/* Update state */
	bwatch->current_height = *block_height;
	bwatch->current_blockhash = blockhash;

	/* Persist to datastore, then update in-memory history */
	struct block_record_wire br = { *block_height, blockhash, block->hdr.prev_hash };
	bwatch_add_block_to_datastore(cmd, &br);
	bwatch_add_block_to_history(bwatch, *block_height, &blockhash, &block->hdr.prev_hash);

	/* Notify watchman that we've processed this block */
	bwatch_send_block_processed(cmd, *block_height);

	/* Schedule immediate re-poll to check if there are more blocks */
	bwatch->poll_timer = global_timer(cmd->plugin, time_from_sec(0), bwatch_poll_chain, NULL);
	return timer_complete(cmd);
}

/* Handle getchaininfo response */
static struct command_result *getchaininfo_done(struct command *cmd,
						const char *method,
						const char *buf,
						const jsmntok_t *result,
						void *unused)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	u32 blockheight;
	const char *err;

	/* Extract block height */
	err = json_scan(tmpctx, buf, result,
			"{blockcount:%}",
			JSON_SCAN(json_to_number, &blockheight));
	if (err) {
		plugin_log(cmd->plugin, LOG_BROKEN, "getchaininfo parse failed: %s", err);
		return poll_finished(cmd);
	}

	/* Check if block height changed (or if we need to initialize) */
	if (blockheight > bwatch->current_height) {
		u32 *target_height = tal(cmd, u32);
		
		if (bwatch->current_height == 0) {
			plugin_log(cmd->plugin, LOG_DBG, "First poll: init at block %u", blockheight);
			*target_height = blockheight;  /* Jump to tip on first init */
		} else {
			*target_height = bwatch->current_height + 1;  /* Catch up sequentially */
		}

		return fetch_block_handle(cmd, *target_height, handle_block, target_height);
	}

	/* No change, reschedule at normal interval */
	plugin_log(cmd->plugin, LOG_DBG, "No block change, current_height remains %u", bwatch->current_height);
	return poll_finished(cmd);
}

/* Non-fatal error callback for getchaininfo — bcli may not be ready yet */
static struct command_result *getchaininfo_failed(struct command *cmd,
						  const char *method UNUSED,
						  const char *buf,
						  const jsmntok_t *result,
						  void *unused UNUSED)
{
	plugin_log(cmd->plugin, LOG_DBG,
		   "getchaininfo failed (bcli not ready?): %.*s",
		   json_tok_full_len(result), json_tok_full(buf, result));
	return poll_finished(cmd);
}

/* Timer callback to poll the chain (exposed for bwatch_interface.c) */
struct command_result *bwatch_poll_chain(struct command *cmd, void *unused)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	struct out_req *req;

	plugin_log(cmd->plugin, LOG_DBG, "Polling chain for new blocks (current_height=%u)",
		   bwatch->current_height);

	req = jsonrpc_request_start(cmd, "getchaininfo",
				    getchaininfo_done,
				    getchaininfo_failed,
				    NULL);
	json_add_u32(req->js, "last_height", bwatch->current_height);
	return send_outreq(req);
}

/*
 * ============================================================================
 * RESCAN FUNCTIONS
 *
 * When a watch is added with start_block <= current_height, we need to scan
 * historical blocks for that specific watch. We scan from start_block up to
 * current_height (inclusive), but no further - this ensures rescans don't
 * race ahead of normal polling, keeping all watches synchronized.
 *
 * The rescan runs asynchronously: fetch block -> process -> fetch next.
 * ============================================================================
 */

/* Called when we receive a block during rescan */
static struct command_result *rescan_block_done(struct command *cmd,
						const char *method,
						const char *buf,
						const jsmntok_t *result,
						struct rescan_state *rescan)
{
	struct bitcoin_blkid blockhash;
	struct bitcoin_block *block = block_from_response(buf, result, &blockhash);

	if (!block) {
		plugin_log(cmd->plugin, LOG_BROKEN,
			   "Rescan: Failed to get/parse block %u",
			   rescan->current_block);
		return command_fail(cmd, LIGHTNINGD,
				    "Rescan failed at block %u",
				    rescan->current_block);
	}

	/* Process block: if rescan->watch is NULL, check all watches; otherwise check only that watch */
	bwatch_process_block_txs(cmd, bwatch_of(cmd->plugin), block, rescan->current_block,
			  &blockhash, rescan->watch);

	/* More blocks to scan? */
	if (++rescan->current_block <= rescan->target_block)
		return fetch_block_rescan(cmd, rescan->current_block, rescan_block_done, rescan);

	/* Rescan complete */
	bwatch_send_block_processed(cmd, rescan->target_block);

	plugin_log(cmd->plugin, LOG_INFORM, "Rescan complete");
	return command_success(cmd, json_out_obj(cmd, NULL, NULL));
}

/* Start scanning historical blocks (exposed for bwatch_interface.c) */
void bwatch_start_rescan(struct command *cmd,
			 const struct watch *w,
			 u32 start_block,
			 u32 target_block)
{
	struct rescan_state *rescan;

	if (w) {
		plugin_log(cmd->plugin, LOG_INFORM, "Starting rescan for %s watch: blocks %u-%u",
			   bwatch_get_watch_type_name(w->type), start_block, target_block);
	} else {
		plugin_log(cmd->plugin, LOG_INFORM, "Starting rescan for all watches: blocks %u-%u",
			   start_block, target_block);
	}

	rescan = tal(cmd, struct rescan_state);
	rescan->watch = w;
	rescan->current_block = start_block;
	rescan->target_block = target_block;

	fetch_block_rescan(cmd, rescan->current_block, rescan_block_done, rescan);
}

/*
 * ============================================================================
 * PLUGIN INITIALIZATION
 * ============================================================================
 */

static const char *init(struct command *cmd,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);

	bwatch->plugin = cmd->plugin;

	/* Initialize watch storage */
	bwatch->scriptpubkey_watches = new_htable(bwatch, scriptpubkey_watches);
	bwatch->outpoint_watches = new_htable(bwatch, outpoint_watches);
	bwatch->txid_watches = new_htable(bwatch, txid_watches);

	/* Initialize block history */
	bwatch->block_history = tal_arr(bwatch, struct block_record_wire *, 0);

	/* Load block history from datastore */
	bwatch_load_block_history(cmd, bwatch);

	/* If no history, initialize to zero (will be set on first poll) */
	if (tal_count(bwatch->block_history) == 0) {
		bwatch->current_height = 0;
		memset(&bwatch->current_blockhash, 0, sizeof(bwatch->current_blockhash));
	}

	/* Restore watches from datastore */
	bwatch_load_watches_from_datastore(cmd, bwatch);

	/* Defer watchman height sync to a timer so init can complete synchronously */
	global_timer(cmd->plugin, time_from_sec(0), bwatch_sync_with_watchman, NULL);
	
	return NULL; /* Success */
}

static const struct plugin_command commands[] = {
	{
		"addwatch",
		json_bwatch_add,
	},
	{
		"addutxo",
		json_bwatch_addutxo,
	},
	{
		"delwatch",
		json_bwatch_del,
	},
	{
		"listwatch",
		json_bwatch_list,
	},
	{
		"gettransaction",
		json_bwatch_get_transaction,
	},
};

int main(int argc, char *argv[])
{
	struct bwatch *bwatch;

	setup_locale();
	bwatch = tal(NULL, struct bwatch);
	bwatch->poll_interval_ms = 30000;  /* Default: 30 seconds */
	plugin_main(argv, init, take(bwatch), PLUGIN_RESTARTABLE, true, NULL,
		    commands, ARRAY_SIZE(commands),
		    NULL, 0,
		    NULL, 0,
		    NULL, 0,
		    plugin_option("bwatch-poll-interval", "int",
				  "Milliseconds between chain polls (default: 30000)",
				  u32_option, u32_jsonfmt, &bwatch->poll_interval_ms),
		    NULL);
}
