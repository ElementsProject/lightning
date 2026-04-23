#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/ptrint/ptrint.h>
#include <common/json_param.h>
#include <common/json_parse.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <plugins/bwatch/bwatch.h>
#include <plugins/bwatch/bwatch_interface.h>
#include <plugins/bwatch/bwatch_scanner.h>
#include <plugins/bwatch/bwatch_store.h>
#include <plugins/bwatch/bwatch_wiregen.h>

struct bwatch *bwatch_of(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct bwatch);
}

/*
 * ============================================================================
 * BLOCK PROCESSING: Polling
 *
 * Each cycle: getchaininfo → if blockcount > current_height, fetch the next
 * block via getrawblockbyheight, append it to the in-memory history, persist
 * it, and reschedule the next poll once the datastore write completes.
 *
 * Reorg detection (parent-hash mismatch) and watch matching land in
 * subsequent commits.
 * ============================================================================
 */

static struct command_result *handle_block(struct command *cmd,
					   const char *method,
					   const char *buf,
					   const jsmntok_t *result,
					   ptrint_t *block_height);

/* Parse the bitcoin block out of a getrawblockbyheight response. */
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

/* Fetch a block by height for normal polling. */
static struct command_result *fetch_block_handle(struct command *cmd,
						 u32 height)
{
	struct out_req *req = jsonrpc_request_start(cmd, "getrawblockbyheight",
						    handle_block, handle_block,
						    int2ptr(height));
	json_add_u32(req->js, "height", height);
	return send_outreq(req);
}

/* Reschedule at the configured interval (used when there's nothing new to
 * fetch, or on error).  Once we're caught up to bitcoind's tip, this is
 * what governs the steady-state poll cadence. */
static struct command_result *poll_finished(struct command *cmd)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);

	bwatch->poll_timer = global_timer(cmd->plugin,
					  time_from_msec(bwatch->poll_interval_ms),
					  bwatch_poll_chain, NULL);
	return timer_complete(cmd);
}

/* Process one block fetched from bitcoind: update tip, append to history,
 * then persist; once persisted we notify watchman, and the next poll is
 * scheduled from the block_processed ack so we don't race ahead of it. */
static struct command_result *handle_block(struct command *cmd,
					   const char *method UNUSED,
					   const char *buf,
					   const jsmntok_t *result,
					   ptrint_t *block_height)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	struct bitcoin_blkid blockhash;
	struct bitcoin_block *block;

	block = block_from_response(buf, result, &blockhash);
	if (!block) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Failed to get/parse block %u: '%.*s'",
			   (unsigned int)ptr2int(block_height),
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
		return poll_finished(cmd);
	}

	bwatch->current_height = ptr2int(block_height);
	bwatch->current_blockhash = blockhash;
	bwatch_add_block_to_history(bwatch, bwatch->current_height, &blockhash,
				    &block->hdr.prev_hash);

	struct block_record_wire br = {
		bwatch->current_height,
		bwatch->current_blockhash,
		block->hdr.prev_hash,
	};
	return bwatch_add_block_to_datastore(cmd, &br,
					     bwatch_send_block_processed);
}

/* getchaininfo response: pick the next block to fetch (or just reschedule). */
static struct command_result *getchaininfo_done(struct command *cmd,
						const char *method UNUSED,
						const char *buf,
						const jsmntok_t *result,
						void *unused UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	u32 blockheight;
	const char *err;

	err = json_scan(tmpctx, buf, result,
			"{blockcount:%}",
			JSON_SCAN(json_to_number, &blockheight));
	if (err) {
		plugin_log(cmd->plugin, LOG_BROKEN,
			   "getchaininfo parse failed: %s", err);
		return poll_finished(cmd);
	}

	if (blockheight > bwatch->current_height) {
		u32 target_height;

		/* On first init we jump straight to the chain tip; afterwards
		 * we catch up one block at a time so handle_block can validate
		 * each parent hash (added in a later commit). */
		if (bwatch->current_height == 0) {
			plugin_log(cmd->plugin, LOG_DBG,
				   "First poll: init at block %u",
				   blockheight);
			target_height = blockheight;
		} else {
			target_height = bwatch->current_height + 1;
		}

		return fetch_block_handle(cmd, target_height);
	}

	plugin_log(cmd->plugin, LOG_DBG,
		   "No block change, current_height remains %u",
		   bwatch->current_height);
	return poll_finished(cmd);
}

/* Non-fatal: bcli may not have come up yet — log and retry on the next poll. */
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

struct command_result *bwatch_poll_chain(struct command *cmd,
					 void *unused UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	struct out_req *req;

	req = jsonrpc_request_start(cmd, "getchaininfo",
				    getchaininfo_done, getchaininfo_failed,
				    NULL);
	json_add_u32(req->js, "last_height", bwatch->current_height);
	return send_outreq(req);
}

static const char *init(struct command *cmd,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);

	bwatch->plugin = cmd->plugin;

	bwatch->scriptpubkey_watches = new_htable(bwatch, scriptpubkey_watches);
	bwatch->outpoint_watches = new_htable(bwatch, outpoint_watches);
	bwatch->scid_watches = new_htable(bwatch, scid_watches);
	bwatch->blockdepth_watches = new_htable(bwatch, blockdepth_watches);

	bwatch->block_history = tal_arr(bwatch, struct block_record_wire, 0);

	/* Replay persisted block history.  load_block_history sets
	 * current_height / current_blockhash from the most recent record;
	 * if there are no records, fall back to zero so the first poll
	 * initialises us at the chain tip. */
	bwatch_load_block_history(cmd, bwatch);
	bwatch_load_watches_from_datastore(cmd, bwatch);

	/* Kick off the chain-poll loop. */
	bwatch->poll_timer = global_timer(cmd->plugin, time_from_sec(0),
					  bwatch_poll_chain, NULL);
	return NULL;
}

static const struct plugin_command commands[] = {
	/* Subsequent commits register addwatch / delwatch / listwatch here. */
};

int main(int argc, char *argv[])
{
	struct bwatch *bwatch;

	setup_locale();
	bwatch = tal(NULL, struct bwatch);
	bwatch->poll_interval_ms = 30000;

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
