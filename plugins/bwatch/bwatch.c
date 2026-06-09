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

/* Send watch_revert for every owner affected by losing @removed_height. */
static void bwatch_notify_reorg_watches(struct command *cmd,
					struct bwatch *bwatch,
					u32 removed_height)
{
	const char **owners = tal_arr(tmpctx, const char *, 0);
	struct watch *w;

	/* Snapshot owners first; revert handlers may call watchman_del and
	 * mutate these tables. */

	/* Scriptpubkey watches are perennial: always notify. */
	struct scriptpubkey_watches_iter sit;
	for (w = scriptpubkey_watches_first(bwatch->scriptpubkey_watches, &sit);
	     w;
	     w = scriptpubkey_watches_next(bwatch->scriptpubkey_watches, &sit)) {
		for (size_t i = 0; i < tal_count(w->owners); i++)
			tal_arr_expand(&owners, w->owners[i]);
	}

	/* Outpoint/scid/blockdepth: only notify watches whose anchor block is
	 * being torn down (start_block >= removed_height).  Older long-lived
	 * watches stay armed and will refire naturally on the new chain. */
	struct outpoint_watches_iter oit;
	for (w = outpoint_watches_first(bwatch->outpoint_watches, &oit);
	     w;
	     w = outpoint_watches_next(bwatch->outpoint_watches, &oit)) {
		if (w->start_block < removed_height)
			continue;
		for (size_t i = 0; i < tal_count(w->owners); i++)
			tal_arr_expand(&owners, w->owners[i]);
	}

	struct scid_watches_iter scit;
	for (w = scid_watches_first(bwatch->scid_watches, &scit);
	     w;
	     w = scid_watches_next(bwatch->scid_watches, &scit)) {
		if (w->start_block < removed_height)
			continue;
		for (size_t i = 0; i < tal_count(w->owners); i++)
			tal_arr_expand(&owners, w->owners[i]);
	}

	struct blockdepth_watches_iter bdit;
	for (w = blockdepth_watches_first(bwatch->blockdepth_watches, &bdit);
	     w;
	     w = blockdepth_watches_next(bwatch->blockdepth_watches, &bdit)) {
		if (w->start_block < removed_height)
			continue;
		for (size_t i = 0; i < tal_count(w->owners); i++)
			tal_arr_expand(&owners, w->owners[i]);
	}

	for (size_t i = 0; i < tal_count(owners); i++)
		bwatch_send_watch_revert(cmd, owners[i], removed_height);
}

/* Remove tip block on reorg  */
void bwatch_remove_tip(struct command *cmd, struct bwatch *bwatch)
{
	const struct block_record_wire *newtip;
	size_t count = tal_count(bwatch->block_history);

	if (count == 0) {
		plugin_log(bwatch->plugin, LOG_BROKEN,
			   "remove_tip called with no block history!");
		return;
	}

	plugin_log(bwatch->plugin, LOG_DBG, "Removing stale block %u: %s",
		   bwatch->current_height,
		   fmt_bitcoin_blkid(tmpctx, &bwatch->current_blockhash));

	/* Notify owners of any watch affected by losing this block before we
	 * tear it down, so they can roll back in the same order things happened. */
	bwatch_notify_reorg_watches(cmd, bwatch, bwatch->current_height);

	/* Delete block from datastore */
	bwatch_delete_block_from_datastore(cmd, bwatch->current_height);

	/* Remove last block from history */
	tal_resize(&bwatch->block_history, count - 1);

	/* Move tip back one */
	newtip = bwatch_last_block(bwatch);
	if (newtip) {
		assert(newtip->height == bwatch->current_height - 1);
		bwatch->current_height = newtip->height;
		bwatch->current_blockhash = newtip->hash;

		/* Tell watchman the tip rolled back so it persists the new height+hash.
		 * If we crash before the ack, watchman's stale height > bwatch's height
		 * on restart, which naturally retriggers the rollback via getwatchmanheight. */
		bwatch_send_revert_block_processed(cmd, bwatch->current_height,
						   &bwatch->current_blockhash);
	} else {
		/* History exhausted: we've rolled back past everything we stored.
		 * Set current_height to 0 so getwatchmanheight_done can reset it to
		 * watchman_height.  Don't notify watchman — it already knows its own
		 * height and we're about to resume from there via sequential polling. */
		bwatch->current_height = 0;
		memset(&bwatch->current_blockhash, 0, sizeof(bwatch->current_blockhash));
	}
}

/* Process or initialize from a block. */
static struct command_result *handle_block(struct command *cmd,
					   const char *method UNUSED,
					   const char *buf,
					   const jsmntok_t *result,
					   ptrint_t *block_heightptr)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	struct bitcoin_blkid blockhash;
	struct bitcoin_block *block;
	bool is_init = (bwatch->current_height == 0);
	u32 block_height = ptr2int(block_heightptr);

	block = block_from_response(buf, result, &blockhash);
	if (!block) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Failed to get/parse block %u: '%.*s'",
			   block_height,
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
		return poll_finished(cmd);
	}

	if (!is_init) {
		/* Verify the parent of the new block is our current tip; if
		 * not, we have a reorg.  Pop the tip and refetch the block
		 * until we find a common ancestor, then roll forward from
		 * there.  Skip when history is empty (rollback exhausted it). */
		if (tal_count(bwatch->block_history) > 0 &&
		    !bitcoin_blkid_eq(&block->hdr.prev_hash, &bwatch->current_blockhash)) {
			plugin_log(cmd->plugin, LOG_INFORM,
				   "Reorg detected at block %u: expected parent %s, got %s (fetched block hash: %s)",
				   block_height,
				   fmt_bitcoin_blkid(tmpctx, &bwatch->current_blockhash),
				   fmt_bitcoin_blkid(tmpctx, &block->hdr.prev_hash),
				   fmt_bitcoin_blkid(tmpctx, &blockhash));
			bwatch_remove_tip(cmd, bwatch);
			return fetch_block_handle(cmd, bwatch->current_height + 1);
		}

		/* Depth first: restart-marker watches (e.g. onchaind/
		 * channel_close) start subdaemons before outpoint watches
		 * fire for the same block. */
		bwatch_check_blockdepth_watches(cmd, bwatch, block_height);
		bwatch_process_block_txs(cmd, bwatch, block, block_height,
					 &blockhash, NULL);
	}

	/* Update state */
	bwatch->current_height = block_height;
	bwatch->current_blockhash = blockhash;

	/* Update in-memory history immediately */
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

/*
 * ============================================================================
 * RESCAN
 *
 * When a watch is added with start_block <= current_height, replay the
 * historical blocks for that one watch so it sees confirmations that
 * happened before it was registered.  Bounded by current_height so we
 * never race the live polling loop.
 *
 * Async chain: fetch_block_rescan -> rescan_block_done -> next fetch.
 * ============================================================================
 */

/* Fetch a single block by height during a rescan. */
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

/* Finish a rescan chain: RPC commands get a JSON result; aux/timer
 * commands just terminate. */
static struct command_result *rescan_complete(struct command *cmd)
{
	switch (cmd->type) {
	case COMMAND_TYPE_NORMAL:
	case COMMAND_TYPE_HOOK:
		return command_success(cmd, json_out_obj(cmd, NULL, NULL));
	case COMMAND_TYPE_AUX:
		return aux_command_done(cmd);
	case COMMAND_TYPE_NOTIFICATION:
	case COMMAND_TYPE_TIMER:
	case COMMAND_TYPE_CHECK:
	case COMMAND_TYPE_USAGE_ONLY:
		break;
	}
	abort();
}

/* getrawblockbyheight callback for one block of a rescan: process the
 * block, then either fetch the next or finish. */
static struct command_result *rescan_block_done(struct command *cmd,
						const char *method UNUSED,
						const char *buf,
						const jsmntok_t *result,
						struct rescan_state *rescan)
{
	struct bitcoin_blkid blockhash;
	struct bitcoin_block *block = block_from_response(buf, result, &blockhash);

	if (!block) {
		/* Chain may have rolled back past this height; stop quietly. */
		plugin_log(cmd->plugin, LOG_DBG,
			   "Rescan: block %u unavailable (chain rolled back?), stopping",
			   rescan->current_block);
		return rescan_complete(cmd);
	}

	/* rescan->watch is forwarded so the scanner only checks that one
	 * watch (or all watches when watch == NULL). */
	bwatch_process_block_txs(cmd, bwatch_of(cmd->plugin), block,
				 rescan->current_block, &blockhash, rescan->watch);

	/* Advance the cursor; if we still have blocks to scan, fetch the
	 * next one and chain back into rescan_block_done. */
	if (++rescan->current_block <= rescan->target_block)
		return fetch_block_rescan(cmd, rescan->current_block,
					  rescan_block_done, rescan);

	plugin_log(cmd->plugin, LOG_INFORM, "Rescan complete");
	return rescan_complete(cmd);
}

void bwatch_start_rescan(struct command *cmd,
			 const struct watch *w,
			 u32 start_block,
			 u32 target_block)
{
	struct rescan_state *rescan;

	if (w) {
		plugin_log(cmd->plugin, LOG_INFORM,
			   "Starting rescan for %s watch: blocks %u-%u",
			   bwatch_get_watch_type_name(w->type),
			   start_block, target_block);
	} else {
		plugin_log(cmd->plugin, LOG_INFORM,
			   "Starting rescan for all watches: blocks %u-%u",
			   start_block, target_block);
	}

	/* Owned by `cmd` so it lives across the async chain and gets
	 * freed automatically when the command completes. */
	rescan = tal(cmd, struct rescan_state);
	rescan->watch = w;
	rescan->current_block = start_block;
	rescan->target_block = target_block;

	/* Fire the first getrawblockbyheight; each response runs
	 * rescan_block_done, which fetches the next block until we
	 * pass target_block. */
	fetch_block_rescan(cmd, rescan->current_block,
			   rescan_block_done, rescan);
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

	/* Default to "no chain seen yet"; bwatch_load_block_history will
	 * overwrite these from the datastore when we're enabled. */
	bwatch->current_height = 0;
	memset(&bwatch->current_blockhash, 0, sizeof(bwatch->current_blockhash));

	/* bwatch is opt-in: leave the plugin loaded but skip chain polling until the
	 * user passes --experimental-bwatch. */
	if (!bwatch->experimental)
		return NULL;

	/* Replay persisted block history.  load_block_history sets
	 * current_height / current_blockhash from the most recent record;
	 * if there are no records, fall back to zero so the first poll
	 * initialises us at the chain tip. */
	bwatch_load_block_history(cmd, bwatch);
	bwatch_load_watches_from_datastore(cmd, bwatch);

	/* Send chaininfo to watchman first; the ack/err callbacks then
	 * kick off the chain-poll loop. */
	global_timer(cmd->plugin, time_from_sec(0),
		     bwatch_send_chaininfo, NULL);
	return NULL;
}

static const struct plugin_command commands[] = {
	{ "addscriptpubkeywatch", json_bwatch_add_scriptpubkey },
	{ "addoutpointwatch",     json_bwatch_add_outpoint     },
	{ "addscidwatch",         json_bwatch_add_scid         },
	{ "addblockdepthwatch",   json_bwatch_add_blockdepth   },
	{ "delscriptpubkeywatch", json_bwatch_del_scriptpubkey },
	{ "deloutpointwatch",     json_bwatch_del_outpoint     },
	{ "delscidwatch",         json_bwatch_del_scid         },
	{ "delblockdepthwatch",   json_bwatch_del_blockdepth   },
	{ "listwatch",            json_bwatch_list             },
};

int main(int argc, char *argv[])
{
	struct bwatch *bwatch;

	setup_locale();
	bwatch = tal(NULL, struct bwatch);
	bwatch->poll_interval_ms = 30000;
	bwatch->experimental = false;

	plugin_main(argv, init, take(bwatch), PLUGIN_RESTARTABLE, true, NULL,
		    commands, ARRAY_SIZE(commands),
		    NULL, 0,
		    NULL, 0,
		    NULL, 0,
		    plugin_option("experimental-bwatch", "flag",
				  "experimental: enable the bwatch chain"
				  " watcher (off by default)",
				  flag_option, flag_jsonfmt,
				  &bwatch->experimental),
		    plugin_option("bwatch-poll-interval", "int",
				  "Milliseconds between chain polls (default: 30000)",
				  u32_option, u32_jsonfmt, &bwatch->poll_interval_ms),
		    NULL);
}
