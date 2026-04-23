#include "config.h"
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/json_out/json_out.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_parse.h>
#include <common/mkdatastorekey.h>
#include <plugins/bwatch/bwatch_store.h>
#include <plugins/bwatch/bwatch_wiregen.h>

const struct scriptpubkey *scriptpubkey_watch_keyof(const struct watch *w)
{
	assert(w->type == WATCH_SCRIPTPUBKEY);
	return &w->key.scriptpubkey;
}

size_t scriptpubkey_hash(const struct scriptpubkey *scriptpubkey)
{
	return siphash24(siphash_seed(), scriptpubkey->script, scriptpubkey->len);
}

bool scriptpubkey_watch_eq(const struct watch *w, const struct scriptpubkey *scriptpubkey)
{
	return w->key.scriptpubkey.len == scriptpubkey->len &&
	       memeq(w->key.scriptpubkey.script, scriptpubkey->len,
		     scriptpubkey->script, scriptpubkey->len);
}

const struct bitcoin_outpoint *outpoint_watch_keyof(const struct watch *w)
{
	assert(w->type == WATCH_OUTPOINT);
	return &w->key.outpoint;
}

size_t outpoint_hash(const struct bitcoin_outpoint *outpoint)
{
	size_t h1 = siphash24(siphash_seed(), &outpoint->txid, sizeof(outpoint->txid));
	size_t h2 = siphash24(siphash_seed(), &outpoint->n, sizeof(outpoint->n));
	return h1 ^ h2;
}

bool outpoint_watch_eq(const struct watch *w, const struct bitcoin_outpoint *outpoint)
{
	return bitcoin_outpoint_eq(&w->key.outpoint, outpoint);
}

const struct short_channel_id *scid_watch_keyof(const struct watch *w)
{
	assert(w->type == WATCH_SCID);
	return &w->key.scid;
}

size_t scid_hash(const struct short_channel_id *scid)
{
	return siphash24(siphash_seed(), scid, sizeof(*scid));
}

bool scid_watch_eq(const struct watch *w, const struct short_channel_id *scid)
{
	return short_channel_id_eq(w->key.scid, *scid);
}

const u32 *blockdepth_watch_keyof(const struct watch *w)
{
	assert(w->type == WATCH_BLOCKDEPTH);
	return &w->start_block;
}

size_t u32_hash(const u32 *height)
{
	return siphash24(siphash_seed(), height, sizeof(*height));
}

bool blockdepth_watch_eq(const struct watch *w, const u32 *height)
{
	return w->start_block == *height;
}

const char *bwatch_get_watch_type_name(enum watch_type type)
{
	switch (type) {
	case WATCH_SCRIPTPUBKEY:
		return "scriptpubkey";
	case WATCH_OUTPOINT:
		return "outpoint";
	case WATCH_SCID:
		return "scid";
	case WATCH_BLOCKDEPTH:
		return "blockdepth";
	}
	abort();
}

void bwatch_add_watch_to_hash(struct bwatch *bwatch, struct watch *w)
{
	switch (w->type) {
	case WATCH_SCRIPTPUBKEY:
		scriptpubkey_watches_add(bwatch->scriptpubkey_watches, w);
		return;
	case WATCH_OUTPOINT:
		outpoint_watches_add(bwatch->outpoint_watches, w);
		return;
	case WATCH_SCID:
		scid_watches_add(bwatch->scid_watches, w);
		return;
	case WATCH_BLOCKDEPTH:
		blockdepth_watches_add(bwatch->blockdepth_watches, w);
		return;
	}
	abort();
}

struct watch *bwatch_get_watch(struct bwatch *bwatch,
			       enum watch_type type,
			       const struct bitcoin_outpoint *outpoint,
			       const u8 *scriptpubkey,
			       const struct short_channel_id *scid,
			       const u32 *confirm_height)
{
	switch (type) {
	case WATCH_SCRIPTPUBKEY: {
		struct scriptpubkey k = {
			.script = scriptpubkey,
			.len = tal_bytelen(scriptpubkey),
		};
		return scriptpubkey_watches_get(bwatch->scriptpubkey_watches, &k);
	}
	case WATCH_OUTPOINT:
		return outpoint_watches_get(bwatch->outpoint_watches, outpoint);
	case WATCH_SCID:
		return scid_watches_get(bwatch->scid_watches, scid);
	case WATCH_BLOCKDEPTH:
		return blockdepth_watches_get(bwatch->blockdepth_watches, confirm_height);
	}
	abort();
}

void bwatch_remove_watch_from_hash(struct bwatch *bwatch, struct watch *w)
{
	switch (w->type) {
	case WATCH_SCRIPTPUBKEY:
		scriptpubkey_watches_del(bwatch->scriptpubkey_watches, w);
		return;
	case WATCH_OUTPOINT:
		outpoint_watches_del(bwatch->outpoint_watches, w);
		return;
	case WATCH_SCID:
		scid_watches_del(bwatch->scid_watches, w);
		return;
	case WATCH_BLOCKDEPTH:
		blockdepth_watches_del(bwatch->blockdepth_watches, w);
		return;
	}
	abort();
}

/* List all datastore entries under a key prefix (up to 2 components).
 * Shared between block_history loading and (in a follow-up commit)
 * watch loading. */
static const jsmntok_t *bwatch_list_datastore(const tal_t *ctx,
					      struct command *cmd,
					      const char *key1, const char *key2,
					      const char **buf_out)
{
	struct json_out *params = json_out_new(tmpctx);
	const jsmntok_t *result;

	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	json_out_addstr(params, NULL, key1);
	if (key2)
		json_out_addstr(params, NULL, key2);
	json_out_end(params, ']');
	json_out_end(params, '}');

	result = jsonrpc_request_sync(ctx, cmd, "listdatastore", params, buf_out);
	return json_get_member(*buf_out, result, "datastore");
}

/* Datastore write completed (success or expected failure such as duplicate).
 * Either way, invoke the caller's continuation to keep the poll chain alive. */
static struct command_result *block_store_done(struct command *cmd,
					       const char *method UNNEEDED,
					       const char *buf UNNEEDED,
					       const jsmntok_t *result UNNEEDED,
					       struct command_result *(*done)(struct command *))
{
	return done(cmd);
}

struct command_result *bwatch_add_block_to_datastore(
	struct command *cmd,
	const struct block_record_wire *br,
	struct command_result *(*done)(struct command *cmd))
{
	/* Zero-pad to 10 digits so listdatastore returns blocks in height
	 * order ("0000000100" < "0000000101"). */
	const char **key = mkdatastorekey(tmpctx, "bwatch", "block_history",
					  take(tal_fmt(NULL, "%010u", br->height)));
	const u8 *data = towire_bwatch_block(tmpctx, br);

	plugin_log(cmd->plugin, LOG_DBG, "Added block %u to datastore", br->height);

	/* Chain `done` as both success and failure continuation so the poll
	 * cmd is held alive until the write is acknowledged. Write failure
	 * (e.g. duplicate on restart) is non-fatal — the poll must continue. */
	return jsonrpc_set_datastore_binary(cmd, key,
					    data, tal_bytelen(data),
					    "must-create",
					    block_store_done, block_store_done,
					    done);
}

void bwatch_add_block_to_history(struct bwatch *bwatch, u32 height,
				 const struct bitcoin_blkid *hash,
				 const struct bitcoin_blkid *prev_hash)
{
	struct block_record_wire br;

	br.height = height;
	br.hash = *hash;
	br.prev_hash = *prev_hash;
	tal_arr_expand(&bwatch->block_history, br);

	plugin_log(bwatch->plugin, LOG_DBG,
		   "Added block %u to history (now %zu blocks)",
		   height, tal_count(bwatch->block_history));
}

void bwatch_delete_block_from_datastore(struct command *cmd, u32 height)
{
	struct json_out *params = json_out_new(tmpctx);
	const char *buf;

	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	json_out_addstr(params, NULL, "bwatch");
	json_out_addstr(params, NULL, "block_history");
	json_out_addstr(params, NULL, tal_fmt(tmpctx, "%010u", height));
	json_out_end(params, ']');
	json_out_end(params, '}');

	jsonrpc_request_sync(tmpctx, cmd, "deldatastore", params, &buf);

	plugin_log(cmd->plugin, LOG_DBG, "Deleted block %u from datastore", height);
}

const struct block_record_wire *bwatch_last_block(const struct bwatch *bwatch)
{
	if (tal_count(bwatch->block_history) == 0)
		return NULL;

	return &bwatch->block_history[tal_count(bwatch->block_history) - 1];
}

void bwatch_load_block_history(struct command *cmd, struct bwatch *bwatch)
{
	const char *buf;
	const jsmntok_t *datastore, *t;
	size_t i;
	const struct block_record_wire *most_recent;

	datastore = bwatch_list_datastore(tmpctx, cmd, "bwatch", "block_history", &buf);

	json_for_each_arr(i, t, datastore) {
		const u8 *data = json_tok_bin_from_hex(tmpctx, buf,
						       json_get_member(buf, t, "hex"));
		struct block_record_wire br;

		if (!data)
			plugin_err(cmd->plugin,
				   "Bad block_history hex %.*s",
				   json_tok_full_len(t),
				   json_tok_full(buf, t));

		if (!fromwire_bwatch_block(data, &br)) {
			plugin_err(cmd->plugin,
				   "Bad block_history %.*s",
				   json_tok_full_len(t),
				   json_tok_full(buf, t));
		}
		tal_arr_expand(&bwatch->block_history, br);
	}

	most_recent = bwatch_last_block(bwatch);
	if (most_recent) {
		bwatch->current_height = most_recent->height;
		bwatch->current_blockhash = most_recent->hash;
		plugin_log(cmd->plugin, LOG_DBG,
			   "Restored %zu blocks from datastore, current height=%u",
			   tal_count(bwatch->block_history),
			   bwatch->current_height);
	} else {
		bwatch->current_height = 0;
		memset(&bwatch->current_blockhash, 0,
		       sizeof(bwatch->current_blockhash));
	}
}
