#include "config.h"
#include <bitcoin/block.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/json_out/json_out.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_parse.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/mkdatastorekey.h>
#include <common/wireaddr.h>
#include <plugins/bwatch/bwatch_wiregen.h>
#include <plugins/libplugin.h>
#include <wire/wire.h>

/*
 * ============================================================================
 * IN-MEMORY DATA STRUCTURES
 * Wire structs are used ONLY for serialization/deserialization.
 * ============================================================================
 */

/* Watch type enumeration */
enum watch_type {
	WATCH_SCRIPTPUBKEY,
	WATCH_OUTPOINT,
	WATCH_TXID
};

/* Scriptpubkey wrapper for easier handling */
struct scriptpubkey {
	const u8 *script;
	size_t len;
};

/* Watch structure */
struct watch {
	enum watch_type type;
	u32 start_block;  /* Block height to start watching from */
	wirestring **owners;  /* tal_arr of owner identifiers */
	union {
		struct scriptpubkey scriptpubkey;
		struct bitcoin_outpoint outpoint;
		struct bitcoin_txid txid;
	} key;
};

/* Hash table key functions for scriptpubkey watches */
static const struct scriptpubkey *scriptpubkey_watch_keyof(const struct watch *w)
{
	assert(w->type == WATCH_SCRIPTPUBKEY);
	return &w->key.scriptpubkey;
}

static size_t scriptpubkey_hash(const struct scriptpubkey *scriptpubkey)
{
	return siphash24(siphash_seed(), scriptpubkey->script, scriptpubkey->len);
}

static bool scriptpubkey_watch_eq(const struct watch *w, const struct scriptpubkey *scriptpubkey)
{
	return w->key.scriptpubkey.len == scriptpubkey->len &&
	       memeq(w->key.scriptpubkey.script, scriptpubkey->len, scriptpubkey->script, scriptpubkey->len);
}

HTABLE_DEFINE_NODUPS_TYPE(struct watch, scriptpubkey_watch_keyof,
			  scriptpubkey_hash, scriptpubkey_watch_eq,
			  scriptpubkey_watch_hash);

/* Hash table key functions for outpoint watches */
static const struct bitcoin_outpoint *outpoint_watch_keyof(const struct watch *w)
{
	assert(w->type == WATCH_OUTPOINT);
	return &w->key.outpoint;
}

static size_t outpoint_hash(const struct bitcoin_outpoint *outpoint)
{
	size_t h1 = siphash24(siphash_seed(), &outpoint->txid, sizeof(outpoint->txid));
	size_t h2 = siphash24(siphash_seed(), &outpoint->n, sizeof(outpoint->n));
	return h1 ^ h2;
}

static bool outpoint_watch_eq(const struct watch *w, const struct bitcoin_outpoint *outpoint)
{
	return bitcoin_outpoint_eq(&w->key.outpoint, outpoint);
}

HTABLE_DEFINE_NODUPS_TYPE(struct watch, outpoint_watch_keyof,
			  outpoint_hash, outpoint_watch_eq,
			  outpoint_watch_hash);

/* Hash table key functions for txid watches */
static const struct bitcoin_txid *txid_watch_keyof(const struct watch *w)
{
	assert(w->type == WATCH_TXID);
	return &w->key.txid;
}

static size_t txid_hash(const struct bitcoin_txid *txid)
{
	return siphash24(siphash_seed(),
			 txid->shad.sha.u.u8, sizeof(txid->shad.sha.u.u8));
}

static bool txid_watch_eq(const struct watch *w, const struct bitcoin_txid *txid)
{
	return bitcoin_txid_eq(&w->key.txid, txid);
}

HTABLE_DEFINE_NODUPS_TYPE(struct watch, txid_watch_keyof, txid_hash,
			  txid_watch_eq, txid_watch_hash);

/* Global plugin state */
struct bwatch {
	struct plugin *plugin;		/* Back pointer to plugin */

	/* Watch hash tables (one per type) */
	struct scriptpubkey_watch_hash *scriptpubkey_watches;
	struct outpoint_watch_hash *outpoint_watches;
	struct txid_watch_hash *txid_watches;

	/* Chain tracking */
	u32 current_height;
	struct bitcoin_blkid current_blockhash;
	struct block_record_wire **block_history;	/* Oldest first, most recent last */

	/* Polling */
	u32 poll_interval;
	struct plugin_timer *poll_timer;
};

/* Rescan state for catching up on historical blocks */
struct rescan_state {
	const struct watch *watch;	/* NULL = rescan all watches, non-NULL = single watch */
	u32 current_block;		/* Next block to fetch */
	u32 target_block;		/* Stop after this block */
};

static struct bwatch *bwatch_of(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct bwatch);
}

/*
 * ============================================================================
 * DATASTORE OPERATIONS:
 * Individual items are stored at specific keys for efficient updates.
 *
 * STORAGE KEYS:
 * - bwatch/block_history/<height> - individual block records
 * - bwatch/{watch_type}/<key> - individual watches
 * - bwatch/pending_events/<event_id> - individual pending events
 * ============================================================================
 */

/* Helper to list datastore entries under a key path */
static const jsmntok_t *list_datastore(const tal_t *ctx,
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

/* ==== BLOCK HISTORY DATASTORE OPERATIONS ==== */

/* Add a single block to the datastore */
static void add_block_to_datastore(struct command *cmd, const struct block_record_wire *br)
{
	/* Zero-pad to 10 digits for lexicographic sorting: ensures keys sort
	 * numerically by height (e.g., "0000000100" < "0000000101") */
	const char **key = mkdatastorekey(tmpctx, "bwatch", "block_history",
					  take(tal_fmt(NULL, "%010u", br->height)));
	const u8 *data = towire_bwatch_block(tmpctx, br);

	jsonrpc_set_datastore_binary(cmd, key,
				     data, tal_bytelen(data),
				     "must-create",
				     NULL, NULL, NULL);

	plugin_log(cmd->plugin, LOG_DBG, "Added block %u to datastore", br->height);
}

/* Add a block to the history (append, oldest first, most recent last) */
static void add_block_to_history(struct bwatch *bwatch, u32 height,
				 const struct bitcoin_blkid *hash,
				 const struct bitcoin_blkid *prev_hash)
{
	struct block_record_wire *br = tal(bwatch, struct block_record_wire);

	br->height = height;
	br->hash = *hash;
	br->prev_hash = *prev_hash;

	tal_arr_expand(&bwatch->block_history, br);

	plugin_log(bwatch->plugin, LOG_DBG, "Added block %u to history (now %zu blocks)",
		   height, tal_count(bwatch->block_history));
}

/* Delete a single block from datastore */
static void delete_block_from_datastore(struct command *cmd, u32 height)
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

	/* Use synchronous delete to avoid race with subsequent add */
	jsonrpc_request_sync(tmpctx, cmd, "deldatastore", params, &buf);

	plugin_log(cmd->plugin, LOG_DBG, "Deleted block %u from datastore", height);
}

/* Load block history from datastore on startup */
static void load_block_history(struct command *cmd, struct bwatch *bwatch)
{
	const char *buf;
	const jsmntok_t *datastore, *t;
	size_t i;

	datastore = list_datastore(tmpctx, cmd, "bwatch", "block_history", &buf);

	json_for_each_arr(i, t, datastore) {
		const u8 *data = json_tok_bin_from_hex(tmpctx, buf,
						       json_get_member(buf, t, "hex"));
		if (!data)
			plugin_err(cmd->plugin,
				   "Bad block_history hex %.*s",
				   json_tok_full_len(t),
				   json_tok_full(buf, t));

		struct block_record_wire *br = tal(bwatch, struct block_record_wire);
		if (!fromwire_bwatch_block(data, br)) {
			plugin_err(cmd->plugin,
				   "Bad block_history %.*s",
				   json_tok_full_len(t),
				   json_tok_full(buf, t));
		}

		tal_arr_expand(&bwatch->block_history, br);
	}

	/* Datastore returns keys in lexicographic order, and we zero-pad heights,
	 * so blocks are already in ascending order (oldest first). */
	if (tal_count(bwatch->block_history) > 0) {
		size_t count = tal_count(bwatch->block_history);
		struct block_record_wire *most_recent = bwatch->block_history[count - 1];

		bwatch->current_height = most_recent->height;
		bwatch->current_blockhash = most_recent->hash;
		plugin_log(cmd->plugin, LOG_DBG,
			   "Restored %zu blocks from datastore, current height=%u",
			   count, bwatch->current_height);
	}
}

/* ==== WATCH DATASTORE OPERATIONS ==== */

/* Get the watch type subdirectory name */
static const char *get_watch_type_name(enum watch_type type)
{
	switch (type) {
	case WATCH_SCRIPTPUBKEY:
		return "scriptpubkey_watches";
	case WATCH_OUTPOINT:
		return "outpoint_watches";
	case WATCH_TXID:
		return "txid_watches";
	}
	abort();
}

/* Get datastore key for a watch */
static const char **get_watch_datastore_key(const tal_t *ctx, const struct watch *w)
{
	const char *type_name = get_watch_type_name(w->type);

	switch (w->type) {
	case WATCH_SCRIPTPUBKEY: {
		char *hex = tal_hexstr(ctx, w->key.scriptpubkey.script, w->key.scriptpubkey.len);
		return mkdatastorekey(ctx, "bwatch", type_name, hex);
	}
	case WATCH_OUTPOINT:
		return mkdatastorekey(ctx, "bwatch", type_name,
				      take(fmt_bitcoin_outpoint(NULL, &w->key.outpoint)));
	case WATCH_TXID:
		return mkdatastorekey(ctx, "bwatch", type_name,
				      take(fmt_bitcoin_txid(NULL, &w->key.txid)));
	}
	abort();
}

/* Datastore operation finished, but we're not the one to complete the command. */
static struct command_result *datastore_done(struct command *cmd,
					     const char *method,
					     const char *buf,
					     const jsmntok_t *result,
					     void *arg)
{
	return command_still_pending(cmd);
}

/*
 * ============================================================================
 * CONVERSION FUNCTIONS: in-memory <-> wire
 * Wire structs are used ONLY for serialization/deserialization.
 * ============================================================================
 */

/* Convert in-memory watch to wire format for persistence */
static struct watch_wire *watch_to_wire(const tal_t *ctx, const struct watch *w)
{
	struct watch_wire *wire = tal(ctx, struct watch_wire);

	wire->type = w->type;
	wire->start_block = w->start_block;

	/* Initialize all key fields */
	wire->scriptpubkey = NULL;
	memset(&wire->outpoint, 0, sizeof(wire->outpoint));
	memset(&wire->txid, 0, sizeof(wire->txid));

	/* Copy the relevant key field based on type */
	switch (w->type) {
	case WATCH_SCRIPTPUBKEY:
		wire->scriptpubkey = tal_dup_arr(wire, u8, w->key.scriptpubkey.script, w->key.scriptpubkey.len, 0);
		break;
	case WATCH_OUTPOINT:
		wire->outpoint = w->key.outpoint;
		break;
	case WATCH_TXID:
		wire->txid = w->key.txid;
		break;
	}

	/* Copy owners array */
	size_t num_owners = tal_count(w->owners);
	wire->owners = tal_arr(wire, wirestring *, num_owners);
	for (size_t i = 0; i < num_owners; i++)
		wire->owners[i] = tal_strdup(wire->owners, w->owners[i]);

	return wire;
}

/* Convert wire format to in-memory watch */
static struct watch *watch_from_wire(const tal_t *ctx, const struct watch_wire *wire)
{
	struct watch *w = tal(ctx, struct watch);

	w->type = wire->type;
	w->start_block = wire->start_block;

	/* Copy the relevant key field based on type */
	switch (wire->type) {
	case WATCH_SCRIPTPUBKEY:
		w->key.scriptpubkey.len = tal_bytelen(wire->scriptpubkey);
		w->key.scriptpubkey.script = tal_dup_arr(w, u8, wire->scriptpubkey, w->key.scriptpubkey.len, 0);
		break;
	case WATCH_OUTPOINT:
		w->key.outpoint = wire->outpoint;
		break;
	case WATCH_TXID:
		w->key.txid = wire->txid;
		break;
	}

	/* Copy owners array */
	size_t num_owners = tal_count(wire->owners);
	w->owners = tal_arr(w, wirestring *, num_owners);
	for (size_t i = 0; i < num_owners; i++)
		w->owners[i] = tal_strdup(w->owners, wire->owners[i]);

	return w;
}

/* ==== HASH TABLE OPERATIONS ==== */

/* Add watch to appropriate hash table */
static void add_watch_to_hash(struct bwatch *bwatch, struct watch *w)
{
	switch (w->type) {
	case WATCH_SCRIPTPUBKEY:
		scriptpubkey_watch_hash_add(bwatch->scriptpubkey_watches, w);
		break;
	case WATCH_OUTPOINT:
		outpoint_watch_hash_add(bwatch->outpoint_watches, w);
		break;
	case WATCH_TXID:
		txid_watch_hash_add(bwatch->txid_watches, w);
		break;
	}
}

/* Get a watch from the appropriate hash table by key */
static struct watch *get_watch(struct bwatch *bwatch,
			       enum watch_type type,
			       /* Exactly one of these three is non-NULL */
			       const struct bitcoin_outpoint *outpoint,
			       const u8 *scriptpubkey,
			       const struct bitcoin_txid *txid)
{
	switch (type) {
	case WATCH_SCRIPTPUBKEY: {
		struct scriptpubkey k = {
			.script = scriptpubkey,
			.len = tal_bytelen(scriptpubkey),
		};
		return scriptpubkey_watch_hash_get(bwatch->scriptpubkey_watches, &k);
	}
	case WATCH_OUTPOINT:
		return outpoint_watch_hash_get(bwatch->outpoint_watches, outpoint);
	case WATCH_TXID:
		return txid_watch_hash_get(bwatch->txid_watches, txid);
	}
	abort();
}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
/* Remove a watch from its hash table */
static void remove_watch_from_hash(struct bwatch *bwatch, struct watch *w)
{
	switch (w->type) {
	case WATCH_SCRIPTPUBKEY:
		scriptpubkey_watch_hash_del(bwatch->scriptpubkey_watches, w);
		return;
	case WATCH_OUTPOINT:
		outpoint_watch_hash_del(bwatch->outpoint_watches, w);
		return;
	case WATCH_TXID:
		txid_watch_hash_del(bwatch->txid_watches, w);
		return;
	}
	abort();
}

/* Load watches from datastore by type */
static void load_watches_by_type(struct command *cmd, struct bwatch *bwatch,
				 enum watch_type type)
{
	const char *watch_type_name = get_watch_type_name(type);
	const char *buf;
	const jsmntok_t *datastore, *t;
	size_t i, count = 0;

	datastore = list_datastore(tmpctx, cmd, "bwatch", watch_type_name, &buf);

	json_for_each_arr(i, t, datastore) {
		const u8 *data = json_tok_bin_from_hex(tmpctx, buf,
						       json_get_member(buf, t, "hex"));
		if (!data)
			continue;

		struct watch_wire *wire;
		if (!fromwire_bwatch_watch(tmpctx, data, &wire))
			continue;

		struct watch *w = watch_from_wire(bwatch, wire);
		if (!w || w->type != type)
			continue;

		add_watch_to_hash(bwatch, w);
		count++;
	}

	plugin_log(cmd->plugin, LOG_DBG, "Restored %zu %s from datastore",
		   count, watch_type_name);
}

/* Save watch to datastore (converts to wire format) */
static void save_watch_to_datastore(struct command *cmd, const struct watch *w)
{
	const u8 *data = towire_bwatch_watch(tmpctx, watch_to_wire(tmpctx, w));

	jsonrpc_set_datastore_binary(cmd, get_watch_datastore_key(tmpctx, w),
				     data, tal_bytelen(data),
				     "create-or-replace",
				     datastore_done, datastore_done, NULL);

	plugin_log(cmd->plugin, LOG_DBG, "Saved watch to datastore (type=%d, num_owners=%zu)",
		   w->type, tal_count(w->owners));
}

/* Simple callback for async deldatastore (watches) - handles both success and error */
static struct command_result *deldatastore_done(struct command *cmd,
						const char *method UNUSED,
						const char *buf UNUSED,
						const jsmntok_t *result UNUSED,
						void *arg UNUSED)
{
	return command_still_pending(cmd);
}

/* Delete a watch from datastore */
static void delete_watch_from_datastore(struct command *cmd, const struct watch *w)
{
	const char **key = get_watch_datastore_key(tmpctx, w);
	struct out_req *req = jsonrpc_request_start(cmd, "deldatastore",
						    deldatastore_done,
						    deldatastore_done,
						    NULL);
	json_add_keypath(req->js->jout, "key", key);
	send_outreq(req);

	plugin_log(cmd->plugin, LOG_DBG,
		   "Deleting watch from datastore: ...%s", key[tal_count(key)-1]);
}

/*
 * ============================================================================
 * BLOCK PROCESSING: Polling
 * ============================================================================
 */

/* ==== BLOCK FETCHING AND PARSING ==== */

/* Forward declarations */
static void send_block_processed(struct command *cmd, u32 blockheight);

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

/* Forward declarations for chain polling */
static struct command_result *poll_chain(struct command *cmd, void *unused);

/* Reschedule the timer and complete */
static struct command_result *poll_finished(struct command *cmd)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);

	plugin_log(cmd->plugin, LOG_DBG, "Rescheduling poll timer (current_height=%u)",
		   bwatch->current_height);
	bwatch->poll_timer = global_timer(cmd->plugin, time_from_sec(bwatch->poll_interval),
					   poll_chain, NULL);
	return timer_complete(cmd);
}

/* Remove tip block on reorg, update to the new chain's hash for the previous block */
static void remove_tip(struct command *cmd, struct bwatch *bwatch)
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
	delete_block_from_datastore(cmd, bwatch->current_height);

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

/*
 * ============================================================================
 * TRANSACTION WATCH CHECKING
 * ============================================================================
 */

/* Send watch_found notification to lightningd
 * @txindex: position of tx in the block (0 = coinbase)
 * @outnum: for scriptpubkey watches, which output matched
 * @innum: for outpoint watches, which input matched
 */
static void json_watch_found(struct command *cmd,
			     const struct bitcoin_tx *tx,
			     u32 blockheight,
			     const struct watch *w,
			     u32 txindex,
			     u32 outnum,
			     u32 innum)
{
	struct json_stream *js;
	const char *tx_hex = fmt_bitcoin_tx(tmpctx, tx);

	js = plugin_notification_start(tmpctx, "watch_found");
	json_add_string(js, "tx", tx_hex);
	json_add_u32(js, "blockheight", blockheight);
	json_add_u32(js, "txindex", txindex);

	/* Add type and corresponding field */
	switch (w->type) {
	case WATCH_TXID:
		json_add_string(js, "type", "txid");
		json_add_txid(js, "txid", &w->key.txid);
		assert(outnum == UINT32_MAX);
		assert(innum == UINT32_MAX);
		break;
	case WATCH_SCRIPTPUBKEY:
		json_add_string(js, "type", "scriptpubkey");
		json_add_hex(js, "scriptpubkey", w->key.scriptpubkey.script,
			     w->key.scriptpubkey.len);
		assert(outnum != UINT32_MAX);
		assert(innum == UINT32_MAX);
		json_add_u32(js, "outnum", outnum);
		break;
	case WATCH_OUTPOINT:
		json_add_string(js, "type", "outpoint");
		json_add_outpoint(js, "outpoint", &w->key.outpoint);
		assert(outnum == UINT32_MAX);
		assert(innum != UINT32_MAX);
		json_add_u32(js, "innum", innum);
		break;
	}

	/* Add owners array */
	json_array_start(js, "owners");
	for (size_t i = 0; i < tal_count(w->owners); i++)
		json_add_string(js, NULL, w->owners[i]);
	json_array_end(js);

	plugin_notification_end(cmd->plugin, js);
}

/* Check all txid watches via hash lookup */
static void check_txid_watches(struct command *cmd,
			       struct bwatch *bwatch,
			       const struct bitcoin_tx *tx,
			       u32 blockheight,
			       const struct bitcoin_blkid *blockhash,
			       u32 txindex)
{
	struct bitcoin_txid txid;
	struct watch *w;

	bitcoin_txid(tx, &txid);
	w = txid_watch_hash_get(bwatch->txid_watches, &txid);
	if (!w)
		return;

	if (blockheight < w->start_block) {
		plugin_log(cmd->plugin, LOG_BROKEN,
			   "Watch for txid %s on height >= %u found on block %u???",
			   fmt_bitcoin_txid(tmpctx, &txid),
			   w->start_block, blockheight);
		return;
	}
	json_watch_found(cmd, tx, blockheight, w, txindex, UINT32_MAX, UINT32_MAX);
}

/* Check all scriptpubkey watches via hash lookup */
static void check_scriptpubkey_watches(struct command *cmd,
				       struct bwatch *bwatch,
				       const struct bitcoin_tx *tx,
				       u32 blockheight,
				       const struct bitcoin_blkid *blockhash,
				       u32 txindex)
{
	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		struct watch *w;
		struct scriptpubkey k = {
			.script = tx->wtx->outputs[i].script,
			.len = tx->wtx->outputs[i].script_len
		};

		w = scriptpubkey_watch_hash_get(bwatch->scriptpubkey_watches, &k);
		if (!w)
			continue;
		if (blockheight < w->start_block) {
			plugin_log(cmd->plugin, LOG_BROKEN,
				   "Watch for script %s on height >= %u found on block %u???",
				   tal_hexstr(tmpctx, k.script, k.len),
				   w->start_block, blockheight);
			continue;
		}
		json_watch_found(cmd, tx, blockheight, w, txindex, i, UINT32_MAX);
	}
}

/* Check all outpoint watches via hash lookup */
static void check_outpoint_watches(struct command *cmd,
				   struct bwatch *bwatch,
				   const struct bitcoin_tx *tx,
				   u32 blockheight,
				   const struct bitcoin_blkid *blockhash,
				   u32 txindex)
{
	for (size_t i = 0; i < tx->wtx->num_inputs; i++) {
		struct watch *w;
		struct bitcoin_outpoint outpoint;

		bitcoin_tx_input_get_txid(tx, i, &outpoint.txid);
		outpoint.n = tx->wtx->inputs[i].index;

		w = outpoint_watch_hash_get(bwatch->outpoint_watches, &outpoint);
		if (!w)
			continue;
		if (blockheight < w->start_block) {
			plugin_log(cmd->plugin, LOG_BROKEN,
				   "Watch for outpoint %s on height >= %u found on block %u???",
				   fmt_bitcoin_outpoint(tmpctx, &outpoint),
				   w->start_block, blockheight);
			continue;
		}
		json_watch_found(cmd, tx, blockheight, w, txindex, UINT32_MAX, i);
	}
}

/* Check a tx against all watches (during normal block processing) */
static void check_tx_against_all_watches(struct command *cmd,
					 struct bwatch *bwatch,
					 const struct bitcoin_tx *tx,
					 u32 blockheight,
					 const struct bitcoin_blkid *blockhash,
					 u32 txindex)
{
	check_txid_watches(cmd, bwatch, tx, blockheight, blockhash, txindex);
	check_scriptpubkey_watches(cmd, bwatch, tx, blockheight, blockhash, txindex);
	check_outpoint_watches(cmd, bwatch, tx, blockheight, blockhash, txindex);
}

/* Check tx against a specific txid */
static void check_tx_txid(struct command *cmd,
			  const struct bitcoin_tx *tx,
			  const struct bitcoin_txid *tx_txid,
			  const struct watch *w,
			  u32 blockheight,
			  const struct bitcoin_blkid *blockhash,
			  u32 txindex)
{
	if (bitcoin_txid_eq(tx_txid, &w->key.txid))
		json_watch_found(cmd, tx, blockheight, w, txindex, UINT32_MAX, UINT32_MAX);
}

/* Check tx outputs against a specific scriptpubkey */
static void check_tx_scriptpubkey(struct command *cmd,
				  const struct bitcoin_tx *tx,
				  const struct watch *w,
				  u32 blockheight,
				  const struct bitcoin_blkid *blockhash,
				  u32 txindex)
{
	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		if (memeq(tx->wtx->outputs[i].script, tx->wtx->outputs[i].script_len,
			  w->key.scriptpubkey.script, w->key.scriptpubkey.len)) {
			json_watch_found(cmd, tx, blockheight, w, txindex, i, UINT32_MAX);
			/* Don't return - tx might have multiple outputs to same scriptpubkey */
		}
	}
}

/* Check tx inputs against a specific outpoint */
static void check_tx_outpoint(struct command *cmd,
			      const struct bitcoin_tx *tx,
			      const struct watch *w,
			      u32 blockheight,
			      const struct bitcoin_blkid *blockhash,
			      u32 txindex)
{
	for (size_t i = 0; i < tx->wtx->num_inputs; i++) {
		struct bitcoin_outpoint outpoint;

		bitcoin_tx_input_get_txid(tx, i, &outpoint.txid);
		outpoint.n = tx->wtx->inputs[i].index;

		if (bitcoin_outpoint_eq(&outpoint, &w->key.outpoint)) {
			json_watch_found(cmd, tx, blockheight, w, txindex, UINT32_MAX, i);
			return; /* An outpoint can only be spent once */
		}
	}
}

/* Check a tx against a single watch key (during rescan) */
static void check_tx_for_single_watch(struct command *cmd,
				      const struct watch *w,
				      const struct bitcoin_tx *tx,
				      u32 blockheight,
				      const struct bitcoin_blkid *blockhash,
				      u32 txindex)
{
	struct bitcoin_txid txid;

	switch (w->type) {
	case WATCH_TXID:
		bitcoin_txid(tx, &txid);
		check_tx_txid(cmd, tx, &txid, w, blockheight, blockhash, txindex);
		break;
	case WATCH_SCRIPTPUBKEY:
		check_tx_scriptpubkey(cmd, tx, w, blockheight, blockhash, txindex);
		break;
	case WATCH_OUTPOINT:
		check_tx_outpoint(cmd, tx, w, blockheight, blockhash, txindex);
		break;
	}
}

/* Process all transactions in a block against watches.
 * If w is NULL, checks all watches (normal polling).
 * If w is non-NULL, checks only that specific watch (rescan). */
static void process_block_txs(struct command *cmd,
			      struct bwatch *bwatch,
			      const struct bitcoin_block *block,
			      u32 blockheight,
			      const struct bitcoin_blkid *blockhash,
			      const struct watch *w)
{
	for (size_t i = 0; i < tal_count(block->tx); i++) {
		if (w)
			check_tx_for_single_watch(cmd, w, block->tx[i],
						  blockheight, blockhash, i);
		else
			check_tx_against_all_watches(cmd, bwatch, block->tx[i],
						      blockheight, blockhash, i);
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
			remove_tip(cmd, bwatch);
			/* Retry from new current height + 1 */
			*block_height = bwatch->current_height + 1;
			return fetch_block_handle(cmd, *block_height, handle_block, block_height);
		}

		/* Good block, process watches */
		process_block_txs(cmd, bwatch, block, *block_height, &blockhash, NULL);
	}

	/* Update state */
	bwatch->current_height = *block_height;
	bwatch->current_blockhash = blockhash;

	/* Persist to datastore, then update in-memory history */
	struct block_record_wire br = { *block_height, blockhash, block->hdr.prev_hash };
	add_block_to_datastore(cmd, &br);
	add_block_to_history(bwatch, *block_height, &blockhash, &block->hdr.prev_hash);

	/* Notify watchman that we've processed this block */
	send_block_processed(cmd, *block_height);

	/* Schedule immediate re-poll to check if there are more blocks */
	bwatch->poll_timer = global_timer(cmd->plugin, time_from_sec(0), poll_chain, NULL);
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

	plugin_log(cmd->plugin, LOG_DBG, "getchaininfo_done: current_height=%u", bwatch->current_height);

	/* Parse the response */

	/* Extract block height */
	err = json_scan(tmpctx, buf, result,
			"{blockcount:%}",
			JSON_SCAN(json_to_number, &blockheight));
	if (err) {
		plugin_log(cmd->plugin, LOG_BROKEN, "getchaininfo parse failed for '%.*s': %s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result),
			   err);
		return poll_finished(cmd);
	}

	plugin_log(cmd->plugin, LOG_DBG, "Parsed getchaininfo: blockheight=%u", blockheight);

	/* Check if block height changed (or if we need to initialize) */
	if (blockheight > bwatch->current_height) {
		u32 *target_height;
		bool is_first_init = (bwatch->current_height == 0);

		target_height = tal(cmd, u32);
		if (is_first_init) {
			plugin_log(cmd->plugin, LOG_DBG, "First poll: init at block %u", blockheight);
			*target_height = blockheight;  /* Jump to tip */
		} else {
			plugin_log(cmd->plugin, LOG_DBG, "Block change: %u -> %u",
				   bwatch->current_height, blockheight);
			*target_height = bwatch->current_height + 1;  /* Catch up sequentially */
		}

		return fetch_block_handle(cmd, *target_height, handle_block, target_height);
	}

	/* No change, reschedule at normal interval */
	plugin_log(cmd->plugin, LOG_DBG, "No block change, current_height remains %u", bwatch->current_height);
	return poll_finished(cmd);
}

/* Timer callback to poll the chain */
static struct command_result *poll_chain(struct command *cmd, void *unused)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	struct out_req *req;

	plugin_log(cmd->plugin, LOG_DBG, "Polling chain for new blocks (current_height=%u)",
		   bwatch->current_height);

	req = jsonrpc_request_start(cmd, "getchaininfo",
				    getchaininfo_done,
				    getchaininfo_done,
				    NULL);
	json_add_u32(req->js, "last_height", bwatch->current_height);
	return send_outreq(req);
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
		plugin_log(cmd->plugin, LOG_BROKEN,
			   "Failed to parse getwatchmanheight response");
		watchman_height = 0; /* Fall through to normal init */
	}

	plugin_log(cmd->plugin, LOG_DBG,
		   "Watchman reports height %u, bwatch has height %u",
		   watchman_height, bwatch->current_height);

	/* Roll back to watchman's height if we're ahead.
	 * Normal polling will catch up and re-send block_processed for each block. */
	if (bwatch->current_height > watchman_height) {
		plugin_log(cmd->plugin, LOG_INFORM,
			   "Watchman height (%u) < bwatch height (%u), rescanning from watchman height",
			   watchman_height, bwatch->current_height);
		while (bwatch->current_height > watchman_height)
			remove_tip(cmd, bwatch);
	}

	/* Start polling - will catch up naturally with proper reorg handling */
	bwatch->poll_timer = global_timer(cmd->plugin, time_from_sec(1),
					   poll_chain, NULL);

	plugin_log(cmd->plugin, LOG_INFORM,
		   "bwatch plugin initialized at height %u with %zu blocks in history, polling every %u seconds",
		   bwatch->current_height, tal_count(bwatch->block_history),
		   bwatch->poll_interval);

	return timer_complete(cmd);
}

/* Timer callback to sync with watchman's height before starting normal polling */
static struct command_result *sync_with_watchman(struct command *cmd, void *unused UNUSED)
{
	struct out_req *req = jsonrpc_request_start(cmd, "getwatchmanheight",
						    getwatchmanheight_done,
						    getwatchmanheight_done,
						    NULL);
	return send_outreq(req);
}

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

/* Send block_processed notification to watchman */
static void send_block_processed(struct command *cmd, u32 blockheight)
{
	struct out_req *req;

	req = jsonrpc_request_start(cmd, "block_processed",
				    block_processed_ack, plugin_broken_cb, NULL);
	json_add_u32(req->js, "blockheight", blockheight);
	send_outreq(req);
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
	process_block_txs(cmd, bwatch_of(cmd->plugin), block, rescan->current_block,
			  &blockhash, rescan->watch);

	/* More blocks to scan? */
	if (++rescan->current_block <= rescan->target_block)
		return fetch_block_rescan(cmd, rescan->current_block, rescan_block_done, rescan);

	/* Rescan complete - notify watchman about the final block height */
	send_block_processed(cmd, rescan->target_block);

	plugin_log(cmd->plugin, LOG_INFORM, "Rescan complete");
	return command_success(cmd, json_out_obj(cmd, NULL, NULL));
}

/* Start scanning historical blocks.
 * If w is NULL, rescans all watches; otherwise rescans only that watch.
 * Rescan state is tied to command lifetime. */
static void start_rescan(struct command *cmd,
			 const struct watch *w,
			 u32 start_block, u32 target_block)
{
	struct rescan_state *rescan;

	if (w) {
		plugin_log(cmd->plugin, LOG_INFORM, "Starting rescan for %s watch: blocks %u-%u",
			   get_watch_type_name(w->type), start_block, target_block);
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

/* Forward declaration */
static void save_watch_to_datastore(struct command *cmd, const struct watch *w);

/* Add or update a watch.  Returns NULL if we already had it. */
static struct watch *add_watch(struct command *cmd,
			       struct bwatch *bwatch,
			       enum watch_type type,
			       /* Exactly one of these three is non-NULL */
			       const struct bitcoin_outpoint *outpoint,
			       const u8 *scriptpubkey,
			       const struct bitcoin_txid *txid,
			       u32 start_block,
			       const char *owner_id)
{
	struct watch *w = get_watch(bwatch, type, outpoint, scriptpubkey, txid);

	if (!w) {
		/* Woah!  A new one */
		w = tal(bwatch, struct watch);
		w->type = type;
		w->start_block = start_block;
		w->owners = tal_arr(w, wirestring *, 0);
		switch (w->type) {
		case WATCH_TXID:
			w->key.txid = *txid;
			break;
		case WATCH_SCRIPTPUBKEY:
			w->key.scriptpubkey.len = tal_bytelen(scriptpubkey);
			w->key.scriptpubkey.script = tal_dup_talarr(w, u8, scriptpubkey);
			break;
		case WATCH_OUTPOINT:
			w->key.outpoint = *outpoint;
		}
		add_watch_to_hash(bwatch, w);
	}

	/* Check if this owner already exists */
	for (size_t i = 0; i < tal_count(w->owners); i++) {
		if (streq(w->owners[i], owner_id)) {
			/* FIXME: Determine if this actually happens
			 * across crash scenarios, and maybe downgrade
			 * this msg if it does.  Or, if it really
			 * cannot happen, fail the caller! */
			plugin_log(cmd->plugin, LOG_UNUSUAL,
				   "Owner %s already watching", owner_id);
			return NULL;
		}
	}

	/* In case this starts before the previous identical watch */
	if (start_block < w->start_block)
		w->start_block = start_block;

	tal_arr_expand(&w->owners, tal_strdup(w->owners, owner_id));
	save_watch_to_datastore(cmd, w);
	return w;
}

/* Remove a watch */
static void del_watch(struct command *cmd, struct bwatch *bwatch,
		      enum watch_type type,
		      /* Exactly one of these three is non-NULL */
		      const struct bitcoin_outpoint *outpoint,
		      const u8 *scriptpubkey,
		      const struct bitcoin_txid *txid,
		      const char *owner_id)
{
	struct watch *w = get_watch(bwatch, type, outpoint, scriptpubkey, txid);

	if (!w) {
		plugin_log(cmd->plugin, LOG_BROKEN,
			   "Attempted to remove non-existent %s watch",
			   get_watch_type_name(type));
		return;
	}

	/* Find and remove the specific owner */
	for (size_t i = 0; i < tal_count(w->owners); i++) {
		if (streq(w->owners[i], owner_id)) {
			tal_free(w->owners[i]);
			tal_arr_remove(&w->owners, i);

			/* If no more owners, delete the watch entirely */
			if (tal_count(w->owners) == 0) {
				delete_watch_from_datastore(cmd, w);
				remove_watch_from_hash(bwatch, w);
				tal_free(w);
			} else {
				save_watch_to_datastore(cmd, w);
			}
			return;
		}
	}

	plugin_log(cmd->plugin, LOG_BROKEN,
		   "Attempted to remove watch for owner %s but it wasn't watching", owner_id);
}

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

/* Returns NULL if OK */
static struct command_result *check_type_params(struct command *cmd,
						enum watch_type type,
						/* Ensures exactly one of these three is non-NULL */
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
/* FIXME: consider breaking into three bwatch_add_XXX apis? */
static struct command_result *json_bwatch_add(struct command *cmd,
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

	w = add_watch(cmd, bwatch,
		      type,
		      outpoint,
		      scriptpubkey,
		      txid,
		      *start_block,
		      owner);

	if (w && bwatch->current_height > 0 && w->start_block <= bwatch->current_height) {
		/* Rescan needed - command completes when rescan finishes */
		start_rescan(cmd, w, *start_block, bwatch->current_height);
		return command_still_pending(cmd);
	}

	return command_success(cmd, json_out_obj(cmd, NULL, NULL));
}

/* RPC command: delwatch */
static struct command_result *json_bwatch_del(struct command *cmd,
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

	del_watch(cmd, bwatch, type, outpoint, scriptpubkey, txid, owner);
	return command_success(cmd, json_out_obj(cmd, "removed", "true"));
}

/* Helper to output common watch fields */
static void json_out_watch_common(struct json_out *jout,
				  enum watch_type type,
				  u32 start_block,
				  wirestring **owners)
{
	json_out_addstr(jout, "type", get_watch_type_name(type));
	json_out_add(jout, "start_block", false, "%u", start_block);
	json_out_start(jout, "owners", '[');
	for (size_t i = 0; i < tal_count(owners); i++)
		json_out_addstr(jout, NULL, owners[i]);
	json_out_end(jout, ']');
}

/* RPC command: listwatch */
static struct command_result *json_bwatch_list(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *params)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);
	struct json_out *jout;
	struct watch *w;
	struct scriptpubkey_watch_hash_iter sit;
	struct outpoint_watch_hash_iter oit;
	struct txid_watch_hash_iter tit;

	if (!param(cmd, buffer, params, NULL))
		return command_param_failed();

	jout = json_out_new(cmd);
	json_out_start(jout, NULL, '{');
	json_out_start(jout, "watches", '[');

	w = scriptpubkey_watch_hash_first(bwatch->scriptpubkey_watches, &sit);
	while (w) {
		json_out_start(jout, NULL, '{');
		json_out_addstr(jout, "scriptpubkey",
				tal_hexstr(tmpctx, w->key.scriptpubkey.script, w->key.scriptpubkey.len));
		json_out_watch_common(jout, w->type, w->start_block, w->owners);
		json_out_end(jout, '}');
		w = scriptpubkey_watch_hash_next(bwatch->scriptpubkey_watches, &sit);
	}

	w = outpoint_watch_hash_first(bwatch->outpoint_watches, &oit);
	while (w) {
		json_out_start(jout, NULL, '{');
		json_out_addstr(jout, "outpoint", fmt_bitcoin_outpoint(tmpctx, &w->key.outpoint));
		json_out_watch_common(jout, w->type, w->start_block, w->owners);
		json_out_end(jout, '}');
		w = outpoint_watch_hash_next(bwatch->outpoint_watches, &oit);
	}

	w = txid_watch_hash_first(bwatch->txid_watches, &tit);
	while (w) {
		json_out_start(jout, NULL, '{');
		json_out_addstr(jout, "txid", fmt_bitcoin_txid(tmpctx, &w->key.txid));
		json_out_watch_common(jout, w->type, w->start_block, w->owners);
		json_out_end(jout, '}');
		w = txid_watch_hash_next(bwatch->txid_watches, &tit);
	}

	json_out_end(jout, ']');
	json_out_end(jout, '}');
	return command_success(cmd, jout);
}

static const char *init(struct command *cmd,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	struct bwatch *bwatch = bwatch_of(cmd->plugin);

	bwatch->plugin = cmd->plugin;

	/* Initialize watch storage */
	bwatch->scriptpubkey_watches = new_htable(bwatch, scriptpubkey_watch_hash);
	bwatch->outpoint_watches = new_htable(bwatch, outpoint_watch_hash);
	bwatch->txid_watches = new_htable(bwatch, txid_watch_hash);

	/* Initialize block history */
	bwatch->block_history = tal_arr(bwatch, struct block_record_wire *, 0);

	/* Load block history from datastore */
	load_block_history(cmd, bwatch);

	/* If no history, initialize to zero (will be set on first poll) */
	if (tal_count(bwatch->block_history) == 0) {
		bwatch->current_height = 0;
		memset(&bwatch->current_blockhash, 0, sizeof(bwatch->current_blockhash));
	}

	/* Restore watches from datastore */
	load_watches_by_type(cmd, bwatch, WATCH_SCRIPTPUBKEY);
	load_watches_by_type(cmd, bwatch, WATCH_OUTPOINT);
	load_watches_by_type(cmd, bwatch, WATCH_TXID);

	/* Set poll interval (30 seconds default) */
	bwatch->poll_interval = 30;

	/* Defer watchman height sync to a timer so init can complete synchronously */
	global_timer(cmd->plugin, time_from_sec(0), sync_with_watchman, NULL);
	
	return NULL; /* Success */
}

static const struct plugin_command commands[] = {
	{
		"addwatch",
		json_bwatch_add,
	},
	{
		"delwatch",
		json_bwatch_del,
	},
	{
		"listwatch",
		json_bwatch_list,
	},
};

int main(int argc, char *argv[])
{
	struct bwatch *bwatch;

	setup_locale();
	bwatch = tal(NULL, struct bwatch);
	plugin_main(argv, init, take(bwatch), PLUGIN_RESTARTABLE, true, NULL,
		    commands, ARRAY_SIZE(commands),
		    NULL, 0,  /* notifications */
		    NULL, 0,  /* hooks */
		    NULL, 0,  /* notification topics */
		    NULL);
}
