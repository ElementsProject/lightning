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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
HTABLE_DEFINE_NODUPS_TYPE(struct watch, scriptpubkey_watch_keyof,
			  scriptpubkey_hash, scriptpubkey_watch_eq,
			  scriptpubkey_watch_hash);
#pragma GCC diagnostic pop

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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
HTABLE_DEFINE_NODUPS_TYPE(struct watch, outpoint_watch_keyof,
			  outpoint_hash, outpoint_watch_eq,
			  outpoint_watch_hash);
#pragma GCC diagnostic pop

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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
HTABLE_DEFINE_NODUPS_TYPE(struct watch, txid_watch_keyof, txid_hash,
			  txid_watch_eq, txid_watch_hash);
#pragma GCC diagnostic pop

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

/* ==== BLOCK HISTORY DATASTORE OPERATIONS ==== */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
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
	struct json_out *params = json_out_new(tmpctx);
	const jsmntok_t *result;
	const char *buf;
	const jsmntok_t *datastore, *t;
	size_t i;

	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	json_out_addstr(params, NULL, "bwatch");
	json_out_addstr(params, NULL, "block_history");
	json_out_end(params, ']');
	json_out_end(params, '}');

	result = jsonrpc_request_sync(tmpctx, cmd, "listdatastore", params, &buf);
	datastore = json_get_member(buf, result, "datastore");

	json_for_each_arr(i, t, datastore) {
		const u8 *data = json_tok_bin_from_hex(tmpctx, buf,
						       json_get_member(buf, t, "hex"));
		if (!data)
			plugin_err(cmd->plugin,
				   "Bad block_history hex %.*s",
				   json_tok_full_len(t),
				   json_tok_full(buf, t));

		struct block_record_wire *br = tal(bwatch, struct block_record_wire);
		if (!fromwire_bwatch_block(&data, br)) {
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
#pragma GCC diagnostic pop

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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
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
#pragma GCC diagnostic pop

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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
/* Get a watch from the appropriate hash table by key */
static struct watch *get_watch(struct bwatch *bwatch, const struct watch *key)
{
	switch (key->type) {
	case WATCH_SCRIPTPUBKEY:
		return scriptpubkey_watch_hash_get(bwatch->scriptpubkey_watches, &key->key.scriptpubkey);
	case WATCH_OUTPOINT:
		return outpoint_watch_hash_get(bwatch->outpoint_watches, &key->key.outpoint);
	case WATCH_TXID:
		return txid_watch_hash_get(bwatch->txid_watches, &key->key.txid);
	}
	abort();
}


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
#pragma GCC diagnostic pop

/* Load watches from datastore by type */
static void load_watches_by_type(struct command *cmd, struct bwatch *bwatch,
				 enum watch_type type)
{
	const char *watch_type_name = get_watch_type_name(type);
	struct json_out *params = json_out_new(tmpctx);
	const jsmntok_t *result;
	const char *buf;
	const jsmntok_t *datastore, *t;
	size_t i, count = 0;

	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	json_out_addstr(params, NULL, "bwatch");
	json_out_addstr(params, NULL, watch_type_name);
	json_out_end(params, ']');
	json_out_end(params, '}');

	result = jsonrpc_request_sync(tmpctx, cmd, "listdatastore", params, &buf);
	datastore = json_get_member(buf, result, "datastore");

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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
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
#pragma GCC diagnostic pop

/*
 * ============================================================================
 * BLOCK PROCESSING: Polling
 * ============================================================================
 */

/* ==== BLOCK FETCHING AND PARSING ==== */

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

	/* TODO: Notify watchman when send_block_processed is implemented */

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

	/* Start polling - will catch up naturally with proper reorg handling */
	bwatch->poll_timer = global_timer(cmd->plugin, time_from_sec(1), poll_chain, NULL);
	
	plugin_log(bwatch->plugin, LOG_INFORM, "bwatch plugin initialized");
	return NULL;
}

int main(int argc, char *argv[])
{
	struct bwatch *bwatch;

	setup_locale();
	bwatch = tal(NULL, struct bwatch);
	plugin_main(argv, init, take(bwatch), PLUGIN_RESTARTABLE, true, NULL,
		    NULL, 0,  /* commands */
		    NULL, 0,  /* notifications */
		    NULL, 0,  /* hooks */
		    NULL, 0,  /* notification topics */
		    NULL);
}
