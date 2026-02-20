#include "config.h"
#include "bwatch.h"
#include "bwatch_store.h"
#include <bitcoin/block.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <common/amount.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/json_out/json_out.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_parse.h>
#include <common/memleak.h>
#include <common/mkdatastorekey.h>
#include <plugins/bwatch/bwatch_wiregen.h>
#include <plugins/libplugin.h>

/*
 * ============================================================================
 * HASH TABLE KEY FUNCTIONS
 * ============================================================================
 */

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
	       memeq(w->key.scriptpubkey.script, scriptpubkey->len, scriptpubkey->script, scriptpubkey->len);
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

const struct bitcoin_txid *txid_watch_keyof(const struct watch *w)
{
	assert(w->type == WATCH_TXID);
	return &w->key.txid;
}

size_t txid_hash(const struct bitcoin_txid *txid)
{
	return siphash24(siphash_seed(),
			 txid->shad.sha.u.u8, sizeof(txid->shad.sha.u.u8));
}

bool txid_watch_eq(const struct watch *w, const struct bitcoin_txid *txid)
{
	return bitcoin_txid_eq(&w->key.txid, txid);
}

/* Note: HTABLE_DEFINE macros are in bwatch.h */

/*
 * ============================================================================
 * DATASTORE HELPER FUNCTIONS
 * ============================================================================
 */

/* List all datastore entries under a key prefix (up to 2 components). */
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

/* Fetch a single datastore entry by its exact key (returns NULL if not found). */
static const jsmntok_t *bwatch_get_datastore(const tal_t *ctx,
					     struct command *cmd,
					     const char **key,
					     const char **buf_out)
{
	struct json_out *params = json_out_new(tmpctx);
	const jsmntok_t *result, *entries;

	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	for (size_t i = 0; key[i]; i++)
		json_out_addstr(params, NULL, key[i]);
	json_out_end(params, ']');
	json_out_end(params, '}');

	result = jsonrpc_request_sync(ctx, cmd, "listdatastore", params, buf_out);
	entries = json_get_member(*buf_out, result, "datastore");
	if (!entries || entries->size == 0)
		return NULL;
	/* listdatastore returns an array; exact key match is the first element */
	return json_get_arr(entries, 0);
}

/*
 * ============================================================================
 * BLOCK STORAGE
 * ============================================================================
 */

void bwatch_add_block_to_datastore(struct command *cmd, const struct block_record_wire *br)
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

void bwatch_add_block_to_history(struct bwatch *bwatch, u32 height,
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

/*
 * ============================================================================
 * UTXOSET STORAGE
 *
 * Each unspent output we care about is stored under the key:
 *   ["bwatch", "utxoset", <txid_hex>, "<outnum>"]
 *
 * The value is a serialised utxoset_entry_wire (see bwatch_wire.csv).
 * spendheight == BWATCH_UTXOSET_UNSPENT (UINT32_MAX) means the output
 * has not yet been spent.
 * ============================================================================
 */

#define BWATCH_UTXOSET_UNSPENT UINT32_MAX

/* Record a newly-created output in the datastore.
 *
 * Called when bwatch sees a scriptpubkey we watch appear in a confirmed block.
 * The key encodes the outpoint so we can look it up in O(1) later. */
void bwatch_utxoset_add(struct command *cmd,
			const struct bitcoin_outpoint *outpoint,
			u32 blockheight, u32 txindex,
			const u8 *scriptpubkey, size_t scriptpubkey_len UNUSED,
			struct amount_sat satoshis)
{
	/* The wire-gen struct uses u8 * (not const), but towire only reads it,
	 * so stripping const here is safe. */
	struct utxoset_entry_wire entry = {
		.txid = outpoint->txid,
		.outnum = outpoint->n,
		.blockheight = blockheight,
		.spendheight = BWATCH_UTXOSET_UNSPENT,
		.txindex = txindex,
		.scriptpubkey = cast_const(u8 *, scriptpubkey),
		.satoshis = satoshis,
	};
	const char **key = mkdatastorekey(tmpctx, "bwatch", "utxoset",
					  fmt_bitcoin_txid(tmpctx, &outpoint->txid),
					  tal_fmt(tmpctx, "%u", outpoint->n));
	const u8 *data = towire_bwatch_utxoset_entry(tmpctx, &entry);

	jsonrpc_set_datastore_binary(cmd, key, data, tal_bytelen(data),
				     "must-create", NULL, NULL, NULL);
}

/* Mark an existing utxoset entry as spent by setting its spendheight.
 *
 * Fetches the entry by its exact outpoint key (O(1)), deserialises it,
 * updates spendheight, and writes it back with must-replace. */
void bwatch_utxoset_spend(struct command *cmd,
			 const struct bitcoin_outpoint *outpoint,
			 u32 spendheight)
{
	const char **key = mkdatastorekey(tmpctx, "bwatch", "utxoset",
					  fmt_bitcoin_txid(tmpctx, &outpoint->txid),
					  tal_fmt(tmpctx, "%u", outpoint->n));
	const char *buf;
	const jsmntok_t *entry_tok = bwatch_get_datastore(tmpctx, cmd, key, &buf);
	if (!entry_tok)
		return;

	const u8 *data = json_tok_bin_from_hex(tmpctx, buf,
					       json_get_member(buf, entry_tok, "hex"));
	if (!data)
		return;

	struct utxoset_entry_wire *entry = tal(tmpctx, struct utxoset_entry_wire);
	if (!fromwire_bwatch_utxoset_entry(tmpctx, data, &entry))
		return;

	entry->spendheight = spendheight;
	data = towire_bwatch_utxoset_entry(tmpctx, entry);
	jsonrpc_set_datastore_binary(cmd, key, data, tal_bytelen(data),
				     "must-replace", NULL, NULL, NULL);
}

/*
 * ============================================================================
 * TRANSACTION STORAGE (replaces wallet transactions table)
 * ============================================================================
 */

void bwatch_transaction_add(struct command *cmd,
			    const struct bitcoin_tx *tx,
			    u32 blockheight, u32 txindex)
{
	struct bitcoin_txid txid;
	struct transaction_entry_wire entry;

	bitcoin_txid(tx, &txid);
	entry.txid = txid;
	entry.blockheight = blockheight;
	entry.txindex = txindex;
	entry.rawtx = linearize_wtx(tmpctx, tx->wtx);

	const char **key = mkdatastorekey(tmpctx, "bwatch", "transactions",
					  fmt_bitcoin_txid(tmpctx, &txid));
	const u8 *data = towire_bwatch_transaction_entry(tmpctx, &entry);

	jsonrpc_set_datastore_binary(cmd, key, data, tal_bytelen(data),
				     "create-or-replace", NULL, NULL, NULL);
}

void bwatch_load_block_history(struct command *cmd, struct bwatch *bwatch)
{
	const char *buf;
	const jsmntok_t *datastore, *t;
	size_t i;

	datastore = bwatch_list_datastore(tmpctx, cmd, "bwatch", "block_history", &buf);

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

/*
 * ============================================================================
 * WATCH STORAGE AND MANAGEMENT
 * ============================================================================
 */

const char *bwatch_get_watch_type_name(enum watch_type type)
{
	switch (type) {
	case WATCH_SCRIPTPUBKEY:
		return "scriptpubkey";
	case WATCH_OUTPOINT:
		return "outpoint";
	case WATCH_TXID:
		return "txid";
	}
	abort();
}

static const char **get_watch_datastore_key(const tal_t *ctx, const struct watch *w)
{
	const char *type_name = bwatch_get_watch_type_name(w->type);

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

static struct watch_wire *watch_to_wire(const tal_t *ctx, const struct watch *w)
{
	struct watch_wire *wire = tal(ctx, struct watch_wire);

	wire->type = w->type;
	wire->start_block = w->start_block;

	wire->scriptpubkey = NULL;
	memset(&wire->outpoint, 0, sizeof(wire->outpoint));
	memset(&wire->txid, 0, sizeof(wire->txid));

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

	size_t num_owners = tal_count(w->owners);
	wire->owners = tal_arr(wire, wirestring *, num_owners);
	for (size_t i = 0; i < num_owners; i++)
		wire->owners[i] = tal_strdup(wire->owners, w->owners[i]);

	return wire;
}

static struct watch *watch_from_wire(const tal_t *ctx, const struct watch_wire *wire)
{
	struct watch *w = tal(ctx, struct watch);

	w->type = wire->type;
	w->start_block = wire->start_block;

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

	size_t num_owners = tal_count(wire->owners);
	w->owners = tal_arr(w, wirestring *, num_owners);
	for (size_t i = 0; i < num_owners; i++)
		w->owners[i] = tal_strdup(w->owners, wire->owners[i]);

	return w;
}

void bwatch_add_watch_to_hash(struct bwatch *bwatch, struct watch *w)
{
	switch (w->type) {
	case WATCH_SCRIPTPUBKEY:
		scriptpubkey_watches_add(bwatch->scriptpubkey_watches, w);
		break;
	case WATCH_OUTPOINT:
		outpoint_watches_add(bwatch->outpoint_watches, w);
		break;
	case WATCH_TXID:
		txid_watches_add(bwatch->txid_watches, w);
		break;
	}
}

struct watch *bwatch_get_watch(struct bwatch *bwatch,
			       enum watch_type type,
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
		return scriptpubkey_watches_get(bwatch->scriptpubkey_watches, &k);
	}
	case WATCH_OUTPOINT:
		return outpoint_watches_get(bwatch->outpoint_watches, outpoint);
	case WATCH_TXID:
		return txid_watches_get(bwatch->txid_watches, txid);
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
	case WATCH_TXID:
		txid_watches_del(bwatch->txid_watches, w);
		return;
	}
	abort();
}

static void load_watches_by_type(struct command *cmd, struct bwatch *bwatch,
				 enum watch_type type)
{
	const char *watch_type_name = bwatch_get_watch_type_name(type);
	const char *buf;
	const jsmntok_t *datastore, *t;
	size_t i, count = 0;

	datastore = bwatch_list_datastore(tmpctx, cmd, "bwatch", watch_type_name, &buf);

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

		bwatch_add_watch_to_hash(bwatch, w);
		count++;
	}

	plugin_log(cmd->plugin, LOG_DBG, "Restored %zu %s from datastore",
		   count, watch_type_name);
}

void bwatch_save_watch_to_datastore(struct command *cmd, const struct watch *w)
{
	const u8 *data = towire_bwatch_watch(tmpctx, watch_to_wire(tmpctx, w));
	const char **key = get_watch_datastore_key(tmpctx, w);
	struct json_out *params = json_out_new(tmpctx);
	const char *buf;

	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	for (size_t i = 0; i < tal_count(key); i++)
		json_out_addstr(params, NULL, key[i]);
	json_out_end(params, ']');
	json_out_addstr(params, "mode", "create-or-replace");
	json_out_addstr(params, "hex", tal_hex(tmpctx, data));
	json_out_end(params, '}');

	jsonrpc_request_sync(tmpctx, cmd, "datastore", params, &buf);

	plugin_log(cmd->plugin, LOG_DBG, "Saved watch to datastore (type=%d, num_owners=%zu)",
		   w->type, tal_count(w->owners));
}

void bwatch_delete_watch_from_datastore(struct command *cmd, const struct watch *w)
{
	const char **key = get_watch_datastore_key(tmpctx, w);
	struct json_out *params = json_out_new(tmpctx);
	const char *buf;

	json_out_start(params, NULL, '{');
	json_out_start(params, "key", '[');
	for (size_t i = 0; i < tal_count(key); i++)
		json_out_addstr(params, NULL, key[i]);
	json_out_end(params, ']');
	json_out_end(params, '}');

	jsonrpc_request_sync(tmpctx, cmd, "deldatastore", params, &buf);

	plugin_log(cmd->plugin, LOG_DBG,
		   "Deleted watch from datastore: ...%s", key[tal_count(key)-1]);
}

void bwatch_load_watches_from_datastore(struct command *cmd, struct bwatch *bwatch)
{
	load_watches_by_type(cmd, bwatch, WATCH_SCRIPTPUBKEY);
	load_watches_by_type(cmd, bwatch, WATCH_OUTPOINT);
	load_watches_by_type(cmd, bwatch, WATCH_TXID);
}

/*
 * ============================================================================
 * WATCH MANAGEMENT (ADD/DELETE LOGIC)
 * ============================================================================
 */

/* Add or update a watch.  Returns NULL if we already had it. */
struct watch *bwatch_add_watch(struct command *cmd,
			       struct bwatch *bwatch,
			       enum watch_type type,
			       const struct bitcoin_outpoint *outpoint,
			       const u8 *scriptpubkey,
			       const struct bitcoin_txid *txid,
			       u32 start_block,
			       const char *owner_id)
{
	struct watch *w = bwatch_get_watch(bwatch, type, outpoint, scriptpubkey, txid);

	if (w) {
		/* Existing watch: just add owner. The hash table pointer already
		 * points to w, so mutating w->owners is visible without re-adding. */
		for (size_t i = 0; i < tal_count(w->owners); i++) {
			if (streq(w->owners[i], owner_id)) {
				plugin_log(cmd->plugin, LOG_UNUSUAL,
					   "Owner %s already watching", owner_id);
				return NULL;
			}
		}
		if (start_block < w->start_block)
			w->start_block = start_block;
		tal_arr_expand(&w->owners, tal_strdup(w->owners, owner_id));
		bwatch_save_watch_to_datastore(cmd, w);
		return w;
	}

	/* New watch */
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
	tal_arr_expand(&w->owners, tal_strdup(w->owners, owner_id));
	bwatch_save_watch_to_datastore(cmd, w);
	bwatch_add_watch_to_hash(bwatch, w);
	return w;
}

/* Remove a watch */
void bwatch_del_watch(struct command *cmd,
		      struct bwatch *bwatch,
		      enum watch_type type,
		      const struct bitcoin_outpoint *outpoint,
		      const u8 *scriptpubkey,
		      const struct bitcoin_txid *txid,
		      const char *owner_id)
{
	struct watch *w = bwatch_get_watch(bwatch, type, outpoint, scriptpubkey, txid);

	if (!w) {
		plugin_log(cmd->plugin, LOG_BROKEN,
			   "Attempted to remove non-existent %s watch",
			   bwatch_get_watch_type_name(type));
		return;
	}

	/* Find and remove the specific owner */
	for (size_t i = 0; i < tal_count(w->owners); i++) {
		if (streq(w->owners[i], owner_id)) {
			tal_free(w->owners[i]);
			tal_arr_remove(&w->owners, i);

			/* If no more owners, delete the watch entirely */
			if (tal_count(w->owners) == 0) {
				bwatch_delete_watch_from_datastore(cmd, w);
				bwatch_remove_watch_from_hash(bwatch, w);
				tal_free(w);
			} else {
				bwatch_save_watch_to_datastore(cmd, w);
			}
			return;
		}
	}

	plugin_log(cmd->plugin, LOG_BROKEN,
		   "Attempted to remove watch for owner %s but it wasn't watching", owner_id);
}
