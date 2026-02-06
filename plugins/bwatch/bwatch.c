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
#pragma GCC diagnostic pop

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

	/* If no history, initialize to zero (will be set on first poll) */
	if (tal_count(bwatch->block_history) == 0) {
		bwatch->current_height = 0;
		memset(&bwatch->current_blockhash, 0, sizeof(bwatch->current_blockhash));
	}
	
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
