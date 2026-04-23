#ifndef LIGHTNING_PLUGINS_BWATCH_BWATCH_H
#define LIGHTNING_PLUGINS_BWATCH_BWATCH_H

#include "config.h"
#include <bitcoin/block.h>
#include <bitcoin/short_channel_id.h>
#include <bitcoin/tx.h>
#include <plugins/libplugin.h>
#include <wire/wire.h>

/* Forward declare hash table types (defined in bwatch_store.h) */
struct scriptpubkey_watches;
struct outpoint_watches;
struct scid_watches;
struct blockdepth_watches;

/* Timer handle returned by global_timer; defined in libplugin. */
struct plugin_timer;

/* Wire-format block record stored in lightningd's datastore.
 * Defined by bwatch_wiregen.h; forward-declared here to avoid pulling
 * the generated header into every consumer of bwatch.h. */
struct block_record_wire;

/* Watch type discriminator. */
enum watch_type {
	WATCH_SCRIPTPUBKEY,
	WATCH_OUTPOINT,
	WATCH_SCID,
	WATCH_BLOCKDEPTH,
};

/* Scriptpubkey wrapper: tal-allocated bytes don't carry a length, so we
 * keep them in a struct with an explicit length for hashing/equality. */
struct scriptpubkey {
	const u8 *script;
	size_t len;
};

/* A single watch: one key plus the set of owner ids that registered it. */
struct watch {
	enum watch_type type;
	u32 start_block;
	wirestring **owners;
	union {
		struct scriptpubkey scriptpubkey;
		struct bitcoin_outpoint outpoint;
		struct short_channel_id scid;
	} key;
};

/* Main bwatch state.
 *
 * The four watch hash tables are typed (see bwatch_store.h) so each
 * lookup hits the right key shape (script bytes / outpoint / scid /
 * confirm-height) without dispatching on type at every call site. */
struct bwatch {
	struct plugin *plugin;
	u32 current_height;
	struct bitcoin_blkid current_blockhash;
	/* Oldest first, most recent last. Used to replay a reorg by
	 * peeling tips off until the parent hash matches the new chain. */
	struct block_record_wire *block_history;

	struct scriptpubkey_watches *scriptpubkey_watches;
	struct outpoint_watches *outpoint_watches;
	struct scid_watches *scid_watches;
	struct blockdepth_watches *blockdepth_watches;

	/* Active poll timer; rescheduled at the end of every poll cycle. */
	struct plugin_timer *poll_timer;
	u32 poll_interval_ms;
};

/* Helper: get last block_history (or NULL) */
const struct block_record_wire *bwatch_last_block(const struct bwatch *bwatch);

/* Helper: retrieve the bwatch state from a plugin handle. */
struct bwatch *bwatch_of(struct plugin *plugin);

/* Timer callback: kicks off one chain-poll cycle (getchaininfo →
 * getrawblockbyheight → persist → reschedule).  Exposed so other modules
 * can schedule a poll from their own callbacks. */
struct command_result *bwatch_poll_chain(struct command *cmd, void *unused);

/* Pop the current tip from in-memory + persisted history.  Exposed so the
 * startup chaininfo path can roll back when bitcoind's chain is shorter
 * than what we have stored. */
void bwatch_remove_tip(struct command *cmd, struct bwatch *bwatch);

#endif /* LIGHTNING_PLUGINS_BWATCH_BWATCH_H */
