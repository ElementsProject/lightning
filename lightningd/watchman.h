#ifndef LIGHTNING_LIGHTNINGD_WATCHMAN_H
#define LIGHTNING_LIGHTNINGD_WATCHMAN_H

#include "config.h"
#include <bitcoin/tx.h>

struct lightningd;
struct watchman;
struct bitcoin_tx;

/**
 * watch_found_fn - Handler for watch_found notifications
 * @ld: lightningd instance
 * @id: the parsed ID from the owner string (keyindex for wallet, dbid for channels, etc.)
 * @tx: the transaction that matched
 * @outnum: which output matched (for scriptpubkey watches) or input for outpoint watches
 * @blockheight: the block height where tx was found
 * @txindex: position of tx in block (0 = coinbase)
 *
 * Called when bwatch detects a watched item in a block.
 */
typedef void (*watch_found_fn)(struct lightningd *ld,
			       u32 id,
			       const struct bitcoin_tx *tx,
			       size_t outnum,
			       u32 blockheight,
			       u32 txindex);

/**
 * watchman_new - Create and initialize a new watchman instance
 * @ctx: tal context to allocate from
 * @ld: lightningd instance
 *
 * Returns a new watchman instance, loading pending operations from datastore.
 */
struct watchman *watchman_new(const tal_t *ctx, struct lightningd *ld);

/**
 * watchman_add - Add a watch via raw JSON params
 * @ld: lightningd instance
 * @owner: the owner identifier (e.g., "wallet/p2wpkh/42")
 * @json_params: the raw JSON params string to send to bwatch
 *
 * Adds a watch to the pending queue and sends it to bwatch.
 * If a conflicting delete is pending, it will be canceled.
 */
void watchman_add(struct lightningd *ld,
		  const char *owner,
		  const char *json_params);

/**
 * watchman_del - Remove a watch via raw JSON params
 * @ld: lightningd instance
 * @owner: the owner identifier
 * @json_params: the raw JSON params string to send to bwatch
 *
 * Removes a watch by adding a delete operation to the pending queue.
 * If a conflicting add is pending, it will be canceled instead.
 */
void watchman_del(struct lightningd *ld,
		  const char *owner,
		  const char *json_params);

/**
 * watchman_ack - Acknowledge a completed watch operation
 * @ld: lightningd instance
 * @op_id: the operation ID that was acknowledged
 *
 * Called when bwatch acknowledges a watch operation.
 */
void watchman_ack(struct lightningd *ld, const char *op_id);

/**
 * watchman_replay_pending - Replay all pending operations
 * @ld: lightningd instance
 *
 * Resends all pending watch operations to bwatch.
 * Call this when bwatch is ready (e.g., on startup).
 */
void watchman_replay_pending(struct lightningd *ld);

/**
 * watchman_get_height - Get watchman's last processed block height
 * @ld: lightningd instance
 *
 * Returns the last block height that bwatch has processed.
 * This should be used as the start_block when adding new watches
 * to avoid rescanning from genesis.
 */
u32 watchman_get_height(struct lightningd *ld);

/* Typed watch helpers — prefer these over calling watchman_add/del directly. */

/** Register a WATCH_SCRIPTPUBKEY — fires channel_funding_watch_found when seen. */
void watchman_watch_scriptpubkey(struct lightningd *ld,
				 const char *owner,
				 const u8 *scriptpubkey,
				 size_t script_len,
				 u32 start_block);

/** Register a WATCH_OUTPOINT — fires when the outpoint is spent. */
void watchman_watch_outpoint(struct lightningd *ld,
			     const char *owner,
			     const struct bitcoin_outpoint *outpoint,
			     u32 start_block);

/** Remove a WATCH_OUTPOINT (e.g. during splice before re-adding for new outpoint). */
void watchman_unwatch_outpoint(struct lightningd *ld,
			       const char *owner,
			       const struct bitcoin_outpoint *outpoint);

/**
 * watchman_add_utxo - Add a wallet-originated UTXO to bwatch's datastore
 * @ld: lightningd instance
 * @outpoint: the output to add
 * @blockheight: block height (0 for unconfirmed)
 * @txindex: position in block (0 for unconfirmed)
 * @script: scriptpubkey
 * @script_len: script length
 * @sat: amount in satoshis
 *
 * Called when we create our own outputs (e.g. change outputs).
 * Fire-and-forget; bwatch must be ready.
 */
void watchman_add_utxo(struct lightningd *ld,
		       const struct bitcoin_outpoint *outpoint,
		       u32 blockheight, u32 txindex,
		       const u8 *script, size_t script_len,
		       struct amount_sat sat);

#endif /* LIGHTNING_LIGHTNINGD_WATCHMAN_H */
