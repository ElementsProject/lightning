#ifndef LIGHTNING_LIGHTNINGD_WATCHMAN_H
#define LIGHTNING_LIGHTNINGD_WATCHMAN_H

#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/tal/tal.h>

struct lightningd;
struct pending_op;

/* lightningd's view of bwatch.  bwatch lives in a separate process and tells
 * us about new/reverted blocks and watch hits via JSON-RPC; watchman tracks
 * what we've already processed and queues outbound watch ops while bwatch is
 * starting up. */
struct watchman {
	struct lightningd *ld;
	u32 last_processed_height;
	struct bitcoin_blkid last_processed_hash;
	u32 bitcoind_blockcount;
	struct pending_op **pending_ops;
};

/**
 * watch_found_fn - Handler for watch_found notifications (tx-based watches)
 * @ld: lightningd instance
 * @suffix: the owner string after the prefix (e.g. "42" for wallet/p2wpkh/42,
 *          or "100x1x0" for gossip/100x1x0); the handler is responsible for
 *          parsing whatever identifier it stored in that suffix
 * @tx: the transaction that matched
 * @outnum: which output matched (for scriptpubkey watches) or input for outpoint watches
 * @blockheight: the block height where tx was found
 * @txindex: position of tx in block (0 = coinbase)
 *
 * Called when bwatch detects a watched item in a block.
 */
typedef void (*watch_found_fn)(struct lightningd *ld,
			       const char *suffix,
			       const struct bitcoin_tx *tx,
			       size_t outnum,
			       u32 blockheight,
			       u32 txindex);

typedef void (*watch_revert_fn)(struct lightningd *ld,
				const char *suffix,
				u32 blockheight);

/**
 * depth_found_fn - Handler for blockdepth watch notifications.
 * @depth: new_height - confirm_height + 1 (always >= 1)
 * @blockheight: current chain tip height
 *
 * Called once per new block.  When the confirming block is reorged away,
 * watch_revert_fn is called instead.
 */
typedef void (*depth_found_fn)(struct lightningd *ld,
			       const char *suffix,
			       u32 depth,
			       u32 blockheight);

/**
 * watchman_new - Create and initialize a new watchman instance
 * @ctx: tal context to allocate from
 * @ld: lightningd instance
 *
 * Returns a new watchman instance, loading pending operations from datastore.
 */
struct watchman *watchman_new(const tal_t *ctx, struct lightningd *ld);

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

#endif /* LIGHTNING_LIGHTNINGD_WATCHMAN_H */
