#ifndef LIGHTNING_LIGHTNINGD_WATCHMAN_H
#define LIGHTNING_LIGHTNINGD_WATCHMAN_H

#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <inttypes.h>

struct lightningd;
struct pending_op;
struct short_channel_id;

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

/** Register a WATCH_SCRIPTPUBKEY — fires when @scriptpubkey appears in a tx output. */
void watchman_watch_scriptpubkey(struct lightningd *ld,
				 const char *owner,
				 const u8 *scriptpubkey,
				 size_t script_len,
				 u32 start_block);

/** Remove a WATCH_SCRIPTPUBKEY. */
void watchman_unwatch_scriptpubkey(struct lightningd *ld,
				   const char *owner,
				   const u8 *scriptpubkey,
				   size_t script_len);

/** Register a WATCH_OUTPOINT — fires when @outpoint is spent. */
void watchman_watch_outpoint(struct lightningd *ld,
			     const char *owner,
			     const struct bitcoin_outpoint *outpoint,
			     u32 start_block);

/** Remove a WATCH_OUTPOINT (e.g. during splice before re-adding for new outpoint). */
void watchman_unwatch_outpoint(struct lightningd *ld,
			       const char *owner,
			       const struct bitcoin_outpoint *outpoint);

/** Register a WATCH_SCID — fires when bwatch finds the output (for gossip get_txout). */
void watchman_watch_scid(struct lightningd *ld,
			 const char *owner,
			 const struct short_channel_id *scid,
			 u32 start_block);

/** Remove a WATCH_SCID. */
void watchman_unwatch_scid(struct lightningd *ld,
			   const char *owner,
			   const struct short_channel_id *scid);

/**
 * watchman_watch_blockdepth - Register a WATCH_BLOCKDEPTH
 * @ld: lightningd instance
 * @owner: the owner identifier (e.g. "channel/funding_depth/42")
 * @confirm_height: the block height where the tx of interest was confirmed
 */
void watchman_watch_blockdepth(struct lightningd *ld,
			       const char *owner,
			       u32 confirm_height);

/** Remove a WATCH_BLOCKDEPTH. */
void watchman_unwatch_blockdepth(struct lightningd *ld,
				 const char *owner,
				 u32 confirm_height);

/*
 * Owner string constructors.
 *
 * Always use these instead of raw tal_fmt() to build owner strings.  Sharing
 * one constructor between watchman_watch_* and watchman_unwatch_* guarantees
 * the strings are identical and the unwatch can never silently fail due to a
 * format mismatch (e.g. %u vs PRIu64).
 */

/* wallet/ owners */
static inline const char *owner_wallet_utxo(const tal_t *ctx,
					    const struct bitcoin_outpoint *op)
{ return tal_fmt(ctx, "wallet/utxo/%s", fmt_bitcoin_outpoint(ctx, op)); }

static inline const char *owner_wallet_p2wpkh(const tal_t *ctx, u64 keyidx)
{ return tal_fmt(ctx, "wallet/p2wpkh/%"PRIu64, keyidx); }

static inline const char *owner_wallet_p2tr(const tal_t *ctx, u64 keyidx)
{ return tal_fmt(ctx, "wallet/p2tr/%"PRIu64, keyidx); }

#endif /* LIGHTNING_LIGHTNINGD_WATCHMAN_H */
