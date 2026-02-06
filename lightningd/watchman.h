#ifndef LIGHTNING_LIGHTNINGD_WATCHMAN_H
#define LIGHTNING_LIGHTNINGD_WATCHMAN_H

#include "config.h"

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

#endif /* LIGHTNING_LIGHTNINGD_WATCHMAN_H */
