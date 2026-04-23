#include "config.h"
#include <db/exec.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/watchman.h>
#include <wallet/wallet.h>

/*
 * Watchman is the lightningd-side counterpart to the bwatch plugin.
 * It tracks how far we've processed the chain (last_processed_height +
 * hash, persisted in the SQL `vars` table), queues outbound watch ops
 * while bwatch is starting up, and dispatches watch_found / watch_revert /
 * blockdepth notifications to subdaemon-specific handlers.
 *
 * This commit lands just enough machinery to construct a watchman and
 * recover the persisted tip; the pending-op queue and ack lifecycle land
 * in subsequent commits.
 */

static void load_tip(struct watchman *wm)
{
	struct db *db = wm->ld->wallet->db;
	const u8 *blob;

	wm->last_processed_height = db_get_intvar(db, "last_watchman_block_height", 0);

	blob = db_get_blobvar(tmpctx, db, "last_watchman_block_hash");
	if (blob) {
		assert(tal_bytelen(blob) == sizeof(struct bitcoin_blkid));
		memcpy(&wm->last_processed_hash, blob, sizeof(wm->last_processed_hash));
	}
}

/* Apply --rescan: negative means absolute height (only go back),
 * positive means relative (go back N blocks from stored tip). */
static void apply_rescan(struct watchman *wm, struct lightningd *ld)
{
	u32 stored = wm->last_processed_height;
	u32 target;

	if (ld->config.rescan < 0)
		target = (u32)(-ld->config.rescan);  /* absolute height */
	else if (stored > (u32)ld->config.rescan)
		target = stored - (u32)ld->config.rescan;  /* go back N blocks */
	else
		target = 0;  /* rescan exceeds stored height, start from genesis */

	/* Only adjust downward; upward targets are validated later in chaininfo */
	if (target < stored) {
		log_debug(ld->log,
			 "Rescanning: adjusting watchman height from %u to %u",
			 stored, target);
		wm->last_processed_height = target;
	}
}

struct watchman *watchman_new(const tal_t *ctx, struct lightningd *ld)
{
	struct watchman *wm = talz(ctx, struct watchman);

	wm->ld = ld;
	wm->pending_ops = tal_arr(wm, struct pending_op *, 0);

	load_tip(wm);
	apply_rescan(wm, ld);

	log_info(ld->log, "Watchman: height=%u, %zu pending ops",
		 wm->last_processed_height, tal_count(wm->pending_ops));

	return wm;
}
