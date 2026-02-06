#include "config.h"
#include <lightningd/watchman.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <wallet/wallet.h>
#include <db/exec.h>
#include <common/utils.h>

/*
 * Watchman is the interface between lightningd and the bwatch plugin.
 * It manages a pending operation queue to ensure reliable delivery of
 * watch add/delete requests to bwatch, even across crashes.
 *
 * Architecture:
 * - Subsystems (channel, onchaind, wallet) call watchman_add/watchman_del
 * - Watchman queues operations and sends them to bwatch via RPC
 * - Operations stay in queue until bwatch acknowledges them
 * - On crash/restart, pending ops are replayed from datastore
 * - Bwatch handles duplicate operations idempotently
 */

/* A pending operation - just the raw JSON params to send to bwatch */
struct pending_op {
	const char *op_id;       /* "add:{owner}" or "del:{owner}" */
	const char *json_params; /* The JSON params to send to bwatch */
};

struct watchman {
	struct lightningd *ld;
	u32 last_processed_height;
	struct pending_op **pending_ops;  /* Array of pending operations */
};

struct watchman *watchman_new(const tal_t *ctx, struct lightningd *ld)
{
	struct watchman *wm = tal(ctx, struct watchman);

	wm->ld = ld;
	wm->last_processed_height = db_get_intvar(ld->wallet->db,
						  "last_watchman_block_height", 0);
	wm->pending_ops = tal_arr(wm, struct pending_op *, 0);

	/* TODO: load_pending_ops(wm); */

	log_info(ld->log, "Watchman: height=%u, %zu pending ops",
		 wm->last_processed_height, tal_count(wm->pending_ops));

	return wm;
}
