#ifndef LIGHTNING_PLUGINS_BWATCH_BWATCH_INTERFACE_H
#define LIGHTNING_PLUGINS_BWATCH_BWATCH_INTERFACE_H

#include "config.h"
#include <plugins/bwatch/bwatch.h>

/* Outward-facing interface from bwatch to lightningd. */

/* Send watch_found notification to lightningd */
void bwatch_send_watch_found(struct command *cmd,
			     const struct bitcoin_tx *tx,
			     u32 blockheight,
			     const struct watch *w,
			     u32 txindex,
			     u32 index);

void bwatch_send_watch_revert(struct command *cmd,
			      const char *owner,
			      u32 blockheight);

/* Send a block_processed RPC to watchman after a new block has been
 * persisted.  The next poll is started from the ack callback so we don't
 * race ahead of watchman's view of the chain.  Chains on the same poll
 * command so timer_complete fires once watchman has acknowledged. */
struct command_result *bwatch_send_block_processed(struct command *cmd);

/* Notify watchman that the tip has been rolled back during a reorg, so
 * watchman can update and persist its own height.  Fire-and-forget via
 * an aux_command — the poll timer doesn't depend on this ack.  Crash
 * safety: if we crash before the ack lands, watchman's stale height will
 * be higher than bwatch's on restart, which retriggers the rollback. */
void bwatch_send_revert_block_processed(struct command *cmd, u32 new_height,
					const struct bitcoin_blkid *new_hash);

#endif /* LIGHTNING_PLUGINS_BWATCH_BWATCH_INTERFACE_H */
