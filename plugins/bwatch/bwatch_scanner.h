#ifndef LIGHTNING_PLUGINS_BWATCH_BWATCH_SCANNER_H
#define LIGHTNING_PLUGINS_BWATCH_BWATCH_SCANNER_H

#include "config.h"
#include <plugins/bwatch/bwatch.h>

/* Scan a block against scriptpubkey and outpoint watches, firing
 * watch_found for each match. If `w` is NULL all active watches are
 * checked (normal polling); if non-NULL only that watch is checked
 * (single-watch rescan). */
void bwatch_process_block_txs(struct command *cmd,
			      struct bwatch *bwatch,
			      const struct bitcoin_block *block,
			      u32 blockheight,
			      const struct bitcoin_blkid *blockhash,
			      const struct watch *w);

/* Fire watch_found for scid watches anchored to this block.
 * w==NULL walks every scid watch (normal polling); w non-NULL
 * fires only that watch (single-watch rescan). */
void bwatch_check_scid_watches(struct command *cmd,
			       struct bwatch *bwatch,
			       const struct bitcoin_block *block,
			       u32 blockheight,
			       const struct watch *w);

/* Fire depth notifications for every active blockdepth watch at
 * new_height. Called once per new block on the happy path. */
void bwatch_check_blockdepth_watches(struct command *cmd,
				     struct bwatch *bwatch,
				     u32 new_height);

#endif /* LIGHTNING_PLUGINS_BWATCH_BWATCH_SCANNER_H */
