#ifndef LIGHTNING_PLUGINS_BWATCH_BWATCH_SCANNER_H
#define LIGHTNING_PLUGINS_BWATCH_BWATCH_SCANNER_H

#include "config.h"
#include <plugins/bwatch/bwatch.h>

/* Scan every transaction in a block against the active scriptpubkey
 * and outpoint watches, firing watch_found for each match. */
void bwatch_process_block_txs(struct command *cmd,
			      struct bwatch *bwatch,
			      const struct bitcoin_block *block,
			      u32 blockheight,
			      const struct bitcoin_blkid *blockhash);

#endif /* LIGHTNING_PLUGINS_BWATCH_BWATCH_SCANNER_H */
