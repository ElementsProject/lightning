#ifndef LIGHTNING_PLUGINS_BWATCH_BWATCH_SCANNER_H
#define LIGHTNING_PLUGINS_BWATCH_BWATCH_SCANNER_H

#include "config.h"
#include "bwatch.h"

/* Process all transactions in a block against watches */
void bwatch_process_block_txs(struct command *cmd,
			      struct bwatch *bwatch,
			      const struct bitcoin_block *block,
			      u32 blockheight,
			      const struct bitcoin_blkid *blockhash,
			      const struct watch *w);

#endif /* LIGHTNING_PLUGINS_BWATCH_BWATCH_SCANNER_H */
