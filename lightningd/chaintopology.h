#ifndef LIGHTNING_LIGHTNINGD_CHAINTOPOLOGY_H
#define LIGHTNING_LIGHTNINGD_CHAINTOPOLOGY_H
#include "config.h"
#include <lightningd/broadcast.h>
#include <lightningd/feerate.h>

struct bitcoin_tx;
struct bitcoind;
struct command;
struct lightningd;
struct peer;
struct wallet;

struct chain_topology {
	struct lightningd *ld;

	/* Where to log things. */
	struct logger *log;
};

/* Information relevant to locating a TX in a blockchain. */
struct txlocator {

	/* The height of the block that includes this transaction */
	u32 blkheight;

	/* Position of the transaction in the transactions list */
	u32 index;
};

struct chain_topology *new_topology(struct lightningd *ld, struct logger *log);

#endif /* LIGHTNING_LIGHTNINGD_CHAINTOPOLOGY_H */
