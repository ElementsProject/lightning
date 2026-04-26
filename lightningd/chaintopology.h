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

	/* Timers we're running. */
	struct oneshot *checkchain_timer;

	/* The number of headers known to the bitcoin backend at startup. Not
	 * updated after the initial check. */
	u32 headercount;
};

/* Information relevant to locating a TX in a blockchain. */
struct txlocator {

	/* The height of the block that includes this transaction */
	u32 blkheight;

	/* Position of the transaction in the transactions list */
	u32 index;
};

/* Get highest block number. */
u32 get_block_height(const struct chain_topology *topo);

/* Get the highest block number in the network that we are aware of. Unlike
 * `get_block_height` this takes into consideration the block header counter
 * in the bitcoin backend as well. If an absolute time is required, rather
 * than our current scan position this is preferable since it is far less
 * likely to lag behind the rest of the network.*/
u32 get_network_blockheight(const struct chain_topology *topo);

struct chain_topology *new_topology(struct lightningd *ld, struct logger *log);
void setup_topology(struct chain_topology *topology);

void begin_topology(struct chain_topology *topo);

void stop_topology(struct chain_topology *topo);

#endif /* LIGHTNING_LIGHTNINGD_CHAINTOPOLOGY_H */
