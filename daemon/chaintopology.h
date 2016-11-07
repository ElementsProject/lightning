#ifndef LIGHTNING_DAEMON_CHAINTOPOLOGY_H
#define LIGHTNING_DAEMON_CHAINTOPOLOGY_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stddef.h>

struct bitcoin_tx;
struct lightningd_state;
struct peer;
struct sha256_double;
struct txwatch;

/* Information relevant to locating a TX in a blockchain. */
struct txlocator {

	/* The height of the block that includes this transaction */
	u32 blkheight;

	/* Position of the transaction in the transactions list */
	u32 index;
};

/* This is the number of blocks which would have to be mined to invalidate
 * the tx. */
size_t get_tx_depth(struct lightningd_state *dstate,
		    const struct sha256_double *txid);

/* Get the mediantime of the block including this tx (must be one!) */
u32 get_tx_mediantime(struct lightningd_state *dstate,
		      const struct sha256_double *txid);

/* Get mediantime of the tip; if more than one, pick greatest time. */
u32 get_tip_mediantime(struct lightningd_state *dstate);

/* Get highest block number. */
u32 get_block_height(struct lightningd_state *dstate);

/* Get fee rate. */
u64 get_feerate(struct lightningd_state *dstate);

/* Broadcast a single tx, and rebroadcast as reqd (copies tx). */
void broadcast_tx(struct peer *peer, const struct bitcoin_tx *tx);

void setup_topology(struct lightningd_state *dstate);

struct txlocator *locate_tx(const void *ctx, struct lightningd_state *dstate, const struct sha256_double *txid);

#endif /* LIGHTNING_DAEMON_CRYPTOPKT_H */
