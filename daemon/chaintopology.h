#ifndef LIGHTNING_DAEMON_CHAINTOPOLOGY_H
#define LIGHTNING_DAEMON_CHAINTOPOLOGY_H
#include "config.h"
#include <stddef.h>

struct lightningd_state;
struct txwatch;

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

/* Broadcast a single tx, and rebroadcast as reqd (takes ownership of tx) */
void broadcast_tx(struct peer *peer, const struct bitcoin_tx *tx);

void setup_topology(struct lightningd_state *dstate);

#endif /* LIGHTNING_DAEMON_CRYPTOPKT_H */
