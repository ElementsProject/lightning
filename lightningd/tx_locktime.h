#ifndef LIGHTNING_LIGHTNINGD_TX_LOCKTIME_H
#define LIGHTNING_LIGHTNINGD_TX_LOCKTIME_H

#include "config.h"
#include <lightningd/chaintopology.h>

/* Tue Nov 5 00:53:20 1985 UTC */
#define LOCKTIME_THRESHOLD 500000000

/* locktime_for_new_tx - given a current height, return the locktime
 *                       a new tx should lock to
 *
 * meant to 1) discourage fee sniping on the miner's part and 2)
 * mimic the logic of bitcoind's locktime selection
 *
 * note that if our chain is lagging behind tip, we use zero to
 * prevent leaking a 'locktime fingerprint'
 */
u32 locktime_for_new_tx(struct chain_topology *topology);

#endif /* LIGHTNING_LIGHTNINGD_TX_LOCKTIME_H */
