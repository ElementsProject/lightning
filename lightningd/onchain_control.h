#ifndef LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#define LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#include "config.h"
#include <lightningd/lightningd.h>

struct channel;
struct bitcoin_tx;
struct block;

enum watch_result onchaind_funding_spent(struct channel *channel,
					 const struct bitcoin_tx *tx,
					 u32 blockheight);

void onchaind_replay_channels(struct lightningd *ld);

/* Tear down all bwatch watches that onchaind registered for this channel.
 * Called when the funding-spend tx is reorged out (channel is no longer
 * closing) or when we lose track of an onchaind session for any reason. */
void onchaind_clear_watches(struct channel *channel);

#endif /* LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H */
