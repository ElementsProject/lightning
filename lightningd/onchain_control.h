#ifndef LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#define LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <lightningd/lightningd.h>
#include <onchaind/onchaind_wiregen.h>

struct channel;
struct bitcoin_tx;
struct block;

enum watch_result onchaind_funding_spent(struct channel *channel,
					 const struct bitcoin_tx *tx,
					 u32 blockheight,
					 bool is_replay);

void onchaind_replay_channels(struct lightningd *ld);

#endif /* LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H */
