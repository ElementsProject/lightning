#ifndef LIGHTNING_LIGHTNINGD_COIN_MVTS_H
#define LIGHTNING_LIGHTNINGD_COIN_MVTS_H
#include "config.h"

#include <common/coin_mvt.h>
#include <lightningd/lightningd.h>

void notify_channel_mvt(struct lightningd *ld, const struct channel_coin_mvt *mvt);
void notify_chain_mvt(struct lightningd *ld, const struct chain_coin_mvt *mvt);

/* Initialize the coin movement counter on lightningd */
void coin_mvts_init_count(struct lightningd *ld);
#endif /* LIGHTNING_LIGHTNINGD_COIN_MVTS_H */
