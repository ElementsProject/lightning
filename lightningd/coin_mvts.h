#ifndef LIGHTNING_LIGHTNINGD_COIN_MVTS_H
#define LIGHTNING_LIGHTNINGD_COIN_MVTS_H
#include "config.h"

#include <common/coin_mvt.h>
#include <lightningd/channel.h>
#include <lightningd/htlc_end.h>
#include <lightningd/lightningd.h>

void notify_channel_mvt(struct lightningd *ld, const struct channel_coin_mvt *mvt);
void notify_chain_mvt(struct lightningd *ld, const struct chain_coin_mvt *mvt);

struct channel_coin_mvt *new_channel_mvt_invoice_hin(const tal_t *ctx,
						     struct htlc_in *hin,
						     struct channel *channel);
struct channel_coin_mvt *new_channel_mvt_routed_hin(const tal_t *ctx,
						    struct htlc_in *hin,
						    struct channel *channel);
struct channel_coin_mvt *new_channel_mvt_invoice_hout(const tal_t *ctx,
						      struct htlc_out *hout,
						      struct channel *channel);
struct channel_coin_mvt *new_channel_mvt_routed_hout(const tal_t *ctx,
						     struct htlc_out *hout,
						     struct channel *channel);

/* Initialize the coin movement counter on lightningd */
void coin_mvts_init_count(struct lightningd *ld);
#endif /* LIGHTNING_LIGHTNINGD_COIN_MVTS_H */
