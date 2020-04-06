#ifndef LIGHTNING_LIGHTNINGD_WATCHTOWER_H
#define LIGHTNING_LIGHTNINGD_WATCHTOWER_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/derive_basepoints.h>
#include <lightningd/lightningd.h>

const struct bitcoin_tx *
penalty_tx_create(const tal_t *ctx, struct lightningd *ld,
		  const struct channel *channel,
		  const struct secret *revocation_preimage,
		  const struct bitcoin_txid *commitment_txid,
		  s16 to_them_outnum, struct amount_sat to_them_sats);

#endif /* LIGHTNING_LIGHTNINGD_WATCHTOWER_H */
