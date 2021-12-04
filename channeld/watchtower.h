#ifndef LIGHTNING_CHANNELD_WATCHTOWER_H
#define LIGHTNING_CHANNELD_WATCHTOWER_H
#include "config.h"
#include <common/initial_channel.h>

const struct bitcoin_tx *
penalty_tx_create(const tal_t *ctx,
		  const struct channel *channel,
		  u32 penalty_feerate,
		  u8 *final_scriptpubkey,
		  const struct secret *revocation_preimage,
		  const struct bitcoin_txid *commitment_txid,
		  s16 to_them_outnum, struct amount_sat to_them_sats,
		  int hsm_fd);

#endif /* LIGHTNING_CHANNELD_WATCHTOWER_H */
