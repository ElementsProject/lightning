#ifndef LIGHTNING_COMMON_CLOSE_TX_H
#define LIGHTNING_COMMON_CLOSE_TX_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/tx.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>

struct pubkey;

/* Create close tx to spend the anchor tx output; doesn't fill in
 * input scriptsig. */
struct bitcoin_tx *create_close_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   const u8 *our_script,
				   const u8 *their_script,
				   const u8 *funding_wscript,
				   const struct bitcoin_txid *anchor_txid,
				   unsigned int anchor_index,
				   struct amount_sat funding,
				   struct amount_sat to_us,
				   struct amount_sat to_them,
				   struct amount_sat dust_limit);
#endif /* LIGHTNING_COMMON_CLOSE_TX_H */
