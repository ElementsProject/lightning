#ifndef LIGHTNING_COMMON_CLOSE_TX_H
#define LIGHTNING_COMMON_CLOSE_TX_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct pubkey;

/* Create close tx to spend the anchor tx output; doesn't fill in
 * input scriptsig. */
struct bitcoin_tx *create_close_tx(const tal_t *ctx,
				   const u8 *our_script,
				   const u8 *their_script,
				   const struct bitcoin_txid *anchor_txid,
				   unsigned int anchor_index,
				   u64 anchor_satoshis,
				   uint64_t to_us, uint64_t to_them,
				   uint64_t dust_limit);
#endif /* LIGHTNING_COMMON_CLOSE_TX_H */
