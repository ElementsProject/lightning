#ifndef LIGHTNING_COMMON_CLOSE_TX_H
#define LIGHTNING_COMMON_CLOSE_TX_H
#include "config.h"
#include <bitcoin/tx.h>

struct ext_key;

/* Create close tx to spend the anchor tx output; doesn't fill in
 * input scriptsig. */
struct bitcoin_tx *create_close_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   u32 *local_wallet_index,
				   const struct ext_key *local_wallet_ext_key,
				   const u8 *our_script,
				   const u8 *their_script,
				   const u8 *funding_wscript,
				   const struct bitcoin_outpoint *funding,
				   struct amount_sat funding_sats,
				   struct amount_sat to_us,
				   struct amount_sat to_them,
				   struct amount_sat dust_limit);
/* Create simple close tx (option_simple_close) to spend the anchor tx output.
 * The closer pays the fee; closee output is omitted if closee_script is NULL.
 * Closer output is omitted if closer_script is NULL (or OP_RETURN with amount 0).
 * Uses sequence 0xFFFFFFFD (RBF) and the specified locktime. */
struct bitcoin_tx *create_simple_close_tx(const tal_t *ctx,
					  const struct chainparams *chainparams,
					  u32 *local_wallet_index,
					  const struct ext_key *local_wallet_ext_key,
					  const u8 *closer_script,
					  const u8 *closee_script,
					  const u8 *funding_wscript,
					  const struct bitcoin_outpoint *funding,
					  struct amount_sat funding_sats,
					  struct amount_sat closer_amount,
					  struct amount_sat closee_amount,
					  u32 locktime);
#endif /* LIGHTNING_COMMON_CLOSE_TX_H */
