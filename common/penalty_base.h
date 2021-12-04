#ifndef LIGHTNING_COMMON_PENALTY_BASE_H
#define LIGHTNING_COMMON_PENALTY_BASE_H
#include "config.h"
#include <bitcoin/tx.h>

/* To create a penalty, all we need are these. */
struct penalty_base {
	/* The remote commitment index. */
	u64 commitment_num;
	/* The remote commitment txid. */
	struct bitcoin_txid txid;
	/* The remote commitment's "to-local" output. */
	u32 outnum;
	/* The amount of the remote commitment's "to-local" output. */
	struct amount_sat amount;
};

/* txout must be within tx! */
struct penalty_base *penalty_base_new(const tal_t *ctx,
				      u64 commitment_num,
				      const struct bitcoin_tx *tx,
				      const struct wally_tx_output *txout);

void towire_penalty_base(u8 **pptr, const struct penalty_base *pbase);
void fromwire_penalty_base(const u8 **ptr, size_t *max,
			   struct penalty_base *pbase);

#endif /* LIGHTNING_COMMON_PENALTY_BASE_H */
