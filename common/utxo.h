#ifndef LIGHTNING_COMMON_UTXO_H
#define LIGHTNING_COMMON_UTXO_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/shadouble.h>
#include <bitcoin/tx.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>

/* Information needed for their_unilateral/to-us outputs */
struct unilateral_close_info {
	u64 channel_id;
	struct pubkey peer_id;
	struct pubkey commitment_point;
};

struct utxo {
	struct bitcoin_txid txid;
	u32 outnum;
	u64 amount;
	u32 keyindex;
	bool is_p2sh;
	u8 status;

	/* Optional unilateral close information, NULL if this is just
	 * a HD key */
	struct unilateral_close_info *close_info;

	/* NULL if we haven't seen it in a block, otherwise the block it's in */
	const u32 *blockheight;

	/* NULL if not spent yet, otherwise, the block the spending transaction is in */
	const u32 *spendheight;
};

void towire_utxo(u8 **pptr, const struct utxo *utxo);
struct utxo *fromwire_utxo(const tal_t *ctx, const u8 **ptr, size_t *max);
#endif /* LIGHTNING_COMMON_UTXO_H */
