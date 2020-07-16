#ifndef LIGHTNING_COMMON_UTXO_H
#define LIGHTNING_COMMON_UTXO_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/shadouble.h>
#include <bitcoin/tx.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>
#include <common/node_id.h>
#include <stdbool.h>

struct ext_key;

/* Information needed for their_unilateral/to-us outputs */
struct unilateral_close_info {
	u64 channel_id;
	struct node_id peer_id;
	/* NULL if this is an option_static_remotekey commitment */
	struct pubkey *commitment_point;
};

/* Possible states for tracked outputs in the database. Not sure yet
 * whether we really want to have reservations reflected in the
 * database, it would simplify queries at the cost of some IO ops */
/* /!\ This is a DB ENUM, please do not change the numbering of any
 * already defined elements (adding is ok) /!\ */
enum output_status {
	OUTPUT_STATE_AVAILABLE = 0,
	OUTPUT_STATE_RESERVED = 1,
	OUTPUT_STATE_SPENT = 2,
	/* Special status used to express that we don't care in
	 * queries */
	OUTPUT_STATE_ANY = 255
};

struct utxo {
	struct bitcoin_txid txid;
	u32 outnum;
	struct amount_sat amount;
	u32 keyindex;
	bool is_p2sh;
	enum output_status status;

	/* Optional unilateral close information, NULL if this is just
	 * a HD key */
	struct unilateral_close_info *close_info;

	/* NULL if we haven't seen it in a block, otherwise the block it's in */
	const u32 *blockheight;

	/* NULL if not spent yet, otherwise, the block the spending transaction is in */
	const u32 *spendheight;

	/* Block this utxo becomes unreserved, if applicable */
	u32 reserved_til;

	/* The scriptPubkey if it is known */
	u8 *scriptPubkey;
};

/* We lazy-evaluate whether a utxo is really still reserved. */
static inline bool utxo_is_reserved(const struct utxo *utxo, u32 current_height)
{
	if (utxo->status != OUTPUT_STATE_RESERVED)
		return false;

	return utxo->reserved_til > current_height;
}

void towire_utxo(u8 **pptr, const struct utxo *utxo);
struct utxo *fromwire_utxo(const tal_t *ctx, const u8 **ptr, size_t *max);

/* Estimate of (signed) UTXO weight in transaction */
size_t utxo_spend_weight(const struct utxo *utxo);
#endif /* LIGHTNING_COMMON_UTXO_H */
