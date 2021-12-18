#ifndef LIGHTNING_COMMON_UTXO_H
#define LIGHTNING_COMMON_UTXO_H
#include "config.h"
#include <assert.h>
#include <bitcoin/tx.h>
#include <common/node_id.h>

struct ext_key;

/* Information needed for their_unilateral/to-us outputs */
struct unilateral_close_info {
	u64 channel_id;
	struct node_id peer_id;
	bool option_anchor_outputs;
	/* NULL if this is an option_static_remotekey commitment */
	struct pubkey *commitment_point;
	u32 csv;
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
	struct bitcoin_outpoint outpoint;
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

static inline bool utxo_is_csv_locked(const struct utxo *utxo, u32 current_height)
{
	if (!utxo->close_info)
		return false;
	/* All close outputs are csv locked for option_anchor_outputs */
	if (!utxo->blockheight && utxo->close_info->option_anchor_outputs)
		return true;
	assert(*utxo->blockheight + utxo->close_info->csv > *utxo->blockheight);
	return *utxo->blockheight + utxo->close_info->csv > current_height;
}

void towire_utxo(u8 **pptr, const struct utxo *utxo);
struct utxo *fromwire_utxo(const tal_t *ctx, const u8 **ptr, size_t *max);

/* Estimate of (signed) UTXO weight in transaction */
size_t utxo_spend_weight(const struct utxo *utxo, size_t min_witness_weight);
#endif /* LIGHTNING_COMMON_UTXO_H */
