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

struct utxo {
	struct bitcoin_txid txid;
	u32 outnum;
	struct amount_sat amount;
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

	/* Block this utxo becomes unreserved, if applicable */
	u32 *reserved_til;

	/* The scriptPubkey if it is known */
	u8 *scriptPubkey;

	/* scriptSig. Only for P2SH outputs */
	u8 *scriptSig;
};

void towire_utxo(u8 **pptr, const struct utxo *utxo);
struct utxo *fromwire_utxo(const tal_t *ctx, const u8 **ptr, size_t *max);

/* Create a tx, and populate inputs from utxos */
struct bitcoin_tx *tx_spending_utxos(const tal_t *ctx,
				     const struct chainparams *chainparams,
				     const struct utxo **utxos,
				     const struct ext_key *bip32_base,
				     bool add_change_output,
				     size_t num_output,
				     u32 nlocktime,
				     u32 nsequence);

/* Estimate of (signed) UTXO weight in transaction */
size_t utxo_spend_weight(const struct utxo *utxo);
#endif /* LIGHTNING_COMMON_UTXO_H */
