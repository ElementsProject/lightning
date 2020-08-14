#ifndef LIGHTNING_ONCHAIND_ONCHAIN_TYPES_H
#define LIGHTNING_ONCHAIND_ONCHAIN_TYPES_H
#include "config.h"

/* Different transactions we care about. */
enum tx_type {
	/* The initial 2 of 2 funding transaction */
	FUNDING_TRANSACTION,

	/* A mutual close: spends funding */
	MUTUAL_CLOSE,

	/* Their unilateral: spends funding */
	THEIR_UNILATERAL,

	/* Unknown unilateral (presumably theirs): spends funding */
	UNKNOWN_UNILATERAL,

	/* Our unilateral: spends funding */
	OUR_UNILATERAL,

	/* Their old unilateral: spends funding */
	THEIR_REVOKED_UNILATERAL,

	/* The 2 different types of HTLC transaction, each way */
	THEIR_HTLC_TIMEOUT_TO_THEM,
	THEIR_HTLC_FULFILL_TO_US,
	OUR_HTLC_TIMEOUT_TO_US,
	OUR_HTLC_FULFILL_TO_THEM,

	/* Delayed variants */
	OUR_HTLC_TIMEOUT_TX,
	OUR_HTLC_SUCCESS_TX,

	/* When we spend a delayed output (after cltv_expiry) */
	OUR_DELAYED_RETURN_TO_WALLET,

	/* When they spend a delayed output we were attempting to steal */
	THEIR_DELAYED_CHEAT,

	/* When we use revocation key to take output. */
	OUR_PENALTY_TX,

	/* Amount too small, we're just spending it to close UTXO */
	IGNORING_TINY_PAYMENT,

	/* Special type for marking outputs as resolved by self. */
	SELF,

	/* Shouldn't happen. */
	UNKNOWN_TXTYPE
};

/* Different output types. */
enum output_type {
	/* FUNDING_TRANSACTION */
	FUNDING_OUTPUT,

	/* THEIR_UNILATERAL */
	OUTPUT_TO_US,
	DELAYED_OUTPUT_TO_THEM,

	/* THEIR_REVOKED_UNILATERAL (they shouldn't be able to claim these) */
	DELAYED_CHEAT_OUTPUT_TO_THEM,

	/* OUR_UNILATERAL, or OUR_HTLC_TIMEOUT_TX */
	DELAYED_OUTPUT_TO_US,
	OUTPUT_TO_THEM,

	/* HTLC outputs: their offers and our offers */
	THEIR_HTLC,
	OUR_HTLC,

	/* For elements we need a fee output type */
	ELEMENTS_FEE,

	/* Anchor outputs for option_anchor_outputs */
	ANCHOR_TO_US,
	ANCHOR_TO_THEM,
};


#endif /* LIGHTNING_ONCHAIND_ONCHAIN_TYPES_H */
