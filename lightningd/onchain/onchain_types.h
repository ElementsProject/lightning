#ifndef LIGHTNING_LIGHTNINGD_ONCHAIN_TYPES_H
#define LIGHTNING_LIGHTNINGD_ONCHAIN_TYPES_H
#include "config.h"

/* Different transactions we care about. */
enum tx_type {
	/* The initial 2 of 2 funding transaction */
	FUNDING_TRANSACTION,

	/* A mutual close: spends funding */
	MUTUAL_CLOSE,

	/* Their unilateral: spends funding */
	THEIR_UNILATERAL,

	/* Our unilateral: spends funding */
	OUR_UNILATERAL,

	/* The 2 different types of HTLC transaction, each way */
	THEIR_HTLC_TIMEOUT_TO_THEM,
	THEIR_HTLC_FULFILL_TO_US,
	OUR_HTLC_TIMEOUT_TO_US,
	OUR_HTLC_FULFILL_TO_THEM,

	/* When we spend the to-us output (after cltv_expiry) */
	OUR_UNILATERAL_TO_US_RETURN_TO_WALLET,

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

	/* OUR_UNILATERAL */
	DELAYED_OUTPUT_TO_US,
	OUTPUT_TO_THEM,

	/* HTLC outputs: their offers and our offers */
	THEIR_HTLC,
	OUR_HTLC,
};


#endif /* LIGHTNING_LIGHTNINGD_ONCHAIN_TYPES_H */
