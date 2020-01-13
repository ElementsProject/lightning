#ifndef LIGHTNING_LIGHTNINGD_CHANNEL_STATE_H
#define LIGHTNING_LIGHTNINGD_CHANNEL_STATE_H
#include "config.h"

/* These are in the database, so don't renumber them! */
enum channel_state {
	/* In channeld, still waiting for lockin. */
	CHANNELD_AWAITING_LOCKIN = 2,

	/* Normal operating state. */
	CHANNELD_NORMAL,

	/* We are closing, pending HTLC resolution. */
	CHANNELD_SHUTTING_DOWN,

	/* Exchanging signatures on closing tx. */
	CLOSINGD_SIGEXCHANGE,

	/* Waiting for onchain event. */
	CLOSINGD_COMPLETE,

	/* Waiting for unilateral close to hit blockchain. */
	AWAITING_UNILATERAL,

	/* We've seen the funding spent, we're waiting for onchaind. */
	FUNDING_SPEND_SEEN,

	/* On chain */
	ONCHAIN,

	/* Final state after we have fully settled on-chain. Can
	 * also reach this state if opening transaction gets borked
	 * (i.e. is never on chain) */
	CLOSED,

	/* A funding input has been spent in a different tx, will never open.
	 * Waiting for input to get sunk to 6 before deleting/marking CLOSED */
	CHANNELD_BORKED
};
#define CHANNEL_STATE_MAX CLOSED

#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_STATE_H */
