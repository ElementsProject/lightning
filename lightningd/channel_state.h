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

	/* We've seen the funding spent, we're waiting for onchaind. */
	FUNDING_SPEND_SEEN,

	/* On chain */
	ONCHAIN
};
#define CHANNEL_STATE_MAX ONCHAIN

#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_STATE_H */
