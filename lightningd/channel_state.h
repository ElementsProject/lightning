#ifndef LIGHTNING_LIGHTNINGD_CHANNEL_STATE_H
#define LIGHTNING_LIGHTNINGD_CHANNEL_STATE_H
#include "config.h"

#include <ccan/time/time.h>

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

	/* Final state after we have fully settled on-chain */
	CLOSED,

	/* For dual-funded channels, we start at a different state.
	 * We transition to 'awaiting lockin' after sigs have
	 * been exchanged */
	DUALOPEND_OPEN_INIT,

	/* Dual-funded channel, waiting for lock-in */
	DUALOPEND_AWAITING_LOCKIN,
};
#define CHANNEL_STATE_MAX DUALOPEND_AWAITING_LOCKIN

enum state_change {
	/* Anything other than the reasons below. Should not happen. */
	REASON_UNKNOWN,

	/* Unconscious internal reasons, e.g. dev fail of a channel. */
	REASON_LOCAL,

	/* The operator or a plugin opened or closed a channel by intention. */
	REASON_USER,

	/* The remote closed or funded a channel with us by intention. */
	REASON_REMOTE,

	/* E.g. We need to close a channel because of bad signatures and such. */
	REASON_PROTOCOL,

	/* A channel was closed onchain, while we were offline. */
	/* Note: This is very likely a conscious remote decision. */
	REASON_ONCHAIN
};

struct state_change_entry {
	struct timeabs timestamp;
	enum channel_state old_state;
	enum channel_state new_state;
	enum state_change cause;
	char *message;
};

#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_STATE_H */
