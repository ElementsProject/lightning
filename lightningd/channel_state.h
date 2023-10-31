#ifndef LIGHTNING_LIGHTNINGD_CHANNEL_STATE_H
#define LIGHTNING_LIGHTNINGD_CHANNEL_STATE_H
#include "config.h"

#include <ccan/time/time.h>

/* These are in the database, so don't renumber them! */
enum channel_state {
	/* For dual-funded channels: goes to DUALOPEND_OPEN_COMMITTED
	 * after sigs have been exchanged */
	DUALOPEND_OPEN_INIT = 1,

	/* In channeld, still waiting for lockin. */
	CHANNELD_AWAITING_LOCKIN,

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

	/* Dual-funded initialized and committed. */
	DUALOPEND_OPEN_COMMITTED,

	/* Dual-funded channel, waiting for lock-in */
	DUALOPEND_AWAITING_LOCKIN,

	/* Channel has started splice and is awaiting lock-in */
	CHANNELD_AWAITING_SPLICE,

	/* Dual-funded channel initial commitment ready */
	DUALOPEND_OPEN_COMMIT_READY,

};
#define CHANNEL_STATE_MAX CHANNELD_AWAITING_SPLICE

/* These are in the database, so don't renumber them! */
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
