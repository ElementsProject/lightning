#ifndef LIGHTNING_LIGHTNINGD_PEER_STATE_H
#define LIGHTNING_LIGHTNINGD_PEER_STATE_H
#include "config.h"

enum peer_state {
	/* Not important: we can forget about peers in these states. */
	INITIALIZING,
	GOSSIPING,

	/* Negotiating channel opening */
	OPENING_NOT_LOCKED,
	/* Waiting for funding tx to lock in. */
	OPENING_AWAITING_LOCKIN,
	/* Opening, have received funding_locked (not sent). */
	OPENING_RCVD_LOCKED,
	/* Opening, have sent funding_locked (not received). */
	OPENING_SENT_LOCKED,

	/* Normal operating state. */
	NORMAL,

	/* We are closing, pending HTLC resolution. */
	SHUTDOWN_SENT,
	/* Both are closing, pending HTLC resolution. */
	SHUTDOWN_RCVD,

	/* Exchanging signatures on closing tx. */
	CLOSING_SIGEXCHANGE,

	/* Various onchain states. */
	ONCHAIN_CHEATED,
	ONCHAIN_THEIR_UNILATERAL,
	ONCHAIN_OUR_UNILATERAL,
	ONCHAIN_MUTUAL
};

#endif /* LIGHTNING_LIGHTNINGD_PEER_STATE_H */
