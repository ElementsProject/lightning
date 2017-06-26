#ifndef LIGHTNING_LIGHTNINGD_PEER_STATE_H
#define LIGHTNING_LIGHTNINGD_PEER_STATE_H
#include "config.h"

enum peer_state {
	UNINITIALIZED,

	/* In gossip daemon. */
	GOSSIPD,

	/* Negotiating channel opening: in opening daemon */
	OPENINGD,

	/* In channeld, still waiting for lockin. */
	CHANNELD_AWAITING_LOCKIN,

	/* Normal operating state. */
	CHANNELD_NORMAL,

	/* We are closing, pending HTLC resolution. */
	CHANNELD_SHUTTING_DOWN,

	/* Exchanging signatures on closing tx. */
	CLOSINGD_SIGEXCHANGE,

	/* Various onchain states. */
	ONCHAIND_CHEATED,
	ONCHAIND_THEIR_UNILATERAL,
	ONCHAIND_OUR_UNILATERAL,
	ONCHAIND_MUTUAL
};

#endif /* LIGHTNING_LIGHTNINGD_PEER_STATE_H */
