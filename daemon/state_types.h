#ifndef LIGHTNING_STATE_TYPES_H
#define LIGHTNING_STATE_TYPES_H
#include "config.h"
/* FIXME: cdump is really dumb, so we put these in their own header. */
#include "lightning.pb-c.h"

enum state {
	STATE_INIT,

	/*
	 * Opening.
	 */
	STATE_OPEN_WAIT_FOR_OPENPKT,
	STATE_OPEN_WAIT_FOR_ANCHORPKT,
	STATE_OPEN_WAIT_FOR_COMMIT_SIGPKT,

	/* We're waiting for depth+their complete. */
	STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE,
	/* Got their pkt_complete. */
	STATE_OPEN_WAIT_ANCHORDEPTH,
	/* Got anchor depth. */
	STATE_OPEN_WAIT_THEIRCOMPLETE,

	/*
	 * Normal state.
	 */
	STATE_NORMAL,
	STATE_NORMAL_COMMITTING,

	/*
	 * Closing (handled outside state machine).
	 */
	STATE_SHUTDOWN,
	STATE_SHUTDOWN_COMMITTING,
	STATE_MUTUAL_CLOSING,

	/* Four states to represent closing onchain (for getpeers) */
	STATE_CLOSE_ONCHAIN_CHEATED,
	STATE_CLOSE_ONCHAIN_THEIR_UNILATERAL,
	STATE_CLOSE_ONCHAIN_OUR_UNILATERAL,
	STATE_CLOSE_ONCHAIN_MUTUAL,

	/* All closed. */
	STATE_CLOSED,

	/*
	 * Where angels fear to tread.
	 */
	/* Bad packet from them / protocol breakdown. */
	STATE_ERR_BREAKDOWN,
	/* The anchor didn't reach blockchain in reasonable time. */
	STATE_ERR_ANCHOR_TIMEOUT,
	/* We saw a tx we didn't sign. */
	STATE_ERR_INFORMATION_LEAK,
	/* We ended up in an unexpected state. */
	STATE_ERR_INTERNAL,

	STATE_MAX
};

enum state_input {
	/*
	 * Packet inputs.
	 */
	PKT_OPEN = PKT__PKT_OPEN,
	PKT_OPEN_ANCHOR = PKT__PKT_OPEN_ANCHOR,
	PKT_OPEN_COMMIT_SIG = PKT__PKT_OPEN_COMMIT_SIG,
	PKT_OPEN_COMPLETE = PKT__PKT_OPEN_COMPLETE,

	/* Updating the commit transaction: new HTLC */
	PKT_UPDATE_ADD_HTLC = PKT__PKT_UPDATE_ADD_HTLC,
	/* Updating the commit transaction: I have your R value! */
	PKT_UPDATE_FULFILL_HTLC = PKT__PKT_UPDATE_FULFILL_HTLC,
	/* Updating the commit transaction: your HTLC failed upstream */
	PKT_UPDATE_FAIL_HTLC = PKT__PKT_UPDATE_FAIL_HTLC,

	/* Committing updates */
	PKT_UPDATE_COMMIT = PKT__PKT_UPDATE_COMMIT,
	PKT_UPDATE_REVOCATION = PKT__PKT_UPDATE_REVOCATION,

	/* If they want to close. */
	PKT_CLOSE_SHUTDOWN = PKT__PKT_CLOSE_SHUTDOWN,

	/* Something unexpected went wrong. */
	PKT_ERROR = PKT__PKT_ERROR,

	/*
	 * Non-packet inputs.
	 */
	INPUT_NONE,

	/*
	 * Timeouts.
	 */
	INPUT_CLOSE_COMPLETE_TIMEOUT,

	INPUT_MAX
};
#endif /* LIGHTNING_STATE_TYPES_H */
