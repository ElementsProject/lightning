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
	STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR,
	STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR,
	STATE_OPEN_WAIT_FOR_ANCHOR_CREATE,
	STATE_OPEN_WAIT_FOR_ANCHOR,
	STATE_OPEN_WAIT_FOR_COMMIT_SIG,
	STATE_OPEN_WAITING_OURANCHOR,
	STATE_OPEN_WAITING_THEIRANCHOR,
	STATE_OPEN_WAITING_OURANCHOR_THEYCOMPLETED,
	STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED,
	STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR,
	STATE_OPEN_WAIT_FOR_COMPLETE_THEIRANCHOR,

	/*
	 * Normal state.
	 */
	STATE_NORMAL,
	STATE_NORMAL_COMMITTING,
	
	/*
	 * Closing (handled outside state machine).
	 */
	STATE_CLEARING,
	STATE_CLEARING_COMMITTING,
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
	/* Their anchor didn't reach blockchain in reasonable time. */
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
	PKT_CLOSE_CLEARING = PKT__PKT_CLOSE_CLEARING,

	/* Something unexpected went wrong. */
	PKT_ERROR = PKT__PKT_ERROR,

	/*
	 * Non-packet inputs.
	 */
	INPUT_NONE,

	/*
	 * Bitcoin events
	 */
	/* Bitcoin anchor tx created. */
	BITCOIN_ANCHOR_CREATED,
	/* It reached the required depth. */
	BITCOIN_ANCHOR_DEPTHOK,
	/* It didn't reach the required depth in time. */
	BITCOIN_ANCHOR_TIMEOUT,
	/* No more HTLCs in either commitment tx. */
	INPUT_HTLCS_CLEARED,
	
	/*
	 * Timeouts.
	 */
	INPUT_CLOSE_COMPLETE_TIMEOUT,

	/* Commands */
	CMD_OPEN_WITH_ANCHOR,
	CMD_OPEN_WITHOUT_ANCHOR,
	CMD_SEND_HTLC_ADD,
	CMD_SEND_HTLC_FULFILL,
	CMD_SEND_HTLC_FAIL,
	CMD_SEND_COMMIT,

	INPUT_MAX
};
#endif /* LIGHTNING_STATE_TYPES_H */
