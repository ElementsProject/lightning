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
	 * Closing.
	 */
	/* We told them to clear. */
	STATE_US_CLEARING,
	/* They told us to clear, or acked our CLEARING. */
	STATE_BOTH_CLEARING,
	/* We're cleared, waiting for close signature / negotiation */
	STATE_WAIT_FOR_CLOSE_SIG,
	/* We've broadcast the mutual close, waiting for onchain. */
	STATE_CLOSE_WAIT_CLOSE,
	
	/* All closed. */
	STATE_CLOSED,

	/* Four states to represent closing onchain (for getpeers) */
	STATE_CLOSE_ONCHAIN_CHEATED,
	STATE_CLOSE_ONCHAIN_THEIR_UNILATERAL,
	STATE_CLOSE_ONCHAIN_OUR_UNILATERAL,
	STATE_CLOSE_ONCHAIN_MUTUAL,
	
	/*
	 * Where angels fear to tread.
	 */
	/* Bad packet from them / protocol breakdown. */
	STATE_ERR_BREAKDOWN,
	/* Their anchor didn't reach blockchain in reasonable time. */
	STATE_ERR_ANCHOR_TIMEOUT,
	/* Anchor was double-spent, after both considered it sufficient depth. */
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

	/* Mutual close sequence. */
	PKT_CLOSE_CLEARING = PKT__PKT_CLOSE_CLEARING,
	PKT_CLOSE_SIGNATURE = PKT__PKT_CLOSE_SIGNATURE,

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
	CMD_CLOSE,

	INPUT_MAX
};

enum state_peercond {
	/* Ready to accept a new command. */
	PEER_CMD_OK,
	/* Don't send me commands, I'm busy. */
	PEER_BUSY,
	/* No more commands, I'm closing. */
	PEER_CLOSING,
	/* No more packets, I'm closed. */
	PEER_CLOSED
};

enum command_status {
	/* Nothing changed. */
	CMD_NONE,
	/* Command succeeded. */
	CMD_SUCCESS,
	/* HTLC-command needs re-issuing (theirs takes preference) */
	CMD_REQUEUE,
	/* Failed. */
	CMD_FAIL
};

#endif /* LIGHTNING_STATE_TYPES_H */
