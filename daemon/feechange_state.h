#ifndef LIGHTNING_DAEMON_FEECHANGE_STATE_H
#define LIGHTNING_DAEMON_FEECHANGE_STATE_H
#include "config.h"

/* Like HTLCs, but only adding; we never "remove" a feechange. */
enum feechange_state {
	/* When we add a new feechange, it goes in this order. */
	SENT_FEECHANGE,
	SENT_FEECHANGE_COMMIT,
	RCVD_FEECHANGE_REVOCATION,
	RCVD_FEECHANGE_ACK_COMMIT,
	SENT_FEECHANGE_ACK_REVOCATION,

	/* When they add a new feechange, it goes in this order. */
	RCVD_FEECHANGE,
	RCVD_FEECHANGE_COMMIT,
	SENT_FEECHANGE_REVOCATION,
	SENT_FEECHANGE_ACK_COMMIT,
	RCVD_FEECHANGE_ACK_REVOCATION,

	FEECHANGE_STATE_INVALID
};
#endif /* LIGHTNING_DAEMON_FEECHANGE_STATE_H */
