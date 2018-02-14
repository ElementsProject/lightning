#ifndef LIGHTNING_COMMON_HTLC_STATE_H
#define LIGHTNING_COMMON_HTLC_STATE_H
#include "config.h"

/*
 * /!\ The generated enum values are used in the database, DO NOT
 * reorder or insert new values (appending at the end is ok) /!\
 */
enum htlc_state {
	/* When we add a new htlc, it goes in this order. */
	SENT_ADD_HTLC,
	SENT_ADD_COMMIT,
	RCVD_ADD_REVOCATION,
	RCVD_ADD_ACK_COMMIT,
	SENT_ADD_ACK_REVOCATION,

	/* When they remove an HTLC, it goes from SENT_ADD_ACK_REVOCATION: */
	RCVD_REMOVE_HTLC,
	RCVD_REMOVE_COMMIT,
	SENT_REMOVE_REVOCATION,
	SENT_REMOVE_ACK_COMMIT,
	RCVD_REMOVE_ACK_REVOCATION,

	/* When they add a new htlc, it goes in this order. */
	RCVD_ADD_HTLC,
	RCVD_ADD_COMMIT,
	SENT_ADD_REVOCATION,
	SENT_ADD_ACK_COMMIT,
	RCVD_ADD_ACK_REVOCATION,

	/* When we remove an HTLC, it goes from RCVD_ADD_ACK_REVOCATION: */
	SENT_REMOVE_HTLC,
	SENT_REMOVE_COMMIT,
	RCVD_REMOVE_REVOCATION,
	RCVD_REMOVE_ACK_COMMIT,
	SENT_REMOVE_ACK_REVOCATION,

	HTLC_STATE_INVALID
};
#endif /* LIGHTNING_COMMON_HTLC_STATE_H */
