#ifndef LIGHTNING_COMMON_FORWARD_FAILURE_REASON_H
#define LIGHTNING_COMMON_FORWARD_FAILURE_REASON_H
#include "config.h"
#include <ccan/str/str.h>
#include <stdio.h>

/* This is a DB ENUM!!!, please do not change the numbering of any
 * already defined elements (adding is ok) */
enum forward_failure_reason {
	/* Not classified, or not applicable (not a local failure) */
	FORWARD_FAIL_UNKNOWN = 0,
	/* CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED: not enough spendable
	 * balance/reserve on the outgoing channel */
	FORWARD_FAIL_INSUFFICIENT_OUTGOING_LIQUIDITY = 1,
	/* CHANNEL_ERR_TOO_MANY_HTLCS */
	FORWARD_FAIL_TOO_MANY_HTLCS = 2,
	/* CHANNEL_ERR_DUST_FAILURE */
	FORWARD_FAIL_DUST_LIMIT = 3,
	/* CHANNEL_ERR_HTLC_BELOW_MINIMUM, or amount below the next hop's
	 * advertised htlc_minimum_msat */
	FORWARD_FAIL_HTLC_BELOW_MINIMUM = 4,
	/* CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED, or amount above the next
	 * hops advertised htlc_maximum_msat */
	FORWARD_FAIL_HTLC_ABOVE_MAXIMUM = 5,
	/* Forwarding fee offered was insufficient */
	FORWARD_FAIL_FEE_INSUFFICIENT = 6,
	/* CHANNEL_ERR_INVALID_EXPIRY, or cltv_expiry_delta check failed */
	FORWARD_FAIL_CLTV_INCORRECT = 7,
	/* Outgoing cltv too close to the current block height */
	FORWARD_FAIL_CLTV_EXPIRY_TOO_SOON = 8,
	/* Outgoing cltv beyond our configured max_htlc_cltv */
	FORWARD_FAIL_CLTV_EXPIRY_TOO_FAR = 9,
	/* No usable channel/peer for the requested next hop */
	FORWARD_FAIL_UNKNOWN_NEXT_PEER = 10,
	/* Outgoing peers subdaemon is not connected/owned */
	FORWARD_FAIL_OUTGOING_PEER_OFFLINE = 11,
	/* Outgoing HTLC failed permanently (onchain timeout) */
	FORWARD_FAIL_CHANNEL_FAILED_PERMANENT = 12,
	/* Onion could not be parsed/decoded */
	FORWARD_FAIL_INVALID_ONION = 13,
	/* Incoming channel could not accept the htlc because it is
	 * shutting down (not an outgoing/onchain failure) */
	FORWARD_FAIL_CHANNEL_SHUTTING_DOWN = 14,
	/* CHANNEL_ERR_MAX_HTLC_VALUE_IN_FLIGHT_EXCEEDED - aggregate value of
	 * HTLCs already committed on the outgoing channel would exceed its
	 * max_htlc_value_in_flight_msat */
	FORWARD_FAIL_MAX_HTLC_VALUE_IN_FLIGHT = 15,
};

/* Returns NULL for FORWARD_FAIL_UNKNOWN - it is never serialized
 * r is persisted (db column, wire field), so may take a value this
 * binary doesn't know about (after a downgrade) - fall back to
 * a formatted placeholder instead of aborting */
static inline const char *forward_failure_reason_name(enum forward_failure_reason r)
{
	static char invalidbuf[sizeof("unknown_reason_") + STR_MAX_CHARS(int)];

	switch (r) {
	case FORWARD_FAIL_UNKNOWN:
		return NULL;
	case FORWARD_FAIL_INSUFFICIENT_OUTGOING_LIQUIDITY:
		return "insufficient_outgoing_liquidity";
	case FORWARD_FAIL_TOO_MANY_HTLCS:
		return "too_many_htlcs";
	case FORWARD_FAIL_DUST_LIMIT:
		return "dust_limit";
	case FORWARD_FAIL_HTLC_BELOW_MINIMUM:
		return "htlc_below_minimum";
	case FORWARD_FAIL_HTLC_ABOVE_MAXIMUM:
		return "htlc_above_maximum";
	case FORWARD_FAIL_FEE_INSUFFICIENT:
		return "fee_insufficient";
	case FORWARD_FAIL_CLTV_INCORRECT:
		return "cltv_incorrect";
	case FORWARD_FAIL_CLTV_EXPIRY_TOO_SOON:
		return "cltv_expiry_too_soon";
	case FORWARD_FAIL_CLTV_EXPIRY_TOO_FAR:
		return "cltv_expiry_too_far";
	case FORWARD_FAIL_UNKNOWN_NEXT_PEER:
		return "unknown_next_peer";
	case FORWARD_FAIL_OUTGOING_PEER_OFFLINE:
		return "outgoing_peer_offline";
	case FORWARD_FAIL_CHANNEL_FAILED_PERMANENT:
		return "channel_failed_permanent";
	case FORWARD_FAIL_INVALID_ONION:
		return "invalid_onion";
	case FORWARD_FAIL_CHANNEL_SHUTTING_DOWN:
		return "channel_shutting_down";
	case FORWARD_FAIL_MAX_HTLC_VALUE_IN_FLIGHT:
		return "max_htlc_value_in_flight";
	}

	snprintf(invalidbuf, sizeof(invalidbuf), "unknown_reason_%i", (int)r);
	return invalidbuf;
}

#endif /* LIGHTNING_COMMON_FORWARD_FAILURE_REASON_H */
