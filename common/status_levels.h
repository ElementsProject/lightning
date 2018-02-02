#ifndef LIGHTNING_COMMON_STATUS_LEVELS_H
#define LIGHTNING_COMMON_STATUS_LEVELS_H
#include "config.h"

enum log_level {
	/* Logging all IO. */
	LOG_IO,
	/* Gory details which are mainly good for debugging. */
	LOG_DBG,
	/* Information about what's going in. */
	LOG_INFORM,
	/* That's strange... */
	LOG_UNUSUAL,
	/* That's really bad, we're broken. */
	LOG_BROKEN
};
#define LOG_LEVEL_MAX LOG_BROKEN

enum status_failreason {
	/*
	 * These errors shouldn't happen:
	 */
	/* Master daemon sent unknown/malformed command, or fd failed */
	STATUS_FAIL_MASTER_IO,

	/* Hsmd sent unknown/malformed command, or fd failed */
	STATUS_FAIL_HSM_IO,

	/* Gossipd sent unknown/malformed command, or fd failed */
	STATUS_FAIL_GOSSIP_IO,

	/* Other internal error. */
	STATUS_FAIL_INTERNAL_ERROR,

	/*
	 * These errors happen when the other peer misbehaves:
	 */
	/* I/O failure (probably they closed the socket) */
	STATUS_FAIL_PEER_IO,

	/* Peer did something else wrong */
	STATUS_FAIL_PEER_BAD
};
#define STATUS_FAIL_MAX STATUS_FAIL_PEER_BAD

#endif /* LIGHTNING_COMMON_STATUS_LEVELS_H */
