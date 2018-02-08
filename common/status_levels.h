#ifndef LIGHTNING_COMMON_STATUS_LEVELS_H
#define LIGHTNING_COMMON_STATUS_LEVELS_H
#include "config.h"

enum log_level {
	/* Logging all IO. */
	LOG_IO_OUT,
	LOG_IO_IN,
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

/*
 * These errors shouldn't happen:
 */
enum status_failreason {
	/* Master daemon sent unknown/malformed command, or fd failed */
	STATUS_FAIL_MASTER_IO,

	/* Hsmd sent unknown/malformed command, or fd failed */
	STATUS_FAIL_HSM_IO,

	/* Gossipd sent unknown/malformed command, or fd failed */
	STATUS_FAIL_GOSSIP_IO,

	/* Other internal error. */
	STATUS_FAIL_INTERNAL_ERROR,
};
#define STATUS_FAIL_MAX STATUS_FAIL_INTERNAL_ERROR

#endif /* LIGHTNING_COMMON_STATUS_LEVELS_H */
