#ifndef LIGHTNING_COMMON_DEV_DISCONNECT_H
#define LIGHTNING_COMMON_DEV_DISCONNECT_H
#include "config.h"
#include <stdbool.h>

#if DEVELOPER
enum dev_disconnect {
	/* Do nothing. */
	DEV_DISCONNECT_NORMAL = '=',
	/* Close connection before sending packet (and fail write). */
	DEV_DISCONNECT_BEFORE = '-',
	/* Close connection after sending packet. */
	DEV_DISCONNECT_AFTER = '+',
	/* Close connection after dropping packet. */
	DEV_DISCONNECT_DROPPKT = '@',
	/* Swallow all writes from now on, and do no more reads. */
	DEV_DISCONNECT_BLACKHOLE = '0',
};

/* Force a close fd before or after a certain packet type */
enum dev_disconnect dev_disconnect(int pkt_type);

/* Make next write on fd fail as if they'd disconnected. */
void dev_sabotage_fd(int fd);

/* No more data to arrive, what's written is swallowed. */
void dev_blackhole_fd(int fd);

/* For debug code to set in daemon. */
void dev_disconnect_init(int fd);

/* Hack for channeld to do DEV_DISCONNECT_SUPPRESS_COMMIT. */
extern bool dev_suppress_commit;
#endif /* DEVELOPER */

#endif /* LIGHTNING_COMMON_DEV_DISCONNECT_H */
