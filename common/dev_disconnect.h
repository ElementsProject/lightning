#ifndef LIGHTNING_COMMON_DEV_DISCONNECT_H
#define LIGHTNING_COMMON_DEV_DISCONNECT_H
#include "config.h"
#include <stdbool.h>

struct node_id;

enum dev_disconnect_out {
	/* Do nothing. */
	DEV_DISCONNECT_OUT_NORMAL = '=',
	/* Close connection before sending packet. */
	DEV_DISCONNECT_OUT_BEFORE = '-',
	/* Close connection after sending packet. */
	DEV_DISCONNECT_OUT_AFTER = '+',
	/* Drop message (don't send to peer) */
	DEV_DISCONNECT_OUT_DROP = '$',
	/* Swallow all writes from now on, and do no more reads. */
	DEV_DISCONNECT_OUT_BLACKHOLE = '0',
	/* Don't use connection after sending packet, but don't close. */
	DEV_DISCONNECT_OUT_DISABLE_AFTER = 'x',
};

/* Force a close fd before or after a certain packet type */
enum dev_disconnect_out dev_disconnect_out(const struct node_id *id, int pkt_type);

/* Make next write on fd fail as if they'd disconnected. */
void dev_sabotage_fd(int fd, bool close_fd);

/* For debug code to set in daemon. */
void dev_disconnect_init(int fd);

#endif /* LIGHTNING_COMMON_DEV_DISCONNECT_H */
