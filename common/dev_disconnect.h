#ifndef LIGHTNING_LIGHTNINGD_DEV_DISCONNECT_H
#define LIGHTNING_LIGHTNINGD_DEV_DISCONNECT_H
#include "config.h"
#include <stdbool.h>

#define DEV_DISCONNECT_BEFORE '-'
#define DEV_DISCONNECT_AFTER '+'
#define DEV_DISCONNECT_DROPPKT '@'
#define DEV_DISCONNECT_NORMAL 0

/* Force a close fd before or after a certain packet type */
char dev_disconnect(int pkt_type);

/* Make next write on fd fail as if they'd disconnected. */
void dev_sabotage_fd(int fd);

/* For debug code to set in daemon. */
void dev_disconnect_init(int fd);

#endif /* LIGHTNING_LIGHTNINGD_DEV_DISCONNECT_H */
