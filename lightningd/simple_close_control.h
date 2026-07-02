#ifndef LIGHTNING_LIGHTNINGD_SIMPLE_CLOSE_CONTROL_H
#define LIGHTNING_LIGHTNINGD_SIMPLE_CLOSE_CONTROL_H
#include "config.h"

struct channel;
struct peer_fd;

/* Start the simpleclosed subdaemon for option_simple_close negotiation. */
void peer_start_simpleclosed(struct channel *channel, struct peer_fd *peer_fd);

#endif /* LIGHTNING_LIGHTNINGD_SIMPLE_CLOSE_CONTROL_H */
