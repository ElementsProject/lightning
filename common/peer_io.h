#ifndef LIGHTNING_COMMON_PEER_IO_H
#define LIGHTNING_COMMON_PEER_IO_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct per_peer_state;

/* Exits with peer_failed_connection_lost() if write fails. */
void peer_write(struct per_peer_state *pps, const void *msg TAKES);

/* Exits with peer_failed_connection_lost() if can't read packet. */
u8 *peer_read(const tal_t *ctx, struct per_peer_state *pps);

#endif /* LIGHTNING_COMMON_PEER_IO_H */
