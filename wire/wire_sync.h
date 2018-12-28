#ifndef LIGHTNING_WIRE_WIRE_SYNC_H
#define LIGHTNING_WIRE_WIRE_SYNC_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

bool wire_sync_write(int fd, const void *msg TAKES);
u8 *wire_sync_read(const tal_t *ctx, int fd);

#endif /* LIGHTNING_WIRE_WIRE_SYNC_H */
