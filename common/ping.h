#ifndef LIGHTNING_COMMON_PING_H
#define LIGHTNING_COMMON_PING_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* Returns false on error, otherwise *pong set if reply needed. */
bool check_ping_make_pong(const tal_t *ctx, const u8 *ping, u8 **pong);

/* Make a ping packet requesting num_pong_bytes */
u8 *make_ping(const tal_t *ctx, u16 num_pong_bytes, u16 padlen);

#endif /* LIGHTNING_COMMON_PING_H */
