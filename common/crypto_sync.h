#ifndef LIGHTNING_COMMON_CRYPTO_SYNC_H
#define LIGHTNING_COMMON_CRYPTO_SYNC_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct per_peer_state;

/* Exits with peer_failed_connection_lost() if write fails. */
void sync_crypto_write(struct per_peer_state *pps, const void *msg TAKES);

/* Same, but disabled nagle for this message. */
void sync_crypto_write_no_delay(struct per_peer_state *pps,
				const void *msg TAKES);

/* Exits with peer_failed_connection_lost() if can't read packet. */
u8 *sync_crypto_read(const tal_t *ctx, struct per_peer_state *pps);

#endif /* LIGHTNING_COMMON_CRYPTO_SYNC_H */
