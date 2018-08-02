#ifndef LIGHTNING_COMMON_CRYPTO_SYNC_H
#define LIGHTNING_COMMON_CRYPTO_SYNC_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct crypto_state;

/* Exits with peer_failed_connection_lost() if write fails. */
void sync_crypto_write(struct crypto_state *cs, int fd, const void *msg TAKES);

/* Exits with peer_failed_connection_lost() if can't read packet. */
u8 *sync_crypto_read(const tal_t *ctx, struct crypto_state *cs, int fd);

#endif /* LIGHTNING_COMMON_CRYPTO_SYNC_H */
