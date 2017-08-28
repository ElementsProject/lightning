#ifndef LIGHTNING_LIGHTNINGD_CRYPTO_SYNC_H
#define LIGHTNING_LIGHTNINGD_CRYPTO_SYNC_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct crypto_state;

bool sync_crypto_write(struct crypto_state *cs, int fd, const void *msg TAKES);
u8 *sync_crypto_read(const tal_t *ctx, struct crypto_state *cs, int fd);

#endif /* LIGHTNING_LIGHTNINGD_CRYPTO_SYNC_H */
