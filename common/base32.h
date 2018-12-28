#ifndef LIGHTNING_COMMON_BASE32_H
#define LIGHTNING_COMMON_BASE32_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

char *b32_encode(const tal_t *ctx, const void *data, size_t len);
u8 *b32_decode(const tal_t *ctx, const char *str, size_t len);

#endif /* LIGHTNING_COMMON_BASE32_H */
