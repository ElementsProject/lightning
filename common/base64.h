#ifndef LIGHTNING_COMMON_BASE64_H
#define LIGHTNING_COMMON_BASE64_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

char *b64_encode(const tal_t *ctx, const void *data, size_t len);

#endif /* LIGHTNING_COMMON_BASE64_H */
