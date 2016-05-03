#ifndef LIGHTNING_UTILS_H
#define LIGHTNING_UTILS_H
#include "config.h"
#include <ccan/tal/tal.h>

/* Allocate and fill in a hex-encoded string of this data. */
char *tal_hexstr(const tal_t *ctx, const void *data, size_t len);

#endif /* LIGHTNING_UTILS_H */
