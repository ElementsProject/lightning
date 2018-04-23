#ifndef LIGHTNING_COMMON_BECH32_UTIL_H
#define LIGHTNING_COMMON_BECH32_UTIL_H
#include "config.h"

#include <ccan/short_types/short_types.h>
#include <common/hash_u5.h>

/**
 * Push the bytes in src in 5 bit format onto the end of data.
 */
void bech32_push_bits(u5 **data, const void *src, size_t nbits);

#endif /* LIGHTNING_COMMON_BECH32_UTIL_H */
