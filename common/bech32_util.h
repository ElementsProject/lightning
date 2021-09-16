#ifndef LIGHTNING_COMMON_BECH32_UTIL_H
#define LIGHTNING_COMMON_BECH32_UTIL_H
#include "config.h"

#include <ccan/tal/tal.h>
#include <common/hash_u5.h>

/**
 * Push the bytes in src in 5 bit format onto the end of data.
 */
void bech32_push_bits(u5 **data, const void *src, size_t nbits);

/**
 * Push the bytes in src in 8 bit format onto the end of data.
 */
void bech32_pull_bits(u8 **data, const u5 *src, size_t nbits);

/**
 * Checksumless bech32 routines.
 */
bool from_bech32_charset(const tal_t *ctx,
			 const char *bech32, size_t bech32_len,
			 char **hrp, u8 **data);

char *to_bech32_charset(const tal_t *ctx,
			const char *hrp, const u8 *data);

#endif /* LIGHTNING_COMMON_BECH32_UTIL_H */
