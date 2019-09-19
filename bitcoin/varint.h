#ifndef LIGHTNING_BITCOIN_VARINT_H
#define LIGHTNING_BITCOIN_VARINT_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdlib.h>

/* We unpack varints for our in-memory representation */
#define varint_t u64

#define VARINT_MAX_LEN 9

/* Calculate bytes used (up to 9) */
size_t varint_size(varint_t v);

/* Returns bytes used (up to 9) */
size_t varint_put(u8 buf[VARINT_MAX_LEN], varint_t v);

/* Returns bytes used: 0 if max_len too small. */
size_t varint_get(const u8 *p, size_t max_len, varint_t *val);

#endif /* LIGHTNING_BITCOIN_VARINT_H */
