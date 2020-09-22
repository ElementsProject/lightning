#ifndef LIGHTNING_COMMON_BIGSIZE_H
#define LIGHTNING_COMMON_BIGSIZE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stddef.h>

/* typedef for clarity. */
typedef u64 bigsize_t;

#define BIGSIZE_MAX_LEN 9

/* Returns length of buf used. */
size_t bigsize_put(u8 buf[BIGSIZE_MAX_LEN], bigsize_t v);

/* Returns 0 on failure, otherwise length (<= max) used.  */
size_t bigsize_get(const u8 *p, size_t max, bigsize_t *val);

/* How many bytes does it take to encode v? */
size_t bigsize_len(bigsize_t v);

/* Used for wire generation */
typedef bigsize_t bigsize;

/* marshal/unmarshal functions */
void towire_bigsize(u8 **pptr, const bigsize_t val);
bigsize_t fromwire_bigsize(const u8 **cursor, size_t *max);
#endif /* LIGHTNING_COMMON_BIGSIZE_H */
