#ifndef LIGHTNING_COMMON_HASH_STR_H
#define LIGHTNING_COMMON_HASH_STR_H
#include "config.h"
#include <common/pseudorand.h>

static inline size_t hash_str(const char *str)
{
	return siphash24(siphash_seed(), str, strlen(str));
}

#endif /* LIGHTNING_COMMON_HASH_STR_H */
