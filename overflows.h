#ifndef LIGHTNING_OVERFLOWS_H
#define LIGHTNING_OVERFLOWS_H
#include "config.h"

static inline bool add_overflows_size_t(uint64_t a, uint64_t b)
{
	return (size_t)a != a || (size_t)b != b || (a + b) < (size_t)a;
}

static inline bool add_overflows_u64(uint64_t a, uint64_t b)
{
	return (a + b) < a;
}

#endif /* LIGHTNING_OVERFLOWS_H */
