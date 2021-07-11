#ifndef LIGHTNING_COMMON_OVERFLOWS_H
#define LIGHTNING_COMMON_OVERFLOWS_H
#include "config.h"
#include <ccan/short_types/short_types.h>

static inline bool add_overflows_size_t(uint64_t a, uint64_t b)
{
	return (size_t)a != a || (size_t)b != b || (a + b) < (size_t)a;
}

static inline bool add_overflows_u64(uint64_t a, uint64_t b)
{
	return (a + b) < a;
}

static inline bool mul_overflows_u64(uint64_t a, uint64_t b)
{
	uint64_t ret;

	if (a == 0)
		return false;
	ret = a * b;
	return (ret / a != b);
}

static inline bool assign_overflow_u8(u8 *dst, uint64_t v)
{
	*dst = v;
	return *dst == v;
}

static inline bool assign_overflow_u16(u16 *dst, uint64_t v)
{
	*dst = v;
	return *dst == v;
}

static inline bool assign_overflow_u32(u32 *dst, uint64_t v)
{
	*dst = v;
	return *dst == v;
}
#endif /* LIGHTNING_COMMON_OVERFLOWS_H */
