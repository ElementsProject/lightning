/* 5 bit exponent, 11 bit mantissa approximations of min/max */
#ifndef LIGHTNING_COMMON_FP16_H
#define LIGHTNING_COMMON_FP16_H
#include "config.h"
#include <common/amount.h>

typedef u16 fp16_t;

static inline u64 fp16_to_u64(fp16_t val)
{
	return ((u64)val & ((1 << 11)-1)) << (val >> 11);
}

fp16_t u64_to_fp16(u64 val, bool round_up);

bool amount_msat_less_fp16(struct amount_msat amt, fp16_t fp);
bool amount_msat_greater_fp16(struct amount_msat amt, fp16_t fp);

#endif /* LIGHTNING_COMMON_FP16_H */
