#include "config.h"
#include <assert.h>
#include <ccan/bitops/bitops.h>
#include <common/fp16.h>

fp16_t u64_to_fp16(u64 val, bool round_up)
{
	u16 mantissa_bits, mantissa, exponent;

	if (val == 0)
		return 0;

	/* How many bits do we need to represent mantissa? */
	mantissa_bits = bitops_hs64(val) + 1;

	/* We only have 11 bits, so if we need more, we will round. */
	if (mantissa_bits > 11) {
		exponent = mantissa_bits - 11;
		mantissa = (val >> exponent);
		/* If we're losing bits here, we're rounding down */
		if (round_up && (val & ((1ULL << exponent)-1))) {
			mantissa++;
			if (mantissa == (1 << 11)) {
				mantissa >>= 1;
				exponent++;
			}
		}
		/* huge number? Make it max. */
		if (exponent >= 32) {
			exponent = 31;
			mantissa = (1 << 11)-1;
		}
	} else {
		exponent = 0;
		mantissa = val;
	}

	assert((mantissa >> 11) == 0);
	return (exponent << 11) | mantissa;
}

bool amount_msat_less_fp16(struct amount_msat amt, fp16_t fp)
{
	return amt.millisatoshis < fp16_to_u64(fp); /* Raw: fp16 compare */
}

bool amount_msat_greater_fp16(struct amount_msat amt, fp16_t fp)
{
	return amt.millisatoshis > fp16_to_u64(fp); /* Raw: fp16 compare */
}
