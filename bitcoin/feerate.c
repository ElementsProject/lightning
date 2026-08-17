#include "config.h"
#include <assert.h>
#include <bitcoin/feerate.h>

u32 feerate_from_style(u32 feerate, enum feerate_style style)
{
	/* Make sure it's called somewhere! */
	assert(feerate_floor_check() == FEERATE_FLOOR);

	switch (style) {
	case FEERATE_PER_KSIPA:
		return feerate;
	case FEERATE_PER_KBYTE:
		/* Everyone uses satoshi per kbyte, but we use satoshi per ksipa
		 * (don't round down to zero though)!
		 *
		 * Widen before rounding up: on a u32 the +3 wraps for the top
		 * three values, turning an absurd feerate into 0 or 1 perkw.
		 * That is the dangerous direction (it underpays our unilateral
		 * close), and it slips under every bound we check afterwards,
		 * since those are applied to the converted value.  The result
		 * always fits a u32: (UINT_MAX + 3) / 4 < UINT_MAX. */
		return ((u64)feerate + 3) / 4;
	}
	abort();
}

u32 feerate_to_style(u32 feerate_perkw, enum feerate_style style)
{
	switch (style) {
	case FEERATE_PER_KSIPA:
		return feerate_perkw;
	case FEERATE_PER_KBYTE:
		if ((u64)feerate_perkw * 4 > UINT_MAX)
			return UINT_MAX;
		return feerate_perkw * 4;
	}
	abort();
}

bool next_funding_feerate(u32 last_feerate, u32 *next_feerate)
{
	u64 next;

	/* Not a feerate we could ever have proposed, and 25/24 of it is
	 * still 0. */
	if (last_feerate == 0)
		return false;

	/* Widen: anything above UINT_MAX/25 overflows a u32 here, and that
	 * is exactly the range a broken fee estimator can leave in the db. */
	next = (u64)last_feerate * 25 / 24;
	if (next > UINT_MAX)
		return false;

	/* Rounding down means feerates below 24 map back onto themselves,
	 * and the rule requires strictly more to be a valid bump. */
	if (next <= last_feerate)
		return false;

	*next_feerate = next;
	return true;
}

const char *feerate_style_name(enum feerate_style style)
{
	switch (style) {
	case FEERATE_PER_KBYTE:
		return "perkb";
	case FEERATE_PER_KSIPA:
		return "perkw";
	}
	abort();
}
