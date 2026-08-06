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
