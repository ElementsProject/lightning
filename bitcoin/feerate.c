#include "config.h"
#include <bitcoin/feerate.h>

u32 feerate_from_style(u32 feerate, enum feerate_style style)
{
	switch (style) {
	case FEERATE_PER_KSIPA:
		return feerate;
	case FEERATE_PER_KBYTE:
		/* Everyone uses satoshi per kbyte, but we use satoshi per ksipa
		 * (don't round down to zero though)! */
		return (feerate + 3) / 4;
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
