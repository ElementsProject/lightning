#ifndef LIGHTNING_COMMON_HTLC_TRIM_H
#define LIGHTNING_COMMON_HTLC_TRIM_H
#include "config.h"
#include <common/amount.h>
#include <common/htlc.h>

/* If this htlc too small to create an output on @side's commitment tx? */
bool htlc_is_trimmed(enum side htlc_owner,
		     struct amount_msat htlc_amount,
		     u32 feerate_per_kw,
		     struct amount_sat dust_limit,
		     enum side side,
		     bool option_anchor_outputs);

/* Calculate the our htlc-trimming buffer feerate
 * (max(25%, 10s/vbyte) above feerate_per_kw) */
u32 htlc_trim_feerate_ceiling(u32 feerate_per_kw);
#endif /* LIGHTNING_COMMON_HTLC_TRIM_H */
