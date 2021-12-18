#include "config.h"
#include <common/htlc_trim.h>
#include <common/htlc_tx.h>

/* If this htlc too small to create an output on @side's commitment tx? */
bool htlc_is_trimmed(enum side htlc_owner,
		     struct amount_msat htlc_amount,
		     u32 feerate_per_kw,
		     struct amount_sat dust_limit,
		     enum side side,
		     bool option_anchor_outputs)
{
	struct amount_sat htlc_fee, htlc_min;

	/* BOLT #3:
	 *
	 *   - for every offered HTLC:
	 *    - if the HTLC amount minus the HTLC-timeout fee would be less than
	 *    `dust_limit_satoshis` set by the transaction owner:
	 *      - MUST NOT contain that output.
	 *    - otherwise:
	 *      - MUST be generated as specified in
	 *      [Offered HTLC Outputs](#offered-htlc-outputs).
	 */
	if (htlc_owner == side)
		htlc_fee = htlc_timeout_fee(feerate_per_kw,
					    option_anchor_outputs);
	/* BOLT #3:
	 *
	 *  - for every received HTLC:
	 *    - if the HTLC amount minus the HTLC-success fee would be less than
	 *    `dust_limit_satoshis` set by the transaction owner:
	 *      - MUST NOT contain that output.
	 *    - otherwise:
	 *      - MUST be generated as specified in
	 */
	else
		htlc_fee = htlc_success_fee(feerate_per_kw,
					    option_anchor_outputs);

	/* If these overflow, it implies htlc must be less. */
	if (!amount_sat_add(&htlc_min, dust_limit, htlc_fee))
		return true;
	return amount_msat_less_sat(htlc_amount, htlc_min);
}

/*  Minimum amount of headroom we should use for
 *  anticipated feerate adjustments */
#define HTLC_FEE_MIN_RANGE 2530
#define max(a, b) ((a) > (b) ? (a) : (b))

u32 htlc_trim_feerate_ceiling(u32 feerate_per_kw)
{
	/* BOLT-919 #2:
	 *
	 * `dust_buffer_feerate` is defined as the maximum
	 * of either 2530 sats per kWU or 125% of the
	 * current `feerate_per_kw`. */
	return max(feerate_per_kw + feerate_per_kw / 4,
		   feerate_per_kw + HTLC_FEE_MIN_RANGE);
}
