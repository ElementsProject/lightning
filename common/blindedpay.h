/* Code to create onion fragments to make payment down this struct blinded_path */
#ifndef LIGHTNING_COMMON_BLINDEDPAY_H
#define LIGHTNING_COMMON_BLINDEDPAY_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <common/amount.h>

struct blinded_path;

/**
 * blinded_onion_hops - turn this path into a series of onion hops
 * @ctx: context to allocate from
 * @final_amount: amount we want to reach the end
 * @final_cltv: cltv we want to at end
 * @payinfo: fee and other restriction info
 *
 * This calls onion_nonfinal_hop and onion_final_hop to create onion
 * blobs.
 */
u8 **blinded_onion_hops(const tal_t *ctx,
			struct amount_msat final_amount,
			u32 final_cltv,
			const struct blinded_path *path);

#endif /* LIGHTNING_COMMON_BLINDEDPAY_H */
