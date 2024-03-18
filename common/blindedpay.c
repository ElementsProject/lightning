#include "config.h"
#include <assert.h>
#include <common/blindedpay.h>
#include <common/bolt12.h>
#include <common/onion_encode.h>

u8 **blinded_onion_hops(const tal_t *ctx,
			struct amount_msat final_amount,
			u32 final_cltv,
			struct amount_msat total_amount,
			const struct blinded_path *path)
{
	u8 **onions = tal_arr(ctx, u8 *, tal_count(path->path));

	assert(tal_count(onions) > 0);

	for (size_t i = 0; i < tal_count(onions); i++) {
		bool first = (i == 0);
		bool final = (i == tal_count(onions) - 1);

		/* BOLT #4:
		 * - For every node inside a blinded route:
		 *   - MUST include the `encrypted_recipient_data` provided by the
		 *     recipient
		 *   - For the first node in the blinded route:
		 *     - MUST include the `blinding_point` provided by the
		 *       recipient in `current_blinding_point`
		 *   - If it is the final node:
		 *     - MUST include `amt_to_forward`, `outgoing_cltv_value` and `total_amount_msat`.
		 *...
		 *   - MUST NOT include any other tlv field.
		 */
		onions[i] = onion_blinded_hop(onions,
					      final ? &final_amount : NULL,
					      final ? &total_amount : NULL,
					      final ? &final_cltv : NULL,
					      path->path[i]->encrypted_recipient_data,
					      first ? &path->blinding : NULL);
	}
	return onions;
}
