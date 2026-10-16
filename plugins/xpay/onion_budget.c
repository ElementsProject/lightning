#include "config.h"
#include <assert.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <common/bigsize.h>
#include <common/onion_encode.h>
#include <common/overflows.h>
#include <common/sphinx.h>
#include <common/utils.h>
#include <plugins/xpay/onion_budget.h>
#include <wire/onion_wiregen.h>
#include <wire/wire.h>

/* create_onionpacket(ctx, sp, fixed_size, path_secrets) fails if
 * sphinx_path_payloads_size(sp) > fixed_size, where the fixed_size is
 * ROUTING_INFO_SIZE (1300) and sphinx_path_payloads_size is the sum of
 * tal_bytelen(hop->raw_payload) + HMAC_SIZE (32) for every hop. */

/* hop has size prepended, so this isn't a simple "append" */
static void hop_append(u8 **hop, const u8 *appendme)
{
	bigsize_t prepended_len;
	const u8 *cursor = *hop;
	size_t tlvs_len = tal_bytelen(*hop);
	u8 *result;

	/* Pull off length */
	prepended_len = fromwire_bigsize(&cursor, &tlvs_len);
	assert(cursor);
	assert(prepended_len == tlvs_len);

	/* Rewrite: length + contents */
	result = tal_arr(tal_parent(*hop), u8, 0);
	towire_bigsize(&result, tlvs_len + tal_bytelen(appendme));
	towire(&result, cursor, tlvs_len);
	towire(&result, appendme, tal_bytelen(appendme));

	tal_free(*hop);
	*hop = result;
}

u8 *onion_final_payload(const tal_t *ctx,
			struct amount_msat deliver,
			u32 final_cltv,
			struct amount_msat total_msat,
			const struct secret *payment_secret,
			const u8 *payment_metadata,
			const u8 *extra_tlvs)
{
	u8 *final = onion_final_hop(ctx, deliver, final_cltv, total_msat,
				    payment_secret, payment_metadata);
	hop_append(&final, extra_tlvs);
	return final;
}

u8 *onion_blinded_payload(const tal_t *ctx,
			  const struct blinded_path *path,
			  size_t i,
			  const struct amount_msat *deliver,
			  const struct amount_msat *total_msat,
			  const u32 *final_cltv)
{
	bool first = (i == 0);
	bool final = (i == tal_count(path->path) - 1);

	/* BOLT #4:
	 * - For every node inside a blinded route:
	 *   - MUST include the `encrypted_recipient_data` provided by the
	 *     recipient
	 *   - For the first node in the blinded route:
	 *     - MUST include the `path_key` provided by the
	 *       recipient in `current_path_key`
	 *   - If it is the final node:
	 *     - MUST include `amt_to_forward`, `outgoing_cltv_value` and `total_amount_msat`.
	 *...
	 *   - MUST NOT include any other tlv field.
	 */
	return onion_blinded_hop(ctx,
				 final ? deliver : NULL,
				 final ? total_msat : NULL,
				 final ? final_cltv : NULL,
				 path->path[i]->encrypted_recipient_data,
				 first ? &path->first_path_key : NULL);
}

size_t onion_forward_hop_size(struct amount_msat amount_out, u32 outgoing_cltv)
{
	/* The scid is fixed width, so any value will do. */
	const struct short_channel_id scid = {.u64 = 0};
	return onion_hop_size(take(
	    onion_forward_payload(tmpctx, &scid, amount_out, outgoing_cltv)));
}

size_t onion_final_hop_size(struct amount_msat deliver,
			    u32 final_cltv,
			    struct amount_msat total_msat,
			    const struct secret *payment_secret,
			    const u8 *payment_metadata,
			    const u8 *extra_tlvs)
{
	return onion_hop_size(take(
	    onion_final_payload(tmpctx, deliver, final_cltv, total_msat,
				payment_secret, payment_metadata, extra_tlvs)));
}

size_t onion_blinded_tail_size(const struct blinded_path *path,
			       struct amount_msat deliver,
			       struct amount_msat total_msat,
			       u32 final_cltv)
{
	size_t total = 0;
	for (size_t i = 0; i < tal_count(path->path); i++)
		total += onion_hop_size(take(onion_blinded_payload(
		    tmpctx, path, i, &deliver, &total_msat, &final_cltv)));
	return total;
}

u32 onion_budget(struct amount_msat amount,
		 struct amount_msat maxfee,
		 u32 blockheight,
		 u32 maxdelay,
		 const struct blinded_path *blinded_path,
		 const struct secret *payment_secret,
		 const u8 *payment_metadata,
		 const u8 *extra_tlvs,
		 size_t *tail_size)
{
	struct amount_msat worst_amount;
	u32 worst_cltv;
	size_t final_size, per_hop_size;

	if(!amount_msat_add(&worst_amount, amount, maxfee))
		worst_amount = AMOUNT_MSAT(UINT64_MAX);

	if(assign_overflow_u32(&worst_cltv, maxdelay + (u64)blockheight))
		worst_cltv = UINT32_MAX;

	per_hop_size = onion_forward_hop_size(worst_amount, worst_cltv);

	if (blinded_path)
		final_size = onion_blinded_tail_size(blinded_path, amount,
						     amount, worst_cltv);
	else
		final_size = onion_final_hop_size(amount, worst_cltv, amount,
						  payment_secret,
						  payment_metadata, extra_tlvs);

	if (tail_size)
		*tail_size = final_size;
	/* In a case like this we could make a bolt11 self-payment, but
	 * cannot start a blinded path payment even if the sender is the first
	 * node. */
	if(final_size > ROUTING_INFO_SIZE)
		return UINT32_MAX;
	return (ROUTING_INFO_SIZE - final_size) / per_hop_size;
}
