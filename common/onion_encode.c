#include "config.h"
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <common/blindedpath.h>
#include <common/ecdh.h>
#include <common/onion_encode.h>
#include <common/sphinx.h>
#include <sodium/crypto_aead_chacha20poly1305.h>

/* BOLT #4:
 *
 * ### `payload` format
 *
 * This is formatted according to the Type-Length-Value format defined
 * in [BOLT #1](01-messaging.md#type-length-value-format).
 */
static u8 *make_tlv_hop(const tal_t *ctx,
			const struct tlv_payload *tlv)
{
	/* We can't have over 64k anyway */
	u8 *tlvs = tal_arr(ctx, u8, 3);

	towire_tlv_payload(&tlvs, tlv);

	switch (bigsize_put(tlvs, tal_bytelen(tlvs) - 3)) {
	case 1:
		/* Move over two unused bytes */
		memmove(tlvs + 1, tlvs + 3, tal_bytelen(tlvs) - 3);
		tal_resize(&tlvs, tal_bytelen(tlvs) - 2);
		return tlvs;
	case 3:
		return tlvs;
	}
	abort();
}

u8 *onion_nonfinal_hop(const tal_t *ctx,
		       const struct short_channel_id *scid,
		       struct amount_msat forward,
		       u32 outgoing_cltv)
{
	struct tlv_payload *tlv = tlv_payload_new(tmpctx);

	/* BOLT #4:
	 *
	 * The writer of the TLV `payload`:
	 *...
	 * - For every node outside of a blinded route:
	 *    - MUST include `amt_to_forward` and `outgoing_cltv_value`.
	 *  - For every non-final node:
	 *    - MUST include `short_channel_id`
	 *    - MUST NOT include `payment_data`
	 */
	tlv->amt_to_forward = &forward.millisatoshis; /* Raw: TLV convert */
	tlv->outgoing_cltv_value = &outgoing_cltv;
	tlv->short_channel_id = cast_const(struct short_channel_id *, scid);
	return make_tlv_hop(ctx, tlv);
}

u8 *onion_final_hop(const tal_t *ctx,
		    struct amount_msat forward,
		    u32 outgoing_cltv,
		    struct amount_msat total_msat,
		    const struct secret *payment_secret,
		    const u8 *payment_metadata)
{
	struct tlv_payload *tlv = tlv_payload_new(tmpctx);
	struct tlv_payload_payment_data tlv_pdata;

	/* These go together! */
	if (!payment_secret)
		assert(amount_msat_eq(total_msat, forward));

	/* BOLT #4:
	 *
	 * The writer of the TLV `payload`:
	 *...
	 *  - For every node outside of a blinded route:
	 *    - MUST include `amt_to_forward` and `outgoing_cltv_value`.
	 *...
	 *  - For the final node:
	 *    - MUST NOT include `short_channel_id`
	 *    - if the recipient provided `payment_secret`:
	 *      - MUST include `payment_data`
	 *      - MUST set `payment_secret` to the one provided
	 *      - MUST set `total_msat` to the total amount it will send
	 */
	tlv->amt_to_forward = &forward.millisatoshis; /* Raw: TLV convert */
	tlv->outgoing_cltv_value = &outgoing_cltv;

	if (payment_secret) {
		tlv_pdata.payment_secret = *payment_secret;
		tlv_pdata.total_msat = total_msat.millisatoshis; /* Raw: TLV convert */
		tlv->payment_data = &tlv_pdata;
	}
	tlv->payment_metadata = cast_const(u8 *, payment_metadata);
	return make_tlv_hop(ctx, tlv);
}

u8 *onion_blinded_hop(const tal_t *ctx,
		      const struct amount_msat *amt_to_forward,
		      const struct amount_msat *total_amount_msat,
		      const u32 *outgoing_cltv_value,
		      const u8 *enctlv,
		      const struct pubkey *blinding)
{
	struct tlv_payload *tlv = tlv_payload_new(tmpctx);

	if (amt_to_forward) {
		tlv->amt_to_forward
			= cast_const(u64 *,
				     &amt_to_forward->millisatoshis); /* Raw: TLV convert */
	}
	if (total_amount_msat) {
		tlv->total_amount_msat
			= cast_const(u64 *,
				     &total_amount_msat->millisatoshis); /* Raw: TLV convert */
	}
	tlv->outgoing_cltv_value = cast_const(u32 *, outgoing_cltv_value);
	tlv->encrypted_recipient_data = cast_const(u8 *, enctlv);
	tlv->current_path_key = cast_const(struct pubkey *, blinding);

	return make_tlv_hop(ctx, tlv);
}
