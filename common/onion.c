#include "config.h"
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <common/ecdh.h>
#include <common/onion.h>
#include <common/sphinx.h>
#include <sodium/crypto_aead_chacha20poly1305.h>

/* BOLT #4:
 *
 * ### `tlv_payload` format
 *
 * This is a more flexible format, which avoids the redundant
 * `short_channel_id` field for the final node.  It is formatted
 * according to the Type-Length-Value format defined in [BOLT
 * #1](01-messaging.md#type-length-value-format).
 */
static u8 *make_tlv_hop(const tal_t *ctx,
			const struct tlv_tlv_payload *tlv)
{
	/* We can't have over 64k anyway */
	u8 *tlvs = tal_arr(ctx, u8, 3);

	towire_tlv_tlv_payload(&tlvs, tlv);

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
		       u32 outgoing_cltv,
		       const struct pubkey *blinding,
		       const u8 *enctlv)
{
	struct tlv_tlv_payload *tlv = tlv_tlv_payload_new(tmpctx);

	/* BOLT #4:
	 *
	 * The writer:
	 *...
	 *  - For every node:
	 *    - MUST include `amt_to_forward` and `outgoing_cltv_value`.
	 *  - For every non-final node:
	 *    - MUST include `short_channel_id`
	 *    - MUST NOT include `payment_data`
	 */
	tlv->amt_to_forward = &forward.millisatoshis; /* Raw: TLV convert */
	tlv->outgoing_cltv_value = &outgoing_cltv;
	tlv->short_channel_id = cast_const(struct short_channel_id *, scid);
	tlv->blinding_point = cast_const(struct pubkey *, blinding);
	tlv->encrypted_recipient_data = cast_const(u8 *, enctlv);
	return make_tlv_hop(ctx, tlv);
}

u8 *onion_final_hop(const tal_t *ctx,
		    struct amount_msat forward,
		    u32 outgoing_cltv,
		    struct amount_msat total_msat,
		    const struct pubkey *blinding,
		    const u8 *enctlv,
		    const struct secret *payment_secret,
		    const u8 *payment_metadata)
{
	struct tlv_tlv_payload *tlv = tlv_tlv_payload_new(tmpctx);
	struct tlv_tlv_payload_payment_data tlv_pdata;

	/* These go together! */
	if (!payment_secret)
		assert(amount_msat_eq(total_msat, forward));

	/* BOLT #4:
	 *
	 * The writer:
	 *...
	 *  - For every node:
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
	tlv->blinding_point = cast_const(struct pubkey *, blinding);
	tlv->encrypted_recipient_data = cast_const(u8 *, enctlv);
	return make_tlv_hop(ctx, tlv);
}

struct onion_payload *onion_decode(const tal_t *ctx,
				   const struct route_step *rs,
				   const struct pubkey *blinding,
				   const struct secret *blinding_ss,
				   const u64 *accepted_extra_tlvs,
				   u64 *failtlvtype,
				   size_t *failtlvpos)
{
	struct onion_payload *p = tal(ctx, struct onion_payload);
	const u8 *cursor = rs->raw_payload;
	size_t max = tal_bytelen(cursor), len;
	struct tlv_tlv_payload *tlv;

	/* BOLT-remove-legacy-onion #4:
	 * 1. type: `hop_payloads`
	 * 2. data:
	 *    * [`bigsize`:`length`]
	 *    * [`length*byte`:`payload`]
	 */
	len = fromwire_bigsize(&cursor, &max);
	if (!cursor || len > max) {
		*failtlvtype = 0;
		*failtlvpos = tal_bytelen(rs->raw_payload);
		goto fail_no_tlv;
	}

	/* We do this manually so we can accept extra types, and get
	 * error off and type. */
	tlv = tlv_tlv_payload_new(p);
	if (!fromwire_tlv(&cursor, &max, tlvs_tlv_tlv_payload,
			  TLVS_ARRAY_SIZE_tlv_tlv_payload,
			  tlv, &tlv->fields, accepted_extra_tlvs,
			  failtlvpos, failtlvtype)) {
		goto fail;
	}

	/* BOLT #4:
	 *
	 * The reader:
	 *   - MUST return an error if `amt_to_forward` or
	 *     `outgoing_cltv_value` are not present.
	 */
	if (!tlv->amt_to_forward) {
		*failtlvtype = TLV_TLV_PAYLOAD_AMT_TO_FORWARD;
		goto field_bad;
	}
	if (!tlv->outgoing_cltv_value) {
		*failtlvtype = TLV_TLV_PAYLOAD_OUTGOING_CLTV_VALUE;
		goto field_bad;
	}

	p->amt_to_forward = amount_msat(*tlv->amt_to_forward);
	p->outgoing_cltv = *tlv->outgoing_cltv_value;

	/* BOLT #4:
	 *
	 * The writer:
	 *...
	 *  - For every non-final node:
	 *    - MUST include `short_channel_id`
	 */
	if (rs->nextcase == ONION_FORWARD) {
		if (!tlv->short_channel_id) {
			*failtlvtype = TLV_TLV_PAYLOAD_SHORT_CHANNEL_ID;
			goto field_bad;
		}
		p->forward_channel = tal_dup(p, struct short_channel_id,
					     tlv->short_channel_id);
		p->total_msat = NULL;
	} else {
		p->forward_channel = NULL;
		/* BOLT #4:
		 * - if it is the final node:
		 *   - MUST treat `total_msat` as if it were equal to
		 *     `amt_to_forward` if it is not present. */
		p->total_msat = tal_dup(p, struct amount_msat,
					&p->amt_to_forward);
	}

	p->payment_secret = NULL;
	p->blinding = tal_dup_or_null(p, struct pubkey, blinding);

	if (tlv->payment_data) {
		p->payment_secret = tal_dup(p, struct secret,
					    &tlv->payment_data->payment_secret);
		tal_free(p->total_msat);
		p->total_msat = tal(p, struct amount_msat);
		*p->total_msat
			= amount_msat(tlv->payment_data->total_msat);
	}
	if (tlv->payment_metadata)
		p->payment_metadata
			= tal_dup_talarr(p, u8, tlv->payment_metadata);
	else
		p->payment_metadata = NULL;

	p->tlv = tal_steal(p, tlv);
	return p;

field_bad:
	*failtlvpos = tlv_field_offset(rs->raw_payload, tal_bytelen(rs->raw_payload),
				       *failtlvtype);
fail:
	tal_free(tlv);

fail_no_tlv:
	tal_free(p);
	return NULL;
}
