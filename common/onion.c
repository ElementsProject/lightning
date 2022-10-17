#include "config.h"
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <common/blindedpath.h>
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
		       u32 outgoing_cltv)
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
	return make_tlv_hop(ctx, tlv);
}

u8 *onion_final_hop(const tal_t *ctx,
		    struct amount_msat forward,
		    u32 outgoing_cltv,
		    struct amount_msat total_msat,
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
	return make_tlv_hop(ctx, tlv);
}

u8 *onion_blinded_hop(const tal_t *ctx,
		      const struct amount_msat *amt_to_forward,
		      const u32 *outgoing_cltv_value,
		      const u8 *enctlv,
		      const struct pubkey *blinding)
{
	struct tlv_tlv_payload *tlv = tlv_tlv_payload_new(tmpctx);

	if (amt_to_forward) {
		tlv->amt_to_forward
			= cast_const(u64 *,
				     &amt_to_forward->millisatoshis); /* Raw: TLV convert */
	}
	tlv->outgoing_cltv_value = cast_const(u32 *, outgoing_cltv_value);
	tlv->encrypted_recipient_data = cast_const(u8 *, enctlv);
	tlv->blinding_point = cast_const(struct pubkey *, blinding);

	return make_tlv_hop(ctx, tlv);
}

static u64 ceil_div(u64 a, u64 b)
{
	return (a + b - 1) / b;
}

static bool handle_blinded_forward(struct onion_payload *p,
				   struct amount_msat amount_in,
				   u32 cltv_expiry,
				   const struct tlv_tlv_payload *tlv,
				   const struct tlv_encrypted_data_tlv *enc,
				   u64 *failtlvtype)
{
	u64 amt = amount_in.millisatoshis; /* Raw: allowed to wrap */

	/* BOLT-route-blinding #4:
	 * - If it not the final node:
	 *   - MUST return an error if fields other
	 *     than `encrypted_recipient_data` or `blinding_point` are present.
	 */
	for (size_t i = 0; i < tal_count(tlv->fields); i++) {
		if (tlv->fields[i].numtype != TLV_TLV_PAYLOAD_BLINDING_POINT
		    && tlv->fields[i].numtype != TLV_TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA) {
			*failtlvtype = tlv->fields[i].numtype;
			return false;
		}
	}

	/* BOLT-route-blinding #4:
	 * - If it not the final node:
	 *...
	 *   - MUST return an error if `encrypted_recipient_data` does not
	 *     contain `short_channel_id` or `next_node_id`.
	 */
	if (!enc->short_channel_id && !enc->next_node_id) {
		*failtlvtype = TLV_TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
		return false;
	}

	/* FIXME: handle fwd-by-node-id */
	if (!enc->short_channel_id) {
		*failtlvtype = TLV_TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
		return false;
	}

	p->forward_channel = tal_dup(p, struct short_channel_id,
				     enc->short_channel_id);
	p->total_msat = NULL;

	/* BOLT-route-blinding #4:
	 * - If it not the final node:
	 *...
	 *   - MUST return an error if `encrypted_recipient_data` does not
	 *     contain `payment_relay`.
	 */
	if (!enc->payment_relay) {
		*failtlvtype = TLV_TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
		return false;
	}

	/* FIXME: Put these formulae in BOLT 4! */
	/* amt_to_forward = ceil((amount_msat - fee_base_msat) * 1000000 / (1000000 + fee_proportional_millionths)) */
	/* If these values are crap, that's OK: the HTLC will fail. */
	p->amt_to_forward = amount_msat(ceil_div((amt - enc->payment_relay->fee_base_msat) * 1000000,
						 1000000 + enc->payment_relay->fee_proportional_millionths));
	p->outgoing_cltv = cltv_expiry - enc->payment_relay->cltv_expiry_delta;
	return true;
}

static bool handle_blinded_terminal(struct onion_payload *p,
				    const struct tlv_tlv_payload *tlv,
				    const struct tlv_encrypted_data_tlv *enc,
				    u64 *failtlvtype)
{
	/* BOLT-route-blinding #4:
	 * - If it is the final node:
	 *   - MUST return an error if fields other than
	 *     `encrypted_recipient_data`, `blinding_point`, `amt_to_forward`
	 *     or `outgoing_cltv_value` are present.
	 *   - MUST return an error if the `path_id` in
	 *     `encrypted_recipient_data` does not match the one it created.
	 *   - MUST return an error if `amt_to_forward` or
	 *     `outgoing_cltv_value` are not present.
	 *   - MUST return an error if `amt_to_forward` is below what it expects
	 *     for the payment.
	 */
	for (size_t i = 0; i < tal_count(tlv->fields); i++) {
		if (tlv->fields[i].numtype != TLV_TLV_PAYLOAD_BLINDING_POINT
		    && tlv->fields[i].numtype != TLV_TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA
		    && tlv->fields[i].numtype != TLV_TLV_PAYLOAD_AMT_TO_FORWARD
		    && tlv->fields[i].numtype != TLV_TLV_PAYLOAD_OUTGOING_CLTV_VALUE) {
			*failtlvtype = tlv->fields[i].numtype;
			return false;
		}
	}

	if (!tlv->amt_to_forward) {
		*failtlvtype = TLV_TLV_PAYLOAD_AMT_TO_FORWARD;
		return false;
	}

	if (!tlv->outgoing_cltv_value) {
		*failtlvtype = TLV_TLV_PAYLOAD_OUTGOING_CLTV_VALUE;
		return false;
	}

	p->amt_to_forward = amount_msat(*tlv->amt_to_forward);
	p->outgoing_cltv = *tlv->outgoing_cltv_value;

	p->forward_channel = NULL;
	/* BOLT #4:
	 * - if it is the final node:
	 *   - MUST treat `total_msat` as if it were equal to
	 *     `amt_to_forward` if it is not present. */
	p->total_msat = tal_dup(p, struct amount_msat,
				&p->amt_to_forward);
	return true;
}

struct onion_payload *onion_decode(const tal_t *ctx,
				   bool blinding_support,
				   const struct route_step *rs,
				   const struct pubkey *blinding,
				   const u64 *accepted_extra_tlvs,
				   struct amount_msat amount_in,
				   u32 cltv_expiry,
				   u64 *failtlvtype,
				   size_t *failtlvpos)
{
	struct onion_payload *p = tal(ctx, struct onion_payload);
	const u8 *cursor = rs->raw_payload;
	size_t max = tal_bytelen(cursor), len;

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
		return tal_free(p);
	}

	/* We do this manually so we can accept extra types, and get
	 * error off and type. */
	p->tlv = tlv_tlv_payload_new(p);
	if (!fromwire_tlv(&cursor, &max, tlvs_tlv_tlv_payload,
			  TLVS_ARRAY_SIZE_tlv_tlv_payload,
			  p->tlv, &p->tlv->fields, accepted_extra_tlvs,
			  failtlvpos, failtlvtype)) {
		return tal_free(p);
	}

	if (blinding || p->tlv->blinding_point) {
		struct tlv_encrypted_data_tlv *enc;

		/* Only supported with --experimental-onion-messages! */
		if (!blinding_support) {
			if (!blinding)
				return tal_free(p);
			*failtlvtype = TLV_TLV_PAYLOAD_BLINDING_POINT;
			goto field_bad;
		}

		/* BOLT-route-blinding #4:
		 * The reader:
		 *   - If `blinding_point` is set (either in the payload or the
		 *     outer message):
		 *     - MUST return an error if it is set in both the payload
		 *       and the outer message
		 */
		if (blinding && p->tlv->blinding_point) {
			*failtlvtype = TLV_TLV_PAYLOAD_BLINDING_POINT;
			goto field_bad;
		}
		if (p->tlv->blinding_point)
			p->blinding = tal_dup(p, struct pubkey,
					      p->tlv->blinding_point);
		else
			p->blinding = tal_dup(p, struct pubkey,
					      blinding);

		/* BOLT-route-blinding #4:
		 * The reader:
		 *...
		 * - MUST return an error if `encrypted_recipient_data` is not
		 *   present.
		 */
		if (!p->tlv->encrypted_recipient_data) {
			*failtlvtype = TLV_TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
			goto field_bad;
		}

		ecdh(p->blinding, &p->blinding_ss);
		enc = decrypt_encrypted_data(tmpctx, p->blinding, &p->blinding_ss,
					     p->tlv->encrypted_recipient_data);
		if (!enc) {
			*failtlvtype = TLV_TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
			goto field_bad;
		}

		if (enc->payment_constraints) {
			/* BOLT-route-blinding #4:
			 * - MUST return an error if the expiry is greater than
			 *   `encrypted_recipient_data.payment_constraints.max_cltv_expiry`.
			 */
			if (cltv_expiry > enc->payment_constraints->max_cltv_expiry) {
				*failtlvtype = TLV_TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
				goto field_bad;
			}

			/* BOLT-route-blinding #4:
			 * - MUST return an error if the amount is below
			 *   `encrypted_recipient_data.payment_constraints.htlc_minimum_msat`.
			 */
			if (amount_msat_less(amount_in,
					     amount_msat(enc->payment_constraints->htlc_minimum_msat))) {
				*failtlvtype = TLV_TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
				goto field_bad;
			}

			/* BOLT-route-blinding #4:
			 * - MUST return an error if the payment uses a feature
			 *   not included in
			 *   `encrypted_recipient_data.payment_constraints.allowed_features`.
			 */
			/* We don't have any features yet... */
		}

		/* BOLT-route-blinding #4:
		 * - If `allowed_features` is present:
		 *   - MUST return an error if:
		 *     - `encrypted_recipient_data.allowed_features.features`
		 *        contains an unknown feature bit (even if it is odd).
		 *     - the payment uses a feature not included in
		 *       `encrypted_recipient_data.allowed_features.features`.
		 */
		/* No features, this is easy */
		if (!memeqzero(enc->allowed_features,
			       tal_bytelen(enc->allowed_features))) {
			*failtlvtype = TLV_TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
			goto field_bad;
		}

		if (rs->nextcase == ONION_FORWARD) {
			if (!handle_blinded_forward(p, amount_in, cltv_expiry,
						    p->tlv, enc, failtlvtype))
				goto field_bad;
		} else {
			if (!handle_blinded_terminal(p, p->tlv, enc, failtlvtype))
				goto field_bad;
		}

		/* Blinded paths have no payment secret or metadata:
		 * we use the path_id for that. */
		p->payment_secret = NULL;
		p->payment_metadata = NULL;
		return p;
	}

	/* BOLT #4:
	 *
	 * The reader:
	 *   - MUST return an error if `amt_to_forward` or
	 *     `outgoing_cltv_value` are not present.
	 */
	if (!p->tlv->amt_to_forward) {
		*failtlvtype = TLV_TLV_PAYLOAD_AMT_TO_FORWARD;
		goto field_bad;
	}
	if (!p->tlv->outgoing_cltv_value) {
		*failtlvtype = TLV_TLV_PAYLOAD_OUTGOING_CLTV_VALUE;
		goto field_bad;
	}

	p->amt_to_forward = amount_msat(*p->tlv->amt_to_forward);
	p->outgoing_cltv = *p->tlv->outgoing_cltv_value;

	/* BOLT #4:
	 *
	 * The writer:
	 *...
	 *  - For every non-final node:
	 *    - MUST include `short_channel_id`
	 */
	if (rs->nextcase == ONION_FORWARD) {
		if (!p->tlv->short_channel_id) {
			*failtlvtype = TLV_TLV_PAYLOAD_SHORT_CHANNEL_ID;
			goto field_bad;
		}
		p->forward_channel = tal_dup(p, struct short_channel_id,
					     p->tlv->short_channel_id);
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
	if (p->tlv->payment_data) {
		p->payment_secret = tal_dup(p, struct secret,
					    &p->tlv->payment_data->payment_secret);
		tal_free(p->total_msat);
		p->total_msat = tal(p, struct amount_msat);
		*p->total_msat
			= amount_msat(p->tlv->payment_data->total_msat);
	}
	if (p->tlv->payment_metadata)
		p->payment_metadata
			= tal_dup_talarr(p, u8, p->tlv->payment_metadata);
	else
		p->payment_metadata = NULL;

	p->blinding = NULL;

	return p;

field_bad:
	*failtlvpos = tlv_field_offset(rs->raw_payload, tal_bytelen(rs->raw_payload),
				       *failtlvtype);
	return tal_free(p);
}

