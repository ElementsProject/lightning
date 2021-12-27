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
 * ## Legacy `hop_data` payload format
 *
 * The `hop_data` format is identified by a single `0x00`-byte length,
 * for backward compatibility.  Its payload is defined as:
 *
 * 1. type: `hop_data` (for `realm` 0)
 * 2. data:
 *    * [`short_channel_id`:`short_channel_id`]
 *    * [`u64`:`amt_to_forward`]
 *    * [`u32`:`outgoing_cltv_value`]
 *    * [`12*byte`:`padding`]
 */
static u8 *make_v0_hop(const tal_t *ctx,
		       const struct short_channel_id *scid,
		       struct amount_msat forward, u32 outgoing_cltv)
{
	const u8 padding[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			      0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	/* Prepend 0 byte for realm */
	u8 *buf = tal_arrz(ctx, u8, 1);
	towire_short_channel_id(&buf, scid);
	towire_amount_msat(&buf, forward);
	towire_u32(&buf, outgoing_cltv);
	towire(&buf, padding, ARRAY_SIZE(padding));
	assert(tal_bytelen(buf) == 1 + 32);
	return buf;
}

static u8 *make_tlv_hop(const tal_t *ctx,
			const struct tlv_tlv_payload *tlv)
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
		       bool use_tlv,
		       const struct short_channel_id *scid,
		       struct amount_msat forward,
		       u32 outgoing_cltv,
		       const struct pubkey *blinding,
		       const u8 *enctlv)
{
	if (use_tlv) {
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
		tlv->short_channel_id = cast_const(struct short_channel_id *,
						   scid);
#if EXPERIMENTAL_FEATURES
		tlv->blinding_point = cast_const(struct pubkey *, blinding);
		tlv->encrypted_recipient_data = cast_const(u8 *, enctlv);
#endif
		return make_tlv_hop(ctx, tlv);
	} else {
#if EXPERIMENTAL_FEATURES
		if (blinding || enctlv)
			return NULL;
#endif
		return make_v0_hop(ctx, scid, forward, outgoing_cltv);
	}
}

u8 *onion_final_hop(const tal_t *ctx,
		    bool use_tlv,
		    struct amount_msat forward,
		    u32 outgoing_cltv,
		    struct amount_msat total_msat,
		    const struct pubkey *blinding,
		    const u8 *enctlv,
		    const struct secret *payment_secret)
{
	/* These go together! */
	if (!payment_secret)
		assert(amount_msat_eq(total_msat, forward));

	if (use_tlv) {
		struct tlv_tlv_payload *tlv = tlv_tlv_payload_new(tmpctx);
		struct tlv_tlv_payload_payment_data tlv_pdata;

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
#if EXPERIMENTAL_FEATURES
		tlv->blinding_point = cast_const(struct pubkey *, blinding);
		tlv->encrypted_recipient_data = cast_const(u8 *, enctlv);
#endif
		return make_tlv_hop(ctx, tlv);
	} else {
		static struct short_channel_id all_zero_scid;
		/* No payment secrets in legacy format. */
		if (payment_secret)
			return NULL;
#if EXPERIMENTAL_FEATURES
		if (blinding || enctlv)
			return NULL;
#endif
		return make_v0_hop(ctx, &all_zero_scid, forward, outgoing_cltv);
	}
}

/* Returns true if valid, and fills in type. */
static bool pull_payload_length(const u8 **cursor,
				size_t *max,
				bool has_realm,
				enum onion_payload_type *type,
				size_t *len)
{
	/* *len will incorporate bytes we read from cursor */
	const u8 *start = *cursor;

	/* BOLT #4:
	 *
	 * The `length` field determines both the length and the format of the
	 * `hop_payload` field; the following formats are defined:
	 */
	*len = fromwire_bigsize(cursor, max);
	if (!cursor)
		return false;

	/* BOLT #4:
	 * - Legacy `hop_data` format, identified by a single `0x00` byte for
	 *   length. In this case the `hop_payload_length` is defined to be 32
	 *   bytes.
	 */
	if (has_realm && *len == 0) {
		if (type)
			*type = ONION_V0_PAYLOAD;
		assert(*cursor - start == 1);
		*len = 1 + 32;
		return true;
	}

	/* BOLT #4:
	 * - `tlv_payload` format, identified by any length over `1`. In this
	 *   case the `hop_payload_length` is equal to the numeric value of
	 *   `length`.
	 */
	if (!has_realm || *len > 1) {
		/* It's still invalid if it claims to be too long! */
		if (has_realm) {
			if (*len > ROUTING_INFO_SIZE - HMAC_SIZE)
				return false;
		} else {
			if (*len > *max)
				return false;
		}

		if (type)
			*type = ONION_TLV_PAYLOAD;
		*len += (*cursor - start);
		return true;
	}

	return false;
}

size_t onion_payload_length(const u8 *raw_payload, size_t len, bool has_realm,
			    bool *valid,
			    enum onion_payload_type *type)
{
	size_t max = len, payload_len;
	*valid = pull_payload_length(&raw_payload, &max, has_realm, type, &payload_len);

	/* If it's not valid, copy the entire thing. */
	if (!*valid)
		return len;

	return payload_len;
}

#if EXPERIMENTAL_FEATURES
static struct tlv_tlv_payload *decrypt_tlv(const tal_t *ctx,
					   const struct secret *blinding_ss,
					   const u8 *enc)
{
	const unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	struct secret rho;
	u8 *dec;
	const u8 *cursor;
	size_t max;
	int ret;
	struct tlv_tlv_payload *tlv;

	subkey_from_hmac("rho", blinding_ss, &rho);
	if (tal_bytelen(enc) < crypto_aead_chacha20poly1305_ietf_ABYTES)
		return NULL;

	dec = tal_arr(tmpctx, u8,
		      tal_bytelen(enc)
		      - crypto_aead_chacha20poly1305_ietf_ABYTES);
	ret = crypto_aead_chacha20poly1305_ietf_decrypt(dec, NULL,
							NULL,
							enc,
							tal_bytelen(enc),
							NULL, 0,
							npub,
							rho.data);
	if (ret != 0)
		return NULL;

	tlv = tlv_tlv_payload_new(ctx);
	cursor = dec;
	max = tal_bytelen(dec);
	if (!fromwire_tlv_payload(&cursor, &max, tlv))
		return tal_free(tlv);

	return tlv;
}
#endif /* EXPERIMENTAL_FEATURES */

struct onion_payload *onion_decode(const tal_t *ctx,
				   const struct route_step *rs,
				   const struct pubkey *blinding,
				   const struct secret *blinding_ss,
				   u64 *accepted_extra_tlvs,
				   u64 *failtlvtype,
				   size_t *failtlvpos)
{
	struct onion_payload *p = tal(ctx, struct onion_payload);
	const u8 *cursor = rs->raw_payload;
	size_t max = tal_bytelen(cursor), len;
	struct tlv_tlv_payload *tlv;

	if (!pull_payload_length(&cursor, &max, true, &p->type, &len))
		return tal_free(p);

	switch (p->type) {
	case ONION_V0_PAYLOAD:
		p->type = ONION_V0_PAYLOAD;
		p->forward_channel = tal(p, struct short_channel_id);
		fromwire_short_channel_id(&cursor, &max, p->forward_channel);
		p->amt_to_forward = fromwire_amount_msat(&cursor, &max);
		p->outgoing_cltv = fromwire_u32(&cursor, &max);
		p->payment_secret = NULL;
		p->blinding = NULL;
		/* We can't handle blinding with a legacy payload */
		if (blinding)
			return tal_free(p);

		if (rs->nextcase == ONION_FORWARD) {
			p->total_msat = NULL;
		} else {
			/* BOLT #4:
			 * - if it is the final node:
			 *   - MUST treat `total_msat` as if it were equal to
			 *     `amt_to_forward` if it is not present. */
			p->total_msat = tal_dup(p, struct amount_msat,
						&p->amt_to_forward);
		}

		/* If they somehow got an invalid onion this far, fail. */
		if (!cursor)
			return tal_free(p);
		p->tlv = NULL;
		return p;

	case ONION_TLV_PAYLOAD:
		tlv = tlv_tlv_payload_new(p);
		if (!fromwire_tlv_payload(&cursor, &max, tlv))
			goto fail;

		if (!tlv_fields_valid(tlv->fields, accepted_extra_tlvs, failtlvpos)) {
			*failtlvtype = tlv->fields[*failtlvpos].numtype;
			goto fail;
		}

		/* BOLT #4:
		 *
		 * The reader:
		 *   - MUST return an error if `amt_to_forward` or
		 *     `outgoing_cltv_value` are not present.
		 */
		if (!tlv->amt_to_forward || !tlv->outgoing_cltv_value)
			goto fail;

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
			if (!tlv->short_channel_id)
				goto fail;
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

#if EXPERIMENTAL_FEATURES
		if (!p->blinding) {
			/* If we have no blinding, it could be in TLV. */
			if (tlv->blinding_point) {
				p->blinding =
					tal_dup(p, struct pubkey,
						tlv->blinding_point);
				ecdh(p->blinding, &p->blinding_ss);
			}
		} else
			p->blinding_ss = *blinding_ss;

		if (p->blinding) {
			/* If they give us a blinding and we're not terminal,
			 * we must have an enctlv. */
			if (rs->nextcase == ONION_FORWARD) {
				struct tlv_tlv_payload *ntlv;

				if (!tlv->encrypted_recipient_data)
					goto fail;

				ntlv = decrypt_tlv(tmpctx,
						   &p->blinding_ss,
						   tlv->encrypted_recipient_data);
				if (!ntlv)
					goto fail;

				/* Must override short_channel_id */
				if (!ntlv->short_channel_id)
					goto fail;

				*p->forward_channel
					= *ntlv->short_channel_id;
			}
		}
#endif /* EXPERIMENTAL_FEATURES */

		if (tlv->payment_data) {
			p->payment_secret = tal_dup(p, struct secret,
						    &tlv->payment_data->payment_secret);
			tal_free(p->total_msat);
			p->total_msat = tal(p, struct amount_msat);
			*p->total_msat
				= amount_msat(tlv->payment_data->total_msat);
		}
		p->tlv = tal_steal(p, tlv);
		return p;
	}

	/* You said it was a valid type! */
	abort();
fail:
	tal_free(tlv);
	tal_free(p);
	return NULL;
}
