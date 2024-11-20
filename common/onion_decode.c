#include "config.h"
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/blindedpath.h>
#include <common/ecdh.h>
#include <common/onion_decode.h>
#include <common/sphinx.h>
#include <inttypes.h>
#include <sodium/crypto_aead_chacha20poly1305.h>

/* BOLT #4:
 * - If `encrypted_recipient_data` is present:
 *...
 *     - If it is not the final node:
 *       - MUST return an error if the payload contains other tlv fields than
 *         `encrypted_recipient_data` and `current_path_key`.
 */
static bool check_nonfinal_tlv(const struct tlv_payload *tlv,
			       u64 *failtlvtype)
{
	for (size_t i = 0; i < tal_count(tlv->fields); i++) {
		switch (tlv->fields[i].numtype) {
		case TLV_PAYLOAD_CURRENT_PATH_KEY:
		case TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA:
			continue;
		}
		*failtlvtype = tlv->fields[i].numtype;
		return false;
	}
	return true;
}

/* BOLT #4:
 * - If `encrypted_recipient_data` is present:
 *...
 *   - If it is the final node:
 *     - MUST return an error if the payload contains other tlv fields than
 *      `encrypted_recipient_data`, `current_path_key`, `amt_to_forward`,
 *      `outgoing_cltv_value` and `total_amount_msat`.
 */
static bool check_final_tlv(const struct tlv_payload *tlv,
			    u64 *failtlvtype)
{
	for (size_t i = 0; i < tal_count(tlv->fields); i++) {
		switch (tlv->fields[i].numtype) {
		case TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA:
		case TLV_PAYLOAD_CURRENT_PATH_KEY:
		case TLV_PAYLOAD_AMT_TO_FORWARD:
		case TLV_PAYLOAD_OUTGOING_CLTV_VALUE:
		case TLV_PAYLOAD_TOTAL_AMOUNT_MSAT:
			continue;
		}
		*failtlvtype = tlv->fields[i].numtype;
		return false;
	}
	return true;
}

static u64 ceil_div(u64 a, u64 b)
{
	return (a + b - 1) / b;
}

static bool handle_blinded_forward(const tal_t *ctx,
				   struct onion_payload *p,
				   struct amount_msat amount_in,
				   u32 cltv_expiry,
				   const struct tlv_payload *tlv,
				   const struct tlv_encrypted_data_tlv *enc,
				   u64 *failtlvtype,
				   const char **explanation)
{
	u64 amt = amount_in.millisatoshis; /* Raw: allowed to wrap */

	if (!check_nonfinal_tlv(tlv, failtlvtype)) {
		if (explanation)
			*explanation = tal_fmt(ctx, "unexpected tlv type %"PRIu64, *failtlvtype);
		return false;
	}

	/* BOLT #4:
	 * - If it is not the final node:
	 *...
	 *   - MUST return an error if `encrypted_recipient_data` does not
	 *     contain either `short_channel_id` or `next_node_id`.
	 */
	if (!enc->short_channel_id && !enc->next_node_id) {
		if (explanation)
			*explanation = tal_fmt(ctx, "neither short_channel_id nor next_node_id present");
		*failtlvtype = TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
		return false;
	}

	if (enc->short_channel_id) {
		p->forward_channel = tal_dup(p, struct short_channel_id,
					     enc->short_channel_id);
		p->forward_node_id = NULL;
	} else {
		p->forward_channel = NULL;
		p->forward_node_id = tal_dup(p, struct pubkey,
					     enc->next_node_id);
	}

	p->total_msat = NULL;

	/* BOLT #4:
	 * - If it is not the final node:
	 *...
	 *   - MUST return an error if `encrypted_recipient_data` does not
	 *     contain `payment_relay`.
	 */
	if (!enc->payment_relay) {
		if (explanation)
			*explanation = tal_fmt(ctx, "missing payment_relay");
		*failtlvtype = TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
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

static bool handle_blinded_terminal(const tal_t *ctx,
				    struct onion_payload *p,
				    const struct tlv_payload *tlv,
				    const struct tlv_encrypted_data_tlv *enc,
				    u64 *failtlvtype,
				    const char **explanation)
{
	if (!check_final_tlv(tlv, failtlvtype)) {
		if (explanation)
			*explanation = tal_fmt(ctx, "unexpected tlv type %"PRIu64, *failtlvtype);
		return false;
	}

	/* BOLT #4:
	 *   - MUST return an error if `amt_to_forward`, `outgoing_cltv_value`
	 *     or `total_amount_msat` are not present.
	 *   - MUST return an error if `amt_to_forward` is below what it expects
	 *     for the payment.
	 */
	if (!tlv->amt_to_forward) {
		if (explanation)
			*explanation = tal_fmt(ctx, "missing amt_to_forward");
		*failtlvtype = TLV_PAYLOAD_AMT_TO_FORWARD;
		return false;
	}

	if (!tlv->outgoing_cltv_value) {
		if (explanation)
			*explanation = tal_fmt(ctx, "missing outgoing_cltv_value");
		*failtlvtype = TLV_PAYLOAD_OUTGOING_CLTV_VALUE;
		return false;
	}

	if (!tlv->total_amount_msat) {
		if (explanation)
			*explanation = tal_fmt(ctx, "missing total_amount_msat");
		*failtlvtype = TLV_PAYLOAD_TOTAL_AMOUNT_MSAT;
		return false;
	}

	p->amt_to_forward = amount_msat(*tlv->amt_to_forward);
	p->outgoing_cltv = *tlv->outgoing_cltv_value;

	p->forward_channel = NULL;
	p->forward_node_id = NULL;

	if (tlv->total_amount_msat) {
		p->total_msat = tal(p, struct amount_msat);
		*p->total_msat = amount_msat(*tlv->total_amount_msat);
	} else {
		/* BOLT #4:
		 * - If it is the final node:
		 *   - MUST treat `total_msat` as if it were equal to
		 *     `amt_to_forward` if it is not present. */
		p->total_msat = tal_dup(p, struct amount_msat,
					&p->amt_to_forward);
	}
	return true;
}

struct onion_payload *onion_decode(const tal_t *ctx,
				   const struct route_step *rs,
				   const struct pubkey *path_key,
				   const u64 *accepted_extra_tlvs,
				   struct amount_msat amount_in,
				   u32 cltv_expiry,
				   u64 *failtlvtype,
				   size_t *failtlvpos,
				   const char **explanation)
{
	struct onion_payload *p = tal(ctx, struct onion_payload);
	const u8 *cursor = rs->raw_payload;
	size_t max = tal_bytelen(cursor), len;

	p->final = (rs->nextcase == ONION_END);

	/* BOLT #4:
	 * 1. type: `hop_payloads`
	 * 2. data:
	 *    * [`bigsize`:`length`]
	 *    * [`length*byte`:`payload`]
	 */
	len = fromwire_bigsize(&cursor, &max);
	if (!cursor || len > max) {
		*failtlvtype = 0;
		*failtlvpos = tal_bytelen(rs->raw_payload);
		if (explanation)
			*explanation = tal_fmt(ctx, "Too short for initial length");
		return tal_free(p);
	}

	/* We do this manually so we can accept extra types, and get
	 * error off and type. */
	p->tlv = tlv_payload_new(p);
	if (!fromwire_tlv(&cursor, &max, tlvs_tlv_payload,
			  TLVS_ARRAY_SIZE_tlv_payload,
			  p->tlv, &p->tlv->fields, accepted_extra_tlvs,
			  failtlvpos, failtlvtype)) {
		if (explanation)
			*explanation = tal_fmt(ctx, "Unparseable TLV");
		return tal_free(p);
	}

	/* BOLT #4:
	 *
	 * The reader:
	 *
	 *   - If `encrypted_recipient_data` is present:
	 */
	if (p->tlv->encrypted_recipient_data) {
		struct tlv_encrypted_data_tlv *enc;

		/* BOLT #4:
		 *
		 *   - If `path_key` is set in the incoming `update_add_htlc`:
		 *     - MUST return an error if `current_path_key` is present.
		 *     - MUST use that `path_key` as `path_key` for decryption.
		 *   - Otherwise:
		 *     - MUST return an error if `current_path_key` is not present.
		 *     - MUST use that `current_path_key` as the `path_key` for decryption.
		 */
		if (path_key) {
			if (p->tlv->current_path_key) {
				*failtlvtype = TLV_PAYLOAD_CURRENT_PATH_KEY;
				if (explanation)
					*explanation = tal_fmt(ctx, "current_path_key was present");
				goto field_bad;
			}
			p->path_key = tal_dup(p, struct pubkey, path_key);
		} else {
			if (!p->tlv->current_path_key) {
				*failtlvtype = TLV_PAYLOAD_CURRENT_PATH_KEY;
				if (explanation)
					*explanation = tal_fmt(ctx, "current_path_key was not present");
				goto field_bad;
			}
			p->path_key = tal_dup(p, struct pubkey,
					      p->tlv->current_path_key);
		}

		/* BOLT #4:
		 * The reader:
		 *...
		 *    - MUST return an error if `encrypted_recipient_data` does
		 *      not decrypt using the `path_key` as described in
		 *      [Route Blinding](#route-blinding).
		 */
		ecdh(p->path_key, &p->blinding_ss);
		enc = decrypt_encrypted_data(tmpctx, &p->blinding_ss,
					     p->tlv->encrypted_recipient_data);
		if (!enc) {
			if (explanation)
				*explanation = tal_fmt(ctx, "encrypted_recipient_data decryption failed");
			*failtlvtype = TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
			goto field_bad;
		}

		if (enc->payment_constraints) {
			/* BOLT #4:
			 * - MUST return an error if:
			 *   - the expiry is greater than
			 *    `encrypted_recipient_data.payment_constraints.max_cltv_expiry`.
			 */
			if (cltv_expiry > enc->payment_constraints->max_cltv_expiry) {
				if (explanation)
					*explanation = tal_fmt(ctx, "cltv_expiry %u > payment_constraint %u",
							       cltv_expiry,
							       enc->payment_constraints->max_cltv_expiry);
				*failtlvtype = TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
				goto field_bad;
			}

			/* BOLT #4:
			 * - MUST return an error if:
			 *...
			 *   - the amount is below
			 *     `encrypted_recipient_data.payment_constraints.htlc_minimum_msat`.
			 */
			if (amount_msat_less(amount_in,
					     amount_msat(enc->payment_constraints->htlc_minimum_msat))) {
				if (explanation)
					*explanation = tal_fmt(ctx, "amount_in %s < payment_constraint min %"PRIu64,
							       fmt_amount_msat(tmpctx, amount_in),
							       enc->payment_constraints->htlc_minimum_msat);
				*failtlvtype = TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
				goto field_bad;
			}

			/* BOLT #4:
 			 *   - MUST return an error if:
			 *...
			 *     - the payment uses a feature not included in
			 *       `encrypted_recipient_data.allowed_features.features`
			 */
			/* We don't have any features yet... */
		}

		/* BOLT #4:
		 * - If `allowed_features` is missing:
		 *   - MUST process the message as if it were present and contained an
		 *     empty array.
		 *   - MUST return an error if:
		 *     - `encrypted_recipient_data.allowed_features.features`
		 *        contains an unknown feature bit (even if it is odd).
		 *     - `encrypted_recipient_data` contains both
		 *       `short_channel_id` and `next_node_id`.
		 *     - the payment uses a feature not included in
		 *       `encrypted_recipient_data.allowed_features.features`.
		 */
		/* No features, this is easy */
		if (!memeqzero(enc->allowed_features,
			       tal_bytelen(enc->allowed_features))) {
			if (explanation)
				*explanation = tal_fmt(ctx, "non-zero allowed_features (%s)",
						       tal_hex(tmpctx, enc->allowed_features));
			*failtlvtype = TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
			goto field_bad;
		}

		if (enc->short_channel_id && enc->next_node_id) {
			if (explanation)
				*explanation = tal_fmt(ctx, "both scid and next_node_id present");
			*failtlvtype = TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
			goto field_bad;
		}

		if (!p->final) {
			if (!handle_blinded_forward(ctx, p, amount_in, cltv_expiry,
						    p->tlv, enc, failtlvtype, explanation))
				goto field_bad;
		} else {
			if (!handle_blinded_terminal(ctx, p, p->tlv, enc, failtlvtype, explanation))
				goto field_bad;
		}

		/* We stash path_id (if present and valid!) in payment_secret */
		if (tal_bytelen(enc->path_id) == sizeof(*p->payment_secret)) {
			p->payment_secret = tal_steal(p,
						      (struct secret *)enc->path_id);
		} else
			p->payment_secret = NULL;

		/* FIXME: if we supported metadata, it would also be in path_id */
		p->payment_metadata = NULL;
		return p;
	}

	/* BOLT #4:
	 *   - Otherwise (it is not part of a blinded route):
	 *      - MUST return an error if `path_key` is set in the
	 *        incoming `update_add_htlc` or `current_path_key`
	 *        is present.
	 */
	if (path_key || p->tlv->current_path_key) {
		if (explanation)
			*explanation = tal_fmt(ctx, "%s set outside blinded route",
					       path_key ? "update_add_htlc->path_key" : "current_path_key");
		*failtlvtype = TLV_PAYLOAD_ENCRYPTED_RECIPIENT_DATA;
		goto field_bad;
	}

	/* BOLT #4:
	 *
	 * - Otherwise (it is not part of a blinded route):
	 *...
	 *   - MUST return an error if `amt_to_forward` or
	 *     `outgoing_cltv_value` are not present.
	 */
	if (!p->tlv->amt_to_forward) {
		if (explanation)
			*explanation = tal_fmt(ctx, "missing amt_to_forward");
		*failtlvtype = TLV_PAYLOAD_AMT_TO_FORWARD;
		goto field_bad;
	}
	if (!p->tlv->outgoing_cltv_value) {
		if (explanation)
			*explanation = tal_fmt(ctx, "missing outgoing_cltv_value");
		*failtlvtype = TLV_PAYLOAD_OUTGOING_CLTV_VALUE;
		goto field_bad;
	}

	p->amt_to_forward = amount_msat(*p->tlv->amt_to_forward);
	p->outgoing_cltv = *p->tlv->outgoing_cltv_value;

	/* BOLT #4:
	 *
	 *    - if it is not the final node:
	 *      - MUST return an error if:
	 *        - `short_channel_id` is not present,
	 */
	if (!p->final) {
		if (!p->tlv->short_channel_id) {
			if (explanation)
				*explanation = tal_fmt(ctx, "missing short_channel_id");
			*failtlvtype = TLV_PAYLOAD_SHORT_CHANNEL_ID;
			goto field_bad;
		}
		p->forward_channel = tal_dup(p, struct short_channel_id,
					     p->tlv->short_channel_id);
		p->total_msat = NULL;
	} else {
		p->forward_channel = NULL;
		/* BOLT #4:
		 * - If it is the final node:
		 *   - MUST treat `total_msat` as if it were equal to
		 *     `amt_to_forward` if it is not present. */
		p->total_msat = tal_dup(p, struct amount_msat,
					&p->amt_to_forward);
	}

	/* Non-blinded is (currently) always by scid */
	p->forward_node_id = NULL;

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

	p->path_key = NULL;

	return p;

field_bad:
	*failtlvpos = tlv_field_offset(rs->raw_payload, tal_bytelen(rs->raw_payload),
				       *failtlvtype);
	return tal_free(p);
}
