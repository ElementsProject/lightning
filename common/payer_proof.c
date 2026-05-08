#include "config.h"
#include <assert.h>
#include <ccan/asort/asort.h>
#include <ccan/cast/cast.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <common/bech32_util.h>
#include <common/bigsize.h>
#include <common/bolt12.h>
#include <common/bolt12_merkle.h>
#include <common/payer_proof.h>
#include <common/utils.h>
#include <inttypes.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <wire/wire.h>

struct payer_proof_disclosure {
	struct sha256 *leaf_hashes;
	u64 *omitted_tlvs;
	struct sha256 *missing_hashes;
	struct sha256 merkle_root;
};

struct tlv_merkle_data {
	u64 type;
	struct sha256 per_tlv_hash;
	bool included;
};

struct tree_node {
	struct sha256 hash;
	bool has_hash;
	bool included;
	u64 min_order;
};

struct missing_hash {
	u64 min_order;
	struct sha256 hash;
};

struct hash_pos {
	u64 min_order;
	size_t pos;
};

static const u8 *string_to_data(const tal_t *ctx,
				const char *str,
				size_t str_len,
				const char *hrp_expected,
				size_t *dlen,
				char **fail)
{
	char *hrp;
	u8 *data;
	char *bech32;
	size_t bech32_len;
	bool have_plus = false;

	bech32 = tal_arr(tmpctx, char, str_len);
	bech32_len = 0;
	for (size_t i = 0; i < str_len; i++) {
		if (i != 0 && i + 1 != str_len
		    && !have_plus && str[i] == '+') {
			have_plus = true;
			continue;
		}
		if (have_plus && cisspace(str[i]))
			continue;
		have_plus = false;
		bech32[bech32_len++] = str[i];
	}

	if (have_plus) {
		*fail = tal_fmt(ctx, "unfinished string");
		return NULL;
	}

	if (!from_bech32_charset(ctx, bech32, bech32_len, &hrp, &data)) {
		*fail = tal_fmt(ctx, "invalid bech32 string");
		return NULL;
	}
	if (!streq(hrp, hrp_expected)) {
		*fail = tal_fmt(ctx, "unexpected prefix %s", hrp);
		data = tal_free(data);
	} else
		*dlen = tal_bytelen(data);

	tal_free(hrp);
	return data;
}

static bool known_payer_proof_field(u64 typenum)
{
	switch (typenum) {
	case PAYER_PROOF_TLV_SIGNATURE:
	case PAYER_PROOF_TLV_PREIMAGE:
	case PAYER_PROOF_TLV_OMITTED_TLVS:
	case PAYER_PROOF_TLV_MISSING_HASHES:
	case PAYER_PROOF_TLV_LEAF_HASHES:
	case PAYER_PROOF_TLV_PAYER_SIGNATURE:
		return true;
	}
	return false;
}

static void sha256_update_bigsize(struct sha256_ctx *ctx, u64 bigsize)
{
	u8 buf[BIGSIZE_MAX_LEN];
	size_t len;

	len = bigsize_put(buf, bigsize);
	sha256_update(ctx, buf, len);
}

static void sha256_update_tlvfield(struct sha256_ctx *ctx,
				   const struct tlv_field *field)
{
	sha256_update_bigsize(ctx, field->numtype);
	sha256_update_bigsize(ctx, field->length);
	sha256_update(ctx, field->value, field->length);
}

static void tagged_ctx(struct sha256_ctx *ctx, const char *tag)
{
	struct sha256 taghash;

	sha256(&taghash, tag, strlen(tag));
	sha256_init(ctx);
	sha256_update(ctx, &taghash, sizeof(taghash));
	sha256_update(ctx, &taghash, sizeof(taghash));
}

static void lnnonce_ctx(struct sha256_ctx *ctx,
			const struct tlv_field *first_field)
{
	struct sha256_ctx inner;
	struct sha256 taghash;

	sha256_init(&inner);
	sha256_update(&inner, "LnNonce", strlen("LnNonce"));
	sha256_update_tlvfield(&inner, first_field);
	sha256_done(&inner, &taghash);

	sha256_init(ctx);
	sha256_update(ctx, &taghash, sizeof(taghash));
	sha256_update(ctx, &taghash, sizeof(taghash));
}

static void calc_nonce(const struct sha256_ctx *lnnonce_ctx,
		       const struct tlv_field *field,
		       struct sha256 *nonce)
{
	struct sha256_ctx ctx = *lnnonce_ctx;

	sha256_update_bigsize(&ctx, field->numtype);
	sha256_done(&ctx, nonce);
}

static void calc_lnleaf(const struct tlv_field *field, struct sha256 *leaf)
{
	struct sha256_ctx ctx;

	tagged_ctx(&ctx, "LnLeaf");
	sha256_update_tlvfield(&ctx, field);
	sha256_done(&ctx, leaf);
}

static void branch_hash(const struct sha256 *a,
			const struct sha256 *b,
			struct sha256 *hash)
{
	const struct sha256 *lesser, *greater;
	struct sha256_ctx ctx;

	if (memcmp(a, b, sizeof(*a)) < 0) {
		lesser = a;
		greater = b;
	} else {
		lesser = b;
		greater = a;
	}

	tagged_ctx(&ctx, "LnBranch");
	sha256_update(&ctx, lesser, sizeof(*lesser));
	sha256_update(&ctx, greater, sizeof(*greater));
	sha256_done(&ctx, hash);
}

static bool parse_field_bip340sig(const struct tlv_field *field,
				  struct bip340sig *sig)
{
	const u8 *cursor = field->value;
	size_t len = field->length;

	fromwire_bip340sig(&cursor, &len, sig);
	return cursor != NULL && len == 0;
}

static bool parse_field_preimage(const struct tlv_field *field,
				 struct preimage *preimage)
{
	const u8 *cursor = field->value;
	size_t len = field->length;

	fromwire_preimage(&cursor, &len, preimage);
	return cursor != NULL && len == 0;
}

static bool has_field_type(const struct tlv_field *fields, u64 typenum)
{
	for (size_t i = 0; i < tal_count(fields); i++) {
		if (fields[i].numtype == typenum)
			return true;
	}
	return false;
}

static bool has_include_type(const u64 *include_types, u64 typenum)
{
	for (size_t i = 0; i < tal_count(include_types); i++) {
		if (include_types[i] == typenum)
			return true;
	}
	return false;
}

static void add_include_type(u64 **include_types, u64 typenum)
{
	if (has_include_type(*include_types, typenum))
		return;
	tal_arr_expand(include_types, typenum);
}

static int missing_hash_cmp(const struct missing_hash *a,
			    const struct missing_hash *b,
			    void *unused)
{
	if (a->min_order < b->min_order)
		return -1;
	if (a->min_order > b->min_order)
		return 1;
	return 0;
}

static int hash_pos_cmp(const struct hash_pos *a,
			const struct hash_pos *b,
			void *unused)
{
	if (a->min_order < b->min_order)
		return -1;
	if (a->min_order > b->min_order)
		return 1;
	return 0;
}

static size_t count_tail_omitted_tlvs(const struct tlv_merkle_data *tlv_data)
{
	size_t last_included = 0;
	size_t tail_omitted = 0;
	bool have_included = false;

	for (size_t i = 0; i < tal_count(tlv_data); i++) {
		if (tlv_data[i].included) {
			last_included = i;
			have_included = true;
		}
	}

	for (size_t i = have_included ? last_included + 1 : 0;
	     i < tal_count(tlv_data);
	     i++) {
		if (!tlv_data[i].included)
			tail_omitted++;
	}

	return tail_omitted;
}

static bool compute_selective_disclosure(const tal_t *ctx,
					 const struct tlv_field *fields,
					 const u64 *include_types,
					 struct payer_proof_disclosure *disclosure,
					 char **fail)
{
	struct tlv_merkle_data *tlv_data;
	struct sha256_ctx lnnonce;
	const struct tlv_field *first_field = NULL;

	tlv_data = tal_arr(ctx, struct tlv_merkle_data, 0);
	disclosure->leaf_hashes = tal_arr(ctx, struct sha256, 0);
	disclosure->omitted_tlvs = tal_arr(ctx, u64, 0);
	disclosure->missing_hashes = tal_arr(ctx, struct sha256, 0);

	for (size_t i = 0; i < tal_count(fields); i++) {
		if (is_bolt12_signature_field(fields[i].numtype))
			continue;
		first_field = &fields[i];
		break;
	}

	if (!first_field) {
		*fail = tal_fmt(ctx, "invoice has no fields outside signature range");
		return false;
	}

	lnnonce_ctx(&lnnonce, first_field);
	for (size_t i = 0; i < tal_count(fields); i++) {
		struct tlv_merkle_data d;
		struct sha256 leaf, nonce;

		if (is_bolt12_signature_field(fields[i].numtype))
			continue;

		d.type = fields[i].numtype;
		d.included = has_include_type(include_types, fields[i].numtype);
		calc_lnleaf(&fields[i], &leaf);
		calc_nonce(&lnnonce, &fields[i], &nonce);
		branch_hash(&leaf, &nonce, &d.per_tlv_hash);
		if (d.included)
			tal_arr_expand(&disclosure->leaf_hashes, nonce);
		tal_arr_expand(&tlv_data, d);
	}

	if (tal_count(tlv_data) == 0) {
		*fail = tal_fmt(ctx, "invoice has no fields outside signature range");
		return false;
	}
	if (count_tail_omitted_tlvs(tlv_data) > 1) {
		*fail = tal_fmt(ctx,
				"multiple omitted_tlvs markers after last included field");
		return false;
	}

	{
		u64 prev_value = 0;

		for (size_t i = 0; i < tal_count(tlv_data); i++) {
			if (tlv_data[i].type == 0)
				continue;
			if (tlv_data[i].included)
				prev_value = tlv_data[i].type;
			else {
				u64 marker = prev_value + 1;
				tal_arr_expand(&disclosure->omitted_tlvs, marker);
				prev_value = marker;
			}
		}
	}

	{
		struct tree_node *nodes;
		struct missing_hash *missing;
		size_t num_nodes = tal_count(tlv_data);

		nodes = tal_arr(ctx, struct tree_node, num_nodes);
		missing = tal_arr(ctx, struct missing_hash, 0);
		for (size_t i = 0; i < num_nodes; i++) {
			nodes[i].hash = tlv_data[i].per_tlv_hash;
			nodes[i].has_hash = true;
			nodes[i].included = tlv_data[i].included;
			nodes[i].min_order = tlv_data[i].type;
		}

		for (size_t level = 0; ; level++) {
			size_t step = 2ULL << level;
			size_t offset = step / 2;

			if (offset >= num_nodes)
				break;

			for (size_t left = 0; left + offset < num_nodes;
			     left += step) {
				size_t right = left + offset;

				if (!nodes[left].has_hash)
					abort();
				if (!nodes[right].has_hash)
					continue;

				if (nodes[left].included != nodes[right].included) {
					struct missing_hash m;
					if (nodes[right].included) {
						m.min_order = nodes[left].min_order;
						m.hash = nodes[left].hash;
					} else {
						m.min_order = nodes[right].min_order;
						m.hash = nodes[right].hash;
					}
					tal_arr_expand(&missing, m);
				}

				branch_hash(&nodes[left].hash,
					    &nodes[right].hash,
					    &nodes[left].hash);
				nodes[left].included |= nodes[right].included;
				nodes[left].min_order = min_u64(nodes[left].min_order,
							       nodes[right].min_order);
			}
		}

		asort(missing, tal_count(missing), missing_hash_cmp, NULL);
		for (size_t i = 0; i < tal_count(missing); i++)
			tal_arr_expand(&disclosure->missing_hashes,
				       missing[i].hash);
		disclosure->merkle_root = nodes[0].hash;
	}
	return true;
}

static bool validate_omitted_tlvs(const tal_t *ctx,
				  const u64 *omitted_tlvs,
				  const struct tlv_field *fields,
				  char **fail)
{
	size_t inc_idx = 0;
	size_t tail_markers = 0;
	u64 expected_next = 1, prev = 0;
	u64 max_included = tal_count(fields) ? fields[tal_count(fields) - 1].numtype : 0;

	for (size_t i = 0; i < tal_count(omitted_tlvs); i++) {
		u64 marker = omitted_tlvs[i];
		bool found = false;

		if (marker == 0) {
			*fail = tal_fmt(ctx, "invalid omitted_tlvs marker 0");
			return false;
		}
		if (is_bolt12_signature_field(marker)) {
			*fail = tal_fmt(ctx, "invalid omitted_tlvs marker %"PRIu64,
					marker);
			return false;
		}
		if (marker <= prev) {
			*fail = tal_fmt(ctx, "unordered omitted_tlvs marker %"PRIu64,
					marker);
			return false;
		}
		if (has_field_type(fields, marker)) {
			*fail = tal_fmt(ctx, "omitted_tlvs marker %"PRIu64
					" matches disclosed field",
					marker);
			return false;
		}
		if (marker > max_included && ++tail_markers > 1) {
			*fail = tal_fmt(ctx,
					"multiple omitted_tlvs markers after last included field");
			return false;
		}

		if (marker != expected_next) {
			for (; inc_idx < tal_count(fields); inc_idx++) {
				if (fields[inc_idx].numtype + 1 == marker) {
					found = true;
					inc_idx++;
					break;
				}
				if (fields[inc_idx].numtype >= marker) {
					*fail = tal_fmt(ctx, "non-minimal omitted_tlvs marker %"PRIu64,
							marker);
					return false;
				}
			}
			if (!found) {
				*fail = tal_fmt(ctx, "non-minimal omitted_tlvs marker %"PRIu64,
						marker);
				return false;
			}
		}

		expected_next = marker + 1;
		prev = marker;
	}
	return true;
}

static bool reconstruct_merkle_root(const tal_t *ctx,
				    const struct tlv_field *included_fields,
				    const struct sha256 *leaf_hashes,
				    const u64 *omitted_tlvs,
				    const struct sha256 *missing_hashes,
				    struct sha256 *merkle_root,
				    char **fail)
{
	struct tree_node *nodes;
	struct hash_pos *needs_hash;
	size_t inc_idx, mrk_idx, num_nodes;
	u64 prev_marker, node_order;

	if (tal_count(included_fields) != tal_count(leaf_hashes)) {
		*fail = tal_fmt(ctx, "leaf_hashes count does not match disclosed fields");
		return false;
	}

	num_nodes = 1 + tal_count(included_fields) + tal_count(omitted_tlvs);
	nodes = tal_arr(ctx, struct tree_node, 0);
	needs_hash = tal_arr(ctx, struct hash_pos, 0);

	tal_arr_expand(&nodes, ((struct tree_node) {
				.has_hash = false,
				.included = false,
				.min_order = 0,
			}));

	inc_idx = mrk_idx = 0;
	prev_marker = 0;
	node_order = 1;
	while (inc_idx < tal_count(included_fields)
	       || mrk_idx < tal_count(omitted_tlvs)) {
		struct tree_node n;

		memset(&n, 0, sizeof(n));
		n.min_order = node_order;
		if (mrk_idx >= tal_count(omitted_tlvs)) {
			struct sha256 leaf;

			calc_lnleaf(&included_fields[inc_idx], &leaf);
			branch_hash(&leaf, &leaf_hashes[inc_idx], &n.hash);
			n.has_hash = true;
			n.included = true;
			inc_idx++;
		} else if (inc_idx >= tal_count(included_fields)) {
			prev_marker = omitted_tlvs[mrk_idx++];
		} else if (omitted_tlvs[mrk_idx] == prev_marker + 1) {
			prev_marker = omitted_tlvs[mrk_idx++];
		} else {
			struct sha256 leaf;

			calc_lnleaf(&included_fields[inc_idx], &leaf);
			branch_hash(&leaf, &leaf_hashes[inc_idx], &n.hash);
			n.has_hash = true;
			n.included = true;
			prev_marker = included_fields[inc_idx].numtype;
			inc_idx++;
		}
		tal_arr_expand(&nodes, n);
		node_order++;
	}

	for (size_t level = 0; ; level++) {
		size_t step = 2ULL << level;
		size_t offset = step / 2;

		if (offset >= num_nodes)
			break;

		for (size_t left = 0; left + offset < num_nodes;
		     left += step) {
			size_t right = left + offset;

			if (nodes[left].included && !nodes[right].included) {
				struct hash_pos pos = {
					.min_order = nodes[right].min_order,
					.pos = right,
				};
				tal_arr_expand(&needs_hash, pos);
				nodes[left].min_order = min_u64(nodes[left].min_order,
							       nodes[right].min_order);
			} else if (!nodes[left].included && nodes[right].included) {
				struct hash_pos pos = {
					.min_order = nodes[left].min_order,
					.pos = left,
				};
				tal_arr_expand(&needs_hash, pos);
				nodes[left].included = true;
				nodes[left].min_order = min_u64(nodes[left].min_order,
							       nodes[right].min_order);
			} else {
				nodes[left].min_order = min_u64(nodes[left].min_order,
							       nodes[right].min_order);
			}
		}
	}

	asort(needs_hash, tal_count(needs_hash), hash_pos_cmp, NULL);
	if (tal_count(needs_hash) != tal_count(missing_hashes)) {
		*fail = tal_fmt(ctx, "missing_hashes count mismatch");
		return false;
	}

	for (size_t i = 0; i < tal_count(needs_hash); i++) {
		nodes[needs_hash[i].pos].hash = missing_hashes[i];
		nodes[needs_hash[i].pos].has_hash = true;
	}

	for (size_t level = 0; ; level++) {
		size_t step = 2ULL << level;
		size_t offset = step / 2;

		if (offset >= num_nodes)
			break;

		for (size_t left = 0; left + offset < num_nodes;
		     left += step) {
			size_t right = left + offset;

			if (!nodes[left].has_hash) {
				*fail = tal_fmt(ctx, "insufficient missing_hashes");
				return false;
			}
			if (!nodes[right].has_hash)
				continue;
			branch_hash(&nodes[left].hash,
				    &nodes[right].hash,
				    &nodes[left].hash);
		}
	}

	if (!nodes[0].has_hash) {
		*fail = tal_fmt(ctx, "insufficient missing_hashes");
		return false;
	}
	*merkle_root = nodes[0].hash;
	return true;
}

static void payer_proof_sighash(const char *note,
				const struct sha256 *merkle_root,
				struct sha256 *sighash)
{
	struct sha256 inner;
	struct sha256_ctx ctx;

	sha256_init(&ctx);
	if (note)
		sha256_update(&ctx, note, strlen(note));
	sha256_update(&ctx, merkle_root, sizeof(*merkle_root));
	sha256_done(&ctx, &inner);

	bip340_sighash_init(&ctx, "lightning", "payer_proof", "payer_signature");
	sha256_update(&ctx, &inner, sizeof(inner));
	sha256_done(&ctx, sighash);
}

static bool verify_invoice_signature(const tal_t *ctx,
				     const struct payer_proof *proof,
				     char **fail)
{
	struct sha256 sighash;

	if (!proof->invoice->invoice_node_id) {
		*fail = tal_fmt(ctx, "missing invoice_node_id");
		return false;
	}
	if (!proof->invoice_signature) {
		*fail = tal_fmt(ctx, "missing invoice signature");
		return false;
	}

	sighash_from_merkle("invoice", "signature",
			    &proof->merkle_root, &sighash);
	if (!check_schnorr_sig(&sighash,
			       &proof->invoice->invoice_node_id->pubkey,
			       proof->invoice_signature)) {
		*fail = tal_fmt(ctx, "invalid invoice signature");
		return false;
	}
	return true;
}

static bool verify_payer_signature(const tal_t *ctx,
				   const struct payer_proof *proof,
				   char **fail)
{
	struct sha256 sighash;

	if (!proof->invoice->invreq_payer_id) {
		*fail = tal_fmt(ctx, "missing invreq_payer_id");
		return false;
	}
	if (!proof->payer_signature) {
		*fail = tal_fmt(ctx, "missing payer_signature");
		return false;
	}

	payer_proof_sighash(proof->payer_note, &proof->merkle_root, &sighash);
	if (!check_schnorr_sig(&sighash,
			       &proof->invoice->invreq_payer_id->pubkey,
			       proof->payer_signature)) {
		*fail = tal_fmt(ctx, "invalid payer signature");
		return false;
	}
	return true;
}

static bool verify_preimage(const tal_t *ctx,
			    const struct payer_proof *proof,
			    char **fail)
{
	struct sha256 hash;

	if (!proof->preimage) {
		*fail = tal_fmt(ctx, "missing payment preimage");
		return false;
	}
	if (!proof->invoice->invoice_payment_hash) {
		*fail = tal_fmt(ctx, "missing invoice_payment_hash");
		return false;
	}

	sha256(&hash, proof->preimage->r, sizeof(proof->preimage->r));
	if (!sha256_eq(&hash, proof->invoice->invoice_payment_hash)) {
		*fail = tal_fmt(ctx, "payment preimage does not match invoice_payment_hash");
		return false;
	}
	return true;
}

u8 *payer_proof_serialize(const tal_t *ctx, const struct payer_proof *proof)
{
	u8 *wire = tal_arr(ctx, u8, 0);
	struct tlv_field *fields;

	fields = tal_dup_talarr(tmpctx, struct tlv_field, proof->fields);
	towire_tlvstream_raw(&wire, fields);
	return wire;
}

char *payer_proof_encode(const tal_t *ctx, const struct payer_proof *proof)
{
	u8 *wire = payer_proof_serialize(tmpctx, proof);

	return to_bech32_charset(ctx, "lnp", wire);
}

bool payer_proof_has_prefix(const char *str)
{
	return strstarts(str, "lnp1") || strstarts(str, "LNP1");
}

static struct tlv_invoice *decode_disclosed_invoice(const tal_t *ctx,
						    const struct tlv_field *fields,
						    char **fail)
{
	u8 *wire = tal_arr(tmpctx, u8, 0);
	const u8 *cursor;
	size_t len;
	struct tlv_invoice *invoice;

	for (size_t i = 0; i < tal_count(fields); i++) {
		if (is_bolt12_signature_field(fields[i].numtype))
			continue;
		if (fields[i].numtype == 0) {
			*fail = tal_fmt(ctx, "invreq_metadata must not be disclosed");
			return NULL;
		}
		towire_bigsize(&wire, fields[i].numtype);
		towire_bigsize(&wire, fields[i].length);
		towire(&wire, fields[i].value, fields[i].length);
	}

	cursor = wire;
	len = tal_bytelen(wire);
	invoice = fromwire_tlv_invoice(ctx, &cursor, &len);
	if (!invoice || len != 0) {
		*fail = tal_fmt(ctx, "invalid disclosed invoice TLVs");
		return tal_free(invoice);
	}
	return invoice;
}

struct payer_proof *payer_proof_decode(const tal_t *ctx,
				       const char *b12, size_t b12len,
				       char **fail)
{
	struct payer_proof *proof;
	const u8 *data, *cursor;
	size_t dlen;

	data = string_to_data(tmpctx, b12, b12len, "lnp", &dlen, fail);
	if (!data)
		return NULL;

	proof = talz(ctx, struct payer_proof);
	proof->fields = tal_arr(proof, struct tlv_field, 0);
	cursor = data;
	if (!fromwire_tlv(&cursor, &dlen, NULL, 0, proof,
			  &proof->fields, FROMWIRE_TLV_ANY_TYPE,
			  NULL, NULL)
	    || dlen != 0) {
		*fail = tal_fmt(ctx, "invalid payer proof data");
		return tal_free(proof);
	}
	if (tal_count(proof->fields) == 0) {
		*fail = tal_fmt(ctx, "empty payer proof");
		return tal_free(proof);
	}

	for (size_t i = 0; i < tal_count(proof->fields); i++) {
		const struct tlv_field *field = &proof->fields[i];

		/* Unknown field in the 240+ signature range */
		if (is_bolt12_signature_field(field->numtype)
		    && !known_payer_proof_field(field->numtype)) {
			if (field->numtype % 2 == 0) {
				*fail = tal_fmt(ctx, "unknown even payer proof field %"PRIu64,
						field->numtype);
				return tal_free(proof);
			}
			continue;
		}

		switch (field->numtype) {
		case 0:
			*fail = tal_fmt(ctx, "invreq_metadata must not be disclosed");
			return tal_free(proof);
		case PAYER_PROOF_TLV_SIGNATURE:
			proof->invoice_signature = tal(proof, struct bip340sig);
			if (!parse_field_bip340sig(field, proof->invoice_signature)) {
				*fail = tal_fmt(ctx, "invalid invoice signature");
				return tal_free(proof);
			}
			break;
		case PAYER_PROOF_TLV_PREIMAGE:
			proof->preimage = tal(proof, struct preimage);
			if (!parse_field_preimage(field, proof->preimage)) {
				*fail = tal_fmt(ctx, "invalid payment preimage");
				return tal_free(proof);
			}
			break;
		case PAYER_PROOF_TLV_OMITTED_TLVS: {
			const u8 *p = field->value;
			size_t max = field->length;

			proof->omitted_tlvs = tal_arr(proof, u64, 0);
			while (max) {
				u64 marker = fromwire_bigsize(&p, &max);
				if (!p) {
					*fail = tal_fmt(ctx, "invalid omitted_tlvs");
					return tal_free(proof);
				}
				tal_arr_expand(&proof->omitted_tlvs, marker);
			}
			break;
		}
		case PAYER_PROOF_TLV_MISSING_HASHES:
			if (field->length % sizeof(struct sha256) != 0) {
				*fail = tal_fmt(ctx, "invalid missing_hashes");
				return tal_free(proof);
			}
			proof->missing_hashes
				= tal_arr(proof, struct sha256,
					  field->length / sizeof(struct sha256));
			memcpy(proof->missing_hashes, field->value, field->length);
			break;
		case PAYER_PROOF_TLV_LEAF_HASHES:
			if (field->length % sizeof(struct sha256) != 0) {
				*fail = tal_fmt(ctx, "invalid leaf_hashes");
				return tal_free(proof);
			}
			proof->leaf_hashes
				= tal_arr(proof, struct sha256,
					  field->length / sizeof(struct sha256));
			memcpy(proof->leaf_hashes, field->value, field->length);
			break;
		case PAYER_PROOF_TLV_PAYER_SIGNATURE:
			if (field->length < sizeof(*proof->payer_signature)) {
				*fail = tal_fmt(ctx, "invalid payer_signature");
				return tal_free(proof);
			}
			proof->payer_signature = tal(proof, struct bip340sig);
			memcpy(proof->payer_signature,
			       field->value,
			       sizeof(*proof->payer_signature));
			if (field->length != sizeof(*proof->payer_signature)) {
				/* utf8_str returns a NUL-terminated C string,
				 * safe for later strlen() in payer_proof_sighash. */
				proof->payer_note = utf8_str(proof,
							     field->value + sizeof(*proof->payer_signature),
							     field->length - sizeof(*proof->payer_signature));
				if (!proof->payer_note) {
					*fail = tal_fmt(ctx, "invalid payer note");
					return tal_free(proof);
				}
			}
			break;
		}
	}

	if (!proof->omitted_tlvs)
		proof->omitted_tlvs = tal_arr(proof, u64, 0);
	if (!proof->missing_hashes)
		proof->missing_hashes = tal_arr(proof, struct sha256, 0);
	if (!proof->leaf_hashes)
		proof->leaf_hashes = tal_arr(proof, struct sha256, 0);

	proof->invoice = decode_disclosed_invoice(proof, proof->fields, fail);
	if (!proof->invoice)
		return tal_free(proof);

	if (!proof->invoice->invreq_payer_id) {
		*fail = tal_fmt(ctx, "missing invreq_payer_id");
		return tal_free(proof);
	}
	if (!proof->invoice->invoice_payment_hash) {
		*fail = tal_fmt(ctx, "missing invoice_payment_hash");
		return tal_free(proof);
	}
	if (!proof->invoice->invoice_node_id) {
		*fail = tal_fmt(ctx, "missing invoice_node_id");
		return tal_free(proof);
	}

	if (!validate_omitted_tlvs(ctx,
				   proof->omitted_tlvs,
				   proof->invoice->fields,
				   fail))
		return tal_free(proof);
	if (!reconstruct_merkle_root(proof,
				     proof->invoice->fields,
				     proof->leaf_hashes,
				     proof->omitted_tlvs,
				     proof->missing_hashes,
				     &proof->merkle_root,
				     fail))
		return tal_free(proof);
	if (!verify_preimage(ctx, proof, fail))
		return tal_free(proof);
	if (!verify_invoice_signature(ctx, proof, fail))
		return tal_free(proof);
	if (!verify_payer_signature(ctx, proof, fail))
		return tal_free(proof);

	return proof;
}

struct payer_proof *payer_proof_from_invoice(const tal_t *ctx,
					     const struct tlv_invoice *invoice,
					     const struct preimage *preimage,
					     const struct secret *payer_secret,
					     const u64 *extra_include_types,
					     const char *note,
					     char **fail)
{
	struct payer_proof *proof;
	struct payer_proof_disclosure disclosure;
	struct sha256 payment_hash, invoice_merkle, payer_sighash;
	u64 *include_types;
	u8 *invoice_wire;
	const u8 *cursor;
	size_t len;
	struct pubkey payer_id;
	secp256k1_keypair payer_keypair;

	if (!invoice->invreq_payer_id) {
		*fail = tal_fmt(ctx, "invoice missing invreq_payer_id");
		return NULL;
	}
	if (!invoice->invoice_payment_hash) {
		*fail = tal_fmt(ctx, "invoice missing invoice_payment_hash");
		return NULL;
	}
	if (!invoice->invoice_node_id) {
		*fail = tal_fmt(ctx, "invoice missing invoice_node_id");
		return NULL;
	}
	if (!invoice->signature) {
		*fail = tal_fmt(ctx, "invoice missing signature");
		return NULL;
	}

	sha256(&payment_hash, preimage->r, sizeof(preimage->r));
	if (!sha256_eq(&payment_hash, invoice->invoice_payment_hash)) {
		*fail = tal_fmt(ctx, "payment preimage does not match invoice_payment_hash");
		return NULL;
	}

	if (!pubkey_from_secret(payer_secret, &payer_id)) {
		*fail = tal_fmt(ctx, "invalid payer secret");
		return NULL;
	}
	if (!pubkey_eq(&payer_id, invoice->invreq_payer_id)) {
		*fail = tal_fmt(ctx, "payer secret does not match invreq_payer_id");
		return NULL;
	}

	merkle_tlv(invoice->fields, &invoice_merkle);
	{
		struct sha256 sighash;

		sighash_from_merkle("invoice", "signature",
				    &invoice_merkle, &sighash);
		if (!check_schnorr_sig(&sighash, &invoice->invoice_node_id->pubkey,
				       invoice->signature)) {
			*fail = tal_fmt(ctx, "invalid invoice signature");
			return NULL;
		}
	}

	include_types = tal_arr(tmpctx, u64, 0);
	/* Required fields per spec: invreq_payer_id, invoice_payment_hash,
	 * invoice_node_id, and invoice_features if present. */
	add_include_type(&include_types, 88);  /* invreq_payer_id */
	add_include_type(&include_types, 168); /* invoice_payment_hash */
	add_include_type(&include_types, 176); /* invoice_node_id */
	if (has_field_type(invoice->fields, 174)) /* invoice_features */
		add_include_type(&include_types, 174);
	for (size_t i = 0; extra_include_types && i < tal_count(extra_include_types); i++) {
		if (extra_include_types[i] == 0) {
			*fail = tal_fmt(ctx, "invreq_metadata cannot be included");
			return NULL;
		}
		if (is_bolt12_signature_field(extra_include_types[i])) {
			*fail = tal_fmt(ctx, "cannot disclose signature-range field %"PRIu64,
					extra_include_types[i]);
			return NULL;
		}
		add_include_type(&include_types, extra_include_types[i]);
	}

	proof = talz(ctx, struct payer_proof);
	if (!compute_selective_disclosure(tmpctx, invoice->fields,
					  include_types, &disclosure, fail))
	{
		if (*fail)
			*fail = tal_steal(ctx, *fail);
		return tal_free(proof);
	}

	proof->fields = tal_arr(proof, struct tlv_field, 0);
	for (size_t i = 0; i < tal_count(invoice->fields); i++) {
		if (is_bolt12_signature_field(invoice->fields[i].numtype))
			continue;
		if (!has_include_type(include_types, invoice->fields[i].numtype))
			continue;
		tlvstream_set_raw(&proof->fields, invoice->fields[i].numtype,
				  take(tal_dup_arr(NULL, u8,
						   invoice->fields[i].value,
						   invoice->fields[i].length,
						   0)),
				  invoice->fields[i].length);
	}

	tlvstream_set_raw(&proof->fields, PAYER_PROOF_TLV_SIGNATURE,
			  take(tal_dup_arr(NULL, u8,
					   invoice->signature->u8,
					   sizeof(invoice->signature->u8), 0)),
			  sizeof(invoice->signature->u8));
	tlvstream_set_raw(&proof->fields, PAYER_PROOF_TLV_PREIMAGE,
			  take(tal_dup_arr(NULL, u8,
					   preimage->r,
					   sizeof(preimage->r), 0)),
			  sizeof(preimage->r));

	if (tal_count(disclosure.omitted_tlvs) != 0) {
		u8 *v = tal_arr(NULL, u8, 0);
		for (size_t i = 0; i < tal_count(disclosure.omitted_tlvs); i++)
			towire_bigsize(&v, disclosure.omitted_tlvs[i]);
		tlvstream_set_raw(&proof->fields, PAYER_PROOF_TLV_OMITTED_TLVS,
				  take(v), tal_bytelen(v));
	}
	if (tal_count(disclosure.missing_hashes) != 0) {
		tlvstream_set_raw(&proof->fields, PAYER_PROOF_TLV_MISSING_HASHES,
				  take(tal_dup_arr(NULL, struct sha256,
						   disclosure.missing_hashes,
						   tal_count(disclosure.missing_hashes),
						   0)),
				  tal_count(disclosure.missing_hashes)
				  * sizeof(struct sha256));
	}
	if (tal_count(disclosure.leaf_hashes) != 0) {
		tlvstream_set_raw(&proof->fields, PAYER_PROOF_TLV_LEAF_HASHES,
				  take(tal_dup_arr(NULL, struct sha256,
						   disclosure.leaf_hashes,
						   tal_count(disclosure.leaf_hashes),
						   0)),
				  tal_count(disclosure.leaf_hashes)
				  * sizeof(struct sha256));
	}

	payer_proof_sighash(note, &disclosure.merkle_root, &payer_sighash);
	proof->payer_signature = tal(proof, struct bip340sig);
	if (!secp256k1_keypair_create(secp256k1_ctx, &payer_keypair,
				      payer_secret->data)
	    || !secp256k1_schnorrsig_sign32(secp256k1_ctx,
					    proof->payer_signature->u8,
					    payer_sighash.u.u8,
					    &payer_keypair,
					    NULL)) {
		*fail = tal_fmt(ctx, "could not sign payer proof");
		return tal_free(proof);
	}

	{
		u8 *v = tal_dup_arr(NULL, u8,
				    proof->payer_signature->u8,
				    sizeof(proof->payer_signature->u8),
				    strlen(note ? note : ""));
		if (note)
			memcpy(v + sizeof(proof->payer_signature->u8),
			       note, strlen(note));
		tlvstream_set_raw(&proof->fields, PAYER_PROOF_TLV_PAYER_SIGNATURE,
				  take(v),
				  sizeof(proof->payer_signature->u8)
				  + strlen(note ? note : ""));
	}

	if (note)
		proof->payer_note = tal_strdup(proof, note);
	proof->invoice_signature = tal_dup(proof, struct bip340sig, invoice->signature);
	proof->preimage = tal_dup(proof, struct preimage, preimage);
	proof->leaf_hashes = tal_dup_talarr(proof, struct sha256,
					    disclosure.leaf_hashes);
	proof->omitted_tlvs = tal_dup_talarr(proof, u64,
					     disclosure.omitted_tlvs);
	proof->missing_hashes = tal_dup_talarr(proof, struct sha256,
					       disclosure.missing_hashes);
	proof->merkle_root = disclosure.merkle_root;

	invoice_wire = tal_arr(tmpctx, u8, 0);
	for (size_t i = 0; i < tal_count(proof->fields); i++) {
		if (is_bolt12_signature_field(proof->fields[i].numtype))
			continue;
		towire_bigsize(&invoice_wire, proof->fields[i].numtype);
		towire_bigsize(&invoice_wire, proof->fields[i].length);
		towire(&invoice_wire, proof->fields[i].value, proof->fields[i].length);
	}
	cursor = invoice_wire;
	len = tal_bytelen(invoice_wire);
	proof->invoice = fromwire_tlv_invoice(proof, &cursor, &len);
	if (!proof->invoice || len != 0) {
		*fail = tal_fmt(ctx, "could not build disclosed invoice TLVs");
		return tal_free(proof);
	}
	return proof;
}
