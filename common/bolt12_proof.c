#include "config.h"
#include <assert.h>
#include <bitcoin/preimage.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/bech32_util.h>
#include <common/bolt12_merkle.h>
#include <common/bolt12_proof.h>
#include <common/utils.h>
#include <inttypes.h>

struct creator {
	size_t n_inv, n_included;
	const struct tlv_invoice *inv;
	/* A subset of inv->fields */
	const struct tlv_field *included;
	struct sha256 *missing_hashes;
};

static const struct tlv_field *next_field_create(bool *is_omitted,
						 struct creator *creator)
{
	if (creator->n_inv >= tal_count(creator->inv->fields))
		return NULL;
	/* If all included fields consumed, remaining must be omitted */
	if (creator->n_included >= tal_count(creator->included))
		*is_omitted = true;
	else
		*is_omitted = (creator->inv->fields[creator->n_inv].numtype
			       != creator->included[creator->n_included].numtype);

	if (!*is_omitted)
		creator->n_included++;
	return &creator->inv->fields[creator->n_inv++];
}

/* BOLT-payer_proof #12:
 * - MUST populate `proof_missing_hashes` with the merkle hash of the omitted branch
 *     of each internal node that has exactly one branch entirely omitted, in
 *     post-order depth-first smallest-to-largest TLV order.
 */
static void add_merkle(struct sha256 *h, struct creator *creator)
{
	tal_arr_expand(&creator->missing_hashes, *h);
}

/* If we've failed to parse but need to produce a hash */
static struct sha256 dummy_hash(void)
{
	struct sha256 hash;
	memset(hash.u.u8, 1, ARRAY_SIZE(hash.u.u8));
	return hash;
}

struct tlv_payer_proof *make_unsigned_proof_(const tal_t *ctx,
					     const struct tlv_invoice *inv,
					     const struct preimage *preimage,
					     const char *note,
					     bool (*include_field)(const struct tlv_field *f, void *),
					     void *arg)
{
	size_t last_type = 0, len;
	struct sha256 *leaf_hashes, merkle;
	struct creator creator;
	struct tlv_payer_proof *pptlv;
	struct tlv_field *included;
	bigsize_t *omitted;
	u8 *tlvstream;
	struct sha256_ctx lnnonce_ctx;

	/* Calculates (H("LnNonce"||TLV0,...) ready for calc_nonce */
	bolt12_lnnonce_ctx(&lnnonce_ctx, &inv->fields[0]);

	included = tal_arr(tmpctx, struct tlv_field, 0);
	leaf_hashes = tal_arr(tmpctx, struct sha256, 0);
	omitted = tal_arr(tmpctx, bigsize_t, 0);

	/* BOLT-payer_proof #12:
	 * - For each non-signature TLV in the invoice in ascending-type order:
	 */
	for (size_t i = 0; i < tal_count(inv->fields); i++) {
		const struct tlv_field *f = &inv->fields[i];

		if (is_tlv_signature_field(f))
			continue;

		/* BOLT-payer_proof #12:
		 *   - If the field is to be included in the payer_proof:
		 *     - MUST copy it into the payer_proof.
		 *   - MUST append the nonce (H("LnNonce"||TLV0,type)) to
		 *     `proof_leaf_hashes`.
		 */
		if (include_field(f, arg)) {
			struct sha256 hash;
			tal_arr_expand(&included, *f);
			bolt12_calc_nonce(&lnnonce_ctx, f->numtype, &hash, NULL);
			tal_arr_expand(&leaf_hashes, hash);
			last_type = f->numtype;
			continue;
		}
		/* BOLT-payer_proof #12:
		 *   - otherwise, if the TLV type is not zero:
		 *     - MUST append a *marker number* to `proof_omitted_tlvs`
		 *       - If the previous TLV type was included:
		 *         - The *marker number* is that previous tlv type,
		 *           plus one.
		 *       - Otherwise, if `proof_omitted_tlvs` is empty:
		 *         - The *marker number* is 1.
		 *       - Otherwise:
		 *         - The *marker number* is one greater than the last
		 *           `proof_omitted_tlvs` entry.
		 */
		if (f->numtype != 0)
			tal_arr_expand(&omitted, ++last_type);
	}

	/* Arg for next_field_create and add_merkle */
	creator.n_inv = creator.n_included = 0;
	creator.inv = inv;
	creator.included = included;
	creator.missing_hashes = tal_arr(tmpctx, struct sha256, 0);

	merkle_tlv_full(&merkle,
			next_field_create, bolt12_calc_nonce, add_merkle,
			&creator);

	/* Now we make the payer_proof, starting with the invoice fields. */
	tlvstream = tal_arr(tmpctx, u8, 0);
	towire_tlvstream_raw(&tlvstream, included);
	len = tal_bytelen(tlvstream);
	pptlv = fromwire_tlv_payer_proof(ctx,
					 cast_const2(const u8 **, &tlvstream), &len);
	assert(pptlv);

	/* BOLT-payer_proof #12:
	 * A writer of a payer_proof:
	 *...
	 *   - MUST copy `signature` into the payer_proof.
	 */
	pptlv->signature = tal_dup(pptlv, struct bip340sig, inv->signature);

	/* BOLT-payer_proof #12:
	 * A writer of a payer_proof:
	 *...
	 * - MUST include `proof_preimage` containing the `payment_preimage` returned from successful payment of this invoice.
	 */
	pptlv->proof_preimage = tal_dup(pptlv, struct preimage, preimage);
	pptlv->proof_missing_hashes = tal_steal(pptlv, creator.missing_hashes);
	/* BOLT-payer_proof #12:
	 * - If `proof_omitted_tlvs` is empty:
	 *  - MAY omit `proof_omitted_tlvs` from the payer_proof.
	 */
	pptlv->proof_omitted_tlvs = tal_count(omitted) ? tal_steal(pptlv, omitted) : NULL;
	pptlv->proof_leaf_hashes = tal_steal(pptlv, leaf_hashes);

	if (note) {
		/* Not nul-terminated! */
		pptlv->proof_note = tal_dup_arr(pptlv, utf8, note, strlen(note), 0);
		assert(utf8_check(pptlv->proof_note, tal_bytelen(pptlv->proof_note)));
	}

	/* Make sure pptlv->fields correctly reflects values */
	tlv_update_fields(pptlv, tlv_payer_proof, &pptlv->fields);

	return pptlv;
}

struct tlv0_adding_leaf_iter {
	const struct tlv_field *fields;
	struct tlv_field tlv0;
	int n;
};

static const struct tlv_field *next_field_prepend_tlv0(bool *is_omitted,
						       struct tlv0_adding_leaf_iter *iter)
{
	*is_omitted = false;
	if (iter->n == -1) {
		iter->n = 0;
		return &iter->tlv0;
	}
	if (iter->n >= tal_count(iter->fields))
		return NULL;
	return &iter->fields[iter->n++];
}

/* BOLT-payer_proof #12:
 * - MUST set `proof_signature` as detailed in [Signature Calculation](#signature-calculation) using the `invreq_payer_id` using the merkle-root as the `msg` and a `first_tlv` value of 0x0000 (i.e. type 0, length 0).
 */
static void merkle_payer_proof(const struct tlv_field *fields,
			       struct sha256 *merkle)
{
	struct tlv0_adding_leaf_iter iter;

	/* We use a modified iterator to insert tlv0. */
	iter.fields = fields;
	iter.n = -1;
	iter.tlv0.meta = NULL;
	iter.tlv0.numtype = 0;
	iter.tlv0.length = 0;
	iter.tlv0.value = NULL;

	merkle_tlv_full(merkle,
			next_field_prepend_tlv0,
			bolt12_calc_nonce,
			NULL,
			&iter);
}

struct bip340sig *payer_proof_signature_(const tal_t *ctx,
					 const struct tlv_payer_proof *unsignedproof,
					 bool (*sign)(const char *messagename,
						      const char *fieldname,
						      const struct sha256 *msg,
						      struct bip340sig *sig,
						      void *arg),
					 void *arg)
{
	struct sha256 merkle;
	struct bip340sig *sig;

	merkle_payer_proof(unsignedproof->fields, &merkle);

	sig = tal(ctx, struct bip340sig);
	if (!sign("payer_proof", "proof_signature", &merkle, sig, arg))
		sig = tal_free(sig);

	return sig;
}

struct checker {
	const struct tlv_payer_proof *pptlv;

	/* Where we're up to in pptlv->fields[] */
	size_t included_n;

	/* Where we're up to in omitted[] */
	size_t omitted_n;
	struct tlv_field *omitted;

	/* Where we're up to in pptlv->proof_leaf_hashes */
	size_t leaf_hashes_n;
	bool leaf_hashes_exhausted;

	/* Where we're up to in pptlv->proof_missing_hashes */
	size_t missing_hashes_n;
	bool missing_hashes_exhausted;
};

static const struct tlv_field *next_field_check(bool *is_omitted,
						struct checker *checker)
{
	const struct tlv_field *included, *omitted;

	/* BOLT-payer_proof #12:
	 * A reader of a payer_proof:
	 * - MUST reject the payer_proof if:
	 *...
	 *   - `signature` is not a valid signature using `invoice_node_id` as
	 *      described in [Signature Calculation](#signature-calculation)
	 *      (with `messagename` "invoice") of the reconstructed merkle-root
	 *      of the invoice (i.e. without fields 1001 through 999999999
	 *      inclusive).
	 */
next:
	if (checker->included_n < tal_count(checker->pptlv->fields)) {
		included = &checker->pptlv->fields[checker->included_n];
		if (included->numtype >= 1001 && included->numtype <= 999999999) {
			checker->included_n++;
			goto next;
		}
	} else
		included = NULL;

	if (checker->omitted_n < tal_count(checker->omitted))
		omitted = &checker->omitted[checker->omitted_n];
	else
		omitted = NULL;

	/* Both exhausted?  We finish. */
	if (!included && !omitted)
		return NULL;

	/* Only omitted left, or both and omitted comes first */
	if ((omitted && !included)
	    || (omitted && included && omitted->numtype < included->numtype)) {
		checker->omitted_n++;
		*is_omitted = true;
		return omitted;
	}

	*is_omitted = false;
	checker->included_n++;
	return included;
}

static void get_leaf_hash(const struct sha256_ctx *lnnonce_ctx,
			  bigsize_t fieldtype,
			  struct sha256 *hash,
			  struct checker *checker)
{
	if (checker->leaf_hashes_n >= tal_count(checker->pptlv->proof_leaf_hashes)) {
		checker->leaf_hashes_exhausted = true;
		*hash = dummy_hash();
	} else {
		*hash = checker->pptlv->proof_leaf_hashes[checker->leaf_hashes_n++];
	}
}

static void resolve_omitted(struct sha256 *hash, struct checker *checker)
{
	if (checker->missing_hashes_n >= tal_count(checker->pptlv->proof_missing_hashes)) {
		checker->missing_hashes_exhausted = true;
		*hash = dummy_hash();
	} else {
		*hash = checker->pptlv->proof_missing_hashes[checker->missing_hashes_n++];
	}
}

static bool find_tlv_num(const struct tlv_payer_proof *pptlv, bigsize_t num)
{
	for (size_t i = 0; i < tal_count(pptlv->fields); i++) {
		if (pptlv->fields[i].numtype == num)
			return true;
	}
	return false;
}

const char *check_payer_proof(const tal_t *ctx,
			      const struct tlv_payer_proof *pptlv)
{
	struct sha256 hash, merkle, shash;
	struct checker checker;

	/* BOLT-payer_proof #12:
	 * A reader of a payer_proof:
	 * - MUST reject the payer_proof if:
	 *   - `invreq_payer_id`, `invoice_payment_hash`, `invoice_node_id`,
	 *     `signature`, `proof_preimage`, `proof_missing_hashes`,
	 *     `proof_leaf_hashes` or `proof_signature` are missing.
	 */
	if (!pptlv->invreq_payer_id)
		return tal_fmt(ctx, "Missing invreq_payer_id");
	if (!pptlv->invoice_payment_hash)
		return tal_fmt(ctx, "Missing invoice_payment_hash");
	if (!pptlv->invoice_node_id)
		return tal_fmt(ctx, "Missing invoice_node_id");
	if (!pptlv->signature)
		return tal_fmt(ctx, "Missing signature");
	if (!pptlv->proof_preimage)
		return tal_fmt(ctx, "Missing proof_preimage");
	if (!pptlv->proof_missing_hashes)
		return tal_fmt(ctx, "Missing proof_missing_hashes");
	if (!pptlv->proof_leaf_hashes)
		return tal_fmt(ctx, "Missing proof_leaf_hashes");
	if (!pptlv->proof_signature)
		return tal_fmt(ctx, "Missing proof_signature");

	/* BOLT-payer_proof #12:
	 *...
	 * - SHA256(`proof_preimage`) does not equal `invoice_payment_hash`.
	 */
	sha256(&hash, pptlv->proof_preimage, sizeof(*pptlv->proof_preimage));
	if (!sha256_eq(&hash, pptlv->invoice_payment_hash))
		return tal_fmt(ctx, "Incorrect preimage");

	/* BOLT-payer_proof #12:
	 *...
	 *   - `proof_omitted_tlvs` are not in strict ascending order (no duplicates).
	 */
	for (size_t i = 0; i < tal_count(pptlv->proof_omitted_tlvs); i++) {
		bigsize_t omitted = pptlv->proof_omitted_tlvs[i], prev_omitted;

		/* BOLT-payer_proof #12:
		 *...
		 *   - `proof_omitted_tlvs` contains 0.
		 */
		if (omitted == 0)
			return tal_fmt(ctx, "proof_omitted_tlvs[%zu] is 0", i);
		/* BOLT-payer_proof #12:
		 *...
		 *   - `proof_omitted_tlvs` contains number outside both ranges 1 to 239 and 1000000000 to 3999999999.
		 */
		if (!(omitted >= 1 && omitted <= 239)
		    && !(omitted >= 1000000000 && omitted <= 3999999999)) {
			return tal_fmt(ctx, "proof_omitted_tlvs[%zi] is"
				       " non-invoiced field %"PRIu64,
				       i, omitted);
		}
		/* BOLT-payer_proof #12:
		 *...
		 *   - `proof_omitted_tlvs` contains the number of an included TLV
		 *      field.
		 */
		if (find_tlv_num(pptlv, omitted)) {
			return tal_fmt(ctx, "proof_omitted_tlvs[%zi] is included field %"PRIu64,
				       i, omitted);
		}
		/* BOLT-payer_proof #12:
		 *...
		 *   - `proof_omitted_tlvs` is not one greater than:
		 *      - an included TLV number, or
		 *      - the previous `proof_omitted_tlvs` or 0 if it is the first
		 *        number.
		 */
		if (i > 0)
			prev_omitted = pptlv->proof_omitted_tlvs[i-1];
		else
			prev_omitted = 0;

		if (omitted != prev_omitted + 1) {
			/* O(n^2) but doesn't matter */
			if (!find_tlv_num(pptlv, omitted - 1)) {
				return tal_fmt(ctx, "proof_omitted_tlvs[%zi] is"
					       " not one greater than the previous %"PRIu64" nor an included tlv entry",
					       i, prev_omitted);
			}
		}
	}

	checker.pptlv = pptlv;
	checker.included_n = 0;
	checker.omitted_n = 0;
	checker.leaf_hashes_n = 0;
	checker.missing_hashes_n = 0;
	checker.leaf_hashes_exhausted = false;
	checker.missing_hashes_exhausted = false;
	/* Make empty "omitted" fields so we can return them.  0 is implied! */
	checker.omitted = tal_arr(tmpctx, struct tlv_field,
				  1 + tal_count(pptlv->proof_omitted_tlvs));
	checker.omitted[0].numtype = 0;
	checker.omitted[0].length = 0;
	checker.omitted[0].value = NULL;
	for (size_t i = 0; i < tal_count(pptlv->proof_omitted_tlvs); i++) {
		checker.omitted[1 + i].numtype = pptlv->proof_omitted_tlvs[i];
		checker.omitted[1 + i].length = 0;
		checker.omitted[1 + i].value = NULL;
	}
	merkle_tlv_full(&merkle,
			next_field_check, get_leaf_hash, resolve_omitted,
			&checker);

	/* BOLT-payer_proof #12:
	 *...
	 * - `proof_leaf_hashes` does not contain exactly one hash for each
	 *   non-signature TLV field.
	 */
	if (checker.leaf_hashes_exhausted)
		return tal_fmt(ctx, "Not enough proof_leaf_hashes");
	else if (checker.leaf_hashes_n != tal_count(pptlv->proof_leaf_hashes))
		return tal_fmt(ctx, "Too many proof_leaf_hashes");

	/* BOLT-payer_proof #12:
	 *...
	 *  - There are not exactly enough `proof_missing_hashes` to reconstruct the
	 *    merkle tree root using the `proof_omitted_tlvs` values (with `0`
	 *    implied as the first omitted TLV).
	 */
	if (checker.missing_hashes_exhausted)
		return tal_fmt(ctx, "Not enough proof_missing_hashes");
	else if (checker.missing_hashes_n != tal_count(pptlv->proof_missing_hashes))
		return tal_fmt(ctx, "Too many proof_missing_hashes");
	/* BOLT-payer_proof #12:
	 *...
	 * - `signature` is not a valid signature using `invoice_node_id` as
	 *    described in [Signature Calculation](#signature-calculation)
	 *    (with `messagename` "invoice") of the reconstructed merkle-root
	 *    of the invoice (i.e. without fields 1001 through 999999999
	 *    inclusive).
	 */
	sighash_from_merkle("invoice", "signature", &merkle, &shash);
	if (!check_schnorr_sig(&shash, &pptlv->invoice_node_id->pubkey,
			       pptlv->signature)) {
		return tal_fmt(ctx, "Invalid invoice signature");
	}

	/* BOLT-payer_proof #12:
	 *...
	 *  - `proof_signature` is not a valid signature using
	 *  `invreq_payer_id` as described in [Signature
	 *  Calculation](#signature-calculation), using `msg` merkle-root and
	 *  a `first_tlv` value of 0x0000 (i.e. type 0, length 0).
	 */
	merkle_payer_proof(pptlv->fields, &merkle);
	sighash_from_merkle("payer_proof", "proof_signature", &merkle, &shash);
	if (!check_schnorr_sig(&shash, &pptlv->invreq_payer_id->pubkey,
			       pptlv->proof_signature)) {
		return tal_fmt(ctx, "Invalid invoice signature");
	}

	return NULL;
}

const char *payer_proof_encode(const tal_t *ctx, const struct tlv_payer_proof *pptlv)
{
	u8 *wire;

	wire = tal_arr(tmpctx, u8, 0);
	towire_tlv_payer_proof(&wire, pptlv);

	return to_bech32_charset(ctx, "lnp", wire);
}

struct tlv_payer_proof *payer_proof_decode(const tal_t *ctx,
					   const char *b12, size_t b12len,
					   const char **fail)
{
	struct tlv_payer_proof *tlvpp;
	const u8 *data;
	size_t dlen;

	data = b12_string_to_data(tmpctx, b12, b12len, "lnp", &dlen, fail);
	if (!data) {
		tal_steal(ctx, *fail);
		return NULL;
	}

	tlvpp = fromwire_tlv_payer_proof(ctx, &data, &dlen);
	if (!tlvpp) {
		*fail = tal_fmt(ctx, "invalid payer_proof data");
		return NULL;
	}

	*fail = check_payer_proof(ctx, tlvpp);
	if (*fail)
		return tal_free(tlvpp);

	return tlvpp;
}
