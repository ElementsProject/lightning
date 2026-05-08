#include "config.h"
#include <assert.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/ilog/ilog.h>
#include <ccan/mem/mem.h>
#include <common/bolt12_merkle.h>
#include <common/utils.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

/* BOLT #12:
 * Each form is signed using one or more *signature TLV elements*: TLV
 * types 240 through 1000 (inclusive).
 */
bool is_tlv_signature_field(const struct tlv_field *field)
{
	return field->numtype >= 240 && field->numtype <= 1000;
}

static void sha256_update_bigsize(struct sha256_ctx *ctx, u64 bigsize)
{
	u8 buf[BIGSIZE_MAX_LEN];
	size_t len;

	len = bigsize_put(buf, bigsize);
	SUPERVERBOSE("%s", tal_hexstr(tmpctx, buf, len));
	sha256_update(ctx, buf, len);
}

static void sha256_update_tlvfield(struct sha256_ctx *ctx,
				   const struct tlv_field *field)
{
	/* We don't keep it raw, so reconstruct. */
	sha256_update_bigsize(ctx, field->numtype);
	sha256_update_bigsize(ctx, field->length);
	SUPERVERBOSE("%s", tal_hexstr(tmpctx, field->value, field->length));
	sha256_update(ctx, field->value, field->length);
}

/* BOLT #12:
 * Thus we define H(`tag`,`msg`) as SHA256(SHA256(`tag`) || SHA256(`tag`) || `msg`)*/
/* Create a sha256_ctx which has the tag part done. */
static void h_simpletag_ctx(struct sha256_ctx *sctx, const char *tag)
{
	struct sha256 sha;
	sha256(&sha, tag, strlen(tag));
	sha256_init(sctx);
	sha256_update(sctx, &sha, sizeof(sha));
	sha256_update(sctx, &sha, sizeof(sha));
	SUPERVERBOSE("tag=SHA256(%s) -> %s",
		     tal_hexstr(tmpctx, tag, strlen(tag)),
		     fmt_sha256(tmpctx, &sha));
}


/* BOLT #12:
 * The Merkle tree's leaves are, in TLV-ascending order for each tlv:
 * 1. The H("LnLeaf",tlv).
 * 2. The H("LnNonce"||first-tlv,tlv-type) where first-tlv is the numerically-first TLV entry in the stream, and tlv-type is the "type" field (1-9 bytes) of the current tlv.
 */

/* Create a sha256_ctx which has the tag part done. */
void bolt12_lnnonce_ctx(struct sha256_ctx *sctx, const struct tlv_field *field)
{
	struct sha256_ctx inner_sctx;
	struct sha256 sha;

	sha256_init(&inner_sctx);
	sha256_update(&inner_sctx, "LnNonce", 7);
	SUPERVERBOSE("tag=SHA256(%s", tal_hexstr(tmpctx, "LnNonce", 7));
	sha256_update_tlvfield(&inner_sctx, field);
	sha256_done(&inner_sctx, &sha);
	SUPERVERBOSE(") -> %s\n",
		     fmt_sha256(tmpctx, &sha));

	sha256_init(sctx);
	sha256_update(sctx, &sha, sizeof(sha));
	sha256_update(sctx, &sha, sizeof(sha));
}

/* Use h_lnnonce_ctx to create nonce */
void bolt12_calc_nonce(const struct sha256_ctx *lnnonce_ctx,
		       bigsize_t fieldtype,
		       struct sha256 *hash,
		       void *unused)
{
	/* Copy context, to add field */
	struct sha256_ctx ctx = *lnnonce_ctx;

	SUPERVERBOSE("nonce: H(noncetag,");
	sha256_update_bigsize(&ctx, fieldtype);

	sha256_done(&ctx, hash);
	SUPERVERBOSE(") = %s\n", fmt_sha256(tmpctx, hash));
}

static void calc_lnleaf(const struct tlv_field *field, struct sha256 *hash)
{
	struct sha256_ctx sctx;

	SUPERVERBOSE("leaf: H(");
	h_simpletag_ctx(&sctx, "LnLeaf");
	SUPERVERBOSE(",");
	sha256_update_tlvfield(&sctx, field);
	sha256_done(&sctx, hash);
	SUPERVERBOSE(") -> %s\n", fmt_sha256(tmpctx, hash));
}

/* BOLT #12:
 * The Merkle tree inner nodes are H("LnBranch", lesser-SHA256||greater-SHA256)
 */
static struct sha256 merkle_pair(const struct sha256 *a, const struct sha256 *b)
{
	struct sha256 res;
	struct sha256_ctx sctx;

	/* Make sure a < b */
	if (memcmp(a->u.u8, b->u.u8, sizeof(a->u.u8)) > 0)
		return merkle_pair(b, a);

	SUPERVERBOSE("branch: H(");
	h_simpletag_ctx(&sctx, "LnBranch");
	SUPERVERBOSE(",%s %s",
		     tal_hexstr(tmpctx, a->u.u8, sizeof(a->u.u8)),
		     tal_hexstr(tmpctx, b->u.u8, sizeof(b->u.u8)));
	sha256_update(&sctx, a->u.u8, sizeof(a->u.u8));
	sha256_update(&sctx, b->u.u8, sizeof(b->u.u8));

	sha256_done(&sctx, &res);
	SUPERVERBOSE(") -> %s\n", fmt_sha256(tmpctx, &res));
	return res;
}

/* Compute the leaf-pair hash for a TLV field: merkle_pair(H("LnLeaf",f), nonce) */
static void calc_leaf_pair(const struct sha256_ctx *lnnonce_ctx,
			   const struct tlv_field *f,
			   struct sha256 *hash,
			   void *unused)
{
	struct sha256 leafhash, nonce;
	calc_lnleaf(f, &leafhash);
	bolt12_calc_nonce(lnnonce_ctx, f->numtype, &nonce, NULL);
	*hash = merkle_pair(&leafhash, &nonce);
}

/* Omitted nodes in the tree are represented by all-0 hashes */
static bool is_omitted(const struct sha256 *hash)
{
	return memeqzero(hash->u.u8, ARRAY_SIZE(hash->u.u8));
}

static struct sha256 make_omitted(void)
{
	struct sha256 hash;
	memset(hash.u.u8, 0, ARRAY_SIZE(hash.u.u8));
	assert(is_omitted(&hash));
	return hash;
}

/* Compute the actual (non-omitted) subtree hash for all entries in arr[0..len-1].
 * Used by the creator to find the real hash of an omitted subtree. */
static struct sha256 *compute_actual_subtree(struct sha256 **base,
					     struct sha256 **arr, size_t len)
{
	struct sha256 *left, *right, *ret;

	if (len == 1)
		return arr[0];
	left = compute_actual_subtree(base, arr, len / 2);
	right = compute_actual_subtree(base, arr + len / 2, len / 2);
	if (!right)
		return left;
	ret = tal(base, struct sha256);
	*ret = merkle_pair(left, right);
	return ret;
}

static struct sha256 *merkle_recurse(struct sha256 **base,
				     struct sha256 **arr,
				     struct sha256 **actual_arr,
				     size_t len,
				     void (*resolve_omitted)(struct sha256 *, void *),
				     void *arg)

{
	struct sha256 *left, *right;
	struct sha256 *ret;
	bool left_omitted, right_omitted;
	if (len == 1)
		return arr[0];

	SUPERVERBOSE("Merkle recurse [%zu - %zu] and [%zu - %zu]\n",
		     arr - base, arr + len / 2 - 1 - base,
		     arr + len / 2 - base, arr + len - 1 - base);
	left = merkle_recurse(base, arr, actual_arr, len / 2, resolve_omitted, arg);
	right = merkle_recurse(base, arr + len / 2,
			       actual_arr ? actual_arr + len / 2 : NULL,
			       len / 2, resolve_omitted, arg);
	/* left is never NULL if right is not NULL */
	if (!right) {
		SUPERVERBOSE("[%zu - %zu] is NULL!\n",
			     arr + len / 2 - base, arr + len - base);
		return left;
	}
	ret = tal(base, struct sha256);
	left_omitted = is_omitted(left);
	right_omitted = is_omitted(right);
	if (left_omitted && right_omitted) {
		*ret = make_omitted();
		return ret;
	}
	if (left_omitted) {
		if (actual_arr)
			*left = *compute_actual_subtree(base, actual_arr, len / 2);
		resolve_omitted(left, arg);
	} else if (right_omitted) {
		if (actual_arr)
			*right = *compute_actual_subtree(base, actual_arr + len / 2, len / 2);
		resolve_omitted(right, arg);
	}

	*ret = merkle_pair(left, right);
	return ret;
}

struct leaf_iter {
	const struct tlv_field *fields;
	size_t n;
};

static const struct tlv_field *next_field(bool *is_omitted, struct leaf_iter *iter)
{
	if (iter->n >= tal_count(iter->fields))
		return NULL;
	*is_omitted = false;
	return &iter->fields[iter->n++];
}

/* This is not the fastest way, but it is the most intuitive. */
void merkle_tlv_full_(struct sha256 *merkle,
		      const struct tlv_field *(*next_field)(bool *, void *),
		      void (*calc_nonce)(const struct sha256_ctx *lnnonce_ctx,
					 bigsize_t fieldtype,
					 struct sha256 *hash, void *),
		      void (*resolve_omitted)(struct sha256 *, void *),
		      void *arg)
{
	const struct tlv_field *f;
	struct sha256 **leaves, **actual_leaves, *ret;
	struct sha256_ctx lnnonce_ctx;
	bool omitted;

	SUPERVERBOSE("nonce tag:");

	leaves = tal_arr(NULL, struct sha256 *, 0);
	actual_leaves = tal_arr(leaves, struct sha256 *, 0);
	while ((f = next_field(&omitted, arg)) != NULL) {
		struct sha256 leaf;

		/* First field is used as nonce to initialize the lnnonce_ctx */
		if (tal_count(leaves) == 0)
			bolt12_lnnonce_ctx(&lnnonce_ctx, f);

		if (is_tlv_signature_field(f))
			continue;

		if (omitted) {
			struct sha256 actual_leaf;
			leaf = make_omitted();
			calc_leaf_pair(&lnnonce_ctx, f, &actual_leaf, NULL);
			tal_arr_expand(&actual_leaves,
				       tal_dup(actual_leaves, struct sha256, &actual_leaf));
		} else {
			struct sha256 leafhash, nonce;

			calc_lnleaf(f, &leafhash);
			calc_nonce(&lnnonce_ctx, f->numtype, &nonce, arg);
			leaf = merkle_pair(&leafhash, &nonce);
			tal_arr_expand(&actual_leaves,
				       tal_dup(actual_leaves, struct sha256, &leaf));
		}
		tal_arr_expand(&leaves, tal_dup(leaves, struct sha256, &leaf));
	}
	/* No fields means we don't have nonce. */
	assert(tal_count(leaves) != 0);

	/* We build an oversized power-of-2 symmentic tree, but with
	 * NULL nodes at the end.  When we recurse, we pass through
	 * NULL.  This is less efficient than calculating the
	 * power-of-2 split as we recurse, but simpler. */
	tal_resizez(&leaves, 1ULL << ilog64(tal_count(leaves)));
	tal_resizez(&actual_leaves, tal_count(leaves));

	ret = merkle_recurse(leaves, leaves, actual_leaves, tal_count(leaves),
			     resolve_omitted, arg);
	if (!ret) {
		/* This should never happen, but define it a distinctive all-zeroes */
		*merkle = make_omitted();
	} else {
		/* Cannot *all* be omitted! */
		*merkle = *ret;
		assert(!is_omitted(merkle));
	}
	tal_free(leaves);
}

void merkle_tlv(const struct tlv_field *fields, struct sha256 *merkle)
{
	struct leaf_iter iter;

	iter.fields = fields;
	iter.n = 0;

	merkle_tlv_full(merkle, next_field, bolt12_calc_nonce, NULL, &iter);
}

/* BOLT #12:
 * All signatures are created as per
 * [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
 * and tagged as recommended there.  Thus we define H(`tag`,`msg`) as
 * SHA256(SHA256(`tag`) || SHA256(`tag`) || `msg`), and SIG(`tag`,`msg`,`key`)
 * as the signature of H(`tag`,`msg`) using `key`.
 *
 * Each form is signed using one or more *signature TLV elements*: TLV types
 * 240 through 1000 (inclusive).  For these, the tag is "lightning" ||
 * `messagename` || `fieldname`, and `msg` is the Merkle-root; "lightning" is
 * the literal 9-byte ASCII string, `messagename` is the name of the TLV
 * stream being signed (i.e. "invoice_request" or "invoice") and the
 * `fieldname` is the TLV field containing the signature (e.g. "signature").
 */
void sighash_from_merkle(const char *messagename,
			 const char *fieldname,
			 const struct sha256 *merkle,
			 struct sha256 *sighash)
{
	struct sha256_ctx sctx;

	bip340_sighash_init(&sctx, "lightning", messagename, fieldname);
	sha256_update(&sctx, merkle, sizeof(*merkle));
	sha256_done(&sctx, sighash);
}
