#include <bitcoin/signature.h>
#include <ccan/cast/cast.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/ilog/ilog.h>
#include <ccan/mem/mem.h>
#include <common/bolt12_merkle.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

/* BOLT-offers #12:
 * TLV types 240 through 1000 are considered signature elements.
 */
static bool is_signature_field(const struct tlv_field *field)
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

/* BOLT-offers #12:
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
		     type_to_string(tmpctx, struct sha256, &sha));
}


/* BOLT-offers #12:
 * The Merkle tree's leaves are, in TLV-ascending order for each tlv:
 * 1. The H(`LnLeaf`,tlv).
 * 2. The H(`LnAll`|all-tlvs,tlv) where "all-tlvs" consists of all non-signature TLV entries appended in ascending order.
 */

/* Create a sha256_ctx which has the tag part done. */
static void h_lnall_ctx(struct sha256_ctx *sctx, const struct tlv_field *fields)
{
	struct sha256_ctx inner_sctx;
	struct sha256 sha;

	sha256_init(&inner_sctx);
	sha256_update(&inner_sctx, "LnAll", 5);
	SUPERVERBOSE("tag=SHA256(%s", tal_hexstr(tmpctx, "LnAll", 5));
	for (size_t i = 0; i < tal_count(fields); i++) {
		if (!is_signature_field(&fields[i]))
			sha256_update_tlvfield(&inner_sctx, &fields[i]);
	}
	sha256_done(&inner_sctx, &sha);
	SUPERVERBOSE(") -> %s\n",
		     type_to_string(tmpctx, struct sha256, &sha));

	sha256_init(sctx);
	sha256_update(sctx, &sha, sizeof(sha));
	sha256_update(sctx, &sha, sizeof(sha));
}

/* Use h_lnall_ctx to create nonce */
static void calc_nonce(const struct sha256_ctx *lnall_ctx,
		       const struct tlv_field *field,
		       struct sha256 *hash)
{
	/* Copy context, to add field */
	struct sha256_ctx ctx = *lnall_ctx;

	SUPERVERBOSE("nonce: H(noncetag,");
	sha256_update_tlvfield(&ctx, field);

	sha256_done(&ctx, hash);
	SUPERVERBOSE(") = %s\n", type_to_string(tmpctx, struct sha256, hash));
}

static void calc_lnleaf(const struct tlv_field *field, struct sha256 *hash)
{
	struct sha256_ctx sctx;

	SUPERVERBOSE("leaf: H(");
	h_simpletag_ctx(&sctx, "LnLeaf");
	SUPERVERBOSE(",");
	sha256_update_tlvfield(&sctx, field);
	sha256_done(&sctx, hash);
	SUPERVERBOSE(") -> %s\n", type_to_string(tmpctx, struct sha256, hash));
}

/* BOLT-offers #12:
 * The Merkle tree inner nodes are H(`LnBranch`, lesser-SHA256|greater-SHA256);
 */
static struct sha256 *merkle_pair(const tal_t *ctx,
				  const struct sha256 *a, const struct sha256 *b)
{
	struct sha256 *res;
	struct sha256_ctx sctx;

	/* Make sure a < b */
	if (memcmp(a->u.u8, b->u.u8, sizeof(a->u.u8)) > 0)
		return merkle_pair(ctx, b, a);

	SUPERVERBOSE("branch: H(");
	h_simpletag_ctx(&sctx, "LnBranch");
	SUPERVERBOSE(",%s %s",
		     tal_hexstr(tmpctx, a->u.u8, sizeof(a->u.u8)),
		     tal_hexstr(tmpctx, b->u.u8, sizeof(b->u.u8)));
	sha256_update(&sctx, a->u.u8, sizeof(a->u.u8));
	sha256_update(&sctx, b->u.u8, sizeof(b->u.u8));

	res = tal(ctx, struct sha256);
	sha256_done(&sctx, res);
	SUPERVERBOSE(") -> %s\n", type_to_string(tmpctx, struct sha256, res));
	return res;
}

static const struct sha256 *merkle_recurse(const struct sha256 **base,
					   const struct sha256 **arr, size_t len)
{
	const struct sha256 *left, *right;
	if (len == 1)
		return arr[0];

	SUPERVERBOSE("Merkle recurse [%zu - %zu] and [%zu - %zu]\n",
		     arr - base, arr + len / 2 - 1 - base,
		     arr + len / 2 - base, arr + len - base);
	left = merkle_recurse(base, arr, len / 2);
	right = merkle_recurse(base, arr + len / 2, len / 2);
	/* left is never NULL if right is not NULL */
	if (!right)
		return left;
	return merkle_pair(base, left, right);
}

/* This is not the fastest way, but it is the most intuitive. */
void merkle_tlv(const struct tlv_field *fields, struct sha256 *merkle)
{
	struct sha256 **arr;
	struct sha256_ctx lnall_ctx;
	size_t n;

	SUPERVERBOSE("nonce tag:");
	h_lnall_ctx(&lnall_ctx, fields);
	/* NULL-pad to next power of 2 */
	arr = tal_arrz(NULL, struct sha256 *,
		       1ULL << (ilog64(tal_count(fields)) + 1));

	n = 0;
	for (size_t i = 0; i < tal_count(fields); i++) {
		struct sha256 leaf, nonce;
		if (is_signature_field(&fields[i]))
			continue;
		calc_lnleaf(&fields[i], &leaf);
		calc_nonce(&lnall_ctx, &fields[i], &nonce);
		arr[n++] = merkle_pair(arr, &leaf, &nonce);
	}

	/* This should never happen, but define it a distinctive all-zeroes */
	if (n == 0)
		memset(merkle, 0, sizeof(*merkle));
	else
		*merkle = *merkle_recurse(cast_const2(const struct sha256 **, arr),
					  cast_const2(const struct sha256 **, arr),
					  tal_count(arr));
	tal_free(arr);
}

/* BOLT-offers #12:
 * All signatures are created as per
 * [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki),
 * and tagged as recommended there.  Thus we define H(`tag`,`msg`) as
 * SHA256(SHA256(`tag`) || SHA256(`tag`) || `msg`), and SIG(`tag`,`msg`,`key`)
 * as the signature of H(`tag`,`msg`) using `key`.
 *
 * Each form is signed using one or more TLV signature elements; TLV
 * types 240 through 1000 are considered signature elements.  For these
 * the tag is `lightning` | `messagename` | `fieldname`, and `msg` is the
 * Merkle-root; `lightning` is the literal 9-byte ASCII string,
 * `messagename` is the name of the TLV stream being signed (i.e. `offer`,
 * `invoice_request` or `invoice`) and the `fieldname` is the TLV field
 * containing the signature (e.g. `signature` or `payer_signature`).
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

/* We use the SHA(pubkey | publictweak); so reader cannot figure out the
 * tweak and derive the base key */
void payer_key_tweak(const struct pubkey32 *bolt12,
		     const u8 *publictweak, size_t publictweaklen,
		     struct sha256 *tweak)
{
	u8 rawkey[32];
	struct sha256_ctx sha;

	secp256k1_xonly_pubkey_serialize(secp256k1_ctx, rawkey, &bolt12->pubkey);
	sha256_init(&sha);
	sha256_update(&sha, rawkey, sizeof(rawkey));
	sha256_update(&sha,
		      memcheck(publictweak, publictweaklen),
		      publictweaklen);
	sha256_done(&sha, tweak);
}
