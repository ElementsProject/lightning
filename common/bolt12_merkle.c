#include <bitcoin/signature.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/mem/mem.h>
#include <common/bolt12_merkle.h>

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
	sha256_update(ctx, buf, len);
}

static void sha256_update_tlvfield(struct sha256_ctx *ctx,
				   const struct tlv_field *field)
{
	/* We don't keep it raw, so reconstruct. */
	sha256_update_bigsize(ctx, field->numtype);
	sha256_update_bigsize(ctx, field->length);
	sha256_update(ctx, field->value, field->length);
}

/* BOLT-offers #12:
 * The Merkle Tree's leaves are, in TLV-ascending order:
 * 1. The SHA256 of: `LnLeaf` followed by the TLV entry.
 * 2. The SHA256 of: `LnAll` followed all non-signature TLV entries appended
 *    in ascending order.
 */

static void calc_lnall(const struct tlv_field *fields, struct sha256 *hash)
{
	struct sha256_ctx sctx;

	sha256_init(&sctx);
	sha256_update(&sctx, "LnAll", 5);
	for (size_t i = 0; i < tal_count(fields); i++) {
		if (!is_signature_field(&fields[i]))
			sha256_update_tlvfield(&sctx, &fields[i]);
	}
	sha256_done(&sctx, hash);
}

static void calc_lnleaf(const struct tlv_field *field, struct sha256 *hash)
{
	struct sha256_ctx sctx;

	sha256_init(&sctx);
	sha256_update(&sctx, "LnLeaf", 6);
	sha256_update_tlvfield(&sctx, field);
	sha256_done(&sctx, hash);
}

static struct sha256 merkle_pair(const struct sha256 a, const struct sha256 b)
{
	struct sha256 res;
	struct sha256_ctx sctx;

	sha256_init(&sctx);
	sha256_update(&sctx, "LnBranch", 8);
	sha256_update(&sctx, a.u.u8, sizeof(a.u.u8));
	sha256_update(&sctx, b.u.u8, sizeof(b.u.u8));
	sha256_done(&sctx, &res);

	return res;
}

static struct sha256 merkle_recurse(const struct sha256 *arr, size_t len)
{
	if (len == 1)
		return arr[0];

	return merkle_pair(merkle_recurse(arr, len / 2),
			   merkle_recurse(arr + len / 2, len - len / 2));
}

void merkle_tlv(const struct tlv_field *fields, struct sha256 *merkle)
{
	struct sha256 lnall, *arr;
	size_t n;

	calc_lnall(fields, &lnall);
	arr = tal_arr(NULL, struct sha256, tal_count(fields));

	n = 0;
	for (size_t i = 0; i < tal_count(fields); i++) {
		struct sha256 s;
		if (is_signature_field(&fields[i]))
			continue;
		calc_lnleaf(&fields[i], &s);
		arr[n++] = merkle_pair(s, lnall);
	}

	*merkle = merkle_recurse(arr, n);
	tal_free(arr);
}

/* BOLT-offers #12:
 * All signatures are created as per
 * [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki),
 * and tagged as recommended there.  Thus to sign a message `msg` with
 * `tag`, `m` is SHA256(SHA256(`tag`) || SHA256(`tag`) || `msg`).  The
 * notation used here is `SIG(tag,msg,key)`.
 *
 * Each form is signed using one or more TLV signature elements; TLV
 * types 240 through 1000 are considered signature elements.  For these
 * the tag is `lightning` | `messagename` | `fieldname`, and `msg` is the
 * merkle-root; `lightning` is the literal 9-byte ASCII string,
 * `messagename` is the name of the TLV stream being signed (i.e. `offer`
 * or `invoice`) and the `fieldname` is the TLV field containing the
 * signature (e.g. `signature` or `recurrence_signature`).
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
