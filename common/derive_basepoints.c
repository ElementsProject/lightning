#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/sha256/sha256.h>
#include <common/derive_basepoints.h>
#include <common/utils.h>
#include <wire/wire.h>

bool derive_basepoints(const struct secret *seed,
		       struct pubkey *funding_pubkey,
		       struct basepoints *basepoints,
		       struct secrets *secrets,
		       struct sha256 *shaseed)
{
	struct keys {
		struct privkey f, r, h, p, d;
		struct sha256 shaseed;
	} keys;

	hkdf_sha256(&keys, sizeof(keys), NULL, 0, seed, sizeof(*seed),
		    "c-lightning", strlen("c-lightning"));

	if (secrets) {
		secrets->funding_privkey = keys.f;
		secrets->revocation_basepoint_secret = keys.r.secret;
		secrets->payment_basepoint_secret = keys.p.secret;
		secrets->htlc_basepoint_secret = keys.h.secret;
		secrets->delayed_payment_basepoint_secret = keys.d.secret;
	}

	if (funding_pubkey) {
		if (!pubkey_from_privkey(&keys.f, funding_pubkey))
			return false;
	}

	if (basepoints) {
		if (!pubkey_from_privkey(&keys.r, &basepoints->revocation)
		    || !pubkey_from_privkey(&keys.p, &basepoints->payment)
		    || !pubkey_from_privkey(&keys.h, &basepoints->htlc)
		    || !pubkey_from_privkey(&keys.d, &basepoints->delayed_payment))
			return false;
	}

	/* BOLT #3:
	 *
	 * A node:
	 *  - MUST select an unguessable 256-bit seed for each connection,
	 *  - MUST NOT reveal the seed.
	 */
	if (shaseed)
		*shaseed = keys.shaseed;

	return true;
}

void per_commit_secret(const struct sha256 *shaseed,
		       struct secret *commit_secret,
		       u64 per_commit_index)
{
	struct sha256 s;
	shachain_from_seed(shaseed, shachain_index(per_commit_index), &s);

	BUILD_ASSERT(sizeof(s) == sizeof(*commit_secret));
	memcpy(commit_secret, &s, sizeof(s));
}

bool per_commit_point(const struct sha256 *shaseed,
		      struct pubkey *commit_point,
		      u64 per_commit_index)
{
	struct sha256 per_commit_secret;

	/* Derive new per-commitment-point. */
	shachain_from_seed(shaseed, shachain_index(per_commit_index),
			   &per_commit_secret);

	/* BOLT #3:
	 *
	 * The `per_commitment_point` is generated using elliptic-curve
	 * multiplication:
	 *
	 * 	per_commitment_point = per_commitment_secret * G
	 */
	if (secp256k1_ec_pubkey_create(secp256k1_ctx,
				       &commit_point->pubkey,
				       per_commit_secret.u.u8) != 1)
		return false;

	return true;
}

bool derive_payment_basepoint(const struct secret *seed,
			      struct pubkey *payment_basepoint,
			      struct secret *payment_secret)
{
	struct keys {
		struct privkey f, r, h, p, d;
		struct sha256 shaseed;
	} keys;

	hkdf_sha256(&keys, sizeof(keys), NULL, 0, seed, sizeof(*seed),
		    "c-lightning", strlen("c-lightning"));

	if (payment_basepoint) {
		if (!pubkey_from_privkey(&keys.p, payment_basepoint))
			return false;
	}

	if (payment_secret)
		*payment_secret = keys.p.secret;

	return true;
}

bool derive_delayed_payment_basepoint(const struct secret *seed,
				      struct pubkey *delayed_payment_basepoint,
				      struct secret *delayed_payment_secret)
{
	struct keys {
		struct privkey f, r, h, p, d;
		struct sha256 shaseed;
	} keys;

	hkdf_sha256(&keys, sizeof(keys), NULL, 0, seed, sizeof(*seed),
		    "c-lightning", strlen("c-lightning"));

	if (delayed_payment_basepoint) {
		if (!pubkey_from_privkey(&keys.d, delayed_payment_basepoint))
			return false;
	}

	if (delayed_payment_secret)
		*delayed_payment_secret = keys.d.secret;

	return true;
}

bool derive_shaseed(const struct secret *seed, struct sha256 *shaseed)
{
	struct keys {
		struct privkey f, r, h, p, d;
		struct sha256 shaseed;
	} keys;

	hkdf_sha256(&keys, sizeof(keys), NULL, 0, seed, sizeof(*seed),
		    "c-lightning", strlen("c-lightning"));
	*shaseed = keys.shaseed;
	return true;
}

bool derive_funding_key(const struct secret *seed,
			struct pubkey *funding_pubkey,
			struct privkey *funding_privkey)
{
	struct privkey f;

	hkdf_sha256(&f, sizeof(f), NULL, 0, seed, sizeof(*seed),
		    "c-lightning", strlen("c-lightning"));

	if (funding_pubkey) {
		if (!pubkey_from_privkey(&f, funding_pubkey))
			return false;
	}

	if (funding_privkey)
		*funding_privkey = f;

	return true;
}

bool derive_revocation_basepoint(const struct secret *seed,
				 struct pubkey *revocation_basepoint,
				 struct secret *revocation_secret)
{
	struct keys {
		struct privkey f, r, h, p, d;
		struct sha256 shaseed;
	} keys;

	hkdf_sha256(&keys, sizeof(keys), NULL, 0, seed, sizeof(*seed),
		    "c-lightning", strlen("c-lightning"));

	if (revocation_basepoint) {
		if (!pubkey_from_privkey(&keys.r, revocation_basepoint))
			return false;
	}

	if (revocation_secret)
		*revocation_secret = keys.r.secret;

	return true;
}

bool derive_htlc_basepoint(const struct secret *seed,
			   struct pubkey *htlc_basepoint,
			   struct secret *htlc_secret)
{
	struct keys {
		struct privkey f, r, h, p, d;
		struct sha256 shaseed;
	} keys;

	hkdf_sha256(&keys, sizeof(keys), NULL, 0, seed, sizeof(*seed),
		    "c-lightning", strlen("c-lightning"));

	if (htlc_basepoint) {
		if (!pubkey_from_privkey(&keys.h, htlc_basepoint))
			return false;
	}

	if (htlc_secret)
		*htlc_secret = keys.h.secret;

	return true;
}

void towire_basepoints(u8 **pptr, const struct basepoints *b)
{
	towire_pubkey(pptr, &b->revocation);
	towire_pubkey(pptr, &b->payment);
	towire_pubkey(pptr, &b->htlc);
	towire_pubkey(pptr, &b->delayed_payment);
}

void fromwire_basepoints(const u8 **ptr, size_t *max,
			 struct basepoints *b)
{
	fromwire_pubkey(ptr, max, &b->revocation);
	fromwire_pubkey(ptr, max, &b->payment);
	fromwire_pubkey(ptr, max, &b->htlc);
	fromwire_pubkey(ptr, max, &b->delayed_payment);
}
