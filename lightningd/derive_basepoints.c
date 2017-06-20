#include <assert.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/crypto/shachain/shachain.h>
#include <lightningd/derive_basepoints.h>
#include <utils.h>

bool derive_basepoints(const struct privkey *seed,
		       struct pubkey *funding_pubkey,
		       struct basepoints *basepoints,
		       struct secrets *secrets,
		       struct sha256 *shaseed)
{
	struct keys {
		struct privkey f, r, p, d;
		struct sha256 shaseed;
	} keys;

	hkdf_sha256(&keys, sizeof(keys), NULL, 0, seed, sizeof(*seed),
		    "c-lightning", strlen("c-lightning"));

	if (secrets) {
		secrets->funding_privkey = keys.f;
		secrets->revocation_basepoint_secret = keys.r.secret;
		secrets->payment_basepoint_secret = keys.p.secret;
		secrets->delayed_payment_basepoint_secret = keys.d.secret;
	}

	if (funding_pubkey) {
		if (!pubkey_from_privkey(&keys.f, funding_pubkey))
			return false;
	}

	if (basepoints) {
		if (!pubkey_from_privkey(&keys.r, &basepoints->revocation)
		    || !pubkey_from_privkey(&keys.p, &basepoints->payment)
		    || !pubkey_from_privkey(&keys.d, &basepoints->delayed_payment))
			return false;
	}

	/* BOLT #3:
	 *
	 * A node MUST select an unguessable 256-bit seed for each connection,
	 * and MUST NOT reveal the seed.
	 */
	if (shaseed)
		*shaseed = keys.shaseed;

	return true;
}

void per_commit_secret(const struct sha256 *shaseed,
		       struct sha256 *commit_secret,
		       u64 per_commit_index)
{
	shachain_from_seed(shaseed, shachain_index(per_commit_index),
			   commit_secret);
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
	 * The `per_commitment_point` is generated using EC multiplication:
	 *
	 * 	per_commitment_point = per_commitment_secret * G
	 */
	if (secp256k1_ec_pubkey_create(secp256k1_ctx,
				       &commit_point->pubkey,
				       per_commit_secret.u.u8) != 1)
		return false;

	return true;
}
