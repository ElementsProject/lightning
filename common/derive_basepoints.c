#include "config.h"
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <common/derive_basepoints.h>
#include <common/utils.h>

#if DEVELOPER
/* If they specify --dev-force-channel-secrets it ends up in here. */
struct secrets *dev_force_channel_secrets;
struct sha256 *dev_force_channel_secrets_shaseed;

void towire_secrets(u8 **pptr, const struct secrets *s)
{
	towire_privkey(pptr, &s->funding_privkey);
	towire_secret(pptr, &s->revocation_basepoint_secret);
	towire_secret(pptr, &s->payment_basepoint_secret);
	towire_secret(pptr, &s->delayed_payment_basepoint_secret);
	towire_secret(pptr, &s->htlc_basepoint_secret);
}

void fromwire_secrets(const u8 **ptr, size_t *max, struct secrets *s)
{
	fromwire_privkey(ptr, max, &s->funding_privkey);
	fromwire_secret(ptr, max, &s->revocation_basepoint_secret);
	fromwire_secret(ptr, max, &s->payment_basepoint_secret);
	fromwire_secret(ptr, max, &s->delayed_payment_basepoint_secret);
	fromwire_secret(ptr, max, &s->htlc_basepoint_secret);
}
#else /* !DEVELOPER */
/* Generate code refers to this, but should never be called! */
void towire_secrets(u8 **pptr, const struct secrets *s)
{
	abort();
}

void fromwire_secrets(const u8 **ptr, size_t *max, struct secrets *s)
{
	abort();
}
#endif

struct keys {
	struct privkey f, r, h, p, d;
	struct sha256 shaseed;
};

static void derive_keys(const struct secret *seed, struct keys *keys)
{
	hkdf_sha256(keys, sizeof(*keys), NULL, 0, seed, sizeof(*seed),
		    "c-lightning", strlen("c-lightning"));

#if DEVELOPER
	if (dev_force_channel_secrets) {
		keys->f = dev_force_channel_secrets->funding_privkey;
		keys->r.secret = dev_force_channel_secrets->revocation_basepoint_secret;
		keys->p.secret = dev_force_channel_secrets->payment_basepoint_secret;
		keys->h.secret = dev_force_channel_secrets->htlc_basepoint_secret;
		keys->d.secret = dev_force_channel_secrets->delayed_payment_basepoint_secret;
	}
	if (dev_force_channel_secrets_shaseed)
		keys->shaseed = *dev_force_channel_secrets_shaseed;
#endif
}

bool derive_basepoints(const struct secret *seed,
		       struct pubkey *funding_pubkey,
		       struct basepoints *basepoints,
		       struct secrets *secrets,
		       struct sha256 *shaseed)
{
	struct keys keys;

	derive_keys(seed, &keys);

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

bool per_commit_secret(const struct sha256 *shaseed,
		       struct secret *commit_secret,
		       u64 per_commit_index)
{
	struct sha256 s;

	if (per_commit_index >= (1ULL << SHACHAIN_BITS))
		return false;

	shachain_from_seed(shaseed, shachain_index(per_commit_index), &s);

	BUILD_ASSERT(sizeof(s) == sizeof(*commit_secret));
	memcpy(commit_secret, &s, sizeof(s));
	return true;
}

bool per_commit_point(const struct sha256 *shaseed,
		      struct pubkey *commit_point,
		      u64 per_commit_index)
{
	struct secret secret;

	if (!per_commit_secret(shaseed, &secret, per_commit_index))
		return false;

	/* BOLT #3:
	 *
	 * The `per_commitment_point` is generated using elliptic-curve
	 * multiplication:
	 *
	 * 	per_commitment_point = per_commitment_secret * G
	 */
	if (secp256k1_ec_pubkey_create(secp256k1_ctx,
				       &commit_point->pubkey,
				       secret.data) != 1)
		return false;

	return true;
}

bool derive_payment_basepoint(const struct secret *seed,
			      struct pubkey *payment_basepoint,
			      struct secret *payment_secret)
{
	struct keys keys;

	derive_keys(seed, &keys);

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
	struct keys keys;

	derive_keys(seed, &keys);

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
	struct keys keys;

	derive_keys(seed, &keys);

	*shaseed = keys.shaseed;
	return true;
}

bool derive_funding_key(const struct secret *seed,
			struct pubkey *funding_pubkey,
			struct privkey *funding_privkey)
{
	struct keys keys;

	derive_keys(seed, &keys);

	if (funding_pubkey) {
		if (!pubkey_from_privkey(&keys.f, funding_pubkey))
			return false;
	}

	if (funding_privkey)
		*funding_privkey = keys.f;

	return true;
}

bool derive_revocation_basepoint(const struct secret *seed,
				 struct pubkey *revocation_basepoint,
				 struct secret *revocation_secret)
{
	struct keys keys;

	derive_keys(seed, &keys);

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
	struct keys keys;

	derive_keys(seed, &keys);

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

bool shachain_get_secret(const struct shachain *shachain,
			 u64 commit_num,
			 struct secret *preimage)
{
	struct sha256 sha;

	if (commit_num >= (1ULL << SHACHAIN_BITS))
		return false;

	if (!shachain_get_hash(shachain, shachain_index(commit_num), &sha))
		return false;
	BUILD_ASSERT(sizeof(*preimage) == sizeof(sha));
	memcpy(preimage, &sha, sizeof(*preimage));
	return true;
}
