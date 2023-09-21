#ifndef LIGHTNING_COMMON_DERIVE_BASEPOINTS_H
#define LIGHTNING_COMMON_DERIVE_BASEPOINTS_H
#include "config.h"
#include <assert.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <ccan/crypto/shachain/shachain.h>

struct sha256;

struct basepoints {
	struct pubkey revocation;
	struct pubkey payment;
	struct pubkey htlc;
	struct pubkey delayed_payment;
};

struct secrets {
	struct privkey funding_privkey;
	struct secret revocation_basepoint_secret;
	struct secret payment_basepoint_secret;
	struct secret htlc_basepoint_secret;
	struct secret delayed_payment_basepoint_secret;
};

/**
 * derive_basepoints - given a (per-peer) seed, get the basepoints
 * @seed: (in) seed (derived by master daemon from counter and main seed)
 * @funding_pubkey: (out) pubkey for funding tx output (if non-NULL)
 * @basepoints: (out) basepoints for channel (if non-NULL)
 * @secrets: (out) basepoints for channel (if non-NULL)
 * @shaseed: (out) seed for shachain (if non-NULL)
 */
bool derive_basepoints(const struct secret *seed,
		       struct pubkey *funding_pubkey,
		       struct basepoints *basepoints,
		       struct secrets *secrets,
		       struct sha256 *shaseed);

/**
 * derive_funding_key - given a (per-peer) seed, get just funding key
 * @seed: (in) seed (derived by master daemon from counter and main seed)
 * @funding_pubkey: (out) pubkey for funding tx output (if non-NULL)
 * @funding_privkey: (out) privkey for funding tx output (if non-NULL)
 *
 * This is a cut-down version of derive_basepoints.
 */
bool derive_funding_key(const struct secret *seed,
			struct pubkey *funding_pubkey,
			struct privkey *funding_privkey);

/**
 * derive_payment_basepoint - given a (per-channel) seed, get just payment basepoint
 * @seed: (in) seed (derived by master daemon from counter and main seed)
 * @payment_basepoint: (out) basepoint for payment output (if non-NULL)
 * @payment_secret: (out) secret for payment basepoint (if non-NULL)
 *
 * This is a cut-down version of derive_basepoints.
 */
bool derive_payment_basepoint(const struct secret *seed,
			      struct pubkey *payment_basepoint,
			      struct secret *payment_secret);

/**
 * derive_shaseed - given a (per-peer) seed, get just the shaseed
 * @seed: (in) seed (derived by master daemon from counter and main seed)
 * @shaseed: (out) seed for shachain
 *
 * This is a cut-down version of derive_basepoints.
 */
bool derive_shaseed(const struct secret *seed, struct sha256 *shaseed);

/**
 * derive_delayed_payment_basepoint - give a (per-channel) seed, get just delayed payment basepoint
 * @seed: (in) seed (derived by master daemon from counter and main seed)
 * @delayed_payment_basepoint: (out) basepoint for payment output (if non-NULL)
 * @delayed_payment_secret: (out) secret for payment basepoint (if non-NULL)
 *
 * This is a cut-down version of derive_basepoints.
 */
bool derive_delayed_payment_basepoint(const struct secret *seed,
			      struct pubkey *delayed_payment_basepoint,
			      struct secret *delayed_payment_secret);

/**
 * derive_revocation_basepoint - given a (per-channel) seed, get just revocation basepoint
 * @seed: (in) seed (derived by master daemon from counter and main seed)
 * @payment_basepoint: (out) basepoint for revocation keys (if non-NULL)
 * @payment_secret: (out) secret for revocation keys (if non-NULL)
 *
 * This is a cut-down version of derive_basepoints.
 */
bool derive_revocation_basepoint(const struct secret *seed,
				 struct pubkey *revocation_basepoint,
				 struct secret *revocation_secret);

/**
 * derive_htlc_basepoint - give a (per-channel) seed, get just htlc basepoint
 * @seed: (in) seed (derived by master daemon from counter and main seed)
 * @htlc_basepoint: (out) basepoint for htlc output (if non-NULL)
 * @htlc_secret: (out) secret for htlc basepoint (if non-NULL)
 *
 * This is a cut-down version of derive_basepoints.
 */
bool derive_htlc_basepoint(const struct secret *seed,
			   struct pubkey *htlc_basepoint,
			   struct secret *htlc_secret);

/**
 * per_commit_secret - get a secret for this index.
 * @shaseed: the sha256 seed
 * @commit_secret: the returned per-commit secret.
 * @per_commit_index: (in) which @commit_secret to return.
 *
 * Returns false if per_commit_index is invalid, or can't derive.
 */
bool per_commit_secret(const struct sha256 *shaseed,
		       struct secret *commit_secret,
		       u64 per_commit_index);

/**
 * per_commit_point - get the per-commit-point for this index.
 * @shaseed: the sha256 seed
 * @commit_point: the returned per-commit point.
 * @per_commit_index: (in) which @commit_point to return.
 */
bool per_commit_point(const struct sha256 *shaseed,
		      struct pubkey *commit_point,
		      u64 per_commit_index);

/* BOLT #3:
 *
 * The first secret used:
 *   - MUST be index 281474976710655,
 *     - and from there, the index is decremented.
 */
static inline u64 shachain_index(u64 per_commit_index)
{
	BUILD_ASSERT((1ULL << SHACHAIN_BITS)-1 == 281474976710655);
	assert(per_commit_index < (1ULL << SHACHAIN_BITS));
	return (1ULL << SHACHAIN_BITS)-1 - per_commit_index;
}

static inline u64 revocations_received(const struct shachain *shachain)
{
	return (1ULL << SHACHAIN_BITS) - (shachain_next_index(shachain) + 1);
}

bool shachain_get_secret(const struct shachain *shachain,
			 u64 commit_num,
			 struct secret *preimage);

void towire_basepoints(u8 **pptr, const struct basepoints *b);
void fromwire_basepoints(const u8 **ptr, size_t *max,
			 struct basepoints *b);

/* For --dev-force-channel-secrets. */
extern struct secrets *dev_force_channel_secrets;
extern struct sha256 *dev_force_channel_secrets_shaseed;

void towire_secrets(u8 **pptr, const struct secrets *s);
void fromwire_secrets(const u8 **ptr, size_t *max, struct secrets *s);

#endif /* LIGHTNING_COMMON_DERIVE_BASEPOINTS_H */
