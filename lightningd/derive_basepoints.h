#ifndef LIGHTNING_LIGHTNINGD_DERIVE_BASEPOINTS_H
#define LIGHTNING_LIGHTNINGD_DERIVE_BASEPOINTS_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>

struct sha256;

struct basepoints {
	struct pubkey revocation;
	struct pubkey payment;
	struct pubkey delayed_payment;
};

struct secrets {
	struct privkey funding_privkey;
	struct secret revocation_basepoint_secret;
	struct secret payment_basepoint_secret;
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
bool derive_basepoints(const struct privkey *seed,
		       struct pubkey *funding_pubkey,
		       struct basepoints *basepoints,
		       struct secrets *secrets,
		       struct sha256 *shaseed);

/**
 * per_commit_secret - get a secret for this index.
 * @shaseed: the sha256 seed
 * @commit_secret: the returned per-commit secret.
 * @per_commit_index: (in) which @commit_secret to return.
 */
void per_commit_secret(const struct sha256 *shaseed,
		       struct sha256 *commit_secret,
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
 * the first secret used MUST be index 281474976710655, and then the index
 * decremented.
 */
static inline u64 shachain_index(u64 per_commit_index)
{
	assert(per_commit_index < (1ULL << 48));
	return 281474976710655ULL - per_commit_index;
}
#endif /* LIGHTNING_LIGHTNINGD_DERIVE_BASEPOINTS_H */
