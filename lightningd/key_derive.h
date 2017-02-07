#ifndef LIGHTNING_LIGHTNINGD_KEY_DERIVE_H
#define LIGHTNING_LIGHTNINGD_KEY_DERIVE_H
#include "config.h"

struct pubkey;

/* For `localkey`, `remotekey`, `local-delayedkey` and `remote-delayedkey` */
bool derive_simple_key(const struct pubkey *basepoint,
		       const struct pubkey *per_commitment_point,
		       struct pubkey *key);

bool derive_simple_privkey(const struct privkey *base_secret,
			   const struct pubkey *basepoint,
			   const struct pubkey *per_commitment_point,
			   struct privkey *key);

/* For `revocationkey` */
bool derive_revocation_key(const struct pubkey *basepoint,
			   const struct pubkey *per_commitment_point,
			   struct pubkey *key);

bool derive_revocation_privkey(const struct privkey *base_secret,
			       const struct privkey *per_commitment_secret,
			       const struct pubkey *basepoint,
			       const struct pubkey *per_commitment_point,
			       struct privkey *key);

#endif /* LIGHTNING_LIGHTNINGD_KEY_DERIVE_H */
