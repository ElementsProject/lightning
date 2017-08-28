#ifndef LIGHTNING_COMMON_KEY_DERIVE_H
#define LIGHTNING_COMMON_KEY_DERIVE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct pubkey;
struct privkey;
struct secret;

/* For `localkey`, `remotekey`, `local-delayedkey` and `remote-delayedkey` */
bool derive_simple_key(const struct pubkey *basepoint,
		       const struct pubkey *per_commitment_point,
		       struct pubkey *key);

bool derive_simple_privkey(const struct secret *base_secret,
			   const struct pubkey *basepoint,
			   const struct pubkey *per_commitment_point,
			   struct privkey *key);

/* For `revocationkey` */
bool derive_revocation_key(const struct pubkey *basepoint,
			   const struct pubkey *per_commitment_point,
			   struct pubkey *key);

bool derive_revocation_privkey(const struct secret *base_secret,
			       const struct secret *per_commitment_secret,
			       const struct pubkey *basepoint,
			       const struct pubkey *per_commitment_point,
			       struct privkey *key);


struct ext_key;
bool bip32_pubkey(const struct ext_key *bip32_base,
		  struct pubkey *pubkey, u32 index);
#endif /* LIGHTNING_COMMON_KEY_DERIVE_H */
