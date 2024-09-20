#ifndef LIGHTNING_COMMON_BLINDING_H
#define LIGHTNING_COMMON_BLINDING_H
#include "config.h"

struct privkey;
struct pubkey;
struct secret;
struct sha256;

/* H(E(i) || ss(i)) */
void blinding_hash_e_and_ss(const struct pubkey *e,
			    const struct secret *ss,
			    struct sha256 *sha);

/* E(i+1) = H(E(i) || ss(i)) * E(i) */
bool blinding_next_path_key(const struct pubkey *pk,
			    const struct sha256 *h,
			    struct pubkey *next);

/* e(i+1) = H(E(i) || ss(i)) * e(i) */
bool blinding_next_path_privkey(const struct privkey *e,
				const struct sha256 *h,
				struct privkey *next);

#endif /* LIGHTNING_COMMON_BLINDING_H */
