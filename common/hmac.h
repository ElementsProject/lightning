#ifndef LIGHTNING_COMMON_HMAC_H
#define LIGHTNING_COMMON_HMAC_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <sodium/crypto_auth_hmacsha256.h>

struct secret;

/* HMAC used by Sphinx: SHA256 */
struct hmac {
	u8 bytes[crypto_auth_hmacsha256_BYTES];
};

void hmac(const void *src, size_t slen,
	  const void *key, size_t klen,
	  struct hmac *hmac);

void hmac_start(crypto_auth_hmacsha256_state *state,
		const void *key, size_t klen);

void hmac_update(crypto_auth_hmacsha256_state *state,
		 const void *src, size_t slen);

void hmac_done(crypto_auth_hmacsha256_state *state,
	       struct hmac *hmac);

/* Common style: hmac to derive key using fixed string prefix. */
void subkey_from_hmac(const char *prefix,
		      const struct secret *base,
		      struct secret *key);

void towire_hmac(u8 **pptr, const struct hmac *hmac);
void fromwire_hmac(const u8 **ptr, size_t *max, struct hmac *hmac);

/* Define hmac_eq. */
STRUCTEQ_DEF(hmac, 0, bytes);

#endif /* LIGHTNING_COMMON_HMAC_H */
