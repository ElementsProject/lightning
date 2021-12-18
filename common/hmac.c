#include "config.h"
#include <bitcoin/privkey.h>
#include <ccan/array_size/array_size.h>
#include <ccan/mem/mem.h>
#include <common/hmac.h>
#include <wire/wire.h>

void hmac_start(crypto_auth_hmacsha256_state *state,
		const void *key, size_t klen)
{
	crypto_auth_hmacsha256_init(state, memcheck(key, klen), klen);
}

void hmac_update(crypto_auth_hmacsha256_state *state,
		 const void *src, size_t slen)
{
	crypto_auth_hmacsha256_update(state, memcheck(src, slen), slen);
}

void hmac_done(crypto_auth_hmacsha256_state *state,
	       struct hmac *hmac)
{
	crypto_auth_hmacsha256_final(state, hmac->bytes);
}

void hmac(const void *src, size_t slen,
	  const void *key, size_t klen,
	  struct hmac *hmac)
{
	crypto_auth_hmacsha256_state state;

	hmac_start(&state, key, klen);
	hmac_update(&state, src, slen);
	hmac_done(&state, hmac);
}

void subkey_from_hmac(const char *prefix,
		      const struct secret *base,
		      struct secret *key)
{
	struct hmac h;
	hmac(base->data, sizeof(base->data), prefix, strlen(prefix), &h);
	BUILD_ASSERT(sizeof(h.bytes) == sizeof(key->data));
	memcpy(key->data, h.bytes, sizeof(key->data));
}

void towire_hmac(u8 **pptr, const struct hmac *hmac)
{
	towire_u8_array(pptr, hmac->bytes, ARRAY_SIZE(hmac->bytes));
}

void fromwire_hmac(const u8 **ptr, size_t *max, struct hmac *hmac)
{
	fromwire_u8_array(ptr, max, hmac->bytes, ARRAY_SIZE(hmac->bytes));
}
