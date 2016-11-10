#include "privkey.h"
#include "pubkey.h"
#include "utils.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>

bool pubkey_from_der(secp256k1_context *secpctx,
		     const u8 *der, size_t len,
		     struct pubkey *key)
{
	if (len != PUBKEY_DER_LEN)
		return false;

	if (!secp256k1_ec_pubkey_parse(secpctx, &key->pubkey,
				       memcheck(der, len), len))
		return false;

	return true;
}

void pubkey_to_der(secp256k1_context *secpctx, u8 der[PUBKEY_DER_LEN],
		   const struct pubkey *key)
{
	size_t outlen = PUBKEY_DER_LEN;
	if (!secp256k1_ec_pubkey_serialize(secpctx, der, &outlen,
					   &key->pubkey,
					   SECP256K1_EC_COMPRESSED))
		abort();
	assert(outlen == PUBKEY_DER_LEN);
}

/* Pubkey from privkey */
bool pubkey_from_privkey(secp256k1_context *secpctx,
			 const struct privkey *privkey,
			 struct pubkey *key)
{
	if (!secp256k1_ec_pubkey_create(secpctx, &key->pubkey, privkey->secret))
		return false;
	return true;
}

bool pubkey_from_hexstr(secp256k1_context *secpctx,
			const char *derstr, size_t slen, struct pubkey *key)
{
	size_t dlen;
	unsigned char der[PUBKEY_DER_LEN];

	dlen = hex_data_size(slen);
	if (dlen != sizeof(der))
		return false;

	if (!hex_decode(derstr, slen, der, dlen))
		return false;

	return pubkey_from_der(secpctx, der, dlen, key);
}

char *pubkey_to_hexstr(const tal_t *ctx, secp256k1_context *secpctx,
		       const struct pubkey *key)
{
	unsigned char der[PUBKEY_DER_LEN];

	pubkey_to_der(secpctx, der, key);
	return tal_hexstr(ctx, der, sizeof(der));
}

bool pubkey_eq(const struct pubkey *a, const struct pubkey *b)
{
	return structeq(&a->pubkey, &b->pubkey);
}
