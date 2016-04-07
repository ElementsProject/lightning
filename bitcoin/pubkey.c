#include "privkey.h"
#include "pubkey.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>

bool pubkey_from_der(secp256k1_context *secpctx,
		     const u8 *der, size_t len,
		     struct pubkey *key)
{
	if (len != sizeof(key->der))
		return false;

	memcpy(key->der, memcheck(der, sizeof(key->der)), sizeof(key->der));
	if (!secp256k1_ec_pubkey_parse(secpctx, &key->pubkey, key->der,
				       sizeof(key->der)))
		return false;

	return true;
}

/* Pubkey from privkey */
bool pubkey_from_privkey(secp256k1_context *secpctx,
			 const struct privkey *privkey,
			 struct pubkey *key,
			 unsigned int compressed_flags)
{
	size_t outlen;
	
	if (!secp256k1_ec_pubkey_create(secpctx, &key->pubkey, privkey->secret))
		return false;

	if (!secp256k1_ec_pubkey_serialize(secpctx, key->der, &outlen,
					   &key->pubkey, compressed_flags))
		return false;
	assert(outlen == sizeof(key->der));
	return true;
}
	
bool pubkey_from_hexstr(secp256k1_context *secpctx,
			const char *derstr, size_t slen, struct pubkey *key)
{
	size_t dlen;
	unsigned char der[sizeof(key->der)];

	dlen = hex_data_size(slen);
	if (dlen != sizeof(der))
		return false;

	if (!hex_decode(derstr, slen, der, dlen))
		return false;

	return pubkey_from_der(secpctx, der, dlen, key);
}

bool pubkey_eq(const struct pubkey *a, const struct pubkey *b)
{
	return memcmp(a->der, b->der, sizeof(a->der)) == 0;
}
