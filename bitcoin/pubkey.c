#include "privkey.h"
#include "pubkey.h"
#include "type_to_string.h"
#include "utils.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>

bool pubkey_from_der(const u8 *der, size_t len, struct pubkey *key)
{
	if (len != PUBKEY_DER_LEN)
		return false;

	if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &key->pubkey,
				       memcheck(der, len), len))
		return false;

	return true;
}

void pubkey_to_der(u8 der[PUBKEY_DER_LEN], const struct pubkey *key)
{
	size_t outlen = PUBKEY_DER_LEN;
	if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, der, &outlen,
					   &key->pubkey,
					   SECP256K1_EC_COMPRESSED))
		abort();
	assert(outlen == PUBKEY_DER_LEN);
}

/* Pubkey from privkey */
bool pubkey_from_privkey(const struct privkey *privkey,
			 struct pubkey *key)
{
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx,
					&key->pubkey, privkey->secret))
		return false;
	return true;
}

bool pubkey_from_hexstr(const char *derstr, size_t slen, struct pubkey *key)
{
	size_t dlen;
	unsigned char der[PUBKEY_DER_LEN];

	dlen = hex_data_size(slen);
	if (dlen != sizeof(der))
		return false;

	if (!hex_decode(derstr, slen, der, dlen))
		return false;

	return pubkey_from_der(der, dlen, key);
}

char *pubkey_to_hexstr(const tal_t *ctx, const struct pubkey *key)
{
	unsigned char der[PUBKEY_DER_LEN];

	pubkey_to_der(der, key);
	return tal_hexstr(ctx, der, sizeof(der));
}

bool pubkey_eq(const struct pubkey *a, const struct pubkey *b)
{
	return structeq(&a->pubkey, &b->pubkey);
}

REGISTER_TYPE_TO_STRING(pubkey, pubkey_to_hexstr);

int pubkey_cmp(const struct pubkey *a, const struct pubkey *b)
{
	u8 keya[33], keyb[33];
	pubkey_to_der(keya, a);
	pubkey_to_der(keyb, b);
	return memcmp(keya, keyb, sizeof(keya));
}
