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
					&key->pubkey, privkey->secret.data))
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

char *secp256k1_pubkey_to_hexstr(const tal_t *ctx, const secp256k1_pubkey *key)
{
	unsigned char der[PUBKEY_DER_LEN];
	size_t outlen = sizeof(der);
	if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, der, &outlen, key,
					   SECP256K1_EC_COMPRESSED))
		abort();
	assert(outlen == sizeof(der));
	return tal_hexstr(ctx, der, sizeof(der));
}
REGISTER_TYPE_TO_STRING(secp256k1_pubkey, secp256k1_pubkey_to_hexstr);

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

static char *privkey_to_hexstr(const tal_t *ctx, const struct privkey *secret)
{
	/* Bitcoin appends "01" to indicate the pubkey is compressed. */
	char *str = tal_arr(ctx, char, hex_str_size(sizeof(*secret) + 1));
	hex_encode(secret, sizeof(*secret), str, hex_str_size(sizeof(*secret)));
	strcat(str, "01");
	return str;
}
REGISTER_TYPE_TO_STRING(privkey, privkey_to_hexstr);
REGISTER_TYPE_TO_HEXSTR(secret);

void pubkey_to_hash160(const struct pubkey *pk, struct ripemd160 *hash)
{
	u8 der[PUBKEY_DER_LEN];
	struct sha256 h;

	pubkey_to_der(der, pk);
	sha256(&h, der, sizeof(der));
	ripemd160(hash, h.u.u8, sizeof(h));
}
