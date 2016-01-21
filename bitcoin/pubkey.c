#include "privkey.h"
#include "pubkey.h"
#include <assert.h>
#include <ccan/str/hex/hex.h>

/* Must agree on key validity with bitcoin!  Stolen from bitcoin/src/pubkey.h's
 * GetLen:
 * // Copyright (c) 2009-2010 Satoshi Nakamoto
 * // Copyright (c) 2009-2014 The Bitcoin Core developers
 * // Distributed under the MIT software license, see the accompanying
 * // file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
static unsigned int GetLen(unsigned char chHeader)
{
        if (chHeader == 2 || chHeader == 3)
		return 33;
        if (chHeader == 4 || chHeader == 6 || chHeader == 7)
		return 65;
        return 0;
}

size_t pubkey_derlen(const struct pubkey *key)
{
	size_t len = GetLen(key->der[0]);

	assert(len);
	return len;
}

bool pubkey_from_der(const u8 *der, size_t len, struct pubkey *key)
{
	secp256k1_context *secpctx = secp256k1_context_create(0);

	if (len > sizeof(key->der))
		goto fail_free_secpctx;

	memcpy(key->der, der, len);
	if (!secp256k1_ec_pubkey_parse(secpctx, &key->pubkey, key->der, len))
		goto fail_free_secpctx;

	secp256k1_context_destroy(secpctx);
	return true;
	
fail_free_secpctx:
	secp256k1_context_destroy(secpctx);
	return false;
}

/* Pubkey from privkey */
bool pubkey_from_privkey(const struct privkey *privkey,
			 struct pubkey *key,
			 unsigned int compressed_flags)
{
	secp256k1_context *secpctx;
	size_t outlen;
	
	secpctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

	if (!secp256k1_ec_pubkey_create(secpctx, &key->pubkey, privkey->secret))
		goto fail_free_secpctx;

	if (!secp256k1_ec_pubkey_serialize(secpctx, key->der, &outlen,
					   &key->pubkey, compressed_flags))
		goto fail_free_secpctx;
	assert(outlen == pubkey_derlen(key));
	
	secp256k1_context_destroy(secpctx);
	return true;

fail_free_secpctx:
	secp256k1_context_destroy(secpctx);
	return false;
}
	
bool pubkey_from_hexstr(const char *derstr, struct pubkey *key)
{
	size_t slen = strlen(derstr), dlen;
	unsigned char der[65];

	dlen = hex_data_size(slen);
	if (dlen > sizeof(der))
		return false;

	if (!hex_decode(derstr, slen, der, dlen))
		return false;

	return pubkey_from_der(der, dlen, key);
}

bool pubkey_eq(const struct pubkey *a, const struct pubkey *b)
{
	return pubkey_derlen(a) == pubkey_derlen(b)
		&& memcmp(a->der, b->der, pubkey_derlen(a)) == 0;
}
