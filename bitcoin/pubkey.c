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

bool pubkey_from_der(secp256k1_context *secpctx,
		     const u8 *der, size_t len,
		     struct pubkey *key)
{
	if (len > sizeof(key->der))
		return false;

	memcpy(key->der, der, len);
	if (!secp256k1_ec_pubkey_parse(secpctx, &key->pubkey, key->der, len))
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
	assert(outlen == pubkey_derlen(key));
	return true;
}
	
bool pubkey_from_hexstr(secp256k1_context *secpctx,
			const char *derstr, size_t slen, struct pubkey *key)
{
	size_t dlen;
	unsigned char der[65];

	dlen = hex_data_size(slen);
	if (dlen > sizeof(der))
		return false;

	if (!hex_decode(derstr, slen, der, dlen))
		return false;

	return pubkey_from_der(secpctx, der, dlen, key);
}

bool pubkey_eq(const struct pubkey *a, const struct pubkey *b)
{
	return pubkey_derlen(a) == pubkey_derlen(b)
		&& memcmp(a->der, b->der, pubkey_derlen(a)) == 0;
}
