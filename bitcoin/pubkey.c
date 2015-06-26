#include <ccan/str/hex/hex.h>
#include <assert.h>
#include "pubkey.h"

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

bool pubkey_valid(const u8 *first_char, size_t len)
{
	if (len < 1)
		return false;
	return (len == GetLen(*first_char));
}

size_t pubkey_len(const struct pubkey *key)
{
	size_t len = GetLen(key->key[0]);

	assert(len);
	return len;
}

bool pubkey_from_hexstr(const char *str, struct pubkey *key)
{
	size_t slen = strlen(str), dlen;
	dlen = hex_data_size(slen);

	if (dlen != 33 && dlen != 65)
		return false;
	if (!hex_decode(str, slen, key->key, dlen))
		return false;
	return GetLen(key->key[0]) == dlen;
}
