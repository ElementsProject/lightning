#include "pubkey.h"
#include <openssl/ecdsa.h>

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

static bool valid_pubkey(const BitcoinPubkey *key)
{
	if (key->key.len < 1)
		return false;
	return (key->key.len == GetLen(key->key.data[0]));
}

size_t pubkey_len(const struct pubkey *key)
{
	size_t len = GetLen(key->key[0]);

	assert(len);
	return len;
}

BitcoinPubkey *pubkey_to_proto(const tal_t *ctx, const struct pubkey *key)
{
	BitcoinPubkey *p = tal(ctx, BitcoinPubkey);

	bitcoin_pubkey__init(p);
	p->key.len = pubkey_len(key);
	p->key.data = tal_dup_arr(p, u8, key->key, p->key.len, 0);

	assert(valid_pubkey(p));
	return p;
}

bool proto_to_pubkey(const BitcoinPubkey *pb, struct pubkey *key)
{
	if (!valid_pubkey(pb))
		return false;

	memcpy(key->key, pb->key.data, pb->key.len);
	return true;
}
