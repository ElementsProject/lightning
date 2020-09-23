/* Converted to C by Rusty Russell, based on bitcoin source: */
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "address.h"
#include "base58.h"
#include "privkey.h"
#include "pubkey.h"
#include "shadouble.h"
#include <assert.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/tal/str/str.h>
#include <common/utils.h>
#include <string.h>
#include <wally_core.h>

static char *to_base58(const tal_t *ctx, u8 version,
		       const struct ripemd160 *rmd)
{
	char *out;
	size_t total_length = sizeof(*rmd) + 1;
	u8 buf[total_length];
	buf[0] = version;
	memcpy(buf + 1, rmd, sizeof(*rmd));

	if (wally_base58_from_bytes((const unsigned char *) buf,
				    total_length, BASE58_FLAG_CHECKSUM, &out)
	    != WALLY_OK)
		out = NULL;

	return tal_steal(ctx, out);
}

char *bitcoin_to_base58(const tal_t *ctx, const struct chainparams *chainparams,
			const struct bitcoin_address *addr)
{
	return to_base58(ctx, chainparams->p2pkh_version, &addr->addr);
}

char *p2sh_to_base58(const tal_t *ctx, const struct chainparams *chainparams,
		     const struct ripemd160 *p2sh)
{
	return to_base58(ctx, chainparams->p2sh_version, p2sh);
}

static bool from_base58(u8 *version,
			struct ripemd160 *rmd,
			const char *base58, size_t base58_len)
{
	u8 buf[1 + sizeof(*rmd) + 4];
	/* Avoid memcheck complaining if decoding resulted in a short value */
	size_t buflen = sizeof(buf);
	memset(buf, 0, buflen);
	char *terminated_base58 = tal_dup_arr(NULL, char, base58, base58_len, 1);
	terminated_base58[base58_len] = '\0';

	size_t written = 0;
	int r = wally_base58_to_bytes(terminated_base58, BASE58_FLAG_CHECKSUM, buf, buflen, &written);
	tal_free(terminated_base58);
	if (r != WALLY_OK || written > buflen) {
		return false;
	}
	*version = buf[0];
	memcpy(rmd, buf + 1, sizeof(*rmd));
	return true;
}

bool bitcoin_from_base58(u8 *version, struct bitcoin_address *addr,
			 const char *base58, size_t len)
{
	return from_base58(version, &addr->addr, base58, len);
}


bool p2sh_from_base58(u8 *version, struct ripemd160 *p2sh, const char *base58,
		      size_t len)
{

	return from_base58(version, p2sh, base58, len);
}

bool ripemd160_from_base58(u8 *version, struct ripemd160 *rmd,
			   const char *base58, size_t base58_len)
{
	return from_base58(version, rmd, base58, base58_len);
}

bool key_from_base58(const char *base58, size_t base58_len,
		     bool *test_net, struct privkey *priv, struct pubkey *key)
{
	// 1 byte version, 32 byte private key, 1 byte compressed, 4 byte checksum
	u8 keybuf[1 + 32 + 1 + 4];
	char *terminated_base58 = tal_dup_arr(NULL, char, base58, base58_len, 1);
	terminated_base58[base58_len] = '\0';
	size_t keybuflen = sizeof(keybuf);


	size_t written = 0;
	int r = wally_base58_to_bytes(terminated_base58, BASE58_FLAG_CHECKSUM, keybuf, keybuflen, &written);
	wally_bzero(terminated_base58, base58_len + 1);
	tal_free(terminated_base58);
	if (r != WALLY_OK || written > keybuflen)
		return false;

	/* Byte after key should be 1 to represent a compressed key. */
	if (keybuf[1 + 32] != 1)
		return false;

	if (keybuf[0] == 128)
		*test_net = false;
	else if (keybuf[0] == 239)
		*test_net = true;
	else
		return false;

	/* Copy out secret. */
	memcpy(priv->secret.data, keybuf + 1, sizeof(priv->secret.data));

	if (!secp256k1_ec_seckey_verify(secp256k1_ctx, priv->secret.data))
		return false;

	/* Get public key, too. */
	if (!pubkey_from_privkey(priv, key))
		return false;

	return true;
}
