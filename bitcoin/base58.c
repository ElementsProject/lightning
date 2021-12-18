/* Converted to C by Rusty Russell, based on bitcoin source: */
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "config.h"
#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/shadouble.h>
#include <common/utils.h>
#include <wally_core.h>

static char *to_base58(const tal_t *ctx, u8 version,
		       const struct ripemd160 *rmd)
{
	char *out;
	size_t total_length = sizeof(*rmd) + 1;
	u8 buf[total_length];
	buf[0] = version;
	memcpy(buf + 1, rmd, sizeof(*rmd));

	tal_wally_start();
	if (wally_base58_from_bytes((const unsigned char *) buf,
				    total_length, BASE58_FLAG_CHECKSUM, &out)
	    != WALLY_OK)
		out = NULL;
	tal_wally_end(tal_steal(ctx, out));

	return out;
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

bool ripemd160_from_base58(u8 *version, struct ripemd160 *rmd,
			   const char *base58, size_t base58_len)
{
	return from_base58(version, rmd, base58, base58_len);
}
