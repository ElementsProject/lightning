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
#include <openssl/bn.h>
#include <secp256k1.h>
#include <string.h>

static const char enc_16[] = "0123456789abcdef";
static const char enc_58[] =
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static char encode_char(unsigned long val, const char *enc)
{
	assert(val < strlen(enc));
	return enc[val];
}

static int decode_char(char c, const char *enc)
{
	const char *pos = strchr(enc, c);
	if (!pos)
		return -1;
	return pos - enc;
}

/*
 * Encode a byte sequence as a base58-encoded string.  This is a bit
 * weird: returns pointer into buf (or NULL if wouldn't fit).
 */
static char *encode_base58(char *buf, size_t buflen,
			   const u8 *data, size_t data_len)
{
	char *p;
	BIGNUM bn;

	/* Convert to a bignum. */
	BN_init(&bn);
	BN_bin2bn(data, data_len, &bn);

	/* Add NUL terminator */
	if (!buflen) {
		p = NULL;
		goto out;
	}
	p = buf + buflen;
	*(--p) = '\0';

	/* Fill from the back, using a series of divides. */
	while (!BN_is_zero(&bn)) {
		int rem = BN_div_word(&bn, 58);
		if (--p < buf) {
			p = NULL;
			goto out;
		}
		*p = encode_char(rem, enc_58);
	}

	/* Now, this is really weird.  We pad with zeroes, but not at
	 * base 58, but in terms of zero bytes.  This means that some
	 * encodings are shorter than others! */
	while (data_len && *data == '\0') {
		if (--p < buf) {
			p = NULL;
			goto out;
		}
		*p = encode_char(0, enc_58);
		data_len--;
		data++;
	}

out:
	BN_free(&bn);
	return p;
}

/*
 * Decode a base_n-encoded string into a byte sequence.
 */
bool raw_decode_base_n(BIGNUM *bn, const char *src, size_t len, int base)
{
	const char *enc;

	BN_zero(bn);

	assert(base == 16 || base == 58);
	switch (base) {
	case 16:
		enc = enc_16;
		break;
	case 58:
		enc = enc_58;
		break;
	}

	while (len) {
		char current = *src;

		if (base == 16)
			current = tolower(current);	/* TODO: Not in ccan. */
		int val = decode_char(current, enc);
		if (val < 0) {
			BN_free(bn);
			return false;
		}
		BN_mul_word(bn, base);
		BN_add_word(bn, val);
		src++;
		len--;
	}

	return true;
}

/*
 * Decode a base58-encoded string into a byte sequence.
 */
bool raw_decode_base58(BIGNUM *bn, const char *src, size_t len)
{
	return raw_decode_base_n(bn, src, len, 58);
}

void base58_get_checksum(u8 csum[4], const u8 buf[], size_t buflen)
{
	struct sha256_double sha_result;

	/* Form checksum, using double SHA2 (as per bitcoin standard) */
	sha256_double(&sha_result, buf, buflen);

	/* Use first four bytes of that as the checksum. */
	memcpy(csum, sha_result.sha.u.u8, 4);
}

static char *to_base58(const tal_t *ctx, u8 version,
		       const struct ripemd160 *rmd)
{
	u8 buf[1 + sizeof(*rmd) + 4];
	char out[BASE58_ADDR_MAX_LEN + 2], *p;

	buf[0] = version;
	memcpy(buf+1, rmd, sizeof(*rmd));

	/* Append checksum */
	base58_get_checksum(buf + 1 + sizeof(*rmd), buf, 1 + sizeof(*rmd));

	p = encode_base58(out, BASE58_ADDR_MAX_LEN, buf, sizeof(buf));
	return tal_strdup(ctx, p);
}

char *bitcoin_to_base58(const tal_t *ctx, bool test_net,
			const struct bitcoin_address *addr)
{
	return to_base58(ctx, test_net ? 111 : 0, &addr->addr);
}

char *p2sh_to_base58(const tal_t *ctx, bool test_net,
		     const struct ripemd160 *p2sh)
{
	return to_base58(ctx, test_net ? 196 : 5, p2sh);
}

static bool from_base58(u8 *version,
			struct ripemd160 *rmd,
			const char *base58, size_t base58_len)
{
	u8 buf[1 + sizeof(*rmd) + 4];
	BIGNUM bn;
	size_t len;
	u8 csum[4];

	BN_init(&bn);
	if (!raw_decode_base58(&bn, base58, base58_len))
		return false;

	len = BN_num_bytes(&bn);
	if (len > sizeof(buf))
		return false;

	memset(buf, 0, sizeof(buf));
	BN_bn2bin(&bn, buf + sizeof(buf) - len);
	BN_free(&bn);

	*version = buf[0];

	base58_get_checksum(csum, buf, 1 + sizeof(*rmd));
	if (memcmp(csum, buf + 1 + sizeof(*rmd), sizeof(csum)) != 0)
		return false;

	memcpy(rmd, buf+1, sizeof(*rmd));
	return true;
}

bool bitcoin_from_base58(bool *test_net,
			 struct bitcoin_address *addr,
			 const char *base58, size_t len)
{
	u8 version;

	if (!from_base58(&version, &addr->addr, base58, len))
		return false;

	if (version == 111)
		*test_net = true;
	else if (version == 0)
		*test_net = false;
	else
		return false;
	return true;
}

bool p2sh_from_base58(bool *test_net,
		      struct ripemd160 *p2sh,
		      const char *base58, size_t len)
{
	u8 version;

	if (!from_base58(&version, p2sh, base58, len))
		return false;

	if (version == 196)
		*test_net = true;
	else if (version == 5)
		*test_net = false;
	else
		return false;
	return true;
}

/* buf already contains version and ripemd160.  Append checksum and encode */
char *base58_with_check(char dest[BASE58_ADDR_MAX_LEN],
			u8 buf[1 + sizeof(struct ripemd160) + 4])
{
	/* Append checksum */
	base58_get_checksum(buf + 1 + sizeof(struct ripemd160),
			    buf, 1 + sizeof(struct ripemd160));

	/* Now encode. */
	return encode_base58(dest, BASE58_ADDR_MAX_LEN, buf,
			     1 + sizeof(struct ripemd160) + 4);
}

bool ripemd_from_base58(u8 *version,
			struct ripemd160 *ripemd160,
			const char *base58)
{
	u8 buf[1 + sizeof(*ripemd160) + 4];
	u8 csum[4];
	BIGNUM bn;
	size_t len;

	/* Too long?  Check here before doing arithmetic. */
	if (strlen(base58) > BASE58_ADDR_MAX_LEN - 1)
		return false;

	BN_init(&bn);
	/* Fails if it contains invalid characters. */
	if (!raw_decode_base58(&bn, base58, strlen(base58)))
		return false;

	/* Too big? */
	len = BN_num_bytes(&bn);
	if (len > sizeof(buf)) {
		BN_free(&bn);
		return false;
	}

	/* Fill start with zeroes. */
	memset(buf, 0, sizeof(buf) - len);
	BN_bn2bin(&bn, buf + sizeof(buf) - len);
	BN_free(&bn);

	/* Check checksum is correct. */
	base58_get_checksum(csum, buf, sizeof(buf));
	if (memcmp(csum, buf + 1 + sizeof(*ripemd160), 4) != 0)
		return false;

	*version = buf[0];
	memcpy(ripemd160, buf + 1, sizeof(*ripemd160));
	return true;
}

char *key_to_base58(const tal_t *ctx, bool test_net, const struct privkey *key)
{
	u8 buf[1 + 32 + 1 + 4];
	char out[BASE58_KEY_MAX_LEN + 2], *p;

	buf[0] = test_net ? 239 : 128;
	memcpy(buf + 1, key->secret, sizeof(key->secret));

	/* Mark this as a compressed key. */
	buf[1 + 32] = 1;

	/* Append checksum */
	base58_get_checksum(buf + 1 + 32 + 1, buf, 1 + 32 + 1);

	p = encode_base58(out, BASE58_KEY_MAX_LEN, buf, sizeof(buf));
	return tal_strdup(ctx, p);
}

bool key_from_base58(secp256k1_context *secpctx,
		     const char *base58, size_t base58_len,
		     bool *test_net, struct privkey *priv, struct pubkey *key)
{
	u8 keybuf[1 + 32 + 1 + 4];
	u8 csum[4];
	BIGNUM bn;
	size_t keylen;
	
	BN_init(&bn);
	if (!raw_decode_base58(&bn, base58, base58_len))
		return false;

	keylen = BN_num_bytes(&bn);
	if (keylen != 1 + 32 + 1 + 4)
		goto fail_free_bn;
	BN_bn2bin(&bn, keybuf);

	base58_get_checksum(csum, keybuf, keylen - sizeof(csum));
	if (memcmp(csum, keybuf + keylen - sizeof(csum), sizeof(csum)) != 0)
		goto fail_free_bn;

	/* Byte after key should be 1 to represent a compressed key. */
	if (keybuf[1 + 32] != 1)
		goto fail_free_bn;

	if (keybuf[0] == 128)
		*test_net = false;
	else if (keybuf[0] == 239)
		*test_net = true;
	else
		goto fail_free_bn;

	/* Copy out secret. */
	memcpy(priv->secret, keybuf + 1, sizeof(priv->secret));

	if (!secp256k1_ec_seckey_verify(secpctx, priv->secret))
		goto fail_free_bn;

	/* Get public key, too. */
	if (!pubkey_from_privkey(secpctx, priv, key))
		goto fail_free_bn;

	BN_free(&bn);
	return true;

fail_free_bn:
	BN_free(&bn);
	return false;
}
