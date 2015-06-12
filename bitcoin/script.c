#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <openssl/ripemd.h>
#include <assert.h>
#include "address.h"
#include "pubkey.h"
#include "script.h"
#include "signature.h"

/* Some standard ops */
#define OP_PUSHBYTES(val) (val)
#define OP_PUSHDATA1	0x4C
#define OP_PUSHDATA2	0x4D
#define OP_PUSHDATA4	0x4E
#define OP_NOP		0x61
#define OP_IF		0x63
#define OP_ELSE		0x67
#define OP_ENDIF	0x68
#define OP_DEPTH	0x74
#define OP_DROP		0x75
#define OP_DUP		0x76
#define OP_EQUAL	0x87
#define OP_EQUALVERIFY	0x88
#define OP_SIZE		0x82
#define OP_1SUB		0x8C
#define OP_CHECKSIG	0xAC
#define OP_CHECKMULTISIG	0xAE
#define OP_HASH160	0xA9

#ifdef HAS_CSV
#define OP_CHECKSEQUENCEVERIFY	0xB2
#else
/* OP_NOP, otherwise bitcoind complains */
#define OP_CHECKSEQUENCEVERIFY	0x61
#endif
static void add(u8 **scriptp, const void *mem, size_t len)
{
	size_t oldlen = tal_count(*scriptp);
	tal_resize(scriptp, oldlen + len);
	memcpy(*scriptp + oldlen, mem, len);
}

static void add_op(u8 **scriptp, u8 op)
{
	add(scriptp, &op, 1);
}

static void add_push_bytes(u8 **scriptp, const void *mem, size_t len)
{
	if (len < 76)
		add_op(scriptp, OP_PUSHBYTES(len));
	else if (len < 256) {
		char c = len;
		add_op(scriptp, OP_PUSHDATA1);
		add(scriptp, &c, 1);
	} else if (len < 65536) {
		le16 v = cpu_to_le16(len);
		add_op(scriptp, OP_PUSHDATA2);
		add(scriptp, &v, 2);
	} else {
		le32 v = cpu_to_le32(len);
		add_op(scriptp, OP_PUSHDATA4);
		add(scriptp, &v, 4);
	}

	add(scriptp, mem, len);
}

static void add_number(u8 **script, u32 num)
{
	if (num == 0)
		add_op(script, 0);
	else if (num <= 16)
		add_op(script, 0x50 + num);
	else {
		u8 n = num;
		/* We could handle others, but currently unnecessary. */
		assert(num < 256);
		add_push_bytes(script, &n, sizeof(n));
	}
}

static void add_push_key(u8 **scriptp, const struct pubkey *key)
{
	add_push_bytes(scriptp, key->key, pubkey_len(key));
}

/* Stolen direct from bitcoin/src/script/sign.cpp:
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
*/
static bool IsValidSignatureEncoding(const unsigned char sig[], size_t len)
{
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if (len < 9) return false;
    if (len > 73) return false;

    // A signature is of type 0x30 (compound).
    if (sig[0] != 0x30) return false;

    // Make sure the length covers the entire signature.
    if (sig[1] != len - 3) return false;

    // Extract the length of the R element.
    unsigned int lenR = sig[3];

    // Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= len) return false;

    // Extract the length of the S element.
    unsigned int lenS = sig[5 + lenR];

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if ((size_t)(lenR + lenS + 7) != len) return false;
 
    // Check whether the R element is an integer.
    if (sig[2] != 0x02) return false;

    // Zero-length integers are not allowed for R.
    if (lenR == 0) return false;

    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) return false;

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) return false;

    // Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02) return false;

    // Zero-length integers are not allowed for S.
    if (lenS == 0) return false;

    // Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80) return false;

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) return false;

    return true;
}

/* DER encode a value, return length used. */
static size_t der_encode_val(const u8 *val, u8 *der)
{
	size_t len = 0, val_len = 32;

	der[len++] = 0x2; /* value type. */

	/* Strip leading zeroes. */
	while (val_len && val[0] == 0) {
		val++;
		val_len--;
	}

	/* Add zero byte if it would otherwise be signed. */
	if (val[0] & 0x80) {
		der[len++] = 1 + val_len; /* value length */
		der[len++] = 0;
	} else
		der[len++] = val_len; /* value length */

	memcpy(der + len, val, val_len);
	return len + val_len;
}
	
/* Bitcoin wants DER encoding. */
static void add_push_sig(u8 **scriptp, const struct bitcoin_signature *sig)
{
	u8 der[2 + 2 + 1 + sizeof(sig->sig.r) + 2 + 1 + sizeof(sig->sig.s) + 1];
	size_t len = 0;

	der[len++] = 0x30; /* Type */
	der[len++] = 0; /* Total length after this: fill it at end. */

	len += der_encode_val(sig->sig.r, der + len);
	len += der_encode_val(sig->sig.s, der + len);

	/* Fix up total length */
	der[1] = len - 2;

	/* Append sighash type */
	der[len++] = sig->stype;

	assert(IsValidSignatureEncoding(der, len));
	add_push_bytes(scriptp, der, len);
}

/* FIXME: permute? */
/* Is a < b? (If equal we don't care) */
static bool key_less(const struct pubkey *a, const struct pubkey *b)
{
	/* Shorter one wins. */
	if (pubkey_len(a) != pubkey_len(b))
		return pubkey_len(a) < pubkey_len(b);

	return memcmp(a->key, b->key, pubkey_len(a)) < 0;
}
	
/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_2of2(const tal_t *ctx,
			const struct pubkey *key1,
			const struct pubkey *key2)
{
	u8 *script = tal_arr(ctx, u8, 0);
	add_number(&script, 2);
	if (key_less(key1, key2)) {
		add_push_key(&script, key1);
		add_push_key(&script, key2);
	} else {
		add_push_key(&script, key2);
		add_push_key(&script, key1);
	}
	add_number(&script, 2);
	add_op(&script, OP_CHECKMULTISIG);
	return script;
}

/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_single(const tal_t *ctx, const struct pubkey *key)
{
	u8 *script = tal_arr(ctx, u8, 0);
	add_push_key(&script, key);
	add_op(&script, OP_CHECKSIG);
	return script;
}

/* Create p2sh for this redeem script. */
u8 *scriptpubkey_p2sh(const tal_t *ctx, const u8 *redeemscript)
{
	struct sha256 h;
	u8 redeemhash[RIPEMD160_DIGEST_LENGTH];
	u8 *script = tal_arr(ctx, u8, 0);

	add_op(&script, OP_HASH160);
	sha256(&h, redeemscript, tal_count(redeemscript));
	RIPEMD160(h.u.u8, sizeof(h), redeemhash);
	add_push_bytes(&script, redeemhash, sizeof(redeemhash));
	add_op(&script, OP_EQUAL);
	return script;
}

u8 *scriptsig_pay_to_pubkeyhash(const tal_t *ctx,
				const struct pubkey *key,
				const struct bitcoin_signature *sig)
{
	u8 *script = tal_arr(ctx, u8, 0);

	add_push_sig(&script, sig);
	add_push_key(&script, key);

	return script;
}

/* Assumes redeemscript contains CHECKSIG, not CHECKMULTISIG */
u8 *scriptsig_p2sh_single_sig(const tal_t *ctx,
			      const u8 *redeem_script,
			      size_t redeem_len,
			      const struct bitcoin_signature *sig)
{
	u8 *script = tal_arr(ctx, u8, 0);

	add_push_sig(&script, sig);
	add_push_bytes(&script, redeem_script, redeem_len);
	return script;
}
	
u8 *scriptsig_p2sh_2of2(const tal_t *ctx,
			const struct bitcoin_signature *sig1,
			const struct bitcoin_signature *sig2,
			const struct pubkey *key1,
			const struct pubkey *key2)
{
	u8 *script = tal_arr(ctx, u8, 0);
	u8 *redeemscript;

	/* OP_CHECKMULTISIG has an out-by-one bug, which MBZ */
	add_number(&script, 0);
	/* sig order should match key order. */
	if (key_less(key1, key2)) {
		add_push_sig(&script, sig1);
		add_push_sig(&script, sig2);
	} else {
		add_push_sig(&script, sig2);
		add_push_sig(&script, sig1);
	}
	redeemscript = bitcoin_redeem_2of2(script, key1, key2);
	add_push_bytes(&script, redeemscript, tal_count(redeemscript));
	return script;
}

/* Is this a normal pay to pubkey hash? */
bool is_pay_to_pubkey_hash(const u8 *script, size_t script_len)
{
	if (script_len != 25)
		return false;
	if (script[0] != OP_DUP)
		return false;
	if (script[1] != OP_HASH160)
		return false;
	if (script[2] != OP_PUSHBYTES(20))
		return false;
	if (script[23] != OP_EQUALVERIFY)
		return false;
	if (script[24] != OP_CHECKSIG)
		return false;
	return true;
}

bool is_p2sh(const u8 *script, size_t script_len)
{
	if (script_len != 23)
		return false;
	if (script[0] != OP_HASH160)
		return false;
	if (script[1] != OP_PUSHBYTES(20))
		return false;
	if (script[22] != OP_EQUAL)
		return false;
	return true;
}
		
/* One of:
 * mysig and relative locktime passed, OR
 * theirsig and hash preimage. */
u8 *bitcoin_redeem_revocable(const tal_t *ctx,
			     const struct pubkey *mykey,
			     u32 locktime,
			     const struct pubkey *theirkey,
			     const struct sha256 *rhash)
{
	u8 *script = tal_arr(ctx, u8, 0);
	u8 rhash_ripemd[RIPEMD160_DIGEST_LENGTH];
	le32 locktime_le = cpu_to_le32(locktime);

	/* If there are two args: */
	add_op(&script, OP_DEPTH);
	add_op(&script, OP_1SUB);
	add_op(&script, OP_IF);

	/* Must hash to revocation_hash, and be signed by them. */
	RIPEMD160(rhash->u.u8, sizeof(rhash->u), rhash_ripemd);
	add_op(&script, OP_HASH160);
	add_push_bytes(&script, rhash_ripemd, sizeof(rhash_ripemd));
	add_op(&script, OP_EQUALVERIFY);
	add_push_key(&script, theirkey);
	add_op(&script, OP_CHECKSIG);

	/* Not two args?  Must be us using timeout. */
	add_op(&script, OP_ELSE);

	add_push_bytes(&script, &locktime_le, sizeof(locktime_le));
	add_op(&script, OP_CHECKSEQUENCEVERIFY);
	add_op(&script, OP_DROP);
	add_push_key(&script, mykey);
	add_op(&script, OP_CHECKSIG);
	add_op(&script, OP_ENDIF);

	return script;
}

u8 *scriptsig_p2sh_revoke(const tal_t *ctx,
			  const struct sha256 *preimage,
			  const struct bitcoin_signature *sig,
			  const u8 *revocable_redeem,
			  size_t redeem_len)
{
	u8 *script = tal_arr(ctx, u8, 0);

	add_push_sig(&script, sig);
	add_push_bytes(&script, preimage, sizeof(*preimage));
	add_push_bytes(&script, revocable_redeem, redeem_len);

	return script;
}
