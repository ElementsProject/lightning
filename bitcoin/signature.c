#include <ccan/cast/cast.h>
#include "privkey.h"
#include "pubkey.h"
#include "script.h"
#include "secp256k1.h"
#include "shadouble.h"
#include "signature.h"
#include "tx.h"
#include <assert.h>
#ifdef USE_SCHNORR
#include "secp256k1_schnorr.h"
#endif

#undef DEBUG
#ifdef DEBUG
#include <ccan/err/err.h>
#include <stdio.h>
#define SHA_FMT					   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"	   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"	   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"	   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"

#define SHA_VALS(e)							\
	e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7],			\
		e[8], e[9], e[10], e[11], e[12], e[13], e[14], e[15],	\
		e[16], e[17], e[18], e[19], e[20], e[21], e[22], e[23], \
		e[24], e[25], e[25], e[26], e[28], e[29], e[30], e[31]

static void dump_tx(const char *msg,
		    const struct bitcoin_tx *tx, size_t inputnum,
		    const u8 *script, size_t script_len,
		    const struct pubkey *key,
		    const struct sha256_double *h)
{
	size_t i, j;
	warnx("%s tx version %u locktime %#x:",
	      msg, tx->version, tx->lock_time);
	for (i = 0; i < tx->input_count; i++) {
		warnx("input[%zu].txid = "SHA_FMT, i,
		      SHA_VALS(tx->input[i].txid.sha.u.u8));
		warnx("input[%zu].index = %u", i, tx->input[i].index);
	}
	for (i = 0; i < tx->output_count; i++) {
		warnx("output[%zu].amount = %llu",
		      i, (long long)tx->output[i].amount);
		warnx("output[%zu].script = %llu",
		      i, (long long)tx->output[i].script_length);
		for (j = 0; j < tx->output[i].script_length; j++)
			fprintf(stderr, "%02x", tx->output[i].script[j]);
		fprintf(stderr, "\n");
	}
	warnx("input[%zu].script = %zu", inputnum, script_len);
	for (i = 0; i < script_len; i++)
		fprintf(stderr, "%02x", script[i]);
	if (key) {
		fprintf(stderr, "\nPubkey: ");
		for (i = 0; i < pubkey_len(key); i++)
			fprintf(stderr, "%02x", key->key[i]);
		fprintf(stderr, "\n");
	}
	if (h) {
		fprintf(stderr, "\nHash: ");
		for (i = 0; i < sizeof(h->sha.u.u8); i++)
			fprintf(stderr, "%02x", h->sha.u.u8[i]);
		fprintf(stderr, "\n");
	}
}
#else
static void dump_tx(const char *msg,
		    const struct bitcoin_tx *tx, size_t inputnum,
		    const u8 *script, size_t script_len,
		    const struct pubkey *key,
		    const struct sha256_double *h)
{
}
#endif
	
bool sign_hash(const tal_t *ctx, const struct privkey *privkey,
	       const struct sha256_double *h,
	       struct signature *s)
{
	secp256k1_context *secpctx;
	bool ok;
	
	secpctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	if (!secpctx)
		return false;

#ifdef USE_SCHNORR
	ok = secp256k1_schnorr_sign(secpctx,
				    (unsigned char *)s,
				    h->sha.u.u8,
				    privkey->secret, NULL, NULL);
#else
	ok = secp256k1_ecdsa_sign(secpctx,
				  (secp256k1_ecdsa_signature *)s,
				  h->sha.u.u8,
				  privkey->secret, NULL, NULL);
#endif

	secp256k1_context_destroy(secpctx);
	return ok;
}

/* Only does SIGHASH_ALL */
static void sha256_tx_one_input(struct bitcoin_tx *tx,
				size_t input_num,
				const u8 *script, size_t script_len,
				struct sha256_double *hash)
{
	struct sha256_ctx ctx = SHA256_INIT;
	size_t i;

	assert(input_num < tx->input_count);

	/* You must have all inputs zeroed to start. */
	for (i = 0; i < tx->input_count; i++)
		assert(tx->input[i].script_length == 0);

	tx->input[input_num].script_length = script_len;
	tx->input[input_num].script = cast_const(u8 *, script);

	sha256_init(&ctx);
	sha256_tx_for_sig(&ctx, tx, input_num);
	sha256_le32(&ctx, SIGHASH_ALL);

	sha256_double_done(&ctx, hash);

	/* Reset it for next time. */
	tx->input[input_num].script_length = 0;
	tx->input[input_num].script = NULL;
}

/* Only does SIGHASH_ALL */
bool sign_tx_input(const tal_t *ctx, struct bitcoin_tx *tx,
		   unsigned int in,
		   const u8 *subscript, size_t subscript_len,
		   const struct privkey *privkey, const struct pubkey *key,
		   struct signature *sig)
{
	struct sha256_double hash;

	sha256_tx_one_input(tx, in, subscript, subscript_len, &hash);
	dump_tx("Signing", tx, in, subscript, subscript_len, key, &hash);
	return sign_hash(ctx, privkey, &hash, sig);
}

static bool check_signed_hash(const struct sha256_double *hash,
			      const struct signature *signature,
			      const struct pubkey *key)
{
	int ret;
	secp256k1_context *secpctx;
	/* FIXME: Don't convert here! */
	secp256k1_pubkey pubkey;

	secpctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
	if (!secpctx)
		return false;

	if (!secp256k1_ec_pubkey_parse(secpctx, &pubkey, key->key,
				       pubkey_len(key))) {
		secp256k1_context_destroy(secpctx);
		return false;
	}

#ifdef USE_SCHNORR
	ret = secp256k1_schnorr_verify(secpctx, (unsigned char *)signature,
				       hash->sha.u.u8, &pubkey);
#else
	ret = secp256k1_ecdsa_verify(secpctx,
				     (secp256k1_ecdsa_signature *)signature,
				     hash->sha.u.u8, &pubkey);
#endif

	secp256k1_context_destroy(secpctx);
	return ret == 1;
}

bool check_tx_sig(struct bitcoin_tx *tx, size_t input_num,
		  const u8 *redeemscript, size_t redeemscript_len,
		  const struct pubkey *key,
		  const struct bitcoin_signature *sig)
{
	struct sha256_double hash;
	bool ret;

	assert(input_num < tx->input_count);

	sha256_tx_one_input(tx, input_num, redeemscript, redeemscript_len,
			    &hash);

	/* We only use SIGHASH_ALL for the moment. */
	if (sig->stype != SIGHASH_ALL)
		return false;
	
	ret = check_signed_hash(&hash, &sig->sig, key);
	if (!ret)
		dump_tx("Sig failed", tx, input_num,
			redeemscript, redeemscript_len, key, &hash);
	return ret;
}

bool check_2of2_sig(struct bitcoin_tx *tx, size_t input_num,
		    const u8 *redeemscript, size_t redeemscript_len,
		    const struct pubkey *key1, const struct pubkey *key2,
		    const struct bitcoin_signature *sig1,
		    const struct bitcoin_signature *sig2)
{
	struct sha256_double hash;
	assert(input_num < tx->input_count);

	sha256_tx_one_input(tx, input_num, redeemscript, redeemscript_len,
			    &hash);

	/* We only use SIGHASH_ALL for the moment. */
	if (sig1->stype != SIGHASH_ALL || sig2->stype != SIGHASH_ALL)
		return false;
	
	return check_signed_hash(&hash, &sig1->sig, key1)
		&& check_signed_hash(&hash, &sig2->sig, key2);
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
	
size_t signature_to_der(u8 der[72], const struct signature *sig)
{
	size_t len = 0;

	der[len++] = 0x30; /* Type */
	der[len++] = 0; /* Total length after this: fill it at end. */

	len += der_encode_val(sig->r, der + len);
	len += der_encode_val(sig->s, der + len);

	/* Fix up total length */
	der[1] = len - 2;

	/* IsValidSignatureEncoding() expect extra byte for sighash */
	assert(IsValidSignatureEncoding(der, len + 1));
	return len;
}

/* Signature must have low S value. */
bool sig_valid(const struct signature *sig)
{
#ifdef USE_SCHNORR
	/* FIXME: Is there some sanity check we can do here? */
	return true;
#else
	return (sig->s[0] & 0x80) == 0;
#endif
}
