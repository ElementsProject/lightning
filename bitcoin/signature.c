#include "config.h"
#include <assert.h>
#include <bitcoin/privkey.h>
#include <bitcoin/psbt.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/shadouble.h>
#include <bitcoin/signature.h>
#include <bitcoin/tx.h>
#include <ccan/mem/mem.h>
#include <common/type_to_string.h>
#include <wire/wire.h>

#undef DEBUG
#ifdef DEBUG
# include <ccan/err/err.h>
# include <stdio.h>
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
		    const u8 *script,
		    const struct pubkey *key,
		    const struct sha256_double *h)
{
	size_t i, j;
	warnx("%s tx version %u locktime %#x:",
	      msg, tx->wtx->version, tx->wtx->locktime);
	for (i = 0; i < tx->wtx->num_inputs; i++) {
		warnx("input[%zu].txid = "SHA_FMT, i,
		      SHA_VALS(tx->wtx->inputs[i].txhash));
		warnx("input[%zu].index = %u", i, tx->wtx->inputs[i].index);
	}
	for (i = 0; i < tx->wtx->num_outputs; i++) {
		warnx("output[%zu].amount = %llu",
		      i, (long long)tx->wtx->outputs[i].satoshi);
		warnx("output[%zu].script = %zu",
		      i, tx->wtx->outputs[i].script_len);
		for (j = 0; j < tx->wtx->outputs[i].script_len; j++)
			fprintf(stderr, "%02x", tx->wtx->outputs[i].script[j]);
		fprintf(stderr, "\n");
	}
	warnx("input[%zu].script = %zu", inputnum, tal_count(script));
	for (i = 0; i < tal_count(script); i++)
		fprintf(stderr, "%02x", script[i]);
	if (key) {
		fprintf(stderr, "\nPubkey: ");
		for (i = 0; i < sizeof(key->pubkey); i++)
			fprintf(stderr, "%02x", ((u8 *)&key->pubkey)[i]);
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
static void dump_tx(const char *msg UNUSED,
		    const struct bitcoin_tx *tx UNUSED, size_t inputnum UNUSED,
		    const u8 *script UNUSED,
		    const struct pubkey *key UNUSED,
		    const struct sha256_double *h UNUSED)
{
}
#endif

/* Taken from https://github.com/bitcoin/bitcoin/blob/master/src/key.cpp */
/* Check that the sig has a low R value and will be less than 71 bytes */
static bool sig_has_low_r(const secp256k1_ecdsa_signature* sig)
{
	unsigned char compact_sig[64];
	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, compact_sig, sig);

	/* In DER serialization, all values are interpreted as big-endian, signed
	 * integers. The highest bit in the integer indicates its signed-ness; 0 is
	 * positive, 1 is negative. When the value is interpreted as a negative
	 * integer, it must be converted to a positive value by prepending a 0x00
	 * byte so that the highest bit is 0. We can avoid this prepending by
	 * ensuring that our highest bit is always 0, and thus we must check that
	 * the first byte is less than 0x80. */
	return compact_sig[0] < 0x80;
}

#if DEVELOPER
/* Some of the spec test vectors assume no sig grinding. */
extern bool dev_no_grind;

bool dev_no_grind = false;
#endif

void sign_hash(const struct privkey *privkey,
	       const struct sha256_double *h,
	       secp256k1_ecdsa_signature *s)
{
	bool ok;
	unsigned char extra_entropy[32] = {0};

	/* Grind for low R */
	do {
		ok = secp256k1_ecdsa_sign(secp256k1_ctx,
					  s,
					  h->sha.u.u8,
					  privkey->secret.data, NULL,
					  IFDEV(dev_no_grind ? NULL
						: extra_entropy,
						extra_entropy));
		((u32 *)extra_entropy)[0]++;
		if (IFDEV(dev_no_grind, false))
			break;
	} while (!sig_has_low_r(s));

	assert(ok);
}

void bitcoin_tx_hash_for_sig(const struct bitcoin_tx *tx, unsigned int in,
			     const u8 *script,
			     enum sighash_type sighash_type,
			     struct sha256_double *dest)
{
	int ret;
	u8 value[9];
	u64 input_val_sats;
	struct amount_sat input_amt;
	int flags = WALLY_TX_FLAG_USE_WITNESS;

	input_amt = psbt_input_get_amount(tx->psbt, in);
	input_val_sats = input_amt.satoshis; /* Raw: type conversion */

	/* Wally can allocate here, iff tx doesn't fit on stack */
	tal_wally_start();
	if (is_elements(chainparams)) {
		ret = wally_tx_confidential_value_from_satoshi(input_val_sats, value, sizeof(value));
		assert(ret == WALLY_OK);
		ret = wally_tx_get_elements_signature_hash(
		    tx->wtx, in, script, tal_bytelen(script), value,
		    sizeof(value), sighash_type, flags, dest->sha.u.u8,
		    sizeof(*dest));
		assert(ret == WALLY_OK);
	} else {
		ret = wally_tx_get_btc_signature_hash(
		    tx->wtx, in, script, tal_bytelen(script), input_val_sats,
		    sighash_type, flags, dest->sha.u.u8, sizeof(*dest));
		assert(ret == WALLY_OK);
	}
	tal_wally_end(tx->wtx);
}

void sign_tx_input(const struct bitcoin_tx *tx,
		   unsigned int in,
		   const u8 *subscript,
		   const u8 *witness_script,
		   const struct privkey *privkey, const struct pubkey *key,
		   enum sighash_type sighash_type,
		   struct bitcoin_signature *sig)
{
	struct sha256_double hash;
	bool use_segwit = witness_script != NULL;
	const u8 *script = use_segwit ? witness_script : subscript;

	assert(sighash_type_valid(sighash_type));

	sig->sighash_type = sighash_type;
	bitcoin_tx_hash_for_sig(tx, in, script, sighash_type, &hash);

	dump_tx("Signing", tx, in, subscript, key, &hash);
	sign_hash(privkey, &hash, &sig->s);
}

bool check_signed_hash(const struct sha256_double *hash,
		       const secp256k1_ecdsa_signature *signature,
		       const struct pubkey *key)
{
	int ret;

	/* BOLT #2:
	 *
	 * - if `signature` is incorrect OR non-compliant with
	 *   LOW-S-standard rule
	 */
	/* From the secp256k1_ecdsa_verify documentation: "To avoid
	 * accepting malleable signatures, only ECDSA signatures in
	 * lower-S form are accepted." */
	ret = secp256k1_ecdsa_verify(secp256k1_ctx,
				     signature,
				     hash->sha.u.u8, &key->pubkey);
	return ret == 1;
}

bool check_tx_sig(const struct bitcoin_tx *tx, size_t input_num,
		  const u8 *redeemscript,
		  const u8 *witness_script,
		  const struct pubkey *key,
		  const struct bitcoin_signature *sig)
{
	struct sha256_double hash;
	bool use_segwit = witness_script != NULL;
	const u8 *script = use_segwit ? witness_script : redeemscript;
	bool ret;

	/* We only support a limited subset of sighash types. */
	if (sig->sighash_type != SIGHASH_ALL) {
		if (!witness_script)
			return false;
		if (sig->sighash_type != (SIGHASH_SINGLE|SIGHASH_ANYONECANPAY))
			return false;
	}
	assert(input_num < tx->wtx->num_inputs);

	bitcoin_tx_hash_for_sig(tx, input_num, script, sig->sighash_type, &hash);
	dump_tx("check_tx_sig", tx, input_num, script, key, &hash);

	ret = check_signed_hash(&hash, &sig->s, key);
	if (!ret)
		dump_tx("Sig failed", tx, input_num, redeemscript, key, &hash);
	return ret;
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
    if ((size_t)lenR + (size_t)lenS + 7 != len) return false;

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

size_t signature_to_der(u8 der[73], const struct bitcoin_signature *sig)
{
	size_t len = 72;

	secp256k1_ecdsa_signature_serialize_der(secp256k1_ctx,
						der, &len, &sig->s);

	/* Append sighash type */
	der[len++] = sig->sighash_type;

	/* IsValidSignatureEncoding() expect extra byte for sighash */
	assert(IsValidSignatureEncoding(memcheck(der, len), len));
	return len;
}

bool signature_from_der(const u8 *der, size_t len, struct bitcoin_signature *sig)
{
	if (len < 1)
		return false;
	if (!secp256k1_ecdsa_signature_parse_der(secp256k1_ctx,
						 &sig->s, der, len-1))
		return false;
	sig->sighash_type = der[len-1];

	if (!sighash_type_valid(sig->sighash_type))
		return false;

	return true;
}

char *fmt_signature(const tal_t *ctx, const secp256k1_ecdsa_signature *sig)
{
	u8 der[72];
	size_t len = 72;

	secp256k1_ecdsa_signature_serialize_der(secp256k1_ctx,
						der, &len, sig);

	return tal_hexstr(ctx, der, len);
}
REGISTER_TYPE_TO_STRING(secp256k1_ecdsa_signature, fmt_signature);

static char *bitcoin_signature_to_hexstr(const tal_t *ctx,
					 const struct bitcoin_signature *sig)
{
	u8 der[73];
	size_t len = signature_to_der(der, sig);

	return tal_hexstr(ctx, der, len);
}
REGISTER_TYPE_TO_STRING(bitcoin_signature, bitcoin_signature_to_hexstr);

void fromwire_bitcoin_signature(const u8 **cursor, size_t *max,
				struct bitcoin_signature *sig)
{
	fromwire_secp256k1_ecdsa_signature(cursor, max, &sig->s);
	sig->sighash_type = fromwire_u8(cursor, max);
	if (!sighash_type_valid(sig->sighash_type))
		fromwire_fail(cursor, max);
}

void towire_bitcoin_signature(u8 **pptr, const struct bitcoin_signature *sig)
{
	assert(sighash_type_valid(sig->sighash_type));
	towire_secp256k1_ecdsa_signature(pptr, &sig->s);
	towire_u8(pptr, sig->sighash_type);
}

void towire_bip340sig(u8 **pptr, const struct bip340sig *bip340sig)
{
	towire_u8_array(pptr, bip340sig->u8, sizeof(bip340sig->u8));
}

void fromwire_bip340sig(const u8 **cursor, size_t *max,
			struct bip340sig *bip340sig)
{
	fromwire_u8_array(cursor, max, bip340sig->u8, sizeof(bip340sig->u8));
}

char *fmt_bip340sig(const tal_t *ctx, const struct bip340sig *bip340sig)
{
	return tal_hexstr(ctx, bip340sig->u8, sizeof(bip340sig->u8));
}

REGISTER_TYPE_TO_HEXSTR(bip340sig);

/* BIP-340:
 *
 * This proposal suggests to include the tag by prefixing the hashed
 * data with ''SHA256(tag) || SHA256(tag)''. Because this is a 64-byte
 * long context-specific constant and the ''SHA256'' block size is
 * also 64 bytes, optimized implementations are possible (identical to
 * SHA256 itself, but with a modified initial state). Using SHA256 of
 * the tag name itself is reasonably simple and efficient for
 * implementations that don't choose to use the optimization.
 */

/* For caller convenience, we hand in tag in parts (any can be "") */
void bip340_sighash_init(struct sha256_ctx *sctx,
			 const char *tag1,
			 const char *tag2,
			 const char *tag3)
{
	struct sha256 taghash;

	sha256_init(sctx);
	sha256_update(sctx, memcheck(tag1, strlen(tag1)), strlen(tag1));
	sha256_update(sctx, memcheck(tag2, strlen(tag2)), strlen(tag2));
	sha256_update(sctx, memcheck(tag3, strlen(tag3)), strlen(tag3));
	sha256_done(sctx, &taghash);

	sha256_init(sctx);
	sha256_update(sctx, &taghash, sizeof(taghash));
	sha256_update(sctx, &taghash, sizeof(taghash));
}

