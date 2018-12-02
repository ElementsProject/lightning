#ifndef LIGHTNING_BITCOIN_SIGNATURE_H
#define LIGHTNING_BITCOIN_SIGNATURE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <secp256k1.h>
#include <stdbool.h>

struct sha256_double;
struct bitcoin_tx;
struct pubkey;
struct privkey;
struct bitcoin_tx_output;

enum sighash_type {
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80
};

/* We only support a limited range of sighash_type */
static inline bool sighash_type_valid(const enum sighash_type sighash_type)
{
	return sighash_type == SIGHASH_ALL;
}

/**
 * bitcoin_signature - signature with a sighash type.
 *
 * sighash_type is SIGHASH_ALL unless you're being tricky. */
struct bitcoin_signature {
	secp256k1_ecdsa_signature s;
	enum sighash_type sighash_type;
};

/**
 * sign_hash - produce a raw secp256k1 signature.
 * @p: secret key
 * @h: hash to sign.
 * @sig: signature to fill in and return.
 */
void sign_hash(const struct privkey *p,
	       const struct sha256_double *h,
	       secp256k1_ecdsa_signature *sig);

/**
 * check_signed_hash - check a raw secp256k1 signature.
 * @h: hash which was signed.
 * @signature: signature.
 * @key: public key corresponding to private key used to sign.
 *
 * Returns true if the key, hash and signature are correct.  Changing any
 * one of these will make it fail.
 */
bool check_signed_hash(const struct sha256_double *hash,
		       const secp256k1_ecdsa_signature *signature,
		       const struct pubkey *key);

/**
 * sign_tx_input - produce a bitcoin signature for a transaction input
 * @tx: the bitcoin transaction we're signing.
 * @in: the input number to sign.
 * @subscript: NULL (pure segwit) or a tal_arr of the signing subscript
 * @witness: NULL (non-segwit) or the witness script.
 * @privkey: the secret key to use for signing.
 * @pubkey: the public key corresonding to @privkey.
 * @sighash_type: a valid sighash type.
 * @sig: (in) sighash_type indicates what type of signature make in (out) s.
 */
void sign_tx_input(const struct bitcoin_tx *tx,
		   unsigned int in,
		   const u8 *subscript,
		   const u8 *witness,
		   const struct privkey *privkey, const struct pubkey *pubkey,
		   enum sighash_type sighash_type,
		   struct bitcoin_signature *sig);

/**
 * check_tx_sig - produce a bitcoin signature for a transaction input
 * @tx: the bitcoin transaction which has been signed.
 * @in: the input number to which @sig should apply.
 * @subscript: NULL (pure segwit) or a tal_arr of the signing subscript
 * @witness: NULL (non-segwit) or the witness script.
 * @pubkey: the public key corresonding to @privkey used for signing.
 * @sig: the signature to check.
 *
 * Returns true if this signature was created by @privkey and this tx
 * and sighash_type, otherwise false.
 */
bool check_tx_sig(const struct bitcoin_tx *tx, size_t input_num,
		  const u8 *subscript,
		  const u8 *witness,
		  const struct pubkey *key,
		  const struct bitcoin_signature *sig);

/* Give DER encoding of signature: returns length used (<= 73). */
size_t signature_to_der(u8 der[73], const struct bitcoin_signature *sig);

/* Parse DER encoding into signature sig */
bool signature_from_der(const u8 *der, size_t len, struct bitcoin_signature *sig);

#endif /* LIGHTNING_BITCOIN_SIGNATURE_H */
