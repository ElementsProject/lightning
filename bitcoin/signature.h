#ifndef LIGHTNING_BITCOIN_SIGNATURE_H
#define LIGHTNING_BITCOIN_SIGNATURE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <secp256k1.h>
#include <stdbool.h>

enum sighash_type {
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80
};

/* ECDSA of double SHA256. */
struct signature {
	secp256k1_ecdsa_signature sig;
};

struct sha256_double;
struct bitcoin_tx;
struct pubkey;
struct privkey;
struct bitcoin_tx_output;
struct bitcoin_signature;

void sign_hash(secp256k1_context *secpctx,
	       const struct privkey *p,
	       const struct sha256_double *h,
	       struct signature *s);

bool check_signed_hash(secp256k1_context *secpctx,
		       const struct sha256_double *hash,
		       const struct signature *signature,
		       const struct pubkey *key);

/* All tx input scripts must be set to 0 len. */
void sign_tx_input(secp256k1_context *secpctx,
		   struct bitcoin_tx *tx,
		   unsigned int in,
		   const u8 *subscript, size_t subscript_len,
		   const u8 *witness,
		   const struct privkey *privkey, const struct pubkey *pubkey,
		   struct signature *sig);

/* Does this sig sign the tx with this input for this pubkey. */
bool check_tx_sig(secp256k1_context *secpctx,
		  struct bitcoin_tx *tx, size_t input_num,
		  const u8 *redeemscript, size_t redeemscript_len,
		  const u8 *witness,
		  const struct pubkey *key,
		  const struct bitcoin_signature *sig);

/* Signature must have low S value. */
bool sig_valid(secp256k1_context *secpctx, const struct signature *sig);

/* Give DER encoding of signature: returns length used (<= 72). */
size_t signature_to_der(secp256k1_context *secpctx,
			u8 der[72], const struct signature *s);

/* Parse DER encoding into signature sig */
bool signature_from_der(secp256k1_context *secpctx,
			const u8 *der, size_t len, struct signature *sig);

#endif /* LIGHTNING_BITCOIN_SIGNATURE_H */
