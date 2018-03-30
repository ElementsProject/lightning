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

void sign_hash(const struct privkey *p,
	       const struct sha256_double *h,
	       secp256k1_ecdsa_signature *s);

bool check_signed_hash(const struct sha256_double *hash,
		       const secp256k1_ecdsa_signature *signature,
		       const struct pubkey *key);

/* All tx input scripts must be set to 0 len. */
void sign_tx_input(struct bitcoin_tx *tx,
		   unsigned int in,
		   const u8 *subscript,
		   const u8 *witness,
		   const struct privkey *privkey, const struct pubkey *pubkey,
		   secp256k1_ecdsa_signature *sig);

/* Does this sig sign the tx with this input for this pubkey. */
bool check_tx_sig(struct bitcoin_tx *tx, size_t input_num,
		  const u8 *redeemscript,
		  const u8 *witness,
		  const struct pubkey *key,
		  const secp256k1_ecdsa_signature *sig);

/* Give DER encoding of signature: returns length used (<= 72). */
size_t signature_to_der(u8 der[72], const secp256k1_ecdsa_signature *s);

/* Parse DER encoding into signature sig */
bool signature_from_der(const u8 *der, size_t len, secp256k1_ecdsa_signature *sig);

#endif /* LIGHTNING_BITCOIN_SIGNATURE_H */
