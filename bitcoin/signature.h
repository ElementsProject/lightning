#ifndef LIGHTNING_BITCOIN_SIGNATURE_H
#define LIGHTNING_BITCOIN_SIGNATURE_H
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <openssl/ecdsa.h>

enum sighash_type {
    SIGHASH_ALL = 1,
    SIGHASH_NONE = 2,
    SIGHASH_SINGLE = 3,
    SIGHASH_ANYONECANPAY = 0x80
};

/* ECDSA of double SHA256. */
struct signature {
	u8 r[32];
	u8 s[32];
};

struct sha256_double;
struct bitcoin_tx;
struct pubkey;
struct bitcoin_tx_output;
struct bitcoin_signature;

bool sign_hash(const tal_t *ctx, EC_KEY *private_key,
	       const struct sha256_double *h,
	       struct signature *s);

/* All tx input scripts must be set to 0 len. */
bool sign_tx_input(const tal_t *ctx, struct bitcoin_tx *tx,
		   unsigned int in,
		   const u8 *subscript, size_t subscript_len,
		   EC_KEY *privkey, const struct pubkey *pubkey,
		   struct signature *sig);

/* Does this sig sign the tx with this input for this pubkey. */
bool check_tx_sig(struct bitcoin_tx *tx, size_t input_num,
		  const u8 *redeemscript, size_t redeemscript_len,
		  const struct pubkey *key,
		  const struct bitcoin_signature *sig);

bool check_2of2_sig(struct bitcoin_tx *tx, size_t input_num,
		    const u8 *redeemscript, size_t redeemscript_len,
		    const struct pubkey *key1, const struct pubkey *key2,
		    const struct bitcoin_signature *sig1,
		    const struct bitcoin_signature *sig2);

/* Give DER encoding of signature: returns length used (<= 72). */
size_t signature_to_der(u8 der[72], const struct signature *s);

#endif /* LIGHTNING_BITCOIN_SIGNATURE_H */
