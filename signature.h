#ifndef LIGHTNING_SIGNATURE_H
#define LIGHTNING_SIGNATURE_H
#include <ccan/short_types/short_types.h>
#include <openssl/ecdsa.h>
#include <ccan/tal/tal.h>

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

struct signature *sign_hash(const tal_t *ctx, EC_KEY *private_key,
			    const struct sha256_double *h);

/* All tx input scripts must be set to 0 len. */
struct signature *sign_tx_input(const tal_t *ctx,
				struct bitcoin_tx *tx, unsigned int in,
				const u8 *subscript, size_t subscript_len,
				EC_KEY *privkey);

#endif /* LIGHTNING_SIGNATURE_H */
