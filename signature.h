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

struct sha256_double;

u8 *sign_hash(const tal_t *ctx, EC_KEY *private_key,
	      const struct sha256_double *h);

#endif /* LIGHTNING_SIGNATURE_H */
