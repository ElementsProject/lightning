#ifndef LIGHTNING_COMMON_UTILS_H
#define LIGHTNING_COMMON_UTILS_H
#include "config.h"
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>
#include <secp256k1.h>

extern secp256k1_context *secp256k1_ctx;

/* Allocate and fill in a hex-encoded string of this data. */
char *tal_hexstr(const tal_t *ctx, const void *data, size_t len);

/* Allocate and fill a hex-encoding of this tal pointer. */
char *tal_hex(const tal_t *ctx, const tal_t *data);

/* Allocate and fill a buffer with the data of this hex string. */
u8 *tal_hexdata(const tal_t *ctx, const void *str, size_t len);

/* Use the POSIX C locale. */
void setup_locale(void);

/* Global temporary convenience context: children freed in io loop core. */
extern const tal_t *tmpctx;

/* Initial creation of tmpctx. */
void setup_tmpctx(void);

/* Free any children of tmpctx. */
void clean_tmpctx(void);

/* Define sha256_eq. */
STRUCTEQ_DEF(sha256, 0, u);

/* Define ripemd160_eq. */
STRUCTEQ_DEF(ripemd160, 0, u);

#endif /* LIGHTNING_COMMON_UTILS_H */
