#ifndef LIGHTNING_UTILS_H
#define LIGHTNING_UTILS_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <secp256k1.h>

extern secp256k1_context *secp256k1_ctx;

/* Allocate and fill in a hex-encoded string of this data. */
char *tal_hexstr(const tal_t *ctx, const void *data, size_t len);

/* Allocate and fill a hex-encoding of this tal pointer. */
char *tal_hex(const tal_t *ctx, const tal_t *data);

/* Allocate and fill a buffer with the data of this hex string. */
u8 *tal_hexdata(const tal_t *ctx, const void *str, size_t len);

#define tal_tmpctx(ctx)							\
	tal_alloc_((ctx), 0, false, false,				\
		   __FILE__ ":" stringify(__LINE__) ":tal_tmpctx")

#endif /* LIGHTNING_UTILS_H */
