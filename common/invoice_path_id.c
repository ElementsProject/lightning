#include "config.h"
#include <bitcoin/privkey.h>
#include <ccan/crypto/sha256/sha256.h>
#include <common/invoice_path_id.h>

u8 *invoice_path_id(const tal_t *ctx,
		    const struct secret *base_secret,
		    const struct sha256 *payment_hash)
{
	struct sha256_ctx shactx;
	struct sha256 secret;

	sha256_init(&shactx);
	sha256_update(&shactx, base_secret, sizeof(*base_secret));
	sha256_update(&shactx, payment_hash, sizeof(*payment_hash));
	sha256_done(&shactx, &secret);

	return (u8 *)tal_dup(ctx, struct sha256, &secret);
}
