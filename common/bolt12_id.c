#include "config.h"
#include <bitcoin/privkey.h>
#include <ccan/crypto/sha256/sha256.h>
#include <common/bolt12_id.h>
#include <common/utils.h>

/* Given a base secret, an easy one-way function is SHA(base || input) */
static void hash_from_base(const struct secret *base_secret,
			   const void *input,
			   size_t input_len,
			   struct sha256 *hash)
{
	struct sha256_ctx shactx;

	sha256_init(&shactx);
	sha256_update(&shactx, base_secret, sizeof(*base_secret));
	sha256_update(&shactx, input, input_len);
	sha256_done(&shactx, hash);
}

void bolt12_path_secret(const struct secret *base_secret,
			const struct sha256 *payment_hash,
			struct secret *path_secret)
{
	struct sha256 hash;
	hash_from_base(base_secret, payment_hash, sizeof(*payment_hash), &hash);

	CROSS_TYPE_ASSIGNMENT(path_secret, &hash);
}

u8 *bolt12_path_id(const tal_t *ctx,
		   const struct secret *base_secret,
		   const struct sha256 *payment_hash)
{
	struct secret path_secret;
	bolt12_path_secret(base_secret, payment_hash, &path_secret);

	return (u8 *)tal_dup(ctx, struct secret, &path_secret);
}
