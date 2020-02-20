#ifndef LIGHTNING_LIGHTNINGD_DIRECTED_MESSAGE_H
#define LIGHTNING_LIGHTNINGD_DIRECTED_MESSAGE_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <common/pseudorand.h>
#include <common/utils.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>

struct channel;

struct directed_msg {
	struct peer *source;
	struct sha256 hash_in, hash_out;
	struct secret shared_secret;
};

static const struct sha256 *directed_key(const struct directed_msg *di)
{
	return &di->hash_out;
}

static bool directed_msg_eq(const struct directed_msg *di,
			     const struct sha256 *hash)
{
	return sha256_eq(&di->hash_out, hash);
}

static size_t hash_sha256(const struct sha256 *hash)
{
	return siphash24(siphash_seed(), hash, sizeof(*hash));
}

HTABLE_DEFINE_TYPE(struct directed_msg,
		   directed_key, hash_sha256, directed_msg_eq,
		   directed_msg_htable);

void handle_directed_to_us(struct channel *channel, const u8 *msg);
void handle_directed_forward(struct channel *channel, const u8 *msg);
void handle_directed_reply(struct channel *channel, const u8 *msg);

#endif /* LIGHTNING_LIGHTNINGD_DIRECTED_MESSAGE_H */
