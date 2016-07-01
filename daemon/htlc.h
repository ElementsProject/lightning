#ifndef LIGHTNING_DAEMON_HTLC_H
#define LIGHTNING_DAEMON_HTLC_H
#include "config.h"
#include "bitcoin/locktime.h"
#include "channel.h"
#include "pseudorand.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/short_types/short_types.h>

struct htlc {
	/* Useful for debugging, and decoding via ->src. */
	struct peer *peer;
	/* Block number where we abort if it's still live (OURS only) */
	u32 deadline;
	/* Did we create it, or did they? */
	enum channel_side side; 
	/* The unique ID for this peer and this direction (ours or theirs) */
	u64 id;
	/* The amount in millisatoshi. */
	u64 msatoshis;
	/* When the HTLC can no longer be redeemed. */
	struct abs_locktime expiry;
	/* The hash of the preimage which can redeem this HTLC */
	struct sha256 rhash;
	/* The preimage which hashes to rhash (if known) */
	struct rval *r;

	/* FIXME: We could union these together: */
	/* Routing information sent with this HTLC. */
	const u8 *routing;
	/* Previous HTLC (if any) which made us offer this (OURS only) */
	struct htlc *src;
};

/* htlc_map: ID -> htlc mapping. */
static inline u64 htlc_key(const struct htlc *h)
{
	return h->id;
}
static inline bool htlc_cmp(const struct htlc *h, u64 id)
{
	return h->id == id;
}
static inline size_t htlc_hash(u64 id)
{
	return siphash24(siphash_seed(), &id, sizeof(id));
}
HTABLE_DEFINE_TYPE(struct htlc, htlc_key, htlc_hash, htlc_cmp, htlc_map);

static inline size_t htlc_map_count(const struct htlc_map *htlcs)
{
	return htlcs->raw.elems;
}
#endif /* LIGHTNING_DAEMON_HTLC_H */
