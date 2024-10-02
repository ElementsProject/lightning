#ifndef LIGHTNING_CHANNELD_CHANNELD_HTLC_H
#define LIGHTNING_CHANNELD_CHANNELD_HTLC_H
#include "config.h"
#include <ccan/crypto/siphash24/siphash24.h>
#include <common/htlc.h>
#include <common/pseudorand.h>
#include <wire/onion_wire.h>

struct htlc {
	/* What's the status. */
	enum htlc_state state;
	/* The unique ID for this peer and this direction (LOCAL or REMOTE) */
	u64 id;
	/* The amount in millisatoshi. */
	struct amount_msat amount;
	/* When the HTLC can no longer be redeemed. */
	struct abs_locktime expiry;
	/* The hash of the preimage which can redeem this HTLC */
	struct sha256 rhash;
	/* The preimage which hashes to rhash (if known) */
	struct preimage *r;

	/* If they fail the HTLC, we store why here. */
	const struct failed_htlc *failed;

	/* Routing information sent with this HTLC (outgoing only). */
	const u8 *routing;

	/* Blinding (optional). */
	struct pubkey *path_key;

	/* Should we immediately fail this htlc? */
	bool fail_immediate;
};

static inline bool htlc_has(const struct htlc *h, int flag)
{
	return htlc_state_flags(h->state) & flag;
}

static inline enum side htlc_owner(const struct htlc *h)
{
	return htlc_state_owner(h->state);
}

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

static inline struct htlc *htlc_get(struct htlc_map *htlcs, u64 id, enum side owner)
{
	struct htlc *h;
	struct htlc_map_iter it;

	for (h = htlc_map_getfirst(htlcs, id, &it);
	     h;
	     h = htlc_map_getnext(htlcs, id, &it)) {
		if (h->id == id && htlc_has(h, HTLC_FLAG(owner,HTLC_F_OWNER)))
			return h;
	}
	return NULL;
}

static inline bool htlc_is_dead(const struct htlc *htlc)
{
	return htlc->state == RCVD_REMOVE_ACK_REVOCATION
		|| htlc->state == SENT_REMOVE_ACK_REVOCATION;
}
#endif /* LIGHTNING_CHANNELD_CHANNELD_HTLC_H */
