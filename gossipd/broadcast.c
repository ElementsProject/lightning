#include <bitcoin/block.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/mem/mem.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <errno.h>
#include <gossipd/broadcast.h>
#include <gossipd/gossip_store.h>
#include <wire/gen_peer_wire.h>

static void destroy_broadcast_state(struct broadcast_state *bstate)
{
	uintmap_clear(&bstate->broadcasts);
}

struct broadcast_state *new_broadcast_state(struct routing_state *rstate,
					    struct gossip_store *gs,
					    struct list_head *peers)
{
	struct broadcast_state *bstate = tal(rstate, struct broadcast_state);
	uintmap_init(&bstate->broadcasts);
	bstate->count = 0;
	bstate->gs = gs;
	bstate->peers = peers;
	tal_add_destructor(bstate, destroy_broadcast_state);
	return bstate;
}

void broadcast_del(struct broadcast_state *bstate,
		   struct broadcastable *bcast)
{
	const struct broadcastable *b
		= uintmap_del(&bstate->broadcasts, bcast->index);
	if (b != NULL) {
		assert(b == bcast);
		bstate->count--;
		broadcast_state_check(bstate, "broadcast_del");
		bcast->index = 0;
	}
}

static void add_broadcast(struct broadcast_state *bstate,
			  struct broadcastable *bcast)
{
	assert(bcast);
	assert(bcast->index);
	if (!uintmap_add(&bstate->broadcasts, bcast->index, bcast))
		abort();
	bstate->count++;
}

void insert_broadcast_nostore(struct broadcast_state *bstate,
			      struct broadcastable *bcast)
{
	add_broadcast(bstate, bcast);
	broadcast_state_check(bstate, "insert_broadcast");
}

void insert_broadcast(struct broadcast_state **bstate,
		      const u8 *msg,
		      struct broadcastable *bcast)
{
	u32 offset;

	/* If we're loading from the store, we already have index */
	if (!bcast->index) {
		u64 idx;

		bcast->index = idx = gossip_store_add((*bstate)->gs, msg);
		if (!idx)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not add to gossip store: %s",
				      strerror(errno));
		/* We assume we can fit in 32 bits for now! */
		assert(idx == bcast->index);
	}

	insert_broadcast_nostore(*bstate, bcast);

	/* If it compacts, it replaces *bstate */
	gossip_store_maybe_compact((*bstate)->gs, bstate, &offset);
	if (offset)
		update_peers_broadcast_index((*bstate)->peers, offset);
}

struct broadcastable *next_broadcast_raw(struct broadcast_state *bstate,
					 u32 *last_index)
{
	struct broadcastable *b;
	u64 idx = *last_index;

	b = uintmap_after(&bstate->broadcasts, &idx);
	if (!b)
		return NULL;
	/* Assert no overflow */
	*last_index = idx;
	assert(*last_index == idx);
	return b;
}

const u8 *next_broadcast(const tal_t *ctx,
			 struct broadcast_state *bstate,
			 u32 timestamp_min, u32 timestamp_max,
			 u32 *last_index)
{
	struct broadcastable *b;

	while ((b = next_broadcast_raw(bstate, last_index)) != NULL) {
		if (b->timestamp >= timestamp_min
		    && b->timestamp <= timestamp_max) {
			return gossip_store_get(ctx, bstate->gs, b->index);
		}
	}
	return NULL;
}

u64 broadcast_final_index(const struct broadcast_state *bstate)
{
	u64 idx;

	if (!uintmap_last(&bstate->broadcasts, &idx))
		return 0;
	return idx;
}

#ifdef PEDANTIC
static const struct pubkey *
pubkey_keyof(const struct pubkey *pk)
{
	return pk;
}

static size_t pubkey_hash(const struct pubkey *id)
{
	return siphash24(siphash_seed(), id, sizeof(*id));
}

HTABLE_DEFINE_TYPE(struct pubkey,
		   pubkey_keyof,
		   pubkey_hash,
		   pubkey_eq,
		   pubkey_set);

static void *corrupt(const char *abortstr, const char *problem,
		     const struct short_channel_id *scid,
		     const struct pubkey *node_id)
{
	status_broken("Gossip corrupt %s %s: %s",
		      problem, abortstr ? abortstr : "",
		      scid ? type_to_string(tmpctx,
					    struct short_channel_id,
					    scid)
		      : type_to_string(tmpctx, struct pubkey, node_id));
	if (abortstr)
		abort();
	return NULL;
}

struct broadcast_state *broadcast_state_check(struct broadcast_state *b,
					      const char *abortstr)
{
	secp256k1_ecdsa_signature sig;
	const u8 *msg;
	u8 *features, *addresses, color[3], alias[32];
	struct bitcoin_blkid chain_hash;
	struct short_channel_id scid;
	struct pubkey node_id_1,  node_id_2, bitcoin_key;
	u32 timestamp, fees;
	u16 flags, expiry;
	u32 index = 0;
	u64 htlc_minimum_msat;
	struct pubkey_set pubkeys;
	/* We actually only need a set, not a map. */
	UINTMAP(u64 *) channels;

	pubkey_set_init(&pubkeys);
	uintmap_init(&channels);

	while ((msg = next_broadcast(b, 0, UINT32_MAX, &index)) != NULL) {
		if (fromwire_channel_announcement(tmpctx, msg, &sig, &sig, &sig,
						  &sig, &features, &chain_hash,
						  &scid, &node_id_1, &node_id_2,
						  &bitcoin_key, &bitcoin_key)) {
			if (!uintmap_add(&channels, scid.u64, &index))
				return corrupt(abortstr, "announced twice",
					       &scid, NULL);
			pubkey_set_add(&pubkeys, &node_id_1);
			pubkey_set_add(&pubkeys, &node_id_2);
		} else if (fromwire_channel_update(msg, &sig, &chain_hash,
						   &scid, &timestamp, &flags,
						   &expiry, &htlc_minimum_msat,
						   &fees, &fees)) {
			if (!uintmap_get(&channels, scid.u64))
				return corrupt(abortstr,
					       "updated before announce",
					       &scid, NULL);
		} else if (fromwire_node_announcement(tmpctx, msg,
						      &sig, &features,
						      &timestamp,
						      &node_id_1, color, alias,
						      &addresses))
			if (!uintmap_get(&channels, scid.u64))
				return corrupt(abortstr,
					       "node announced before channel",
					       NULL, &node_id_1);
	}

	pubkey_set_clear(&pubkeys);
	uintmap_clear(&channels);
	return b;
}
#else
struct broadcast_state *broadcast_state_check(struct broadcast_state *b,
					      const char *abortstr UNUSED)
{
	return b;
}
#endif
