#include <bitcoin/block.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/mem/mem.h>
#include <common/pseudorand.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <gossipd/broadcast.h>
#include <wire/gen_peer_wire.h>

struct queued_message {
	/* Broadcast index. */
	u64 index;

	/* Timestamp, for filtering. */
	u32 timestamp;

	/* Serialized payload */
	const u8 *payload;
};

struct broadcast_state *new_broadcast_state(tal_t *ctx)
{
	struct broadcast_state *bstate = tal(ctx, struct broadcast_state);
	uintmap_init(&bstate->broadcasts);
	/* Skip 0 because we initialize peers with 0 */
	bstate->next_index = 1;
	bstate->count = 0;
	return bstate;
}

void broadcast_del(struct broadcast_state *bstate, u64 index, const u8 *payload)
{
	const struct queued_message *q = uintmap_del(&bstate->broadcasts, index);
	if (q != NULL) {
		assert(q->payload == payload);
		broadcast_state_check(bstate, "broadcast_del");
	}
}

static void destroy_queued_message(struct queued_message *msg,
				   struct broadcast_state *bstate)
{
	broadcast_del(bstate, msg->index, msg->payload);
	bstate->count--;
}

static struct queued_message *new_queued_message(const tal_t *ctx,
						 struct broadcast_state *bstate,
						 const u8 *payload,
						 u32 timestamp,
						 u64 index)
{
	struct queued_message *msg = tal(ctx, struct queued_message);
	assert(payload);
	msg->payload = payload;
	msg->index = index;
	msg->timestamp = timestamp;
	uintmap_add(&bstate->broadcasts, index, msg);
	tal_add_destructor2(msg, destroy_queued_message, bstate);
	bstate->count++;
	return msg;
}

u64 insert_broadcast(struct broadcast_state *bstate,
		      const u8 *payload, u32 timestamp)
{
	/* Free payload, free index. */
	new_queued_message(payload, bstate, payload, timestamp,
			   bstate->next_index);
	broadcast_state_check(bstate, "insert_broadcast");
	return bstate->next_index++;
}

const u8 *next_broadcast(struct broadcast_state *bstate,
			 u32 timestamp_min, u32 timestamp_max,
			 u64 *last_index)
{
	struct queued_message *m;

	while ((m = uintmap_after(&bstate->broadcasts, last_index)) != NULL) {
		if (m->timestamp >= timestamp_min
		    && m->timestamp <= timestamp_max)
			return m->payload;
	}
	return NULL;
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
	u64 index = 0, htlc_minimum_msat;
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
