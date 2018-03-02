#ifndef LIGHTNING_LIGHTNINGD_GOSSIP_ROUTING_H
#define LIGHTNING_LIGHTNINGD_GOSSIP_ROUTING_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/time/time.h>
#include <gossipd/broadcast.h>
#include <wire/gen_onion_wire.h>
#include <wire/wire.h>

#define ROUTING_MAX_HOPS 20
#define ROUTING_FLAGS_DISABLED 2

struct node_connection {
	/* FIXME: Remove */
	struct node *src, *dst;
	/* millisatoshi. */
	u32 base_fee;
	/* millionths */
	u32 proportional_fee;

	/* Delay for HTLC in blocks.*/
	u32 delay;

	/* Is this connection active? */
	bool active;

	s64 last_timestamp;

	/* Minimum number of msatoshi in an HTLC */
	u32 htlc_minimum_msat;

	/* The channel ID, as determined by the anchor transaction */
	/* FIXME: Remove */
	struct short_channel_id short_channel_id;

	/* Flags as specified by the `channel_update`s, among other
	 * things indicated direction wrt the `channel_id` */
	u16 flags;

	/* Cached `channel_update` we might forward to new peers*/
	u8 *channel_update;

	/* If greater than current time, this connection should not
	 * be used for routing. */
	time_t unroutable_until;
};

struct node {
	struct pubkey id;

	/* -1 means never; other fields undefined */
	s64 last_timestamp;

	/* IP/Hostname and port of this node (may be NULL) */
	struct wireaddr *addresses;

	/* Channels connecting us to other nodes */
	struct routing_channel **channels;

	/* Temporary data for routefinding. */
	struct {
		/* Total to get to here from target. */
		u64 total;
		/* Total risk premium of this route. */
		u64 risk;
		/* Where that came from. */
		struct node_connection *prev;
	} bfg[ROUTING_MAX_HOPS+1];

	/* UTF-8 encoded alias as tal_arr, not zero terminated */
	u8 *alias;

	/* Color to be used when displaying the name */
	u8 rgb_color[3];

	/* Cached `node_announcement` we might forward to new peers. */
	u8 *node_announcement;

	/* What index does the announcement broadcast have? */
	u64 announcement_idx;
};

const secp256k1_pubkey *node_map_keyof_node(const struct node *n);
size_t node_map_hash_key(const secp256k1_pubkey *key);
bool node_map_node_eq(const struct node *n, const secp256k1_pubkey *key);
HTABLE_DEFINE_TYPE(struct node, node_map_keyof_node, node_map_hash_key, node_map_node_eq, node_map);

struct pending_node_map;
struct pending_cannouncement;

struct routing_channel {
	struct short_channel_id scid;
	u8 *txout_script;

	/*
	 * connections[0]->src == nodes[0] connections[0]->dst == nodes[1]
	 * connections[1]->src == nodes[1] connections[1]->dst == nodes[0]
	 */
	struct node_connection *connections[2];
	/* nodes[0].id < nodes[1].id */
	struct node *nodes[2];

	/* Cached `channel_announcement` we might forward to new peers*/
	const u8 *channel_announcement;

	/* FIXME: Move msg_index[MSG_INDEX_CUPDATE*] into connections[] */
	u64 msg_indexes[3];

	/* Is this a public channel, or was it only added locally? */
	bool public;
};

/* If the two nodes[] are id1 and id2, which index would id1 be? */
static inline int pubkey_idx(const struct pubkey *id1, const struct pubkey *id2)
{
	return pubkey_cmp(id1, id2) > 0;
}

/* FIXME: We could avoid these by having two channels arrays */
static inline struct node_connection *connection_from(const struct node *n,
						      struct routing_channel *chan)
{
	int idx = (chan->nodes[1] == n);

	assert(chan->connections[idx]->src == n);
	assert(chan->connections[!idx]->dst == n);
	return chan->connections[idx];
}

static inline struct node_connection *connection_to(const struct node *n,
						    struct routing_channel *chan)
{
	int idx = (chan->nodes[1] == n);

	assert(chan->connections[idx]->src == n);
	assert(chan->connections[!idx]->dst == n);
	return chan->connections[!idx];
}

struct routing_state {
	/* All known nodes. */
	struct node_map *nodes;

	/* node_announcements which are waiting on pending_cannouncement */
	struct pending_node_map *pending_node_map;

	/* FIXME: Make this a htable! */
	/* channel_announcement which are pending short_channel_id lookup */
	struct list_head pending_cannouncement;

	struct broadcast_state *broadcasts;

	struct bitcoin_blkid chain_hash;

	/* Our own ID so we can identify local channels */
	struct pubkey local_id;

	/* How old does a channel have to be before we prune it? */
	u32 prune_timeout;

        /* A map of channels indexed by short_channel_ids */
	UINTMAP(struct routing_channel*) channels;
};

static inline struct routing_channel *
get_channel(const struct routing_state *rstate,
	    const struct short_channel_id *scid)
{
	return uintmap_get(&rstate->channels, scid->u64);
}

struct route_hop {
	struct short_channel_id channel_id;
	struct pubkey nodeid;
	u32 amount;
	u32 delay;
};

struct routing_state *new_routing_state(const tal_t *ctx,
					const struct bitcoin_blkid *chain_hash,
					const struct pubkey *local_id,
					u32 prune_timeout);

struct routing_channel *new_routing_channel(struct routing_state *rstate,
					    const struct short_channel_id *scid,
					    const struct pubkey *id1,
					    const struct pubkey *id2);

/* Handlers for incoming messages */

/**
 * handle_channel_announcement -- Check channel announcement is valid
 *
 * Returns a short_channel_id to look up if signatures pass.
 */
const struct short_channel_id *
handle_channel_announcement(struct routing_state *rstate,
			    const u8 *announce TAKES);

/**
 * handle_pending_cannouncement -- handle channel_announce once we've
 * completed short_channel_id lookup.
 *
 * Returns true if the channel was new and is local. This means that
 * if we haven't sent a node_announcement just yet, now would be a
 * good time.
 */
bool handle_pending_cannouncement(struct routing_state *rstate,
				  const struct short_channel_id *scid,
				  const u8 *txscript);
void handle_channel_update(struct routing_state *rstate, const u8 *update);
void handle_node_announcement(struct routing_state *rstate, const u8 *node);

/* Set values on the struct node_connection */
void set_connection_values(struct routing_channel *chan,
			   int idx,
			   u32 base_fee,
			   u32 proportional_fee,
			   u32 delay,
			   bool active,
			   u64 timestamp,
			   u32 htlc_minimum_msat);

/* Get a node: use this instead of node_map_get() */
struct node *get_node(struct routing_state *rstate, const struct pubkey *id);

/* Compute a route to a destination, for a given amount and riskfactor. */
struct route_hop *get_route(tal_t *ctx, struct routing_state *rstate,
			    const struct pubkey *source,
			    const struct pubkey *destination,
			    const u32 msatoshi, double riskfactor,
			    u32 final_cltv,
			    double fuzz,
			    const struct siphash_seed *base_seed);
/* Disable channel(s) based on the given routing failure. */
void routing_failure(struct routing_state *rstate,
		     const struct pubkey *erring_node,
		     const struct short_channel_id *erring_channel,
		     enum onion_type failcode,
		     const u8 *channel_update);
/* Disable specific channel from routing. */
void mark_channel_unroutable(struct routing_state *rstate,
			     const struct short_channel_id *channel);

void route_prune(struct routing_state *rstate);

/* Utility function that, given a source and a destination, gives us
 * the direction bit the matching channel should get */
#define get_channel_direction(from, to) (pubkey_cmp(from, to) > 0)

#endif /* LIGHTNING_LIGHTNINGD_GOSSIP_ROUTING_H */
