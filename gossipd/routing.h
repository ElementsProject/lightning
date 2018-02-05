#ifndef LIGHTNING_LIGHTNINGD_GOSSIP_ROUTING_H
#define LIGHTNING_LIGHTNINGD_GOSSIP_ROUTING_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/htable/htable_type.h>
#include <ccan/time/time.h>
#include <gossipd/broadcast.h>
#include <wire/gen_onion_wire.h>
#include <wire/wire.h>

#define ROUTING_MAX_HOPS 20
#define ROUTING_FLAGS_DISABLED 2

struct node_connection {
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
	struct short_channel_id short_channel_id;

	/* Flags as specified by the `channel_update`s, among other
	 * things indicated direction wrt the `channel_id` */
	u16 flags;

	/* Cached `channel_announcement` and `channel_update` we might forward to new peers*/
	u8 *channel_announcement;
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

	/* Routes connecting to us, from us. */
	struct node_connection **in, **out;

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

enum txout_state {
	TXOUT_FETCHING,
	TXOUT_PRESENT,
	TXOUT_MISSING
};

struct routing_channel {
	struct short_channel_id scid;
	enum txout_state state;
	u8 *txout_script;

	struct node_connection *connections[2];
	struct node *nodes[2];

	u64 msg_indexes[3];

	/* Is this a public channel, or was it only added locally? */
	bool public;

	struct pending_cannouncement *pending;
};

struct routing_state {
	/* All known nodes. */
	struct node_map *nodes;

	struct pending_node_map *pending_node_map;

	/* channel_announcement which are pending short_channel_id lookup */
	struct list_head pending_cannouncement;

	struct broadcast_state *broadcasts;

	struct bitcoin_blkid chain_hash;

	/* Our own ID so we can identify local channels */
	struct pubkey local_id;

        /* A map of channels indexed by short_channel_ids */
	UINTMAP(struct routing_channel*) channels;
};

struct route_hop {
	struct short_channel_id channel_id;
	struct pubkey nodeid;
	u32 amount;
	u32 delay;
};

struct routing_state *new_routing_state(const tal_t *ctx,
					const struct bitcoin_blkid *chain_hash,
					const struct pubkey *local_id);

/* Add a connection to the routing table, but do not mark it as usable
 * yet. Used by channel_announcements before the channel_update comes
 * in. */
struct node_connection *half_add_connection(struct routing_state *rstate,
					    const struct pubkey *from,
					    const struct pubkey *to,
					    const struct short_channel_id *schanid,
					    const u16 flags);

/* Given a short_channel_id, retrieve the matching connection, or NULL if it is
 * unknown. */
struct node_connection *get_connection_by_scid(const struct routing_state *rstate,
					       const struct short_channel_id *schanid,
					      const u8 direction);

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

/* Compute a route to a destination, for a given amount and riskfactor. */
struct route_hop *get_route(tal_t *ctx, struct routing_state *rstate,
			    const struct pubkey *source,
			    const struct pubkey *destination,
			    const u32 msatoshi, double riskfactor,
			    u32 final_cltv);
/* Disable channel(s) based on the given routing failure. */
void routing_failure(struct routing_state *rstate,
		     const struct pubkey *erring_node,
		     const struct short_channel_id *erring_channel,
		     enum onion_type failcode,
		     const u8 *channel_update);

/* routing_channel constructor */
struct routing_channel *routing_channel_new(const tal_t *ctx,
					    struct short_channel_id *scid);

/* Add the connection to the channel */
void channel_add_connection(struct routing_state *rstate,
			    struct routing_channel *chan,
			    struct node_connection *nc);

/* Utility function that, given a source and a destination, gives us
 * the direction bit the matching channel should get */
#define get_channel_direction(from, to) (pubkey_cmp(from, to) > 0)

#endif /* LIGHTNING_LIGHTNINGD_GOSSIP_ROUTING_H */
