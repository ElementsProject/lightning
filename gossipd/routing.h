#ifndef LIGHTNING_GOSSIPD_ROUTING_H
#define LIGHTNING_GOSSIPD_ROUTING_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/time/time.h>
#include <gossipd/broadcast.h>
#include <gossipd/gossip_constants.h>
#include <gossipd/gossip_store.h>
#include <wire/gen_onion_wire.h>
#include <wire/wire.h>

struct half_chan {
	/* Cached `channel_update` which initialized below (or NULL) */
	const u8 *channel_update;

	/* millisatoshi. */
	u32 base_fee;
	/* millionths */
	u32 proportional_fee;

	/* Delay for HTLC in blocks.*/
	u32 delay;

	/* -1 if channel_update is NULL */
	s64 last_timestamp;

	/* Minimum number of msatoshi in an HTLC */
	u32 htlc_minimum_msat;

	/* Flags as specified by the `channel_update`s, among other
	 * things indicated direction wrt the `channel_id` */
	u16 flags;

	/* If greater than current time, this connection should not
	 * be used for routing. */
	time_t unroutable_until;
};

struct chan {
	struct short_channel_id scid;
	u8 *txout_script;

	/*
	 * half[0]->src == nodes[0] half[0]->dst == nodes[1]
	 * half[1]->src == nodes[1] half[1]->dst == nodes[0]
	 */
	struct half_chan half[2];
	/* node[0].id < node[1].id */
	struct node *nodes[2];

	/* NULL if not announced yet (ie. not public). */
	const u8 *channel_announce;
	/* Index in broadcast map, if public (otherwise 0) */
	u64 channel_announcement_index;

	/* Disabled locally (due to peer disconnect) */
	bool local_disabled;

	u64 satoshis;
};

static inline bool is_chan_public(const struct chan *chan)
{
	return chan->channel_announce != NULL;
}

static inline bool is_halfchan_defined(const struct half_chan *hc)
{
	return hc->channel_update != NULL;
}

static inline bool is_halfchan_enabled(const struct half_chan *hc)
{
	return is_halfchan_defined(hc) && !(hc->flags & ROUTING_FLAGS_DISABLED);
}

struct node {
	struct pubkey id;

	/* -1 means never; other fields undefined */
	s64 last_timestamp;

	/* IP/Hostname and port of this node (may be NULL) */
	struct wireaddr *addresses;

	/* Channels connecting us to other nodes */
	struct chan **chans;

	/* Temporary data for routefinding. */
	struct {
		/* Total to get to here from target. */
		u64 total;
		/* Total risk premium of this route. */
		u64 risk;
		/* Where that came from. */
		struct chan *prev;
	} bfg[ROUTING_MAX_HOPS+1];

	/* UTF-8 encoded alias as tal_arr, not zero terminated */
	u8 *alias;

	/* Color to be used when displaying the name */
	u8 rgb_color[3];

	/* (Global) features */
	u8 *gfeatures;

	/* Cached `node_announcement` we might forward to new peers (or NULL). */
	const u8 *node_announcement;
	/* If public, this is non-zero. */
	u64 node_announcement_index;
};

const struct pubkey *node_map_keyof_node(const struct node *n);
size_t node_map_hash_key(const struct pubkey *key);
bool node_map_node_eq(const struct node *n, const struct pubkey *key);
HTABLE_DEFINE_TYPE(struct node, node_map_keyof_node, node_map_hash_key, node_map_node_eq, node_map);

struct pending_node_map;
struct pending_cannouncement;

/* If the two nodes[] are id1 and id2, which index would id1 be? */
static inline int pubkey_idx(const struct pubkey *id1, const struct pubkey *id2)
{
	return pubkey_cmp(id1, id2) > 0;
}

/* Fast versions: if you know n is one end of the channel */
static inline struct node *other_node(const struct node *n, struct chan *chan)
{
	int idx = (chan->nodes[1] == n);

	assert(chan->nodes[0] == n || chan->nodes[1] == n);
	return chan->nodes[!idx];
}

/* If you know n is one end of the channel, get connection src == n */
static inline struct half_chan *half_chan_from(const struct node *n,
					       struct chan *chan)
{
	int idx = (chan->nodes[1] == n);

	assert(chan->nodes[0] == n || chan->nodes[1] == n);
	return &chan->half[idx];
}

/* If you know n is one end of the channel, get index dst == n */
static inline int half_chan_to(const struct node *n, struct chan *chan)
{
	int idx = (chan->nodes[1] == n);

	assert(chan->nodes[0] == n || chan->nodes[1] == n);
	return !idx;
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

	/* Store for processed messages that we might want to remember across
	 * restarts */
	struct gossip_store *store;

        /* A map of channels indexed by short_channel_ids */
	UINTMAP(struct chan *) chanmap;

	/* Has one of our own channels been announced? */
	bool local_channel_announced;
};

static inline struct chan *
get_channel(const struct routing_state *rstate,
	    const struct short_channel_id *scid)
{
	return uintmap_get(&rstate->chanmap, scid->u64);
}

struct route_hop {
	struct short_channel_id channel_id;
	struct pubkey nodeid;
	u64 amount;
	u32 delay;
};

struct routing_state *new_routing_state(const tal_t *ctx,
					const struct bitcoin_blkid *chain_hash,
					const struct pubkey *local_id,
					u32 prune_timeout);

/**
 * Add a new bidirectional channel from id1 to id2 with the given
 * short_channel_id and capacity to the local network view. The channel may not
 * already exist, and might create the node entries for the two endpoints, if
 * they do not exist yet.
 */
struct chan *new_chan(struct routing_state *rstate,
		      const struct short_channel_id *scid,
		      const struct pubkey *id1,
		      const struct pubkey *id2,
		      u64 satoshis);

/* Handlers for incoming messages */

/**
 * handle_channel_announcement -- Check channel announcement is valid
 *
 * Returns error message if we should fail channel.  Make *scid non-NULL
 * (for checking) if we extracted a short_channel_id, otherwise ignore.
 */
u8 *handle_channel_announcement(struct routing_state *rstate,
				const u8 *announce TAKES,
				const struct short_channel_id **scid);

/**
 * handle_pending_cannouncement -- handle channel_announce once we've
 * completed short_channel_id lookup.
 */
void handle_pending_cannouncement(struct routing_state *rstate,
				  const struct short_channel_id *scid,
				  const u64 satoshis,
				  const u8 *txscript);

/* Returns NULL if all OK, otherwise an error for the peer which sent. */
u8 *handle_channel_update(struct routing_state *rstate, const u8 *update,
			  const char *source);

/* Returns NULL if all OK, otherwise an error for the peer which sent. */
u8 *handle_node_announcement(struct routing_state *rstate, const u8 *node);

/* Get a node: use this instead of node_map_get() */
struct node *get_node(struct routing_state *rstate, const struct pubkey *id);

/* Compute a route to a destination, for a given amount and riskfactor. */
struct route_hop *get_route(const tal_t *ctx, struct routing_state *rstate,
			    const struct pubkey *source,
			    const struct pubkey *destination,
			    const u64 msatoshi, double riskfactor,
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

/**
 * Add a channel_announcement to the network view without checking it
 *
 * Directly add the channel to the local network, without checking it first. Use
 * this only for messages from trusted sources. Untrusted sources should use the
 * @see{handle_channel_announcement} entrypoint to check before adding.
 */
bool routing_add_channel_announcement(struct routing_state *rstate,
				      const u8 *msg TAKES, u64 satoshis);

/**
 * Add a channel_update without checking for errors
 *
 * Used to actually insert the information in the channel update into the local
 * network view. Only use this for messages that are known to be good. For
 * untrusted source, requiring verification please use
 * @see{handle_channel_update}
 */
bool routing_add_channel_update(struct routing_state *rstate,
				const u8 *update TAKES);

/**
 * Add a node_announcement to the network view without checking it
 *
 * Directly add the node being announced to the network view, without verifying
 * it. This must be from a trusted source, e.g., gossip_store. For untrusted
 * sources (peers) please use @see{handle_node_announcement}.
 */
bool routing_add_node_announcement(struct routing_state *rstate,
                                  const u8 *msg TAKES);


/**
 * Add a local channel.
 *
 * Entrypoint to add a local channel that was not learned through gossip. This
 * is the case for private channels or channels that have not yet reached
 * `announce_depth`.
 */
void handle_local_add_channel(struct routing_state *rstate, const u8 *msg);

#endif /* LIGHTNING_GOSSIPD_ROUTING_H */
