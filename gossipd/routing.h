#ifndef LIGHTNING_GOSSIPD_ROUTING_H
#define LIGHTNING_GOSSIPD_ROUTING_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/intmap/intmap.h>
#include <ccan/time/time.h>
#include <common/amount.h>
#include <common/gossip_constants.h>
#include <common/node_id.h>
#include <common/route.h>
#include <gossipd/broadcast.h>
#include <gossipd/gossip_store.h>
#include <wire/onion_wire.h>
#include <wire/wire.h>

struct daemon;
struct peer;
struct routing_state;

struct half_chan {
	/* Timestamp and index into store file */
	struct broadcastable bcast;

	/* Token bucket */
	u8 tokens;
};

struct chan {
	struct short_channel_id scid;

	/*
	 * half[0]->src == nodes[0] half[0]->dst == nodes[1]
	 * half[1]->src == nodes[1] half[1]->dst == nodes[0]
	 */
	struct half_chan half[2];
	/* node[0].id < node[1].id */
	struct node *nodes[2];

	/* Timestamp and index into store file */
	struct broadcastable bcast;

	struct amount_sat sat;
};

/* Shadow structure for local channels: owned by the chan above, but kept
 * separately to keep `struct chan` minimal since there may be millions
 * of non-local channels. */
struct local_chan {
	struct chan *chan;
	int direction;

	/* We soft-disable local channels when a peer disconnects */
	bool local_disabled;

	/* Timer if we're deferring an update. */
	struct oneshot *channel_update_timer;
};

/* Use this instead of tal_free(chan)! */
void free_chan(struct routing_state *rstate, struct chan *chan);

/* A local channel can exist which isn't announced: we abuse timestamp
 * to indicate this. */
static inline bool is_chan_public(const struct chan *chan)
{
	return chan->bcast.timestamp != 0;
}

static inline bool is_halfchan_defined(const struct half_chan *hc)
{
	return hc->bcast.index != 0;
}

/* Container for per-node channel pointers.  Better cache performance
 * than uintmap, and we don't need ordering. */
static inline const struct short_channel_id *chan_map_scid(const struct chan *c)
{
	return &c->scid;
}

static inline size_t hash_scid(const struct short_channel_id *scid)
{
	/* scids cost money to generate, so simple hash works here */
	return (scid->u64 >> 32) ^ (scid->u64 >> 16) ^ scid->u64;
}

static inline bool chan_eq_scid(const struct chan *c,
				const struct short_channel_id *scid)
{
	return short_channel_id_eq(scid, &c->scid);
}

HTABLE_DEFINE_TYPE(struct chan, chan_map_scid, hash_scid, chan_eq_scid, chan_map);

/* For a small number of channels (by far the most common) we use a simple
 * array, with empty buckets NULL.  For larger, we use a proper hash table,
 * with the extra allocation that implies. */
#define NUM_IMMEDIATE_CHANS (sizeof(struct chan_map) / sizeof(struct chan *) - 1)

struct node {
	struct node_id id;

	/* Timestamp and index into store file */
	struct broadcastable bcast;

	/* Token bucket */
	u8 tokens;

	/* Channels connecting us to other nodes */
	union {
		struct chan_map map;
		struct chan *arr[NUM_IMMEDIATE_CHANS+1];
	} chans;
};

const struct node_id *node_map_keyof_node(const struct node *n);
size_t node_map_hash_key(const struct node_id *pc);
bool node_map_node_eq(const struct node *n, const struct node_id *pc);
HTABLE_DEFINE_TYPE(struct node, node_map_keyof_node, node_map_hash_key, node_map_node_eq, node_map);

/* We've unpacked and checked its signatures, now we wait for master to tell
 * us the txout to check */
struct pending_cannouncement {
	/* Unpacked fields here */

	/* also the key in routing_state->pending_cannouncements */
	struct short_channel_id short_channel_id;
	struct node_id node_id_1;
	struct node_id node_id_2;
	struct pubkey bitcoin_key_1;
	struct pubkey bitcoin_key_2;

	/* Automagically turns to NULL of peer freed */
	struct peer *peer_softref;

	/* The raw bits */
	const u8 *announce;

	/* Deferred updates, if we received them while waiting for
	 * this (one for each direction) */
	const u8 *updates[2];
	/* Peers responsible: turns to NULL if they're freed */
	struct peer *update_peer_softref[2];

	/* Only ever replace with newer updates */
	u32 update_timestamps[2];
};

static inline const struct short_channel_id *panding_cannouncement_map_scid(
				const struct pending_cannouncement *pending_ann)
{
	return &pending_ann->short_channel_id;
}

static inline size_t hash_pending_cannouncement_scid(
				const struct short_channel_id *scid)
{
	/* like hash_scid() for struct chan above */
	return (scid->u64 >> 32) ^ (scid->u64 >> 16) ^ scid->u64;
}

static inline bool pending_cannouncement_eq_scid(
				const struct pending_cannouncement *pending_ann,
				const struct short_channel_id *scid)
{
	return short_channel_id_eq(scid, &pending_ann->short_channel_id);
}

HTABLE_DEFINE_TYPE(struct pending_cannouncement, panding_cannouncement_map_scid,
		   hash_pending_cannouncement_scid, pending_cannouncement_eq_scid,
		   pending_cannouncement_map);

struct pending_node_map;
struct unupdated_channel;

/* If you know n is one end of the channel, get index of src == n */
static inline int half_chan_idx(const struct node *n, const struct chan *chan)
{
	int idx = (chan->nodes[1] == n);

	assert(chan->nodes[0] == n || chan->nodes[1] == n);
	return idx;
}

struct routing_state {
	/* TImers base from struct gossipd. */
	struct timers *timers;

	/* All known nodes. */
	struct node_map *nodes;

	/* node_announcements which are waiting on pending_cannouncement */
	struct pending_node_map *pending_node_map;

	/* channel_announcement which are pending short_channel_id lookup */
	struct pending_cannouncement_map pending_cannouncements;

	/* Gossip store */
	struct gossip_store *gs;

	/* Our own ID so we can identify local channels */
	struct node_id local_id;

        /* A map of channels indexed by short_channel_ids */
	UINTMAP(struct chan *) chanmap;

        /* A map of channel_announcements indexed by short_channel_ids:
	 * we haven't got a channel_update for these yet. */
	UINTMAP(struct unupdated_channel *) unupdated_chanmap;

	/* Has one of our own channels been announced? */
	bool local_channel_announced;

	/* Cache for txout queries that failed. Allows us to skip failed
	 * checks if we get another announcement for the same scid. */
	size_t num_txout_failures;
	UINTMAP(bool) txout_failures, txout_failures_old;
	struct oneshot *txout_failure_timer;

	/* Highest timestamp of gossip we accepted (before now) */
	u32 last_timestamp;

#if DEVELOPER
	/* Override local time for gossip messages */
	struct timeabs *gossip_time;

	/* Speed up gossip. */
	bool dev_fast_gossip;

	/* Speed up pruning. */
	bool dev_fast_gossip_prune;
#endif
};

/* Which direction are we?  False if neither. */
static inline bool local_direction(struct routing_state *rstate,
				   const struct chan *chan,
				   int *direction)
{
	for (int dir = 0; dir <= 1; (dir)++) {
		if (node_id_eq(&chan->nodes[dir]->id, &rstate->local_id)) {
			if (direction)
				*direction = dir;
			return true;
		}
	}
	return false;
}

static inline struct chan *
get_channel(const struct routing_state *rstate,
	    const struct short_channel_id *scid)
{
	return uintmap_get(&rstate->chanmap, scid->u64);
}

struct routing_state *new_routing_state(const tal_t *ctx,
					const struct node_id *local_id,
					struct list_head *peers,
					struct timers *timers,
					const u32 *dev_gossip_time TAKES,
					bool dev_fast_gossip,
					bool dev_fast_gossip_prune);

/**
 * Add a new bidirectional channel from id1 to id2 with the given
 * short_channel_id and capacity to the local network view. The channel may not
 * already exist, and might create the node entries for the two endpoints, if
 * they do not exist yet.
 */
struct chan *new_chan(struct routing_state *rstate,
		      const struct short_channel_id *scid,
		      const struct node_id *id1,
		      const struct node_id *id2,
		      struct amount_sat sat);

/* Handlers for incoming messages */

/**
 * handle_channel_announcement -- Check channel announcement is valid
 *
 * Returns error message if we should fail channel.  Make *scid non-NULL
 * (for checking) if we extracted a short_channel_id, otherwise ignore.
 */
u8 *handle_channel_announcement(struct routing_state *rstate,
				const u8 *announce TAKES,
				u32 current_blockheight,
				const struct short_channel_id **scid,
				struct peer *peer);

/**
 * handle_pending_cannouncement -- handle channel_announce once we've
 * completed short_channel_id lookup.  Returns true if handling created
 * a new channel.
 */
bool handle_pending_cannouncement(struct daemon *daemon,
				  struct routing_state *rstate,
				  const struct short_channel_id *scid,
				  const struct amount_sat sat,
				  const u8 *txscript);

/* Iterate through channels in a node */
struct chan *first_chan(const struct node *node, struct chan_map_iter *i);
struct chan *next_chan(const struct node *node, struct chan_map_iter *i);

/* Returns NULL if all OK, otherwise an error for the peer which sent.
 * If the error is that the channel is unknown, fills in *unknown_scid
 * (if not NULL). */
u8 *handle_channel_update(struct routing_state *rstate, const u8 *update TAKES,
			  struct peer *peer,
			  struct short_channel_id *unknown_scid,
			  bool force);

/* Returns NULL if all OK, otherwise an error for the peer which sent.
 * If was_unknown is not NULL, sets it to true if that was the reason for
 * the error: the node was unknown to us. */
u8 *handle_node_announcement(struct routing_state *rstate, const u8 *node,
			     struct peer *peer, bool *was_unknown);

/* Get a node: use this instead of node_map_get() */
struct node *get_node(struct routing_state *rstate,
		      const struct node_id *id);

void route_prune(struct routing_state *rstate);

/**
 * Add a channel_announcement to the network view without checking it
 *
 * Directly add the channel to the local network, without checking it first. Use
 * this only for messages from trusted sources. Untrusted sources should use the
 * @see{handle_channel_announcement} entrypoint to check before adding.
 *
 * index is usually 0, in which case it's set by insert_broadcast adding it
 * to the store.
 *
 * peer is an optional peer responsible for this.
 */
bool routing_add_channel_announcement(struct routing_state *rstate,
				      const u8 *msg TAKES,
				      struct amount_sat sat,
				      u32 index,
				      struct peer *peer);

/**
 * Add a channel_update without checking for errors
 *
 * Used to actually insert the information in the channel update into the local
 * network view. Only use this for messages that are known to be good. For
 * untrusted source, requiring verification please use
 * @see{handle_channel_update}
 */
bool routing_add_channel_update(struct routing_state *rstate,
				const u8 *update TAKES,
				u32 index,
				struct peer *peer,
				bool ignore_timestamp);
/**
 * Add a node_announcement to the network view without checking it
 *
 * Directly add the node being announced to the network view, without verifying
 * it. This must be from a trusted source, e.g., gossip_store. For untrusted
 * sources (peers) please use @see{handle_node_announcement}.
 */
bool routing_add_node_announcement(struct routing_state *rstate,
				   const u8 *msg TAKES,
				   u32 index,
				   struct peer *peer,
				   bool *was_unknown);


/**
 * Add a local channel.
 *
 * Entrypoint to add a local channel that was not learned through gossip. This
 * is the case for private channels or channels that have not yet reached
 * `announce_depth`.
 */
bool routing_add_private_channel(struct routing_state *rstate,
				 const struct node_id *id,
				 struct amount_sat sat,
				 const u8 *chan_ann, u64 index);

/**
 * Get the local time.
 *
 * This gets overridden in dev mode so we can use canned (stale) gossip.
 */
struct timeabs gossip_time_now(const struct routing_state *rstate);

/* Would we ratelimit a channel_update with this timestamp? */
bool would_ratelimit_cupdate(struct routing_state *rstate,
			     const struct half_chan *hc,
			     u32 timestamp);

/* Remove channel from store: announcement and any updates. */
void remove_channel_from_store(struct routing_state *rstate,
			       struct chan *chan);

/* Returns an error string if there are unfinalized entries after load */
const char *unfinalized_entries(const tal_t *ctx, struct routing_state *rstate);

void remove_all_gossip(struct routing_state *rstate);

/* This scid is dead to us. */
void add_to_txout_failures(struct routing_state *rstate,
			   const struct short_channel_id *scid);
#endif /* LIGHTNING_GOSSIPD_ROUTING_H */
