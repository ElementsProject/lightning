#ifndef LIGHTNING_GOSSIPD_GOSSIPD_H
#define LIGHTNING_GOSSIPD_GOSSIPD_H
#include "config.h"
#include <bitcoin/block.h>
#include <ccan/bitmap/bitmap.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/timer/timer.h>
#include <common/bigsize.h>
#include <common/node_id.h>

/* We talk to `hsmd` to sign our gossip messages with the node key */
#define HSM_FD 3
/* connectd asks us for help finding nodes, and gossip fds for new peers */
#define CONNECTD_FD 4

struct chan;
struct channel_update_timestamps;
struct broadcastable;
struct seeker;

/*~ The core daemon structure: */
struct daemon {
	/* Who am I?  Helps us find ourself in the routing map. */
	struct node_id id;

	/* Peers we are gossiping to: id is unique */
	struct list_head peers;

	/* Current blockheight: 0 means we're not up-to-date. */
	u32 current_blockheight;

	/* Connection to lightningd. */
	struct daemon_conn *master;

	/* Connection to connect daemon. */
	struct daemon_conn *connectd;

	/* Routing information */
	struct routing_state *rstate;

	/* Timers: we batch gossip, and also refresh announcements */
	struct timers timers;

	/* Alias (not NUL terminated) and favorite color for node_announcement */
	u8 alias[32];
	u8 rgb[3];

	/* What addresses we can actually announce. */
	struct wireaddr *announcable;

	/* Timer until we can send a new node_announcement */
	struct oneshot *node_announce_timer;

	/* Channels we have an announce for, but aren't deep enough. */
	struct short_channel_id *deferred_txouts;

	/* What, if any, gossip we're seeker from peers. */
	struct seeker *seeker;

	/* Features lightningd told us to set. */
	struct feature_set *our_features;
};

/* This represents each peer we're gossiping with */
struct peer {
	/* daemon->peers */
	struct list_node list;

	/* parent pointer. */
	struct daemon *daemon;

	/* The ID of the peer (always unique) */
	struct node_id id;

	/* How much contribution have we made to gossip? */
	size_t gossip_counter;

	/* The two features gossip cares about (so far) */
	bool gossip_queries_feature, initial_routing_sync_feature;

	/* Are there outstanding responses for queries on short_channel_ids? */
	const struct short_channel_id *scid_queries;
	const bigsize_t *scid_query_flags;
	size_t scid_query_idx;

	/* Are there outstanding node_announcements from scid_queries? */
	struct node_id *scid_query_nodes;
	size_t scid_query_nodes_idx;

	/* Do we have an scid_query outstanding?  What to call when it's done? */
	bool scid_query_outstanding;
	void (*scid_query_cb)(struct peer *peer, bool complete);

	/* How many pongs are we expecting? */
	size_t num_pings_outstanding;

	/* Map of outstanding channel_range requests. */
	bitmap *query_channel_blocks;
	/* What we're querying: [range_first_blocknum, range_end_blocknum) */
	u32 range_first_blocknum, range_end_blocknum;
	u32 range_blocks_remaining;
	struct short_channel_id *query_channel_scids;
	struct channel_update_timestamps *query_channel_timestamps;
	void (*query_channel_range_cb)(struct peer *peer,
				       u32 first_blocknum, u32 number_of_blocks,
				       const struct short_channel_id *scids,
				       const struct channel_update_timestamps *,
				       bool complete);

	/* The daemon_conn used to queue messages to/from the peer. */
	struct daemon_conn *dc;
};

/* Search for a peer. */
struct peer *find_peer(struct daemon *daemon, const struct node_id *id);

/* This peer (may be NULL) gave is valid gossip. */
void peer_supplied_good_gossip(struct peer *peer, size_t amount);

/* Pick a random peer which passes check_peer */
struct peer *random_peer(struct daemon *daemon,
			 bool (*check_peer)(const struct peer *peer));

/* Queue a gossip message for the peer: the subdaemon on the other end simply
 * forwards it to the peer. */
void queue_peer_msg(struct peer *peer, const u8 *msg TAKES);

/* Queue a gossip_store message for the peer: the subdaemon on the
 * other end simply forwards it to the peer. */
void queue_peer_from_store(struct peer *peer,
			   const struct broadcastable *bcast);

/* Reset gossip range for this peer. */
void setup_gossip_range(struct peer *peer);

/* A peer has given us these short channel ids: see if we need to catch up */
void process_scids(struct daemon *daemon, const struct short_channel_id *scids);

#endif /* LIGHTNING_GOSSIPD_GOSSIPD_H */
