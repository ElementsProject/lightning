#ifndef LIGHTNING_GOSSIPD_GOSSIPD_H
#define LIGHTNING_GOSSIPD_GOSSIPD_H
#include "config.h"
#include <ccan/ccan/opt/opt.h>
#include <ccan/timer/timer.h>
#include <common/node_id.h>
#include <lightningd/options.h>
#include <wire/peer_wire.h>

/* We talk to `hsmd` to sign our gossip messages with the node key */
#define HSM_FD 3
/* connectd asks us for help finding nodes, and gossip fds for new peers */
#define CONNECTD_FD 4
#define CONNECTD2_FD 5

struct chan;
struct peer;
struct channel_update_timestamps;
struct broadcastable;
struct lease_rates;
struct seeker;
struct dying_channel;

/* Helpers for htable */
const struct node_id *peer_node_id(const struct peer *peer);
bool peer_node_id_eq(const struct peer *peer, const struct node_id *node_id);

/* Defines struct peer_node_id_map */
HTABLE_DEFINE_NODUPS_TYPE(struct peer,
			  peer_node_id, node_id_hash, peer_node_id_eq,
			  peer_node_id_map);

/*~ The core daemon structure: */
struct daemon {
	/* Who am I?  Helps us find ourself in the routing map. */
	struct node_id id;

	/* Peers we are gossiping to: id is unique */
	struct peer_node_id_map *peers;

	/* --developer? */
	bool developer;

	/* Current blockheight: 0 means we're not up-to-date. */
	u32 current_blockheight;

	/* Connection to lightningd. */
	struct daemon_conn *master;

	/* Connection to connect daemon. */
	struct daemon_conn *connectd;

	/* Manager of writing to the gossip_store */
	struct gossmap_manage *gm;

	/* Timers: we batch gossip, and also refresh announcements */
	struct timers timers;

	/* Channels we have an announce for, but aren't deep enough. */
	struct short_channel_id *deferred_txouts;

	/* What, if any, gossip we're seeker from peers. */
	struct seeker *seeker;

	/* Features lightningd told us to set. */
	struct feature_set *our_features;

	/* Override local time for gossip messages */
	struct timeabs *dev_gossip_time;

	/* Speed up gossip. */
	bool dev_fast_gossip;

	/* Speed up pruning. */
	bool dev_fast_gossip_prune;

	/* Minimum gossip peers - seeker connects to random peers to fill. */
	u32 autoconnect_seeker_peers;
};

struct range_query_reply {
	struct short_channel_id scid;
	struct channel_update_timestamps ts;
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

	/* How much gossip have we sent in response to gossip queries? */
	size_t query_reply_counter;

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

	/* What we're querying: [range_first_blocknum, range_end_blocknum) */
	u32 range_first_blocknum, range_end_blocknum;
	u32 range_blocks_outstanding;
	struct range_query_reply *range_replies;
	void (*query_channel_range_cb)(struct peer *peer,
				       u32 first_blocknum, u32 number_of_blocks,
				       const struct range_query_reply *replies);
};

/* Search for a peer. */
struct peer *find_peer(struct daemon *daemon, const struct node_id *id);

/* This peer (may be NULL) gave us valid gossip. */
void peer_supplied_good_gossip(struct daemon *daemon,
			       const struct node_id *source_peer,
			       size_t amount);

/* Increase peer's query_reply_counter, if peer not NULL */
void peer_supplied_query_response(struct daemon *daemon,
				  const struct node_id *source_peer,
				  size_t amount);

/* Get a random peer.  NULL if no peers. */
struct peer *first_random_peer(struct daemon *daemon,
			       struct peer_node_id_map_iter *it);

/* Get another... return NULL when we're back at frist. */
struct peer *next_random_peer(struct daemon *daemon,
			      const struct peer *first,
			      struct peer_node_id_map_iter *it);

/* Queue a gossip message for the peer: the subdaemon on the other end simply
 * forwards it to the peer. */
void queue_peer_msg(struct daemon *daemon,
		    const struct node_id *peer,
		    const u8 *msg TAKES);

/* We have an update for one of our channels (or unknown). */
void tell_lightningd_peer_update(struct daemon *daemon,
				 const struct node_id *source_peer,
				 struct short_channel_id scid,
				 u32 fee_base_msat,
				 u32 fee_ppm,
				 u16 cltv_delta,
				 struct amount_msat htlc_minimum,
				 struct amount_msat htlc_maximum);

/**
 * Get the local time.
 *
 * This gets overridden in dev mode so we can use canned (stale) gossip.
 */
struct timeabs gossip_time_now(const struct daemon *daemon);

/**
 * Is this gossip timestamp reasonable?
 */
bool timestamp_reasonable(const struct daemon *daemon, u32 timestamp);

#endif /* LIGHTNING_GOSSIPD_GOSSIPD_H */
