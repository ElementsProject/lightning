#ifndef LIGHTNING_GOSSIPD_GOSSIPD_H
#define LIGHTNING_GOSSIPD_GOSSIPD_H
#include "config.h"
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <common/node_id.h>

/* We talk to `hsmd` to sign our gossip messages with the node key */
#define HSM_FD 3
/* connectd asks us for help finding nodes, and gossip fds for new peers */
#define CONNECTD_FD 4

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

	/* chainhash for checking/making gossip msgs */
	struct bitcoin_blkid chain_hash;

	/* Timers: we batch gossip, and also refresh announcements */
	struct timers timers;

	/* Global features to list in node_announcement. */
	u8 *globalfeatures;

	/* Alias (not NUL terminated) and favorite color for node_announcement */
	u8 alias[32];
	u8 rgb[3];

	/* What addresses we can actually announce. */
	struct wireaddr *announcable;

	/* Do we think we're missing gossip?  Contains timer to re-check */
	struct oneshot *gossip_missing;

	/* Channels we've heard about, but don't know. */
	struct short_channel_id *unknown_scids;

	/* Timer until we can send a new node_announcement */
	struct oneshot *node_announce_timer;
};

/* Search for a peer. */
struct peer *find_peer(struct daemon *daemon, const struct node_id *id);

/* Queue a gossip message for the peer: the subdaemon on the other end simply
 * forwards it to the peer. */
void queue_peer_msg(struct peer *peer, const u8 *msg TAKES);
#endif /* LIGHTNING_GOSSIPD_GOSSIPD_H */
