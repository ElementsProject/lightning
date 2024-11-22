#ifndef LIGHTNING_CONNECTD_CONNECTD_H
#define LIGHTNING_CONNECTD_CONNECTD_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/timer/timer.h>
#include <common/bigsize.h>
#include <common/channel_id.h>
#include <common/crypto_state.h>
#include <common/node_id.h>
#include <common/pseudorand.h>
#include <common/wireaddr.h>
#include <connectd/handshake.h>

struct io_conn;
struct connecting;
struct wireaddr_internal;

/*~ All the gossip_store related fields are kept together for convenience. */
struct gossip_state {
	/* Is it active right now? */
	bool active;
	/* Except with dev override, this fires every 60 seconds */
	struct oneshot *gossip_timer;
	/* Timestamp filtering for gossip. */
	u32 timestamp_min, timestamp_max;
	/* I think this is called "echo cancellation" */
	struct gossip_rcvd_filter *grf;
	/* Offset within the gossip_store file */
	struct gossmap_iter *iter;
	/* Bytes sent in the last second. */
	size_t bytes_this_second;
	/* When that second starts */
	struct timemono bytes_start_time;
};

/*~ We need to know if we were expecting a pong, and why */
enum pong_expect_type {
	/* We weren't expecting a ping reply */
	PONG_UNEXPECTED = 0,
	/* We were expecting a ping reply due to ping command */
	PONG_EXPECTED_COMMAND = 1,
	/* We were expecting a ping reply due to ping timer */
	PONG_EXPECTED_PROBING = 2,
};

/*~ We classify connections by loose priority */
enum connection_prio {
	/* We deliberately connected to them. */
	PRIO_DELIBERATE,
	/* They connected to us, unsolicited. */
	PRIO_UNSOLICITED,
	/* We connected, but transiently. */
	PRIO_TRANSIENT,
};

/*~ We keep a hash table (ccan/htable) of peers, which tells us what peers are
 * already connected (by peer->id). */
struct peer {
	/* Main daemon */
	struct daemon *daemon;

	/* Are we connected via a websocket? */
	enum is_websocket is_websocket;

	/* The pubkey of the node */
	struct node_id id;
	/* Counters and keys for symmetric crypto */
	struct crypto_state cs;

	/* Connection to the peer */
	struct io_conn *to_peer;

	/* Counter to distinguish this connection from the next re-connection */
	u64 counter;

	/* Is this draining?  If so, just keep writing until queue empty */
	bool draining;

	/* Connections to the subdaemons */
	struct subd **subds;

	/* When socket has Nagle overridden */
	bool urgent;

	/* Input buffer. */
	u8 *peer_in;

	/* Output buffer. */
	struct msg_queue *peer_outq;

	/* Peer sent buffer (for freeing after sending) */
	const u8 *sent_to_peer;

	/* We stream from the gossip_store for them, when idle */
	struct gossip_state gs;

	/* Are we expecting a pong? */
	enum pong_expect_type expecting_pong;

	/* Random ping timer, to detect dead connections. */
	struct oneshot *ping_timer;

	/* Last time we received traffic */
	struct timeabs last_recv_time;

	/* How important does this peer seem to be? */
	enum connection_prio prio;

	/* Ratelimits for onion messages.  One token per msec. */
	size_t onionmsg_incoming_tokens;
	struct timemono onionmsg_last_incoming;
	bool onionmsg_limit_warned;

	bool dev_read_enabled;
	/* If non-NULL, this counts down; 0 means disable */
	u32 *dev_writes_enabled;

	/* Are there outstanding responses for queries on short_channel_ids? */
	const struct short_channel_id *scid_queries;
	const bigsize_t *scid_query_flags;
	size_t scid_query_idx;

	/* Are there outstanding node_announcements from scid_queries? */
	struct node_id *scid_query_nodes;
	size_t scid_query_nodes_idx;
};

/* We gain one token per msec, and each msg uses 250 tokens. */
#define ONION_MSG_MSEC		250
#define ONION_MSG_TOKENS_MAX	(4*ONION_MSG_MSEC)

/*~ The HTABLE_DEFINE_TYPE() macro needs a keyof() function to extract the key:
 */
static const struct node_id *peer_keyof(const struct peer *peer)
{
	return &peer->id;
}

/*~ We reuse node_id_hash from common/node_id.h, which uses siphash
 * and a per-run seed. */

/*~ We also define an equality function: is this element equal to this key? */
static bool peer_eq_node_id(const struct peer *peer,
			    const struct node_id *id)
{
	return node_id_eq(&peer->id, id);
}

/*~ This defines 'struct peer_htable' which contains 'struct peer' pointers. */
HTABLE_DEFINE_TYPE(struct peer,
		   peer_keyof,
		   node_id_hash,
		   peer_eq_node_id,
		   peer_htable);

/*~ Peers we're trying to reach: we iterate through addrs until we succeed
 * or fail. */
struct connecting {
	struct daemon *daemon;

	struct io_conn *conn;

	/* The ID of the peer (not necessarily unique, in transit!) */
	struct node_id id;

	/* We iterate through the tal_count(addrs) */
	size_t addrnum;
	struct wireaddr_internal *addrs;

	/* How far did we get? */
	const char *connstate;

	/* Accumulated errors */
	char *errors;

	/* Is this a transient connection? */
	bool transient;
};

static const struct node_id *connecting_keyof(const struct connecting *connecting)
{
	return &connecting->id;
}

static bool connecting_eq_node_id(const struct connecting *connecting,
				  const struct node_id *id)
{
	return node_id_eq(&connecting->id, id);
}

/*~ This defines 'struct connecting_htable' which contains 'struct connecting'
 *  pointers. */
HTABLE_DEFINE_TYPE(struct connecting,
		   connecting_keyof,
		   node_id_hash,
		   connecting_eq_node_id,
		   connecting_htable);

struct scid_to_node_id {
	struct short_channel_id scid;
	struct node_id node_id;
};

static struct short_channel_id scid_to_node_id_keyof(const struct scid_to_node_id *scid_to_node_id)
{
	return scid_to_node_id->scid;
}

static bool scid_to_node_id_eq_scid(const struct scid_to_node_id *scid_to_node_id,
				    const struct short_channel_id scid)
{
	return short_channel_id_eq(scid_to_node_id->scid, scid);
}

/*~ This defines 'struct scid_htable' which maps short_channel_ids to peers:
 * we use this to forward onion messages which specify the next hop by scid/dir. */
HTABLE_DEFINE_TYPE(struct scid_to_node_id,
		   scid_to_node_id_keyof,
		   short_channel_id_hash,
		   scid_to_node_id_eq_scid,
		   scid_htable);

/*~ This is the global state, like `struct lightningd *ld` in lightningd. */
struct daemon {
	/* Who am I? */
	struct node_id id;

	/* --developer? */
	bool developer;

	/* pubkey equivalent. */
	struct pubkey mykey;

	/* Counter from which we derive connection identifiers. */
	u64 connection_counter;

	/* Base for timeout timers, and how long to wait for init msg */
	struct timers timers;
	u32 timeout_secs;

	/* Peers that we've handed to `lightningd`, which it hasn't told us
	 * have disconnected. */
	struct peer_htable *peers;

	/* Peers we are trying to reach */
	struct connecting_htable *connecting;

	/* Connection to main daemon. */
	struct daemon_conn *master;

	/* Connection to gossip daemon. */
	struct daemon_conn *gossipd;

	/* Map of short_channel_ids to peers */
	struct scid_htable *scid_htable;

	/* Any listening sockets we have. */
	struct io_listener **listeners;

	/* Allow localhost to be considered "public", only with --developer */
	bool dev_allow_localhost;

	/* How much to gossip allow a peer every 60 seconds (bytes) */
	size_t gossip_stream_limit;

	/* We support use of a SOCKS5 proxy (e.g. Tor) */
	struct addrinfo *proxyaddr;

	/* They can tell us we must use proxy even for non-Tor addresses. */
	bool always_use_proxy;

	/* There are DNS seeds we can use to look up node addresses as a last
	 * resort, but doing so leaks our address so can be disabled. */
	bool use_dns;

	/* The address that the broken response returns instead of
	 * NXDOMAIN. NULL if we have not detected a broken resolver. */
	struct sockaddr *broken_resolver_response;

	/* File descriptors to listen on once we're activated. */
	const struct listen_fd **listen_fds;

	/* Our features, as lightningd told us */
	struct feature_set *our_features;

	/* Subdaemon to proxy websocket requests. */
	char *websocket_helper;

	/* If non-zero, port to listen for websocket connections. */
	u16 websocket_port;

	/* The gossip store (access via get_gossmap!) */
	struct gossmap *gossmap_raw;
	/* Iterator which we keep at "recent" time */
	u32 gossip_recent_time;
	struct gossmap_iter *gossmap_iter_recent;

	/* We only announce websocket addresses if !deprecated_apis */
	bool announce_websocket;

	/* Shutting down, don't send new stuff */
	bool shutting_down;

	/* What (even) custom messages we accept */
	u16 *custom_msgs;

	/* Hack to speed up gossip timer */
	bool dev_fast_gossip;
	/* Hack to avoid ping timeouts */
	bool dev_no_ping_timer;
	/* Hack to no longer send gossip */
	bool dev_suppress_gossip;
	/* dev_disconnect file */
	int dev_disconnect_fd;
	/* Did we exhaust fds?  If so, skip dev_report_fds */
	bool dev_exhausted_fds;
	/* Allow connections in, but don't send anything */
	bool dev_handshake_no_reply;
	/* --dev-no-reconnect */
	bool dev_no_reconnect;
	/* --dev-fast-reconnect */
	bool dev_fast_reconnect;
 };

/* Called by io_tor_connect once it has a connection out. */
struct io_plan *connection_out(struct io_conn *conn, struct connecting *connect);

/* Get and refresh gossmap */
struct gossmap *get_gossmap(struct daemon *daemon);

/* Catch up with recent changes */
void update_recent_timestamp(struct daemon *daemon, struct gossmap *gossmap);

/* add erros to error list */
void add_errors_to_error_list(struct connecting *connect, const char *error);

/* Called by peer_exchange_initmsg if successful. */
struct io_plan *peer_connected(struct io_conn *conn,
			       struct daemon *daemon,
			       const struct node_id *id,
			       const struct wireaddr_internal *addr,
			       const struct wireaddr *remote_addr,
			       struct crypto_state *cs,
			       const u8 *their_features TAKES,
			       enum is_websocket is_websocket,
			       bool incoming);

/* Removes peer from hash table, tells gossipd and lightningd. */
void destroy_peer(struct peer *peer);

/* Remove a random connection, when under stress. */
void close_random_connection(struct daemon *daemon);
#endif /* LIGHTNING_CONNECTD_CONNECTD_H */
