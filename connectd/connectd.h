#ifndef LIGHTNING_CONNECTD_CONNECTD_H
#define LIGHTNING_CONNECTD_CONNECTD_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/timer/timer.h>
#include <common/channel_id.h>
#include <common/crypto_state.h>
#include <common/node_id.h>
#include <common/pseudorand.h>
#include <common/wireaddr.h>

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
	size_t off;
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

/*~ We keep a hash table (ccan/htable) of peers, which tells us what peers are
 * already connected (by peer->id). */
struct peer {
	/* Main daemon */
	struct daemon *daemon;

	/* The pubkey of the node */
	struct node_id id;
	/* Counters and keys for symmetric crypto */
	struct crypto_state cs;

	/* Connection to the peer */
	struct io_conn *to_peer;

	/* Connections to the subdaemons */
	struct subd **subds;

	/* Final message to send to peer (and hangup) */
	u8 *final_msg;

	/* Set once lightningd says it's OK to close (subd tells it
	 * it's done). */
	bool ready_to_die;

	/* Has this ever been active?  (i.e. ever had a subd attached?) */
	bool active;

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

#if DEVELOPER
	bool dev_read_enabled;
	/* If non-NULL, this counts down; 0 means disable */
	u32 *dev_writes_enabled;
#endif
};

/*~ The HTABLE_DEFINE_TYPE() macro needs a keyof() function to extract the key:
 */
static const struct node_id *peer_keyof(const struct peer *peer)
{
	return &peer->id;
}

/*~ We also need to define a hashing function. siphash24 is a fast yet
 * cryptographic hash in ccan/crypto/siphash24; we might be able to get away
 * with a slightly faster hash with fewer guarantees, but it's good hygiene to
 * use this unless it's a proven bottleneck.  siphash_seed() is a function in
 * common/pseudorand which sets up a seed for our hashing; it's different
 * every time the program is run. */
static size_t node_id_hash(const struct node_id *id)
{
	return siphash24(siphash_seed(), id->k, sizeof(id->k));
}

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

/*~ This is an ad-hoc marshalling structure where we store arguments so we
 * can call peer_connected again. */
struct peer_reconnected {
	struct daemon *daemon;
	struct node_id id;
	struct wireaddr_internal addr;
	const struct wireaddr *remote_addr;
	struct crypto_state cs;
	const u8 *their_features;
	bool incoming;
};

static const struct node_id *
peer_reconnected_keyof(const struct peer_reconnected *pr)
{
	return &pr->id;
}

static bool peer_reconnected_eq_node_id(const struct peer_reconnected *pr,
					const struct node_id *id)
{
	return node_id_eq(&pr->id, id);
}

/*~ This defines 'struct peer_reconnected_htable'. */
HTABLE_DEFINE_TYPE(struct peer_reconnected,
		   peer_reconnected_keyof,
		   node_id_hash,
		   peer_reconnected_eq_node_id,
		   peer_reconnected_htable);

/*~ This is the global state, like `struct lightningd *ld` in lightningd. */
struct daemon {
	/* Who am I? */
	struct node_id id;

	/* pubkey equivalent. */
	struct pubkey mykey;

	/* Base for timeout timers, and how long to wait for init msg */
	struct timers timers;
	u32 timeout_secs;

	/* Peers that we've handed to `lightningd`, which it hasn't told us
	 * have disconnected. */
	struct peer_htable peers;

	/* Peers which have reconnected, waiting for us to kill existing conns */
	struct peer_reconnected_htable reconnected;

	/* Peers we are trying to reach */
	struct list_head connecting;

	/* Connection to main daemon. */
	struct daemon_conn *master;

	/* Connection to gossip daemon. */
	struct daemon_conn *gossipd;

	/* Allow localhost to be considered "public": DEVELOPER-only option,
	 * but for simplicity we don't #if DEVELOPER-wrap it here. */
	bool dev_allow_localhost;

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

	/* The gossip_store */
	int gossip_store_fd;
	size_t gossip_store_end;

	/* We only announce websocket addresses if !deprecated_apis */
	bool announce_websocket;

#if DEVELOPER
	/* Hack to speed up gossip timer */
	bool dev_fast_gossip;
	/* Hack to avoid ping timeouts */
	bool dev_no_ping_timer;
	/* Hack to no longer send gossip */
	bool dev_suppress_gossip;
#endif
};

/* Called by io_tor_connect once it has a connection out. */
struct io_plan *connection_out(struct io_conn *conn, struct connecting *connect);

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
			       bool incoming);

/* Called when peer->peer_conn is finally freed */
void peer_conn_closed(struct peer *peer);

#endif /* LIGHTNING_CONNECTD_CONNECTD_H */
