/*~ Welcome to the connect daemon: maintainer of connectivity!
 *
 * This is another separate daemon which is responsible for reaching out to
 * other peers, and also accepting their incoming connections.  It talks to
 * them for just long enough to validate their identity using a cryptographic
 * handshake, then receive and send supported feature sets; then it hands them
 * up to lightningd which will fire up a specific per-peer daemon to talk to
 * it.
 */
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/cast/cast.h>
#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/endian/endian.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/list/list.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/str/str.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <ccan/timer/timer.h>
#include <common/bech32.h>
#include <common/bech32_util.h>
#include <common/cryptomsg.h>
#include <common/daemon_conn.h>
#include <common/decode_array.h>
#include <common/ecdh_hsmd.h>
#include <common/errcode.h>
#include <common/features.h>
#include <common/jsonrpc_errors.h>
#include <common/memleak.h>
#include <common/ping.h>
#include <common/pseudorand.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/version.h>
#include <common/wire_error.h>
#include <common/wireaddr.h>
#include <connectd/connectd.h>
#include <connectd/connectd_gossipd_wiregen.h>
#include <connectd/connectd_wiregen.h>
#include <connectd/handshake.h>
#include <connectd/netaddress.h>
#include <connectd/peer_exchange_initmsg.h>
#include <connectd/tor.h>
#include <connectd/tor_autoservice.h>
#include <errno.h>
#include <gossipd/gossipd_wiregen.h>
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>
#include <lightningd/gossip_msg.h>
#include <netdb.h>
#include <netinet/in.h>
#include <secp256k1_ecdh.h>
#include <sodium.h>
#include <sodium/randombytes.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <wire/peer_wire.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>
#include <zlib.h>

/*~ We are passed two file descriptors when exec'ed from `lightningd`: the
 * first is a connection to `hsmd`, which we need for the cryptographic
 * handshake, and the second is to `gossipd`: it gathers network gossip and
 * thus may know how to reach certain peers. */
#define HSM_FD 3
#define GOSSIPCTL_FD 4

/*~ In C convention, constants are UPPERCASE macros.  Not everything needs to
 * be a constant, but it soothes the programmer's conscience to encapsulate
 * arbitrary decisions like these in one place. */
#define MAX_CONNECT_ATTEMPTS 10
#define INITIAL_WAIT_SECONDS	1
#define MAX_WAIT_SECONDS	300

/*~ We keep a hash table (ccan/htable) of public keys, which tells us what
 * peers are already connected.  The HTABLE_DEFINE_TYPE() macro needs a
 * keyof() function to extract the key.  For this simple use case, that's the
 * identity function: */
static const struct node_id *node_id_keyof(const struct node_id *pc)
{
	return pc;
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

/*~ This defines 'struct node_set' which contains 'struct node_id' pointers. */
HTABLE_DEFINE_TYPE(struct node_id,
		   node_id_keyof,
		   node_id_hash,
		   node_id_eq,
		   node_set);

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
	struct node_set peers;

	/* Peers we are trying to reach */
	struct list_head connecting;

	/* Connection to main daemon. */
	struct daemon_conn *master;

	/* Allow localhost to be considered "public": DEVELOPER-only option,
	 * but for simplicity we don't #if DEVELOPER-wrap it here. */
	bool dev_allow_localhost;

	/* We support use of a SOCKS5 proxy (e.g. Tor) */
	struct addrinfo *proxyaddr;

	/* They can tell us we must use proxy even for non-Tor addresses. */
	bool use_proxy_always;

	/* There are DNS seeds we can use to look up node addresses as a last
	 * resort, but doing so leaks our address so can be disabled. */
	bool use_dns;

	/* The address that the broken response returns instead of
	 * NXDOMAIN. NULL if we have not detected a broken resolver. */
	struct sockaddr *broken_resolver_response;

	/* File descriptors to listen on once we're activated. */
	struct listen_fd *listen_fds;

	/* Allow to define the default behavior of tor services calls*/
	bool use_v3_autotor;

	/* Our features, as lightningd told us */
	struct feature_set *our_features;
};

/* Peers we're trying to reach: we iterate through addrs until we succeed
 * or fail. */
struct connecting {
	/* daemon->connecting */
	struct list_node list;

	struct daemon *daemon;

	struct io_conn *conn;

	/* The ID of the peer (not necessarily unique, in transit!) */
	struct node_id id;

	/* We iterate through the tal_count(addrs) */
	size_t addrnum;
	struct wireaddr_internal *addrs;

	/* NULL if there wasn't a hint. */
	struct wireaddr_internal *addrhint;

	/* How far did we get? */
	const char *connstate;

	/* Accumulated errors */
	char *errors;

	/* How many seconds did we wait this time? */
	u32 seconds_waited;
};

/*~ C programs should generally be written bottom-to-top, with the root
 * function at the bottom, and functions it calls above it.  That avoids
 * us having to pre-declare functions; but in the case of mutual recursion
 * pre-declarations are necessary (also, sometimes we do it to avoid making
 * a patch hard to review with gratuitous reorganizations). */
static void try_connect_one_addr(struct connecting *connect);

/*~ Some ISP resolvers will reply with a dummy IP to queries that would otherwise
 * result in an NXDOMAIN reply. This just checks whether we have one such
 * resolver upstream and remembers its reply so we can try to filter future
 * dummies out.
 */
static bool broken_resolver(struct daemon *daemon)
{
	struct addrinfo *addrinfo;
	struct addrinfo hints;
	const char *hostname = "nxdomain-test.doesntexist";
	int err;

	/* If they told us to never do DNS queries, don't even do this one and also not if we just say that we don't */
	if (!daemon->use_dns || daemon->use_proxy_always) {
		daemon->broken_resolver_response = NULL;
		return false;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_ADDRCONFIG;
	err = getaddrinfo(hostname, tal_fmt(tmpctx, "%d", 42),
			  &hints, &addrinfo);

	/*~ Note the use of tal_dup here: it is a memdup for tal, but it's
	 * type-aware so it's less error-prone. */
	if (err == 0) {
		daemon->broken_resolver_response
			= tal_dup(daemon, struct sockaddr, addrinfo->ai_addr);
		freeaddrinfo(addrinfo);
	} else
		daemon->broken_resolver_response = NULL;

	return daemon->broken_resolver_response != NULL;
}

/*~ Here we see our first tal destructor: in this case the 'struct connect'
 * simply removes itself from the list of all 'connect' structs. */
static void destroy_connecting(struct connecting *connect)
{
	/*~ We don't *need* the list_head here; `list_del(&connect->list)`
	 * would work.  But we have access to it, and `list_del_from()` is
	 * clearer for readers, and also does a very brief sanity check that
	 * the list isn't already empty which catches a surprising number of
	 * bugs!  (If CCAN_LIST_DEBUG were defined, it would perform a
	 * complete list traverse to check it was in the list before
	 * deletion). */
	list_del_from(&connect->daemon->connecting, &connect->list);
}

/*~ Most simple search functions start with find_; in this case, search
 * for an existing attempt to connect the given peer id. */
static struct connecting *find_connecting(struct daemon *daemon,
					  const struct node_id *id)
{
	struct connecting *i;

	/*~ Note the node_id_eq function: this is generally preferred over
	 * doing a memcmp() manually, as it is both typesafe and can handle
	 * any padding which the C compiler is allowed to insert between
	 * members (unnecessary here, as there's no padding in a `struct
	 * node_id`). */
	list_for_each(&daemon->connecting, i, list)
		if (node_id_eq(id, &i->id))
			return i;
	return NULL;
}

/*~ Once we've connected out, we disable the callback which would cause us to
 * to try the next address. */
static void connected_out_to_peer(struct daemon *daemon,
				  struct io_conn *conn,
				  const struct node_id *id)
{
	struct connecting *connect = find_connecting(daemon, id);

	/* We allocate 'conn' as a child of 'connect': we don't want to free
	 * it just yet though.  tal_steal() it onto the permanent 'daemon'
	 * struct. */
	tal_steal(daemon, conn);

	/* We only allow one outgoing attempt at a time */
	assert(connect->conn == conn);

	/* Don't call destroy_io_conn, since we're done. */
	io_set_finish(conn, NULL, NULL);

	/* Now free the 'connecting' struct. */
	tal_free(connect);
}

/*~ Once they've connected in, stop trying to connect out (if we were). */
static void peer_connected_in(struct daemon *daemon,
			      struct io_conn *conn,
			      const struct node_id *id)
{
	struct connecting *connect = find_connecting(daemon, id);

	if (!connect)
		return;

	/* Don't call destroy_io_conn, since we're done. */
	io_set_finish(connect->conn, NULL, NULL);

	/* Now free the 'connecting' struct since we succeeded. */
	tal_free(connect);
}

/*~ Every per-peer daemon needs a connection to the gossip daemon; this allows
 * it to forward gossip to/from the peer.  The gossip daemon needs to know a
 * few of the features of the peer and its id (for reporting).
 *
 * Every peer also has read-only access to the gossip_store, which is handed
 * out by gossipd too, and also a "gossip_state" indicating where we're up to.
 *
 * 'features' is a field in the `init` message, indicating properties of the
 * node.
 */
static bool get_gossipfds(struct daemon *daemon,
			  const struct node_id *id,
			  const u8 *their_features,
			  struct per_peer_state *pps)
{
	bool gossip_queries_feature, initial_routing_sync, success;
	u8 *msg;

	/*~ The way features generally work is that both sides need to offer it;
	 * we always offer `gossip_queries`, but this check is explicit. */
	gossip_queries_feature
		= feature_negotiated(daemon->our_features, their_features,
				     OPT_GOSSIP_QUERIES);

	/*~ `initial_routing_sync` is supported by every node, since it was in
	 * the initial lightning specification: it means the peer wants the
	 * backlog of existing gossip. */
	initial_routing_sync
		= feature_offered(their_features, OPT_INITIAL_ROUTING_SYNC);

	/*~ We do this communication sync, since gossipd is our friend and
	 * it's easier.  If gossipd fails, we fail. */
	msg = towire_gossipd_new_peer(NULL, id, gossip_queries_feature,
				     initial_routing_sync);
	if (!wire_sync_write(GOSSIPCTL_FD, take(msg)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing to gossipctl: %s",
			      strerror(errno));

	msg = wire_sync_read(tmpctx, GOSSIPCTL_FD);
	if (!fromwire_gossipd_new_peer_reply(pps, msg, &success, &pps->gs))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed parsing msg gossipctl: %s",
			      tal_hex(tmpctx, msg));

	/* Gossipd might run out of file descriptors, so it tells us, and we
	 * give up on connecting this peer. */
	if (!success) {
		status_broken("Gossipd did not give us an fd: losing peer %s",
			      type_to_string(tmpctx, struct node_id, id));
		return false;
	}

	/* Otherwise, the next thing in the socket will be the file descriptors
	 * for the per-peer daemon. */
	pps->gossip_fd = fdpass_recv(GOSSIPCTL_FD);
	pps->gossip_store_fd = fdpass_recv(GOSSIPCTL_FD);
	return true;
}

/*~ This is an ad-hoc marshalling structure where we store arguments so we
 * can call peer_connected again. */
struct peer_reconnected {
	struct daemon *daemon;
	struct node_id id;
	struct wireaddr_internal addr;
	struct crypto_state cs;
	const u8 *their_features;
	bool incoming;
};

/*~ For simplicity, lightningd only ever deals with a single connection per
 * peer.  So if we already know about a peer, we tell lightning to disconnect
 * the old one and retry once it does. */
static struct io_plan *retry_peer_connected(struct io_conn *conn,
					    struct peer_reconnected *pr)
{
	struct io_plan *plan;

	/*~ As you can see, we've had issues with this code before :( */
	status_peer_debug(&pr->id, "processing now old peer gone");

	/*~ Usually the pattern is to return this directly, but we have to free
	 * our temporary structure. */
	plan = peer_connected(conn, pr->daemon, &pr->id, &pr->addr, &pr->cs,
			      take(pr->their_features), pr->incoming);
	tal_free(pr);
	return plan;
}

/*~ If we already know about this peer, we tell lightningd and it disconnects
 * the old one.  We wait until it tells us that's happened. */
static struct io_plan *peer_reconnected(struct io_conn *conn,
					struct daemon *daemon,
					const struct node_id *id,
					const struct wireaddr_internal *addr,
					const struct crypto_state *cs,
					const u8 *their_features TAKES,
					bool incoming)
{
	u8 *msg;
	struct peer_reconnected *pr;

	status_peer_debug(id, "reconnect");

	/* Tell master to kill it: will send peer_disconnect */
	msg = towire_connectd_reconnected(NULL, id);
	daemon_conn_send(daemon->master, take(msg));

	/* Save arguments for next time. */
	pr = tal(daemon, struct peer_reconnected);
	pr->daemon = daemon;
	pr->id = *id;
	pr->cs = *cs;
	pr->addr = *addr;
	pr->incoming = incoming;

	/*~ Note that tal_dup_talarr() will do handle the take() of features
	 * (turning it into a simply tal_steal() in those cases). */
	pr->their_features = tal_dup_talarr(pr, u8, their_features);

	/*~ ccan/io supports waiting on an address: in this case, the key in
	 * the peer set.  When someone calls `io_wake()` on that address, it
	 * will call retry_peer_connected above. */
	return io_wait(conn, node_set_get(&daemon->peers, id),
			/*~ The notleak() wrapper is a DEVELOPER-mode hack so
			 * that our memory leak detection doesn't consider 'pr'
			 * (which is not referenced from our code) to be a
			 * memory leak. */
		       retry_peer_connected, notleak(pr));
}

/*~ Note the lack of static: this is called by peer_exchange_initmsg.c once the
 * INIT messages are exchanged, and also by the retry code above. */
struct io_plan *peer_connected(struct io_conn *conn,
			       struct daemon *daemon,
			       const struct node_id *id,
			       const struct wireaddr_internal *addr,
			       struct crypto_state *cs,
			       const u8 *their_features TAKES,
			       bool incoming)
{
	u8 *msg;
	struct per_peer_state *pps;
	int unsup;
	size_t depender, missing;

	if (node_set_get(&daemon->peers, id))
		return peer_reconnected(conn, daemon, id, addr, cs,
					their_features, incoming);

	/* We promised we'd take it by marking it TAKEN above; prepare to free it. */
	if (taken(their_features))
		tal_steal(tmpctx, their_features);

	/* BOLT #1:
	 *
	 * The receiving node:
	 * ...
	 *  - upon receiving unknown _odd_ feature bits that are non-zero:
	 *    - MUST ignore the bit.
	 *  - upon receiving unknown _even_ feature bits that are non-zero:
	 *    - MUST fail the connection.
	 */
	unsup = features_unsupported(daemon->our_features, their_features,
				     INIT_FEATURE);
	if (unsup != -1) {
		msg = towire_warningfmt(NULL, NULL, "Unsupported feature %u",
					unsup);
		msg = cryptomsg_encrypt_msg(tmpctx, cs, take(msg));
		return io_write(conn, msg, tal_count(msg), io_close_cb, NULL);
	}

	if (!feature_check_depends(their_features, &depender, &missing)) {
		msg = towire_warningfmt(NULL, NULL,
				      "Feature %zu requires feature %zu",
				      depender, missing);
		msg = cryptomsg_encrypt_msg(tmpctx, cs, take(msg));
		return io_write(conn, msg, tal_count(msg), io_close_cb, NULL);
	}

	/* We've successfully connected. */
	if (incoming)
		peer_connected_in(daemon, conn, id);
	else
		connected_out_to_peer(daemon, conn, id);

	if (find_connecting(daemon, id))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "After %s connection on %p, still trying to connect conn %p?",
			      incoming ? "incoming" : "outgoing",
			      conn, find_connecting(daemon, id)->conn);

	/* This contains the per-peer state info; gossipd fills in pps->gs */
	pps = new_per_peer_state(tmpctx, cs);

	/* If gossipd can't give us a file descriptor, we give up connecting. */
	if (!get_gossipfds(daemon, id, their_features, pps))
		return io_close(conn);

	/* Create message to tell master peer has connected. */
	msg = towire_connectd_peer_connected(NULL, id, addr, incoming,
					     pps, their_features);

	/*~ daemon_conn is a message queue for inter-daemon communication: we
	 * queue up the `connect_peer_connected` message to tell lightningd
	 * we have connected, and give the peer and gossip fds. */
	daemon_conn_send(daemon->master, take(msg));
	/* io_conn_fd() extracts the fd from ccan/io's io_conn */
	daemon_conn_send_fd(daemon->master, io_conn_fd(conn));
	daemon_conn_send_fd(daemon->master, pps->gossip_fd);
	daemon_conn_send_fd(daemon->master, pps->gossip_store_fd);

	/* Don't try to close these on freeing. */
	pps->gossip_store_fd = pps->gossip_fd = -1;

	/*~ Finally, we add it to the set of pubkeys: tal_dup will handle
	 * take() args for us, by simply tal_steal()ing it. */
	node_set_add(&daemon->peers, tal_dup(daemon, struct node_id, id));

	/*~ We want to free the connection, but not close the fd (which is
	 * queued to go to lightningd), so use this variation on io_close: */
	return io_close_taken_fd(conn);
}

/*~ handshake.c's handles setting up the crypto state once we get a connection
 * in; we hand it straight to peer_exchange_initmsg() to send and receive INIT
 * and call peer_connected(). */
static struct io_plan *handshake_in_success(struct io_conn *conn,
					    const struct pubkey *id_key,
					    const struct wireaddr_internal *addr,
					    struct crypto_state *cs,
					    struct daemon *daemon)
{
	struct node_id id;
	node_id_from_pubkey(&id, id_key);
	status_peer_debug(&id, "Connect IN");
	return peer_exchange_initmsg(conn, daemon, daemon->our_features,
				     cs, &id, addr, true);
}

/*~ If the timer goes off, we simply free everything, which hangs up. */
static void conn_timeout(struct io_conn *conn)
{
	status_debug("conn timed out");
	errno = ETIMEDOUT;
	io_close(conn);
}

/*~ When we get a connection in we set up its network address then call
 * handshake.c to set up the crypto state. */
static struct io_plan *connection_in(struct io_conn *conn, struct daemon *daemon)
{
	struct wireaddr_internal addr;
	struct sockaddr_storage s = {};
	socklen_t len = sizeof(s);

	/* The cast here is a weird Berkeley sockets API feature... */
	if (getpeername(io_conn_fd(conn), (struct sockaddr *)&s, &len) != 0) {
		status_debug("Failed to get peername for incoming conn: %s",
			     strerror(errno));
		return io_close(conn);
	}

	if (s.ss_family == AF_INET6) {
		struct sockaddr_in6 *s6 = (void *)&s;
		addr.itype = ADDR_INTERNAL_WIREADDR;
		wireaddr_from_ipv6(&addr.u.wireaddr,
				   &s6->sin6_addr, ntohs(s6->sin6_port));
	} else if (s.ss_family == AF_INET) {
		struct sockaddr_in *s4 = (void *)&s;
		addr.itype = ADDR_INTERNAL_WIREADDR;
		wireaddr_from_ipv4(&addr.u.wireaddr,
				   &s4->sin_addr, ntohs(s4->sin_port));
	} else if (s.ss_family == AF_UNIX) {
		struct sockaddr_un *sun = (void *)&s;
		addr.itype = ADDR_INTERNAL_SOCKNAME;
		memcpy(addr.u.sockname, sun->sun_path, sizeof(sun->sun_path));
	} else {
		status_broken("Unknown socket type %i for incoming conn",
			      s.ss_family);
		return io_close(conn);
	}

	/* If they don't complete handshake in reasonable time, hang up */
	notleak(new_reltimer(&daemon->timers, conn,
			     time_from_sec(daemon->timeout_secs),
			     conn_timeout, conn));

	/*~ The crypto handshake differs depending on whether you received or
	 * initiated the socket connection, so there are two entry points.
	 * Note, again, the notleak() to avoid our simplistic leak detection
	 * code from thinking `conn` (which we don't keep a pointer to) is
	 * leaked */
	return responder_handshake(notleak(conn), &daemon->mykey, &addr,
				   handshake_in_success, daemon);
}

/*~ These are the mirror functions for the connecting-out case. */
static struct io_plan *handshake_out_success(struct io_conn *conn,
					     const struct pubkey *key,
					     const struct wireaddr_internal *addr,
					     struct crypto_state *cs,
					     struct connecting *connect)
{
	struct node_id id;

	node_id_from_pubkey(&id, key);
	connect->connstate = "Exchanging init messages";
	status_peer_debug(&id, "Connect OUT");
	return peer_exchange_initmsg(conn, connect->daemon,
				     connect->daemon->our_features,
				     cs, &id, addr, false);
}

struct io_plan *connection_out(struct io_conn *conn, struct connecting *connect)
{
	struct pubkey outkey;

	/* This shouldn't happen: lightningd should not give invalid ids! */
	if (!pubkey_from_node_id(&outkey, &connect->id)) {
		status_broken("Connection out to invalid id %s",
			      type_to_string(tmpctx, struct node_id,
					     &connect->id));
		return io_close(conn);
	}

	/* If they don't complete handshake in reasonable time, hang up */
	notleak(new_reltimer(&connect->daemon->timers, conn,
			     time_from_sec(connect->daemon->timeout_secs),
			     conn_timeout, conn));
	status_peer_debug(&connect->id, "Connected out, starting crypto");

	connect->connstate = "Cryptographic handshake";
	return initiator_handshake(conn, &connect->daemon->mykey, &outkey,
				   &connect->addrs[connect->addrnum],
				   handshake_out_success, connect);
}

/*~ When we've exhausted all addresses without success, we come here.
 *
 * Note that gcc gets upset if we put the PRINTF_FMT at the end like this if
 * it's an actual function definition, but etags gets confused and ignores the
 * rest of the file if we put PRINTF_FMT at the front.  So we put it at the
 * end, in a gratuitous declaration.
 */
static void connect_failed(struct daemon *daemon,
			   const struct node_id *id,
			   u32 seconds_waited,
			   const struct wireaddr_internal *addrhint,
			   errcode_t errcode,
			   const char *errfmt, ...)
	PRINTF_FMT(6,7);

static void connect_failed(struct daemon *daemon,
			   const struct node_id *id,
			   u32 seconds_waited,
			   const struct wireaddr_internal *addrhint,
			   errcode_t errcode,
			   const char *errfmt, ...)
{
	u8 *msg;
	va_list ap;
	char *errmsg;
	u32 wait_seconds;

	va_start(ap, errfmt);
	errmsg = tal_vfmt(tmpctx, errfmt, ap);
	va_end(ap);

	/* Wait twice as long to reconnect, between min and max. */
	wait_seconds = seconds_waited * 2;
	if (wait_seconds > MAX_WAIT_SECONDS)
		wait_seconds = MAX_WAIT_SECONDS;
	if (wait_seconds < INITIAL_WAIT_SECONDS)
		wait_seconds = INITIAL_WAIT_SECONDS;

	/* lightningd may have a connect command waiting to know what
	 * happened.  We leave it to lightningd to decide if it wants to try
	 * again, with the wait_seconds as a hint of how long before
	 * asking. */
	msg = towire_connectd_connect_failed(NULL, id, errcode, errmsg,
					       wait_seconds, addrhint);
	daemon_conn_send(daemon->master, take(msg));

	status_peer_debug(id, "Failed connected out: %s", errmsg);
}

/* add errors to error list */
void add_errors_to_error_list(struct connecting *connect, const char *error)
{
	tal_append_fmt(&connect->errors,
		       "%s. ", error);
}

/*~ This is the destructor for the (unsuccessful) outgoing connection.  We accumulate
 * the errors which occurred, so we can report to lightningd properly in case
 * they all fail, and try the next address.
 *
 * This is a specialized form of destructor which takes an extra argument;
 * it set up by either the creatively-named tal_add_destructor2(), or by
 * the ccan/io's io_set_finish() on a connection. */
static void destroy_io_conn(struct io_conn *conn, struct connecting *connect)
{
	/*~ tal_append_fmt appends to a tal string.  It's terribly convenient */
	const char *errstr = strerror(errno);
	/* errno 0 means they hung up on us. */
	if (errno == 0) {
		errstr = "peer closed connection";
		if (streq(connect->connstate, "Cryptographic handshake"))
			errstr = "peer closed connection (wrong key?)";
	}

	add_errors_to_error_list(connect,
		       tal_fmt(tmpctx, "%s: %s: %s",
		       type_to_string(tmpctx, struct wireaddr_internal,
				      &connect->addrs[connect->addrnum]),
		       connect->connstate, errstr));
	connect->addrnum++;
	try_connect_one_addr(connect);
}

/* This initializes a fresh io_conn by setting it to io_connect to the
 * destination */
static struct io_plan *conn_init(struct io_conn *conn,
				 struct connecting *connect)
{
	/*~ I generally dislike the pattern of "set to NULL, assert if NULL at
	 * bottom".  On -O2 and above the compiler will warn you at compile time
	 * if a there is a path by which the variable is not set, which is always
	 * preferable to a runtime assertion.  In this case, it's the best way
	 * to use the "enum in a switch" trick to make sure we handle all enum
	 * cases, so I use it. */
	struct addrinfo *ai = NULL;
	const struct wireaddr_internal *addr = &connect->addrs[connect->addrnum];

	switch (addr->itype) {
	case ADDR_INTERNAL_SOCKNAME:
		ai = wireaddr_internal_to_addrinfo(tmpctx, addr);
		break;
	case ADDR_INTERNAL_ALLPROTO:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't connect to all protocols");
		break;
	case ADDR_INTERNAL_AUTOTOR:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't connect to autotor address");
		break;
	case ADDR_INTERNAL_STATICTOR:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't connect to statictor address");
		break;
	case ADDR_INTERNAL_FORPROXY:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't connect to forproxy address");
		break;
	case ADDR_INTERNAL_WIREADDR:
		/* If it was a Tor address, we wouldn't be here. */
		ai = wireaddr_to_addrinfo(tmpctx, &addr->u.wireaddr);
		break;
	}
	assert(ai);

	io_set_finish(conn, destroy_io_conn, connect);
	return io_connect(conn, ai, connection_out, connect);
}

/* This initializes a fresh io_conn by setting it to io_connect to the
 * SOCKS proxy, as handled in tor.c. */
static struct io_plan *conn_proxy_init(struct io_conn *conn,
				       struct connecting *connect)
{
	const char *host = NULL;
	u16 port;
	const struct wireaddr_internal *addr = &connect->addrs[connect->addrnum];

	switch (addr->itype) {
	case ADDR_INTERNAL_FORPROXY:
		host = addr->u.unresolved.name;
		port = addr->u.unresolved.port;
		break;
	case ADDR_INTERNAL_WIREADDR:
		host = fmt_wireaddr_without_port(tmpctx, &addr->u.wireaddr);
		port = addr->u.wireaddr.port;
		break;
	case ADDR_INTERNAL_SOCKNAME:
	case ADDR_INTERNAL_ALLPROTO:
	case ADDR_INTERNAL_AUTOTOR:
	case ADDR_INTERNAL_STATICTOR:
		break;
	}

	if (!host)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't connect to %u address", addr->itype);

	io_set_finish(conn, destroy_io_conn, connect);
	return io_tor_connect(conn, connect->daemon->proxyaddr, host, port,
			      connect);
}

/*~ This is the routine which tries to connect. */
static void try_connect_one_addr(struct connecting *connect)
{
 	int fd, af;
	bool use_proxy = connect->daemon->use_proxy_always;
	const struct wireaddr_internal *addr = &connect->addrs[connect->addrnum];
	struct io_conn *conn;

	/* In case we fail without a connection, make destroy_io_conn happy */
	connect->conn = NULL;

	/* Out of addresses? */
	if (connect->addrnum == tal_count(connect->addrs)) {
		connect_failed(connect->daemon, &connect->id,
			       connect->seconds_waited,
			       connect->addrhint, CONNECT_ALL_ADDRESSES_FAILED,
			       "%s", connect->errors);
		tal_free(connect);
		return;
	}

 	/* Might not even be able to create eg. IPv6 sockets */
 	af = -1;

	switch (addr->itype) {
	case ADDR_INTERNAL_SOCKNAME:
		af = AF_LOCAL;
		/* Local sockets don't use tor proxy */
		use_proxy = false;
		break;
	case ADDR_INTERNAL_ALLPROTO:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't connect ALLPROTO");
	case ADDR_INTERNAL_AUTOTOR:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't connect AUTOTOR");
	case ADDR_INTERNAL_STATICTOR:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't connect STATICTOR");
	case ADDR_INTERNAL_FORPROXY:
		use_proxy = true;
		break;
	case ADDR_INTERNAL_WIREADDR:
		switch (addr->u.wireaddr.type) {
		case ADDR_TYPE_TOR_V2:
		case ADDR_TYPE_TOR_V3:
			use_proxy = true;
			break;
		case ADDR_TYPE_IPV4:
			af = AF_INET;
			break;
		case ADDR_TYPE_IPV6:
			af = AF_INET6;
			break;
		}
	}

	/* If we have to use proxy but we don't have one, we fail. */
	if (use_proxy) {
		if (!connect->daemon->proxyaddr) {
			status_debug("Need proxy");
			af = -1;
		} else
			af = connect->daemon->proxyaddr->ai_family;
	}

	if (af == -1) {
		fd = -1;
		errno = EPROTONOSUPPORT;
	} else
		fd = socket(af, SOCK_STREAM, 0);

	/* We might not have eg. IPv6 support, or it might be an onion addr
	 * and we have no proxy. */
	if (fd < 0) {
		tal_append_fmt(&connect->errors,
			       "%s: opening %i socket gave %s. ",
			       type_to_string(tmpctx, struct wireaddr_internal,
					      addr),
			       af, strerror(errno));
		/* This causes very limited recursion. */
		connect->addrnum++;
		try_connect_one_addr(connect);
		return;
	}

	/* This creates the new connection using our fd, with the initialization
	 * function one of the above. */
	if (use_proxy)
		conn = io_new_conn(connect, fd, conn_proxy_init, connect);
	else
		conn = io_new_conn(connect, fd, conn_init, connect);

	/* Careful!  io_new_conn can fail (immediate connect() failure), and
	 * that frees connect. */
	if (conn)
		connect->conn = conn;
}

/*~ connectd is responsible for incoming connections, but it's the process of
 * setting up the listening ports which gives us information we need for startup
 * (such as our own address).  So we perform setup in two phases: first we bind
 * the sockets according to the command line arguments (if any), then we start
 * listening for connections to them once lightningd is ready.
 *
 * This stores the fds we're going to listen on: */
struct listen_fd {
	int fd;
	/* If we bind() IPv6 then IPv4 to same port, we *may* fail to listen()
	 * on the IPv4 socket: under Linux, by default, the IPv6 listen()
	 * covers IPv4 too.  Normally we'd consider failing to listen on a
	 * port to be fatal, so we note this when setting up addresses. */
	bool mayfail;
};

static void add_listen_fd(struct daemon *daemon, int fd, bool mayfail)
{
	/*~ utils.h contains a convenience macro tal_arr_expand which
	 * reallocates a tal_arr to make it one longer, then returns a pointer
	 * to the (new) last element. */
	struct listen_fd l;
	l.fd = fd;
	l.mayfail = mayfail;
	tal_arr_expand(&daemon->listen_fds, l);
}

/*~ Helper routine to create and bind a socket of a given type; like many
 * daemons we set it SO_REUSEADDR so we won't have to wait 2 minutes to reuse
 * it on restart.
 *
 * I generally avoid "return -1 on error", but for file-descriptors it's the
 * UNIX standard, so it's not as offensive here as it would be in other
 * contexts.
 */
static int make_listen_fd(int domain, void *addr, socklen_t len, bool mayfail)
{
	int fd = socket(domain, SOCK_STREAM, 0);
	int on = 1;

	if (fd < 0) {
		if (!mayfail)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Failed to create %u socket: %s",
				      domain, strerror(errno));
		status_debug("Failed to create %u socket: %s",
			     domain, strerror(errno));
		return -1;
	}


	/* Re-use, please.. */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
		status_unusual("Failed setting socket reuse: %s",
			       strerror(errno));

	if (bind(fd, addr, len) != 0) {
		if (!mayfail)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Failed to bind on %u socket: %s",
				      domain, strerror(errno));
		status_debug("Failed to create %u socket: %s",
			     domain, strerror(errno));
		goto fail;
	}

	return fd;

fail:
	/*~ ccan/noerr contains convenient routines which don't clobber the
	 * errno global; in this case, the caller can report errno. */
	close_noerr(fd);
	return -1;
}

/* Return true if it created socket successfully. */
static bool handle_wireaddr_listen(struct daemon *daemon,
				   const struct wireaddr *wireaddr,
				   bool mayfail)
{
	int fd;
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;

	/* Note the use of a switch() over enum here, even though it must be
	 * IPv4 or IPv6 here; that will catch future changes. */
	switch (wireaddr->type) {
	case ADDR_TYPE_IPV4:
		wireaddr_to_ipv4(wireaddr, &addr);
		/* We might fail if IPv6 bound to port first */
		fd = make_listen_fd(AF_INET, &addr, sizeof(addr), mayfail);
		if (fd >= 0) {
			status_debug("Created IPv4 listener on port %u",
				     wireaddr->port);
			add_listen_fd(daemon, fd, mayfail);
			return true;
		}
		return false;
	case ADDR_TYPE_IPV6:
		wireaddr_to_ipv6(wireaddr, &addr6);
		fd = make_listen_fd(AF_INET6, &addr6, sizeof(addr6), mayfail);
		if (fd >= 0) {
			status_debug("Created IPv6 listener on port %u",
				     wireaddr->port);
			add_listen_fd(daemon, fd, mayfail);
			return true;
		}
		return false;
	case ADDR_TYPE_TOR_V2:
	case ADDR_TYPE_TOR_V3:
		break;
	}
	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "Invalid listener wireaddress type %u", wireaddr->type);
}

/* If it's a wildcard, turns it into a real address pointing to internet */
static bool public_address(struct daemon *daemon, struct wireaddr *wireaddr)
{
	if (wireaddr_is_wildcard(wireaddr)) {
		if (!guess_address(wireaddr))
			return false;
	}

	/* --dev-allow-localhost treats the localhost as "public" for testing */
	return address_routable(wireaddr, daemon->dev_allow_localhost);
}

static void add_announcable(struct wireaddr **announcable,
			    const struct wireaddr *addr)
{
	tal_arr_expand(announcable, *addr);
}

static void add_binding(struct wireaddr_internal **binding,
			const struct wireaddr_internal *addr)
{
	tal_arr_expand(binding, *addr);
}

/*~ ccan/asort provides a type-safe sorting function; it requires a comparison
 * function, which takes an optional extra argument which is usually unused as
 * here, but deeply painful if you need it and don't have it! */
static int wireaddr_cmp_type(const struct wireaddr *a,
			     const struct wireaddr *b, void *unused)
{
	/* This works, but of course it's inefficient.  We don't
	 * really care, since it's called only once at startup. */
	u8 *a_wire = tal_arr(tmpctx, u8, 0), *b_wire = tal_arr(tmpctx, u8, 0);
	int cmp, minlen;

	towire_wireaddr(&a_wire, a);
	towire_wireaddr(&b_wire, b);

	minlen = tal_bytelen(a_wire) < tal_bytelen(b_wire)
		? tal_bytelen(a_wire) : tal_bytelen(b_wire);
	cmp = memcmp(a_wire, b_wire, minlen);
	/* On a tie, shorter one goes first. */
	if (cmp == 0)
		return tal_bytelen(a_wire) - tal_bytelen(b_wire);
	return cmp;
}

/*~ The user can specify three kinds of addresses: ones we bind to but don't
 * announce, ones we announce but don't bind to, and ones we bind to and
 * announce if they seem to be public addresses.
 *
 * This routine sorts out the mess: it populates the daemon->announcable array,
 * and returns the addresses we bound to (by convention, return is allocated
 * off `ctx` argument).
 */
static struct wireaddr_internal *setup_listeners(const tal_t *ctx,
						 struct daemon *daemon,
						 /* The proposed address. */
						 const struct wireaddr_internal *proposed_wireaddr,
						 /* For each one, listen,
						    announce or both */
						 const enum addr_listen_announce *proposed_listen_announce,
						 const char *tor_password,
						 struct wireaddr **announcable)
{
	struct sockaddr_un addrun;
	int fd;
	struct wireaddr_internal *binding;
	const u8 *blob = NULL;
	struct secret random;
	struct pubkey pb;
	struct wireaddr *toraddr;

	/* Start with empty arrays, for tal_arr_expand() */
	binding = tal_arr(ctx, struct wireaddr_internal, 0);
	*announcable = tal_arr(ctx, struct wireaddr, 0);

	/* Add addresses we've explicitly been told to *first*: implicit
	 * addresses will be discarded then if we have multiple. */
	for (size_t i = 0; i < tal_count(proposed_wireaddr); i++) {
		struct wireaddr_internal wa = proposed_wireaddr[i];

		/* We want announce-only addresses. */
		if (proposed_listen_announce[i] & ADDR_LISTEN)
			continue;

		assert(proposed_listen_announce[i] & ADDR_ANNOUNCE);
		/* You can only announce wiretypes, not internal formats! */
		assert(proposed_wireaddr[i].itype
		       == ADDR_INTERNAL_WIREADDR);
		add_announcable(announcable, &wa.u.wireaddr);
	}

	/* Now look for listening addresses. */
	for (size_t i = 0; i < tal_count(proposed_wireaddr); i++) {
		struct wireaddr_internal wa = proposed_wireaddr[i];
		bool announce = (proposed_listen_announce[i] & ADDR_ANNOUNCE);
		if (!(proposed_listen_announce[i] & ADDR_LISTEN))
			continue;

		switch (wa.itype) {
		/* We support UNIX domain sockets, but can't announce */
		case ADDR_INTERNAL_SOCKNAME:
			addrun.sun_family = AF_UNIX;
			memcpy(addrun.sun_path, wa.u.sockname,
			       sizeof(addrun.sun_path));
			/* Remove any existing one. */
			unlink(wa.u.sockname);
			fd = make_listen_fd(AF_UNIX, &addrun, sizeof(addrun),
					    false);
			status_debug("Created socket listener on file %s",
				     addrun.sun_path);
			add_listen_fd(daemon, fd, false);
			/* We don't announce socket names, though we allow
			 * them to lazily specify --addr=/socket. */
			add_binding(&binding, &wa);
			continue;
		case ADDR_INTERNAL_AUTOTOR:
			/* We handle these after we have all bindings. */
			continue;
		case ADDR_INTERNAL_STATICTOR:
			/* We handle these after we have all bindings. */
			continue;
		/* Special case meaning IPv6 and IPv4 */
		case ADDR_INTERNAL_ALLPROTO: {
			bool ipv6_ok;

			wa.itype = ADDR_INTERNAL_WIREADDR;
			wa.u.wireaddr.port = wa.u.port;

			/* First, create wildcard IPv6 address. */
			wa.u.wireaddr.type = ADDR_TYPE_IPV6;
			wa.u.wireaddr.addrlen = 16;
			memset(wa.u.wireaddr.addr, 0,
			       sizeof(wa.u.wireaddr.addr));

			ipv6_ok = handle_wireaddr_listen(daemon, &wa.u.wireaddr,
							 true);
			if (ipv6_ok) {
				add_binding(&binding, &wa);
				if (announce
				    && public_address(daemon, &wa.u.wireaddr))
					add_announcable(announcable,
							&wa.u.wireaddr);
			}

			/* Now, create wildcard IPv4 address. */
			wa.u.wireaddr.type = ADDR_TYPE_IPV4;
			wa.u.wireaddr.addrlen = 4;
			memset(wa.u.wireaddr.addr, 0,
			       sizeof(wa.u.wireaddr.addr));
			/* OK if this fails, as long as one succeeds! */
			if (handle_wireaddr_listen(daemon, &wa.u.wireaddr,
						   ipv6_ok)) {
				add_binding(&binding, &wa);
				if (announce
				    && public_address(daemon, &wa.u.wireaddr))
					add_announcable(announcable,
							&wa.u.wireaddr);
			}
			continue;
		}
		/* This is a vanilla wireaddr as per BOLT #7 */
		case ADDR_INTERNAL_WIREADDR:
			handle_wireaddr_listen(daemon, &wa.u.wireaddr, false);
			add_binding(&binding, &wa);
			if (announce && public_address(daemon, &wa.u.wireaddr))
				add_announcable(announcable, &wa.u.wireaddr);
			continue;
		case ADDR_INTERNAL_FORPROXY:
			break;
		}
		/* Shouldn't happen. */
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Invalid listener address type %u",
			      proposed_wireaddr[i].itype);
	}

	/* Now we have bindings, set up any Tor auto addresses: we will point
	 * it at the first bound IPv4 or IPv6 address we have. */
	for (size_t i = 0; i < tal_count(proposed_wireaddr); i++) {
		if (!(proposed_listen_announce[i] & ADDR_LISTEN))
			continue;
		if (proposed_wireaddr[i].itype != ADDR_INTERNAL_AUTOTOR)
			continue;
		toraddr = tor_autoservice(tmpctx,
					  &proposed_wireaddr[i],
					  tor_password,
					  binding,
					  daemon->use_v3_autotor);

		if (!(proposed_listen_announce[i] & ADDR_ANNOUNCE)) {
			continue;
		};
		add_announcable(announcable, toraddr);
	}

	/* Now we have bindings, set up any Tor static addresses: we will point
	 * it at the first bound IPv4 or IPv6 address we have. */
	for (size_t i = 0; i < tal_count(proposed_wireaddr); i++) {
		if (!(proposed_listen_announce[i] & ADDR_LISTEN))
			continue;
		if (proposed_wireaddr[i].itype != ADDR_INTERNAL_STATICTOR)
			continue;
		blob = proposed_wireaddr[i].u.torservice.blob;

		if (tal_strreg(tmpctx, (char *)proposed_wireaddr[i].u.torservice.blob, STATIC_TOR_MAGIC_STRING)) {
			if (pubkey_from_node_id(&pb, &daemon->id)) {
				if (sodium_mlock(&random, sizeof(random)) != 0)
						status_failed(STATUS_FAIL_INTERNAL_ERROR,
									"Could not lock the random prf key memory.");
				randombytes_buf((void * const)&random, 32);
				/* generate static tor node address, take first 32 bytes from secret of node_id plus 32 random bytes from sodiom */
				struct sha256 sha;
				struct secret ss;

				ecdh(&pb, &ss);
				/* let's sha, that will clear ctx of hsm data */
				sha256(&sha, &ss, 32);
				/* even if it's a secret pub derived, tor shall see only the single sha */
				memcpy((void *)&blob[0], &sha, 32);
				memcpy((void *)&blob[32], &random, 32);
				/* clear our temp buffer, don't leak by extern libs core-dumps, our blob we/tal handle later */
				sodium_munlock(&random, sizeof(random));

			} else status_failed(STATUS_FAIL_INTERNAL_ERROR,
							"Could not get the pub of our node id from hsm");
		}

		toraddr = tor_fixed_service(tmpctx,
					    &proposed_wireaddr[i],
					    tor_password,
					    blob,
					    find_local_address(binding),
					    0);
		/* get rid of blob data on our side of tor and add jitter */
		randombytes_buf((void * const)proposed_wireaddr[i].u.torservice.blob, TOR_V3_BLOBLEN);

		if (!(proposed_listen_announce[i] & ADDR_ANNOUNCE)) {
				continue;
		};
		add_announcable(announcable, toraddr);
	}

	/*~ The spec used to ban more than one address of each type, but
	 * nobody could remember exactly why, so now that's allowed. */
	/* BOLT #7:
	 *
	 * The origin node:
	 *...
	 *   - MUST place address descriptors in ascending order.
	 */
	asort(*announcable, tal_count(*announcable), wireaddr_cmp_type, NULL);

	return binding;
}


/*~ Parse the incoming connect init message from lightningd ("master") and
 * assign config variables to the daemon; it should be the first message we
 * get. */
static struct io_plan *connect_init(struct io_conn *conn,
				    struct daemon *daemon,
				    const u8 *msg)
{
	struct wireaddr *proxyaddr;
	struct wireaddr_internal *binding;
	struct wireaddr_internal *proposed_wireaddr;
	enum addr_listen_announce *proposed_listen_announce;
	struct wireaddr *announcable;
	char *tor_password;

	/* Fields which require allocation are allocated off daemon */
	if (!fromwire_connectd_init(
		daemon, msg,
		&chainparams,
		&daemon->our_features,
		&daemon->id,
		&proposed_wireaddr,
		&proposed_listen_announce,
		&proxyaddr, &daemon->use_proxy_always,
		&daemon->dev_allow_localhost, &daemon->use_dns,
		&tor_password,
		&daemon->use_v3_autotor,
		    &daemon->timeout_secs)) {
		/* This is a helper which prints the type expected and the actual
		 * message, then exits (it should never be called!). */
		master_badmsg(WIRE_CONNECTD_INIT, msg);
	}

	if (!pubkey_from_node_id(&daemon->mykey, &daemon->id))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Invalid id for me %s",
			      type_to_string(tmpctx, struct node_id,
					     &daemon->id));

	/* Resolve Tor proxy address if any: we need an addrinfo to connect()
	 * to. */
	if (proxyaddr) {
		status_debug("Proxy address: %s",
			     fmt_wireaddr(tmpctx, proxyaddr));
		daemon->proxyaddr = wireaddr_to_addrinfo(daemon, proxyaddr);
		tal_free(proxyaddr);
	} else
		daemon->proxyaddr = NULL;

	if (broken_resolver(daemon)) {
		status_debug("Broken DNS resolver detected, will check for "
			     "dummy replies");
	}

	/* Figure out our addresses. */
	binding = setup_listeners(tmpctx, daemon,
				  proposed_wireaddr,
				  proposed_listen_announce,
				  tor_password,
				  &announcable);

	/* Free up old allocations */
	tal_free(proposed_wireaddr);
	tal_free(proposed_listen_announce);
	tal_free(tor_password);

	/* Tell it we're ready, handing it the addresses we have. */
	daemon_conn_send(daemon->master,
			 take(towire_connectd_init_reply(NULL,
							   binding,
							   announcable)));

	/* Read the next message. */
	return daemon_conn_read_next(conn, daemon->master);
}

/*~ lightningd tells us to go! */
static struct io_plan *connect_activate(struct io_conn *conn,
					struct daemon *daemon,
					const u8 *msg)
{
	bool do_listen;

	if (!fromwire_connectd_activate(msg, &do_listen))
		master_badmsg(WIRE_CONNECTD_ACTIVATE, msg);

	/* If we're --offline, lightningd tells us not to actually listen. */
	if (do_listen) {
		for (size_t i = 0; i < tal_count(daemon->listen_fds); i++) {
			/* On Linux, at least, we may bind to all addresses
			 * for IPv4 and IPv6, but we'll fail to listen. */
			if (listen(daemon->listen_fds[i].fd, 64) != 0) {
				if (daemon->listen_fds[i].mayfail)
					continue;
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "Failed to listen on socket: %s",
					      strerror(errno));
			}
			notleak(io_new_listener(daemon,
						daemon->listen_fds[i].fd,
						connection_in, daemon));
		}
	}
	/* Free, with NULL assignment just as an extra sanity check. */
	daemon->listen_fds = tal_free(daemon->listen_fds);

	/* OK, we're ready! */
	daemon_conn_send(daemon->master,
			 take(towire_connectd_activate_reply(NULL)));
	return daemon_conn_read_next(conn, daemon->master);
}

/* BOLT #10:
 *
 * The DNS seed:
 *   ...
 *   - upon receiving a _node_ query:
 *     - MUST select the record matching the `node_id`, if any, AND return all
 *       addresses associated with that node.
 */
static const char **seednames(const tal_t *ctx, const struct node_id *id)
{
	char bech32[100];
	u5 *data = tal_arr(ctx, u5, 0);
	const char **seednames = tal_arr(ctx, const char *, 0);

	bech32_push_bits(&data, id->k, ARRAY_SIZE(id->k)*8);
	bech32_encode(bech32, "ln", data, tal_count(data), sizeof(bech32));
	/* This is cdecker's seed */
	tal_arr_expand(&seednames, tal_fmt(seednames, "%s.lseed.bitcoinstats.com", bech32));
	/* This is darosior's seed */
	tal_arr_expand(&seednames, tal_fmt(seednames, "%s.lseed.darosior.ninja", bech32));
	return seednames;
}

/*~ As a last resort, we do a DNS lookup to the lightning DNS seed to
 * resolve a node name when they say to connect to it.  This is synchronous,
 * so connectd blocks, but it's not very common so we haven't fixed it.
 *
 * This "seed by DNS" approach is similar to what bitcoind uses, and in fact
 * has the nice property that DNS is cached, and the seed only sees a request
 * from the ISP, not directly from the user. */
static void add_seed_addrs(struct wireaddr_internal **addrs,
			   const struct node_id *id,
			   struct sockaddr *broken_reply)
{
	struct wireaddr *new_addrs;
	const char **hostnames = seednames(tmpctx, id);

	for (size_t i = 0; i < tal_count(hostnames); i++) {
		status_peer_debug(id, "Resolving %s", hostnames[i]);
		new_addrs = wireaddr_from_hostname(tmpctx, hostnames[i], DEFAULT_PORT,
		                                   NULL, broken_reply, NULL);
		if (new_addrs) {
			for (size_t j = 0; j < tal_count(new_addrs); j++) {
				struct wireaddr_internal a;
				a.itype = ADDR_INTERNAL_WIREADDR;
				a.u.wireaddr = new_addrs[j];
				status_peer_debug(id, "Resolved %s to %s", hostnames[i],
						  type_to_string(tmpctx, struct wireaddr,
								 &a.u.wireaddr));
				tal_arr_expand(addrs, a);
			}
			/* Other seeds will likely have the same information. */
			return;
		} else
			status_peer_debug(id, "Could not resolve %s", hostnames[i]);
	}
}

/*~ This asks gossipd for any addresses advertized by the node. */
static void add_gossip_addrs(struct wireaddr_internal **addrs,
			     const struct node_id *id)
{
	u8 *msg;
	struct wireaddr *normal_addrs;

	/* For simplicity, we do this synchronous. */
	msg = towire_gossipd_get_addrs(NULL, id);
	if (!wire_sync_write(GOSSIPCTL_FD, take(msg)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing to gossipctl: %s",
			      strerror(errno));

	/* This returns 'struct wireaddr's since that's what's supported by
	 * the BOLT #7 protocol. */
	msg = wire_sync_read(tmpctx, GOSSIPCTL_FD);
	if (!fromwire_gossipd_get_addrs_reply(tmpctx, msg, &normal_addrs))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed parsing get_addrs_reply gossipctl: %s",
			      tal_hex(tmpctx, msg));

	/* Wrap each one in a wireaddr_internal and add to addrs. */
	for (size_t i = 0; i < tal_count(normal_addrs); i++) {
		struct wireaddr_internal addr;
		addr.itype = ADDR_INTERNAL_WIREADDR;
		addr.u.wireaddr = normal_addrs[i];
		tal_arr_expand(addrs, addr);
	}
}

/*~ Consumes addrhint if not NULL.
 *
 * That's a pretty ugly interface: we should use TAKEN, but we only have one
 * caller so it's marginal. */
static void try_connect_peer(struct daemon *daemon,
			     const struct node_id *id,
			     u32 seconds_waited,
			     struct wireaddr_internal *addrhint)
{
	struct wireaddr_internal *addrs;
	bool use_proxy = daemon->use_proxy_always;
	struct connecting *connect;

	/* Already done?  May happen with timer. */
	if (node_set_get(&daemon->peers, id))
		return;

	/* If we're trying to connect it right now, that's OK. */
	if ((connect = find_connecting(daemon, id))) {
		/* If we've been passed in new connection details
		 * for this connection, update our addrhint + add
		 * to addresses to check */
		if (addrhint) {
			connect->addrhint = tal_steal(connect, addrhint);
			tal_arr_expand(&connect->addrs, *addrhint);
		}

		return;
	}

	/* Start an array of addresses to try. */
	addrs = tal_arr(tmpctx, struct wireaddr_internal, 0);

	/* They can supply an optional address for the connect RPC */
	if (addrhint)
		tal_arr_expand(&addrs, *addrhint);

	add_gossip_addrs(&addrs, id);

	if (tal_count(addrs) == 0) {
		/* Don't resolve via DNS seed if we're supposed to use proxy. */
		if (use_proxy) {
			/* You're allowed to use names with proxies; in fact it's
			 * a good idea. */
			struct wireaddr_internal unresolved;
			const char **hostnames = seednames(tmpctx, id);
			for (size_t i = 0; i < tal_count(hostnames); i++) {
				wireaddr_from_unresolved(&unresolved,
				                         hostnames[i],
				                         DEFAULT_PORT);
				tal_arr_expand(&addrs, unresolved);
			}
		} else if (daemon->use_dns) {
			add_seed_addrs(&addrs, id,
			               daemon->broken_resolver_response);
		}
	}

	/* Still no address?  Fail immediately.  Lightningd can still choose
	* to retry; an address may get gossiped or appear on the DNS seed. */
	if (tal_count(addrs) == 0) {
		connect_failed(daemon, id, seconds_waited, addrhint,
			       CONNECT_NO_KNOWN_ADDRESS,
			       "Unable to connect, no address known for peer");
		return;
	}

	/* Start connecting to it: since this is the only place we allocate
	 * a 'struct connecting' we don't write a separate new_connecting(). */
	connect = tal(daemon, struct connecting);
	connect->daemon = daemon;
	connect->id = *id;
	connect->addrs = tal_steal(connect, addrs);
	connect->addrnum = 0;
	/* connstate is supposed to be updated as we go, to give context for
	 * errors which occur.  We miss it in a few places; would be nice to
	 * fix! */
	connect->connstate = "Connection establishment";
	connect->seconds_waited = seconds_waited;
	connect->addrhint = tal_steal(connect, addrhint);
	connect->errors = tal_strdup(connect, "");
	list_add_tail(&daemon->connecting, &connect->list);
	tal_add_destructor(connect, destroy_connecting);

	/* Now we kick it off by recursively trying connect->addrs[connect->addrnum] */
	try_connect_one_addr(connect);
}

/* lightningd tells us to connect to a peer by id, with optional addr hint. */
static struct io_plan *connect_to_peer(struct io_conn *conn,
				       struct daemon *daemon, const u8 *msg)
{
	struct node_id id;
	u32 seconds_waited;
	struct wireaddr_internal *addrhint;

	if (!fromwire_connectd_connect_to_peer(tmpctx, msg,
						 &id, &seconds_waited,
						 &addrhint))
		master_badmsg(WIRE_CONNECTD_CONNECT_TO_PEER, msg);

	try_connect_peer(daemon, &id, seconds_waited, addrhint);
	return daemon_conn_read_next(conn, daemon->master);
}

/* lightningd tells us a peer has disconnected. */
static struct io_plan *peer_disconnected(struct io_conn *conn,
					 struct daemon *daemon, const u8 *msg)
{
	struct node_id id, *node;

	if (!fromwire_connectd_peer_disconnected(msg, &id))
		master_badmsg(WIRE_CONNECTD_PEER_DISCONNECTED, msg);

	/* We should stay in sync with lightningd at all times. */
	node = node_set_get(&daemon->peers, &id);
	if (!node)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "peer_disconnected unknown peer: %s",
			      type_to_string(tmpctx, struct node_id, &id));
	node_set_del(&daemon->peers, node);

	/* Wake up in case there's a reconnecting peer waiting in io_wait. */
	io_wake(node);

	/* Note: deleting from a htable (a-la node_set_del) does not free it:
	 * htable doesn't assume it's a tal object at all. */
	tal_free(node);

	/* Read the next message from lightningd. */
	return daemon_conn_read_next(conn, daemon->master);
}

#if DEVELOPER
static struct io_plan *dev_connect_memleak(struct io_conn *conn,
					   struct daemon *daemon,
					   const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	memtable = memleak_find_allocations(tmpctx, msg, msg);

	/* Now delete daemon and those which it has pointers to. */
	memleak_remove_region(memtable, daemon, sizeof(daemon));

	found_leak = dump_memleak(memtable);
	daemon_conn_send(daemon->master,
			 take(towire_connectd_dev_memleak_reply(NULL,
							      found_leak)));
	return daemon_conn_read_next(conn, daemon->master);
}
#endif /* DEVELOPER */

static struct io_plan *recv_req(struct io_conn *conn,
				const u8 *msg,
				struct daemon *daemon)
{
	enum connectd_wire t = fromwire_peektype(msg);

	/* Demux requests from lightningd: we expect INIT then ACTIVATE, then
	 * connect requests and disconnected messages. */
	switch (t) {
	case WIRE_CONNECTD_INIT:
		return connect_init(conn, daemon, msg);

	case WIRE_CONNECTD_ACTIVATE:
		return connect_activate(conn, daemon, msg);

	case WIRE_CONNECTD_CONNECT_TO_PEER:
		return connect_to_peer(conn, daemon, msg);

	case WIRE_CONNECTD_PEER_DISCONNECTED:
		return peer_disconnected(conn, daemon, msg);

	case WIRE_CONNECTD_DEV_MEMLEAK:
#if DEVELOPER
		return dev_connect_memleak(conn, daemon, msg);
#endif
	/* We send these, we don't receive them */
	case WIRE_CONNECTD_INIT_REPLY:
	case WIRE_CONNECTD_ACTIVATE_REPLY:
	case WIRE_CONNECTD_PEER_CONNECTED:
	case WIRE_CONNECTD_RECONNECTED:
	case WIRE_CONNECTD_CONNECT_FAILED:
	case WIRE_CONNECTD_DEV_MEMLEAK_REPLY:
		break;
	}

	/* Master shouldn't give bad requests. */
	status_failed(STATUS_FAIL_MASTER_IO, "%i: %s",
		      t, tal_hex(tmpctx, msg));
}

/*~ UNUSED is defined to an __attribute__ for GCC; at one stage we tried to use
 * it ubiquitously to make us compile cleanly with -Wunused, but it's bitrotted
 * and we'd need to start again.
 *
 * The C++ method of omitting unused parameter names is *much* neater, and I
 * hope we'll eventually see it in a C standard. */
static void master_gone(struct daemon_conn *master UNUSED)
{
	/* Can't tell master, it's gone. */
	exit(2);
}

/*~ This is a hook used by the memleak code (if DEVELOPER=1): it can't see
 * pointers inside hash tables, so we give it a hint here. */
#if DEVELOPER
static void memleak_daemon_cb(struct htable *memtable, struct daemon *daemon)
{
	memleak_remove_htable(memtable, &daemon->peers.raw);
}
#endif /* DEVELOPER */

int main(int argc, char *argv[])
{
	setup_locale();

	struct daemon *daemon;

	/* Common subdaemon setup code. */
	subdaemon_setup(argc, argv);

	/* Allocate and set up our simple top-level structure. */
	daemon = tal(NULL, struct daemon);
	node_set_init(&daemon->peers);
	memleak_add_helper(daemon, memleak_daemon_cb);
	list_head_init(&daemon->connecting);
	daemon->listen_fds = tal_arr(daemon, struct listen_fd, 0);
	timers_init(&daemon->timers, time_mono());
	/* stdin == control */
	daemon->master = daemon_conn_new(daemon, STDIN_FILENO, recv_req, NULL,
					 daemon);
	tal_add_destructor(daemon->master, master_gone);

	/* This tells the status_* subsystem to use this connection to send
	 * our status_ and failed messages. */
	status_setup_async(daemon->master);

	/* Set up ecdh() function so it uses our HSM fd, and calls
	 * status_failed on error. */
	ecdh_hsmd_setup(HSM_FD, status_failed);

	for (;;) {
		struct timer *expired;
		io_loop(&daemon->timers, &expired);
		timer_expired(daemon, expired);
	}
}

/*~ Getting bored?  This was a pretty simple daemon!
 *
 * The good news is that the next daemon gossipd/gossipd.c is the most complex
 * global daemon we have!
 */
