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
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <ccan/timer/timer.h>
#include <common/bech32.h>
#include <common/bech32_util.h>
#include <common/cryptomsg.h>
#include <common/daemon_conn.h>
#include <common/decode_short_channel_ids.h>
#include <common/features.h>
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
#include <connectd/gen_connect_gossip_wire.h>
#include <connectd/gen_connect_wire.h>
#include <connectd/handshake.h>
#include <connectd/netaddress.h>
#include <connectd/tor.h>
#include <connectd/tor_autoservice.h>
#include <errno.h>
#include <gossipd/gen_gossip_wire.h>
#include <hsmd/client.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <lightningd/gossip_msg.h>
#include <netdb.h>
#include <netinet/in.h>
#include <secp256k1_ecdh.h>
#include <sodium/randombytes.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <wire/gen_peer_wire.h>
#include <wire/peer_wire.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>
#include <zlib.h>

#define CONNECT_MAX_REACH_ATTEMPTS 10

#define HSM_FD 3
#define GOSSIPCTL_FD 4

#define INITIAL_WAIT_SECONDS	1
#define MAX_WAIT_SECONDS	300

struct listen_fd {
	int fd;
	/* If we bind() IPv6 then IPv4 to same port, we *may* fail to listen()
	 * on the IPv4 socket: under Linux, by default, the IPv6 listen()
	 * covers IPv4 too.  Normally we'd consider failing to listen on a
	 * port to be fatal, so we note this when setting up addresses. */
	bool mayfail;
};

static const struct pubkey *
pubkey_keyof(const struct pubkey *pk)
{
	return pk;
}

static size_t pubkey_hash(const struct pubkey *id)
{
	return siphash24(siphash_seed(), id, sizeof(*id));
}

HTABLE_DEFINE_TYPE(struct pubkey,
		   pubkey_keyof,
		   pubkey_hash,
		   pubkey_eq,
		   pubkey_set);

struct daemon {
	/* Who am I? */
	struct pubkey id;

	/* Peers we know of */
	struct pubkey_set peers;

	/* Peers reconnecting now (waiting for current peer to die). */
	struct list_head reconnecting;

	/* Peers we are trying to reach */
	struct list_head reaching;

	/* Connection to main daemon. */
	struct daemon_conn master;

	struct timers timers;

	/* Local and global features to offer to peers. */
	u8 *localfeatures, *globalfeatures;

	/* Allow localhost to be considered "public" */
	bool dev_allow_localhost;

	struct addrinfo *proxyaddr;
	bool use_proxy_always;

	/* @see lightningd.config.use_dns */
	bool use_dns;

	/* The address that the broken response returns instead of
	 * NXDOMAIN. NULL if we have not detected a broken resolver. */
	struct sockaddr *broken_resolver_response;

	/* File descriptors to listen on once we're activated. */
	struct listen_fd *listen_fds;
};

/* Peers we're trying to reach. */
struct reaching {
	/* daemon->reaching */
	struct list_node list;

	struct daemon *daemon;

	/* The ID of the peer (not necessarily unique, in transit!) */
	struct pubkey id;

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

/* This is a transitory structure: we hand off to the master daemon as soon
 * as we've completed INIT read/write. */
struct peer {
	/* For reconnecting peers, this is in daemon->reconnecting. */
	struct list_node list;

	struct daemon *daemon;

	/* The ID of the peer */
	struct pubkey id;

	/* Where it's connected to. */
	struct wireaddr_internal addr;

	/* Feature bitmaps. */
	u8 *gfeatures, *lfeatures;

	/* Cryptostate */
	struct peer_crypto_state pcs;

	/* Our connection (and owner) */
	struct io_conn *conn;
};

/* Mutual recursion */
static void try_reach_one_addr(struct reaching *reach);

static struct peer *find_reconnecting_peer(struct daemon *daemon,
					   const struct pubkey *id)
{
	struct peer *peer;

	list_for_each(&daemon->reconnecting, peer, list)
		if (pubkey_eq(&peer->id, id))
			return peer;
	return NULL;
}

static void destroy_reconnecting_peer(struct peer *peer)
{
	list_del_from(&peer->daemon->reconnecting, &peer->list);
	/* This is safe even if we're being destroyed because of peer->conn,
	 * since tal_free protects against loops. */
	io_close(peer->conn);
}

static void add_reconnecting_peer(struct daemon *daemon, struct peer *peer)
{
	/* Drop any previous connecting peer */
	tal_free(find_reconnecting_peer(peer->daemon, &peer->id));

	list_add_tail(&daemon->reconnecting, &peer->list);
	tal_add_destructor(peer, destroy_reconnecting_peer);
}

/**
 * Some ISP resolvers will reply with a dummy IP to queries that would otherwise
 * result in an NXDOMAIN reply. This just checks whether we have one such
 * resolver upstream and remembers its reply so we can try to filter future
 * dummies out.
 */
static bool broken_resolver(struct daemon *daemon)
{
	struct addrinfo *addrinfo;
	struct addrinfo hints;
	char *hostname = "nxdomain-test.doesntexist";
	int err;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_ADDRCONFIG;
	err = getaddrinfo(hostname, tal_fmt(tmpctx, "%d", 42),
			      &hints, &addrinfo);

	daemon->broken_resolver_response =
	    tal_free(daemon->broken_resolver_response);

	if (err == 0) {
		daemon->broken_resolver_response = tal_dup(daemon, struct sockaddr, addrinfo->ai_addr);
		freeaddrinfo(addrinfo);
	}

	return 	daemon->broken_resolver_response != NULL;
}

static struct peer *new_peer(struct io_conn *conn,
			     struct daemon *daemon,
			     const struct pubkey *their_id,
			     const struct wireaddr_internal *addr,
			     const struct crypto_state *cs)
{
	struct peer *peer = tal(conn, struct peer);

	peer->conn = conn;
	peer->id = *their_id;
	peer->addr = *addr;
	peer->daemon = daemon;
	init_peer_crypto_state(peer, &peer->pcs);
	peer->pcs.cs = *cs;

	return peer;
}

static void destroy_reaching(struct reaching *reach)
{
	list_del_from(&reach->daemon->reaching, &reach->list);
}

static struct reaching *find_reaching(struct daemon *daemon,
				      const struct pubkey *id)
{
	struct reaching *r;

	list_for_each(&daemon->reaching, r, list)
		if (pubkey_eq(id, &r->id))
			return r;
	return NULL;
}

static void reached_peer(struct peer *peer, struct io_conn *conn)
{
	/* OK, we've reached the peer successfully, tell everyone. */
	struct reaching *r = find_reaching(peer->daemon, &peer->id);

	if (!r)
		return;

	/* Don't call destroy_io_conn */
	io_set_finish(conn, NULL, NULL);

	/* Don't free conn with reach */
	tal_steal(peer->daemon, conn);
	tal_free(r);
}

static int get_gossipfd(struct peer *peer)
{
	bool gossip_queries_feature, initial_routing_sync, success;
	u8 *msg;

	gossip_queries_feature
		= feature_offered(peer->lfeatures, LOCAL_GOSSIP_QUERIES)
		&& feature_offered(peer->daemon->localfeatures,
				   LOCAL_GOSSIP_QUERIES);
	initial_routing_sync
		= feature_offered(peer->lfeatures, LOCAL_INITIAL_ROUTING_SYNC);

	/* We do this communication sync. */
	msg = towire_gossip_new_peer(NULL, &peer->id, gossip_queries_feature,
				     initial_routing_sync);
	if (!wire_sync_write(GOSSIPCTL_FD, take(msg)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing to gossipctl: %s",
			      strerror(errno));

	msg = wire_sync_read(peer, GOSSIPCTL_FD);
	if (!fromwire_gossip_new_peer_reply(msg, &success))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed parsing msg gossipctl: %s",
			      tal_hex(tmpctx, msg));
	if (!success) {
		status_broken("Gossipd did not give us an fd: losing peer %s",
			      type_to_string(tmpctx, struct pubkey, &peer->id));
		return -1;
	}
	return fdpass_recv(GOSSIPCTL_FD);
}

static struct io_plan *peer_close_after_error(struct io_conn *conn,
					      struct peer *peer)
{
	status_trace("%s: we sent them a fatal error, closing",
		     type_to_string(tmpctx, struct pubkey, &peer->id));
	return io_close(conn);
}

/* Mutual recursion */
static struct io_plan *peer_connected(struct io_conn *conn, struct peer *peer);
static struct io_plan *retry_peer_connected(struct io_conn *conn,
					    struct peer *peer)
{
	status_trace("peer %s: processing now old peer gone",
		     type_to_string(tmpctx, struct pubkey, &peer->id));

	/* Clean up reconnecting state, try again */
	list_del_from(&peer->daemon->reconnecting, &peer->list);
	tal_del_destructor(peer, destroy_reconnecting_peer);

	return peer_connected(conn, peer);
}

static struct io_plan *peer_connected(struct io_conn *conn, struct peer *peer)
{
	struct daemon *daemon = peer->daemon;
	u8 *msg;
	int gossip_fd;

	/* FIXME: We could do this before exchanging init msgs. */
	if (pubkey_set_get(&daemon->peers, &peer->id)) {
		status_trace("peer %s: reconnect",
			     type_to_string(tmpctx, struct pubkey, &peer->id));

		/* Tell master to kill it: will send peer_disconnect */
		msg = towire_connect_reconnected(NULL, &peer->id);
		daemon_conn_send(&daemon->master, take(msg));
		add_reconnecting_peer(daemon, peer);
		return io_wait(conn, peer, retry_peer_connected, peer);
	}

	reached_peer(peer, conn);

	gossip_fd = get_gossipfd(peer);
	if (gossip_fd < 0)
		return io_close(conn);

	msg = towire_connect_peer_connected(tmpctx, &peer->id, &peer->addr,
					    &peer->pcs.cs,
					    peer->gfeatures, peer->lfeatures);
	daemon_conn_send(&daemon->master, msg);
	daemon_conn_send_fd(&daemon->master, io_conn_fd(conn));
	daemon_conn_send_fd(&daemon->master, gossip_fd);

	pubkey_set_add(&daemon->peers,
		       tal_dup(daemon, struct pubkey, &peer->id));

	/* This frees the peer. */
	return io_close_taken_fd(conn);
}

static struct io_plan *peer_init_received(struct io_conn *conn,
					  struct peer *peer,
					  u8 *msg)
{
	if (!fromwire_init(peer, msg, &peer->gfeatures, &peer->lfeatures)) {
		status_trace("peer %s bad fromwire_init '%s', closing",
			     type_to_string(tmpctx, struct pubkey, &peer->id),
			     tal_hex(tmpctx, msg));
		return io_close(conn);
	}

	if (!features_supported(peer->gfeatures, peer->lfeatures)) {
		const u8 *global_features = get_offered_global_features(msg);
		const u8 *local_features = get_offered_local_features(msg);
		msg = towire_errorfmt(NULL, NULL, "Unsupported features %s/%s:"
				      " we only offer globalfeatures %s"
				      " and localfeatures %s",
				      tal_hex(msg, peer->gfeatures),
				      tal_hex(msg, peer->lfeatures),
				      tal_hexstr(msg,
						 global_features,
						 tal_count(global_features)),
				      tal_hexstr(msg,
						 local_features,
						 tal_count(local_features)));
		return peer_write_message(conn, &peer->pcs, take(msg),
					  peer_close_after_error);
	}

	return peer_connected(conn, peer);
}

static struct io_plan *read_init(struct io_conn *conn, struct peer *peer)
{
	/* BOLT #1:
	 *
	 * The receiving node:
	 *  - MUST wait to receive `init` before sending any other messages.
	 */
	return peer_read_message(conn, &peer->pcs, peer_init_received);
}

/* This creates a temporary peer which is not in the list and is owner
 * by the connection; it's placed in the list and owned by daemon once
 * we have the features. */
static struct io_plan *init_new_peer(struct io_conn *conn,
				     const struct pubkey *their_id,
				     const struct wireaddr_internal *addr,
				     const struct crypto_state *cs,
				     struct daemon *daemon)
{
	struct peer *peer = new_peer(conn, daemon, their_id, addr, cs);
	u8 *initmsg;

	/* BOLT #1:
	 *
	 * The sending node:
	 *   - MUST send `init` as the first Lightning message for any
	 *     connection.
	 */
	initmsg = towire_init(NULL,
			      daemon->globalfeatures, daemon->localfeatures);
	return peer_write_message(conn, &peer->pcs, take(initmsg), read_init);
}

static int make_listen_fd(int domain, void *addr, socklen_t len, bool mayfail)
{
	int fd = socket(domain, SOCK_STREAM, 0);
	if (fd < 0) {
		if (!mayfail)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Failed to create %u socket: %s",
				      domain, strerror(errno));
		status_trace("Failed to create %u socket: %s",
			     domain, strerror(errno));
		return -1;
	}

	if (addr) {
		int on = 1;

		/* Re-use, please.. */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
			status_unusual("Failed setting socket reuse: %s",
				       strerror(errno));

		if (bind(fd, addr, len) != 0) {
			if (!mayfail)
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "Failed to bind on %u socket: %s",
					      domain, strerror(errno));
			status_trace("Failed to create %u socket: %s",
				     domain, strerror(errno));
			goto fail;
		}
	}

	return fd;

fail:
	close_noerr(fd);
	return -1;
}

static struct io_plan *handshake_in_success(struct io_conn *conn,
					    const struct pubkey *id,
					    const struct wireaddr_internal *addr,
					    const struct crypto_state *cs,
					    struct daemon *daemon)
{
	status_trace("Connect IN from %s",
		     type_to_string(tmpctx, struct pubkey, id));
	return init_new_peer(conn, id, addr, cs, daemon);
}

static struct io_plan *connection_in(struct io_conn *conn, struct daemon *daemon)
{
	struct wireaddr_internal addr;
	struct sockaddr_storage s = {};
	socklen_t len = sizeof(s);

	if (getpeername(io_conn_fd(conn), (struct sockaddr *)&s, &len) != 0) {
		status_trace("Failed to get peername for incoming conn: %s",
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

	/* FIXME: Timeout */
	return responder_handshake(conn, &daemon->id, &addr,
				   handshake_in_success, daemon);
}

static void add_listen_fd(struct daemon *daemon, int fd, bool mayfail)
{
	size_t n = tal_count(daemon->listen_fds);
	tal_resize(&daemon->listen_fds, n+1);
	daemon->listen_fds[n].fd = fd;
	daemon->listen_fds[n].mayfail = mayfail;
}

/* Return true if it created socket successfully. */
static bool handle_wireaddr_listen(struct daemon *daemon,
				   const struct wireaddr *wireaddr,
				   bool mayfail)
{
	int fd;
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;

	switch (wireaddr->type) {
	case ADDR_TYPE_IPV4:
		wireaddr_to_ipv4(wireaddr, &addr);
		/* We might fail if IPv6 bound to port first */
		fd = make_listen_fd(AF_INET, &addr, sizeof(addr), mayfail);
		if (fd >= 0) {
			status_trace("Created IPv4 listener on port %u",
				     wireaddr->port);
			add_listen_fd(daemon, fd, mayfail);
			return true;
		}
		return false;
	case ADDR_TYPE_IPV6:
		wireaddr_to_ipv6(wireaddr, &addr6);
		fd = make_listen_fd(AF_INET6, &addr6, sizeof(addr6), mayfail);
		if (fd >= 0) {
			status_trace("Created IPv6 listener on port %u",
				     wireaddr->port);
			add_listen_fd(daemon, fd, mayfail);
			return true;
		}
		return false;
	case ADDR_TYPE_PADDING:
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

	return address_routable(wireaddr, daemon->dev_allow_localhost);
}

static void add_announcable(struct wireaddr **announcable,
			    const struct wireaddr *addr)
{
	size_t n = tal_count(*announcable);
	tal_resize(announcable, n+1);
	(*announcable)[n] = *addr;
}

static void add_binding(struct wireaddr_internal **binding,
			const struct wireaddr_internal *addr)
{
	size_t n = tal_count(*binding);
	tal_resize(binding, n+1);
	(*binding)[n] = *addr;
}

static int wireaddr_cmp_type(const struct wireaddr *a,
			     const struct wireaddr *b, void *unused)
{
	return (int)a->type - (int)b->type;
}

static void finalize_announcable(struct wireaddr **announcable)
{
	size_t n = tal_count(*announcable);

	/* BOLT #7:
	 *
	 * The origin node:
	 *...
	 *   - MUST place non-zero typed address descriptors in ascending order.
	 *...
	 *   - MUST NOT include more than one `address descriptor` of the same
	 *     type.
	 */
	asort(*announcable, n, wireaddr_cmp_type, NULL);
	for (size_t i = 1; i < n; i++) {
		/* Note we use > instead of !=: catches asort bugs too. */
		if ((*announcable)[i].type > (*announcable)[i-1].type)
			continue;

		status_unusual("WARNING: Cannot announce address %s,"
			       " already announcing %s",
			       type_to_string(tmpctx, struct wireaddr,
					      &(*announcable)[i]),
			       type_to_string(tmpctx, struct wireaddr,
					      &(*announcable)[i-1]));
		memmove(*announcable + i,
			*announcable + i + 1,
			(n - i - 1) * sizeof((*announcable)[0]));
		tal_resize(announcable, --n);
		--i;
	}
}

/* Initializes daemon->announcable array, returns addresses we bound to. */
static struct wireaddr_internal *setup_listeners(const tal_t *ctx,
						 struct daemon *daemon,
						 const struct wireaddr_internal *proposed_wireaddr,
						 const enum addr_listen_announce *proposed_listen_announce,
						 const char *tor_password,
						 struct wireaddr **announcable)
{
	struct sockaddr_un addrun;
	int fd;
	struct wireaddr_internal *binding;

	binding = tal_arr(ctx, struct wireaddr_internal, 0);
	*announcable = tal_arr(ctx, struct wireaddr, 0);

	/* Add addresses we've explicitly been told to *first*: implicit
	 * addresses will be discarded then if we have multiple. */
	for (size_t i = 0; i < tal_count(proposed_wireaddr); i++) {
		struct wireaddr_internal wa = proposed_wireaddr[i];

		if (proposed_listen_announce[i] & ADDR_LISTEN)
			continue;

		assert(proposed_listen_announce[i] & ADDR_ANNOUNCE);
		/* You can only announce wiretypes! */
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
		case ADDR_INTERNAL_SOCKNAME:
			addrun.sun_family = AF_UNIX;
			memcpy(addrun.sun_path, wa.u.sockname,
			       sizeof(addrun.sun_path));
			fd = make_listen_fd(AF_INET, &addrun, sizeof(addrun),
					    false);
			status_trace("Created socket listener on file %s",
				     addrun.sun_path);
			add_listen_fd(daemon, fd, false);
			/* We don't announce socket names */
			assert(!announce);
			add_binding(&binding, &wa);
			continue;
		case ADDR_INTERNAL_AUTOTOR:
			/* We handle these after we have all bindings. */
			continue;
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

	/* Now we have bindings, set up any Tor auto addresses */
	for (size_t i = 0; i < tal_count(proposed_wireaddr); i++) {
		if (!(proposed_listen_announce[i] & ADDR_LISTEN))
			continue;

		if (!(proposed_listen_announce[i] & ADDR_ANNOUNCE))
			continue;

		if (proposed_wireaddr[i].itype != ADDR_INTERNAL_AUTOTOR)
			continue;

		add_announcable(announcable,
				tor_autoservice(tmpctx,
						&proposed_wireaddr[i].u.torservice,
						tor_password,
						binding));
	}

	finalize_announcable(announcable);

	return binding;
}


/* Parse an incoming connect init message and assign config variables
 * to the daemon.
 */
static struct io_plan *connect_init(struct daemon_conn *master,
				   struct daemon *daemon,
				   const u8 *msg)
{
	struct wireaddr *proxyaddr;
	struct wireaddr_internal *binding;
	struct wireaddr_internal *proposed_wireaddr;
	enum addr_listen_announce *proposed_listen_announce;
	struct wireaddr *announcable;
	char *tor_password;

	if (!fromwire_connectctl_init(
		daemon, msg,
		&daemon->id, &daemon->globalfeatures,
		&daemon->localfeatures, &proposed_wireaddr,
		&proposed_listen_announce,
		&proxyaddr, &daemon->use_proxy_always,
		&daemon->dev_allow_localhost, &daemon->use_dns,
		&tor_password)) {
		master_badmsg(WIRE_CONNECTCTL_INIT, msg);
	}

	/* Resolve Tor proxy address if any */
	if (proxyaddr) {
		status_trace("Proxy address: %s",
			     fmt_wireaddr(tmpctx, proxyaddr));
		daemon->proxyaddr = wireaddr_to_addrinfo(daemon, proxyaddr);
	} else
		daemon->proxyaddr = NULL;

	if (broken_resolver(daemon)) {
		status_trace("Broken DNS resolver detected, will check for "
			     "dummy replies");
	}

	binding = setup_listeners(tmpctx, daemon,
				  proposed_wireaddr,
				  proposed_listen_announce,
				  tor_password,
				  &announcable);

	daemon_conn_send(&daemon->master,
			 take(towire_connectctl_init_reply(NULL,
							   binding,
							   announcable)));

	return daemon_conn_read_next(master->conn, master);
}

static struct io_plan *connect_activate(struct daemon_conn *master,
				       struct daemon *daemon,
				       const u8 *msg)
{
	bool do_listen;

	if (!fromwire_connectctl_activate(msg, &do_listen))
		master_badmsg(WIRE_CONNECTCTL_ACTIVATE, msg);

	if (do_listen) {
		for (size_t i = 0; i < tal_count(daemon->listen_fds); i++) {
			/* On Linux, at least, we may bind to all addresses
			 * for IPv4 and IPv6, but we'll fail to listen. */
			if (listen(daemon->listen_fds[i].fd, 5) != 0) {
				if (daemon->listen_fds[i].mayfail)
					continue;
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "Failed to listen on socket: %s",
					      strerror(errno));
			}
			io_new_listener(daemon, daemon->listen_fds[i].fd,
					connection_in, daemon);
		}
	}
	daemon->listen_fds = tal_free(daemon->listen_fds);

	/* OK, we're ready! */
	daemon_conn_send(&daemon->master,
			 take(towire_connectctl_activate_reply(NULL)));
	return daemon_conn_read_next(master->conn, master);
}

static struct io_plan *handshake_out_success(struct io_conn *conn,
					     const struct pubkey *id,
					     const struct wireaddr_internal *addr,
					     const struct crypto_state *cs,
					     struct reaching *reach)
{
	reach->connstate = "Exchanging init messages";
	status_trace("Connect OUT to %s",
		     type_to_string(tmpctx, struct pubkey, id));
	return init_new_peer(conn, id, addr, cs, reach->daemon);
}

struct io_plan *connection_out(struct io_conn *conn, struct reaching *reach)
{
	/* FIXME: Timeout */
	status_trace("Connected out for %s",
		     type_to_string(tmpctx, struct pubkey, &reach->id));

	reach->connstate = "Cryptographic handshake";
	return initiator_handshake(conn, &reach->daemon->id, &reach->id,
				   &reach->addrs[reach->addrnum],
				   handshake_out_success, reach);
}

static void PRINTF_FMT(5,6)
	connect_failed(struct daemon *daemon,
		       const struct pubkey *id,
		       u32 seconds_waited,
		       const struct wireaddr_internal *addrhint,
		       const char *errfmt, ...)
{
	u8 *msg;
	va_list ap;
	char *err;
	u32 wait_seconds;

	va_start(ap, errfmt);
	err = tal_vfmt(tmpctx, errfmt, ap);
	va_end(ap);

	/* Wait twice as long to reconnect, between min and max. */
	wait_seconds = seconds_waited * 2;
	if (wait_seconds > MAX_WAIT_SECONDS)
		wait_seconds = MAX_WAIT_SECONDS;
	if (wait_seconds < INITIAL_WAIT_SECONDS)
		wait_seconds = INITIAL_WAIT_SECONDS;

	/* Tell any connect command what happened. */
	msg = towire_connectctl_connect_failed(NULL, id, err, wait_seconds,
					       addrhint);
	daemon_conn_send(&daemon->master, take(msg));

	status_trace("Failed connected out for %s: %s",
		     type_to_string(tmpctx, struct pubkey, id),
		     err);
}

static void destroy_io_conn(struct io_conn *conn, struct reaching *reach)
{
	tal_append_fmt(&reach->errors,
		       "%s: %s: %s. ",
		       type_to_string(tmpctx, struct wireaddr_internal,
				      &reach->addrs[reach->addrnum]),
		       reach->connstate, strerror(errno));
	reach->addrnum++;
	try_reach_one_addr(reach);
}

static struct io_plan *conn_init(struct io_conn *conn, struct reaching *reach)
{
	struct addrinfo *ai = NULL;
	const struct wireaddr_internal *addr = &reach->addrs[reach->addrnum];

	switch (addr->itype) {
	case ADDR_INTERNAL_SOCKNAME:
		ai = wireaddr_internal_to_addrinfo(tmpctx, addr);
		break;
	case ADDR_INTERNAL_ALLPROTO:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't reach to all protocols");
		break;
	case ADDR_INTERNAL_AUTOTOR:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't reach to autotor address");
		break;
	case ADDR_INTERNAL_FORPROXY:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't reach to forproxy address");
		break;
	case ADDR_INTERNAL_WIREADDR:
		/* If it was a Tor address, we wouldn't be here. */
		ai = wireaddr_to_addrinfo(tmpctx, &addr->u.wireaddr);
		break;
	}
	assert(ai);

	io_set_finish(conn, destroy_io_conn, reach);
	return io_connect(conn, ai, connection_out, reach);
}

static struct io_plan *conn_proxy_init(struct io_conn *conn,
				       struct reaching *reach)
{
	const char *host = NULL;
	u16 port;
	const struct wireaddr_internal *addr = &reach->addrs[reach->addrnum];

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
		break;
	}

	if (!host)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't reach to %u address", addr->itype);

	io_set_finish(conn, destroy_io_conn, reach);
	return io_tor_connect(conn, reach->daemon->proxyaddr, host, port, reach);
}

static void append_addr(struct wireaddr_internal **addrs,
			const struct wireaddr_internal *addr)
{
	size_t n = tal_count(*addrs);
	tal_resize(addrs, n+1);
	(*addrs)[n] = *addr;
}

static const char *seedname(const tal_t *ctx, const struct pubkey *id)
{
	char bech32[100];
	u8 der[PUBKEY_DER_LEN];
	u5 *data = tal_arr(ctx, u5, 0);

	pubkey_to_der(der, id);
	bech32_push_bits(&data, der, PUBKEY_DER_LEN*8);
	bech32_encode(bech32, "ln", data, tal_count(data), sizeof(bech32));
	return tal_fmt(ctx, "%s.lseed.bitcoinstats.com", bech32);
}

static void add_seed_addrs(struct wireaddr_internal **addrs,
			   const struct pubkey *id,
			   struct sockaddr *broken_reply)
{
	struct wireaddr_internal a;
	const char *addr;

	addr = seedname(tmpctx, id);
	status_trace("Resolving %s", addr);

	a.itype = ADDR_INTERNAL_WIREADDR;
	/* FIXME: wireaddr_from_hostname should return multiple addresses. */
	if (!wireaddr_from_hostname(&a.u.wireaddr, addr, DEFAULT_PORT, NULL,
				    broken_reply, NULL)) {
		status_trace("Could not resolve %s", addr);
	} else {
		status_trace("Resolved %s to %s", addr,
			     type_to_string(tmpctx, struct wireaddr,
					    &a.u.wireaddr));
		append_addr(addrs, &a);
	}
}

static void add_gossip_addrs(struct wireaddr_internal **addrs,
			     const struct pubkey *id)
{
	u8 *msg;
	struct wireaddr *normal_addrs;

	msg = towire_gossip_get_addrs(NULL, id);
	if (!wire_sync_write(GOSSIPCTL_FD, take(msg)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed writing to gossipctl: %s",
			      strerror(errno));

	msg = wire_sync_read(tmpctx, GOSSIPCTL_FD);
	if (!fromwire_gossip_get_addrs_reply(tmpctx, msg, &normal_addrs))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Failed parsing get_addrs_reply gossipctl: %s",
			      tal_hex(tmpctx, msg));

	/* Wrap each one in a wireaddr_internal and add to addrs. */
	for (size_t i = 0; i < tal_count(normal_addrs); i++) {
		struct wireaddr_internal addr;
		addr.itype = ADDR_INTERNAL_WIREADDR;
		addr.u.wireaddr = normal_addrs[i];
		append_addr(addrs, &addr);
	}
}

static void try_reach_one_addr(struct reaching *reach)
{
 	int fd, af;
	bool use_proxy = reach->daemon->use_proxy_always;
	const struct wireaddr_internal *addr = &reach->addrs[reach->addrnum];

	if (reach->addrnum == tal_count(reach->addrs)) {
		connect_failed(reach->daemon, &reach->id, reach->seconds_waited,
			       reach->addrhint, "%s", reach->errors);
		tal_free(reach);
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
			      "Can't reach ALLPROTO");
	case ADDR_INTERNAL_AUTOTOR:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't reach AUTOTOR");
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
		case ADDR_TYPE_PADDING:
			break;
		}
	}

	/* If we have to use proxy but we don't have one, we fail. */
	if (use_proxy) {
		if (!reach->daemon->proxyaddr) {
			status_debug("Need proxy");
			af = -1;
		} else
			af = reach->daemon->proxyaddr->ai_family;
	}

	if (af == -1) {
		fd = -1;
		errno = EPROTONOSUPPORT;
	} else
		fd = socket(af, SOCK_STREAM, 0);

	if (fd < 0) {
		tal_append_fmt(&reach->errors,
			       "%s: opening %i socket gave %s. ",
			       type_to_string(tmpctx, struct wireaddr_internal,
					      addr),
			       af, strerror(errno));
		reach->addrnum++;
		try_reach_one_addr(reach);
		return;
	}

	if (use_proxy)
		io_new_conn(reach, fd, conn_proxy_init, reach);
	else
		io_new_conn(reach, fd, conn_init, reach);
}

/* Consumes addrhint if not NULL */
static void try_reach_peer(struct daemon *daemon,
			   const struct pubkey *id,
			   u32 seconds_waited,
			   struct wireaddr_internal *addrhint)
{
	struct wireaddr_internal *addrs;
	bool use_proxy = daemon->use_proxy_always;
	struct reaching *reach;

	/* Already done?  May happen with timer. */
	if (pubkey_set_get(&daemon->peers, id))
		return;

	/* If we're trying to reach it right now, that's OK. */
	if (find_reaching(daemon, id))
		return;

	addrs = tal_arr(tmpctx, struct wireaddr_internal, 0);
	if (addrhint)
		append_addr(&addrs, addrhint);

	add_gossip_addrs(&addrs, id);

	if (tal_count(addrs) == 0) {
		/* Don't resolve via DNS seed if we're supposed to use proxy. */
		if (use_proxy) {
			struct wireaddr_internal unresolved;
			wireaddr_from_unresolved(&unresolved,
						 seedname(tmpctx, id),
						 DEFAULT_PORT);
			append_addr(&addrs, &unresolved);
		} else if (daemon->use_dns) {
			add_seed_addrs(&addrs, id,
				       daemon->broken_resolver_response);
		}
	}

	if (tal_count(addrs) == 0) {
		connect_failed(daemon, id, seconds_waited, addrhint,
			       "No address known");
		return;
	}

	/* Start connecting to it */
	reach = tal(daemon, struct reaching);
	reach->daemon = daemon;
	reach->id = *id;
	reach->addrs = tal_steal(reach, addrs);
	reach->addrnum = 0;
	reach->connstate = "Connection establishment";
	reach->seconds_waited = seconds_waited;
	reach->addrhint = tal_steal(reach, addrhint);
	reach->errors = tal_strdup(reach, "");
	list_add_tail(&daemon->reaching, &reach->list);
	tal_add_destructor(reach, destroy_reaching);

	try_reach_one_addr(reach);
}

static struct io_plan *connect_to_peer(struct io_conn *conn,
				       struct daemon *daemon, const u8 *msg)
{
	struct pubkey id;
	u32 seconds_waited;
	struct wireaddr_internal *addrhint;

	if (!fromwire_connectctl_connect_to_peer(tmpctx, msg,
						 &id, &seconds_waited,
						 &addrhint))
		master_badmsg(WIRE_CONNECTCTL_CONNECT_TO_PEER, msg);

	try_reach_peer(daemon, &id, seconds_waited, addrhint);
	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *peer_disconnected(struct io_conn *conn,
					 struct daemon *daemon, const u8 *msg)
{
	struct pubkey id, *key;
	struct peer *peer;

	if (!fromwire_connectctl_peer_disconnected(msg, &id))
		master_badmsg(WIRE_CONNECTCTL_PEER_DISCONNECTED, msg);

	key = pubkey_set_get(&daemon->peers, &id);
	if (!key)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "peer_disconnected unknown peer: %s",
			      type_to_string(tmpctx, struct pubkey, &id));
	pubkey_set_del(&daemon->peers, key);
	tal_free(key);

	status_trace("Forgetting peer %s",
		     type_to_string(tmpctx, struct pubkey, &id));

	/* If there was a connecting peer waiting, wake it now */
	peer = find_reconnecting_peer(daemon, &id);
	if (peer)
		io_wake(peer);

	return daemon_conn_read_next(conn, &daemon->master);
}

static struct io_plan *recv_req(struct io_conn *conn, struct daemon_conn *master)
{
	struct daemon *daemon = container_of(master, struct daemon, master);
	enum connect_wire_type t = fromwire_peektype(master->msg_in);

	switch (t) {
	case WIRE_CONNECTCTL_INIT:
		return connect_init(master, daemon, master->msg_in);

	case WIRE_CONNECTCTL_ACTIVATE:
		return connect_activate(master, daemon, master->msg_in);

	case WIRE_CONNECTCTL_CONNECT_TO_PEER:
		return connect_to_peer(conn, daemon, master->msg_in);

	case WIRE_CONNECTCTL_PEER_DISCONNECTED:
		return peer_disconnected(conn, daemon, master->msg_in);

	/* We send these, we don't receive them */
	case WIRE_CONNECTCTL_INIT_REPLY:
	case WIRE_CONNECTCTL_ACTIVATE_REPLY:
	case WIRE_CONNECT_PEER_CONNECTED:
	case WIRE_CONNECT_RECONNECTED:
	case WIRE_CONNECTCTL_CONNECT_FAILED:
		break;
	}

	/* Master shouldn't give bad requests. */
	status_failed(STATUS_FAIL_MASTER_IO, "%i: %s",
		      t, tal_hex(tmpctx, master->msg_in));
}

#ifndef TESTING
static void master_gone(struct io_conn *unused UNUSED, struct daemon_conn *dc UNUSED)
{
	/* Can't tell master, it's gone. */
	exit(2);
}

int main(int argc, char *argv[])
{
	setup_locale();

	struct daemon *daemon;

	subdaemon_setup(argc, argv);

	daemon = tal(NULL, struct daemon);
	pubkey_set_init(&daemon->peers);
	list_head_init(&daemon->reconnecting);
	list_head_init(&daemon->reaching);
	timers_init(&daemon->timers, time_mono());
	daemon->broken_resolver_response = NULL;
	daemon->listen_fds = tal_arr(daemon, struct listen_fd, 0);
	/* stdin == control */
	daemon_conn_init(daemon, &daemon->master, STDIN_FILENO, recv_req,
			 master_gone);
	status_setup_async(&daemon->master);
	hsm_setup(HSM_FD);

	/* When conn closes, everything is freed. */
	tal_steal(daemon->master.conn, daemon);

	for (;;) {
		struct timer *expired = NULL;
		io_loop(&daemon->timers, &expired);

		if (!expired) {
			break;
		} else {
			timer_expired(daemon, expired);
		}
	}
	daemon_shutdown();
	return 0;
}
#endif
