/*~ Welcome to the connect daemon: maintainer of connectivity!
 *
 * This is another separate daemon which is responsible for reaching out to
 * other peers, and also accepting their incoming connections.  It talks to
 * them for just long enough to validate their identity using a cryptographic
 * handshake, then receive and send supported feature sets; then it hands them
 * up to lightningd which will fire up a specific per-peer daemon to talk to
 * it.
 */
#include "config.h"
#include <arpa/inet.h>
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/closefrom/closefrom.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/backend.h>
#include <ccan/noerr/noerr.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/bech32_util.h>
#include <common/daemon_conn.h>
#include <common/dev_disconnect.h>
#include <common/ecdh_hsmd.h>
#include <common/gossip_store.h>
#include <common/jsonrpc_errors.h>
#include <common/memleak.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <connectd/connectd.h>
#include <connectd/connectd_gossipd_wiregen.h>
#include <connectd/connectd_wiregen.h>
#include <connectd/multiplex.h>
#include <connectd/netaddress.h>
#include <connectd/onion_message.h>
#include <connectd/peer_exchange_initmsg.h>
#include <connectd/tor.h>
#include <connectd/tor_autoservice.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sodium.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

/*~ We are passed two file descriptors when exec'ed from `lightningd`: the
 * first is a connection to `hsmd`, which we need for the cryptographic
 * handshake, and the second is to `gossipd`: it gathers network gossip and
 * thus may know how to reach certain peers. */
#define HSM_FD 3
#define GOSSIPCTL_FD 4

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

	/* If they told us to never do DNS queries, don't even do this one and
	 * also not if we just say that we don't */
	if (!daemon->use_dns || daemon->always_use_proxy) {
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

/*~ When we free a peer, we remove it from the daemon's hashtable.
 * We also call this manually if we want to elegantly drain peer's
 * queues. */
void destroy_peer(struct peer *peer)
{
	assert(!peer->draining);

	if (!peer_htable_del(peer->daemon->peers, peer))
		abort();

	/* Tell gossipd to stop asking this peer gossip queries */
	daemon_conn_send(peer->daemon->gossipd,
			 take(towire_gossipd_peer_gone(NULL, &peer->id)));

	/* Tell lightningd it's really disconnected */
	daemon_conn_send(peer->daemon->master,
			 take(towire_connectd_peer_disconnect_done(NULL,
								   &peer->id,
								   peer->counter)));
	/* This makes multiplex.c routines not feed us more, but
	 * *also* means that if we're freed directly, the ->to_peer
	 * destructor won't call drain_peer(). */
	peer->draining = true;
}

/*~ This is where we create a new peer. */
static struct peer *new_peer(struct daemon *daemon,
			     const struct node_id *id,
			     const struct crypto_state *cs,
			     const u8 *their_features,
			     enum is_websocket is_websocket,
			     struct io_conn *conn STEALS,
			     int *fd_for_subd)
{
	struct peer *peer = tal(daemon, struct peer);

	peer->daemon = daemon;
	peer->id = *id;
	peer->counter = daemon->connection_counter++;
	peer->cs = *cs;
	peer->subds = tal_arr(peer, struct subd *, 0);
	peer->peer_in = NULL;
	peer->sent_to_peer = NULL;
	peer->urgent = false;
	peer->draining = false;
	peer->peer_outq = msg_queue_new(peer, false);
	peer->last_recv_time = time_now();
	peer->is_websocket = is_websocket;

#if DEVELOPER
	peer->dev_writes_enabled = NULL;
	peer->dev_read_enabled = true;
#endif

	peer->to_peer = conn;

	/* Now we own it */
	tal_steal(peer, peer->to_peer);
	peer_htable_add(daemon->peers, peer);
	tal_add_destructor(peer, destroy_peer);

	return peer;
}

/*~ Note the lack of static: this is called by peer_exchange_initmsg.c once the
 * INIT messages are exchanged, and also by the retry code above. */
struct io_plan *peer_connected(struct io_conn *conn,
			       struct daemon *daemon,
			       const struct node_id *id,
			       const struct wireaddr_internal *addr,
			       const struct wireaddr *remote_addr,
			       struct crypto_state *cs,
			       const u8 *their_features TAKES,
			       enum is_websocket is_websocket,
			       bool incoming)
{
	u8 *msg;
	struct peer *peer;
	int unsup;
	size_t depender, missing;
	int subd_fd;
	bool option_gossip_queries;

	/* We remove any previous connection immediately, on the assumption it's dead */
	peer = peer_htable_get(daemon->peers, id);
	if (peer)
		tal_free(peer);

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
	 *    - MUST close the connection.
	 */
	unsup = features_unsupported(daemon->our_features, their_features,
				     INIT_FEATURE);
	if (unsup != -1) {
		status_peer_unusual(id, "Unsupported feature %u", unsup);
		msg = towire_warningfmt(NULL, NULL, "Unsupported feature %u",
					unsup);
		msg = cryptomsg_encrypt_msg(NULL, cs, take(msg));
		return io_write_wire(conn, take(msg), io_close_cb, NULL);
	}

	if (!feature_check_depends(their_features, &depender, &missing)) {
		status_peer_unusual(id, "Feature %zu requires feature %zu",
				    depender, missing);
		msg = towire_warningfmt(NULL, NULL,
				      "Feature %zu requires feature %zu",
				      depender, missing);
		msg = cryptomsg_encrypt_msg(NULL, cs, take(msg));
		return io_write_wire(conn, take(msg), io_close_cb, NULL);
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
	peer = new_peer(daemon, id, cs, their_features, is_websocket, conn, &subd_fd);
	/* Only takes over conn if it succeeds. */
	if (!peer)
		return io_close(conn);

	/* Tell gossipd it can ask query this new peer for gossip */
	option_gossip_queries = feature_negotiated(daemon->our_features,
						   their_features,
						   OPT_GOSSIP_QUERIES);
	msg = towire_gossipd_new_peer(NULL, id, option_gossip_queries);
	daemon_conn_send(daemon->gossipd, take(msg));

	/* Get ready for streaming gossip from the store */
	setup_peer_gossip_store(peer, daemon->our_features, their_features);

	/* Create message to tell master peer has connected. */
	msg = towire_connectd_peer_connected(NULL, id, peer->counter,
					     addr, remote_addr,
					     incoming, their_features);

	/*~ daemon_conn is a message queue for inter-daemon communication: we
	 * queue up the `connect_peer_connected` message to tell lightningd
	 * we have connected.  Once it says something interesting, we tell
	 * it that, too. */
	daemon_conn_send(daemon->master, take(msg));

	/*~ Now we set up this connection to read/write from subd */
	return multiplex_peer_setup(conn, peer);
}

/*~ handshake.c's handles setting up the crypto state once we get a connection
 * in; we hand it straight to peer_exchange_initmsg() to send and receive INIT
 * and call peer_connected(). */
static struct io_plan *handshake_in_success(struct io_conn *conn,
					    const struct pubkey *id_key,
					    const struct wireaddr_internal *addr,
					    struct crypto_state *cs,
					    struct oneshot *timeout,
					    enum is_websocket is_websocket,
					    struct daemon *daemon)
{
	struct node_id id;
	node_id_from_pubkey(&id, id_key);
	status_peer_debug(&id, "Connect IN");
	return peer_exchange_initmsg(conn, daemon, daemon->our_features,
				     cs, &id, addr, timeout, is_websocket, true);
}

/*~ If the timer goes off, we simply free everything, which hangs up. */
static void conn_timeout(struct io_conn *conn)
{
	status_debug("conn timed out");
	errno = ETIMEDOUT;
	io_close(conn);
}

/*~ So, where are you from? */
static bool get_remote_address(struct io_conn *conn,
			       struct wireaddr_internal *addr)
{
	struct sockaddr_storage s = {};
	socklen_t len = sizeof(s);

	/* The cast here is a weird Berkeley sockets API feature... */
	if (getpeername(io_conn_fd(conn), (struct sockaddr *)&s, &len) != 0) {
		status_debug("Failed to get peername for incoming conn: %s",
			     strerror(errno));
		return false;
	}

	if (s.ss_family == AF_INET6) {
		struct sockaddr_in6 *s6 = (void *)&s;
		addr->itype = ADDR_INTERNAL_WIREADDR;
		wireaddr_from_ipv6(&addr->u.wireaddr.wireaddr,
				   &s6->sin6_addr, ntohs(s6->sin6_port));
	} else if (s.ss_family == AF_INET) {
		struct sockaddr_in *s4 = (void *)&s;
		addr->itype = ADDR_INTERNAL_WIREADDR;
		wireaddr_from_ipv4(&addr->u.wireaddr.wireaddr,
				   &s4->sin_addr, ntohs(s4->sin_port));
	} else if (s.ss_family == AF_UNIX) {
		struct sockaddr_un *sun = (void *)&s;
		addr->itype = ADDR_INTERNAL_SOCKNAME;
		memcpy(addr->u.sockname, sun->sun_path, sizeof(sun->sun_path));
	} else {
		status_broken("Unknown socket type %i for incoming conn",
			      s.ss_family);
		return false;
	}
	return true;
}

/*~ As so common in C, we need to bundle two args into a callback, so we
 * allocate a temporary structure to hold them: */
struct conn_in {
	struct wireaddr_internal addr;
	struct daemon *daemon;
	enum is_websocket is_websocket;
};

/*~ Once we've got a connection in, we set it up here (whether it's via the
 * websocket proxy, or direct). */
static struct io_plan *conn_in(struct io_conn *conn,
			       struct conn_in *conn_in_arg)
{
	struct daemon *daemon = conn_in_arg->daemon;
	struct oneshot *timeout;

	/* If they don't complete handshake in reasonable time, we hang up */
	timeout = new_reltimer(&daemon->timers, conn,
			       time_from_sec(daemon->timeout_secs),
			       conn_timeout, conn);

	/*~ The crypto handshake differs depending on whether you received or
	 * initiated the socket connection, so there are two entry points.
	 * Note, again, the notleak() to avoid our simplistic leak detection
	 * code from thinking `conn` (which we don't keep a pointer to) is
	 * leaked */
	return responder_handshake(notleak(conn), &daemon->mykey,
				   &conn_in_arg->addr, timeout,
				   conn_in_arg->is_websocket,
				   handshake_in_success, daemon);
}

/*~ When we get a direct connection in we set up its network address
 * then call handshake.c to set up the crypto state. */
static struct io_plan *connection_in(struct io_conn *conn,
				     struct daemon *daemon)
{
	struct conn_in conn_in_arg;

	conn_in_arg.addr.u.wireaddr.is_websocket = false;
	if (!get_remote_address(conn, &conn_in_arg.addr))
		return io_close(conn);

	conn_in_arg.daemon = daemon;
	conn_in_arg.is_websocket = false;
	return conn_in(conn, &conn_in_arg);
}

/*~ <hello>I speak web socket</hello>.
 *
 * Actually that's dumb, websocket (aka rfc6455) looks nothing like that. */
static struct io_plan *websocket_connection_in(struct io_conn *conn,
					       struct daemon *daemon)
{
	int childmsg[2], execfail[2];
	pid_t childpid;
	int err;
	struct conn_in conn_in_arg;

	conn_in_arg.addr.u.wireaddr.is_websocket = true;
	if (!get_remote_address(conn, &conn_in_arg.addr))
		return io_close(conn);

	status_debug("Websocket connection in from %s",
		     type_to_string(tmpctx, struct wireaddr_internal,
				    &conn_in_arg.addr));

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, childmsg) != 0)
		goto fail;

	if (pipe(execfail) != 0)
		goto close_msgfd_fail;

	if (fcntl(execfail[1], F_SETFD, fcntl(execfail[1], F_GETFD)
		  | FD_CLOEXEC) < 0)
		goto close_execfail_fail;

	childpid = fork();
	if (childpid < 0)
		goto close_execfail_fail;

	if (childpid == 0) {
		close(childmsg[0]);
		close(execfail[0]);

		/* Attach remote socket to stdin. */
		if (dup2(io_conn_fd(conn), STDIN_FILENO) == -1)
			goto child_errno_fail;

		/* Attach our socket to stdout. */
		if (dup2(childmsg[1], STDOUT_FILENO) == -1)
			goto child_errno_fail;

		/* Make (fairly!) sure all other fds are closed. */
		closefrom(STDERR_FILENO + 1);

		/* Tell websocket helper what we read so far. */
		execlp(daemon->websocket_helper, daemon->websocket_helper,
		       NULL);

	child_errno_fail:
		err = errno;
		/* Gcc's warn-unused-result fail. */
		if (write(execfail[1], &err, sizeof(err))) {
			;
		}
		exit(127);
	}

	close(childmsg[1]);
	close(execfail[1]);

	/* Child will close this without writing on successful exec. */
	if (read(execfail[0], &err, sizeof(err)) == sizeof(err)) {
		close(execfail[0]);
		waitpid(childpid, NULL, 0);
		status_broken("Exec of helper %s failed: %s",
			      daemon->websocket_helper, strerror(err));
		errno = err;
		return io_close(conn);
	}

	close(execfail[0]);

	/* New connection actually talks to proxy process. */
	conn_in_arg.daemon = daemon;
	conn_in_arg.is_websocket = true;
	io_new_conn(tal_parent(conn), childmsg[0], conn_in, &conn_in_arg);

	/* Abandon original (doesn't close since child has dup'd fd) */
	return io_close(conn);

close_execfail_fail:
	close_noerr(execfail[0]);
	close_noerr(execfail[1]);
close_msgfd_fail:
	close_noerr(childmsg[0]);
	close_noerr(childmsg[1]);
fail:
	status_broken("Preparation of helper failed: %s",
		      strerror(errno));
	return io_close(conn);
}

/*~ These are the mirror functions for the connecting-out case. */
static struct io_plan *handshake_out_success(struct io_conn *conn,
					     const struct pubkey *key,
					     const struct wireaddr_internal *addr,
					     struct crypto_state *cs,
					     struct oneshot *timeout,
					     enum is_websocket is_websocket,
					     struct connecting *connect)
{
	struct node_id id;

	node_id_from_pubkey(&id, key);
	connect->connstate = "Exchanging init messages";
	status_peer_debug(&id, "Connect OUT");
	return peer_exchange_initmsg(conn, connect->daemon,
				     connect->daemon->our_features,
				     cs, &id, addr, timeout, is_websocket, false);
}

struct io_plan *connection_out(struct io_conn *conn, struct connecting *connect)
{
	struct pubkey outkey;
	struct oneshot *timeout;

	/* This shouldn't happen: lightningd should not give invalid ids! */
	if (!pubkey_from_node_id(&outkey, &connect->id)) {
		status_broken("Connection out to invalid id %s",
			      type_to_string(tmpctx, struct node_id,
					     &connect->id));
		return io_close(conn);
	}

	/* If they don't complete handshake in reasonable time, hang up */
	timeout = new_reltimer(&connect->daemon->timers, conn,
			       time_from_sec(connect->daemon->timeout_secs),
			       conn_timeout, conn);
	status_peer_debug(&connect->id, "Connected out, starting crypto");

	connect->connstate = "Cryptographic handshake";
	return initiator_handshake(conn, &connect->daemon->mykey, &outkey,
				   &connect->addrs[connect->addrnum],
				   timeout, NORMAL_SOCKET, handshake_out_success, connect);
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
			   const struct wireaddr_internal *addrhint,
			   enum jsonrpc_errcode errcode,
			   const char *errfmt, ...)
	PRINTF_FMT(5,6);

static void connect_failed(struct daemon *daemon,
			   const struct node_id *id,
			   const struct wireaddr_internal *addrhint,
			   enum jsonrpc_errcode errcode,
			   const char *errfmt, ...)
{
	u8 *msg;
	va_list ap;
	char *errmsg;

	va_start(ap, errfmt);
	errmsg = tal_vfmt(tmpctx, errfmt, ap);
	va_end(ap);

	status_peer_debug(id, "Failed connected out: %s", errmsg);

	/* lightningd may have a connect command waiting to know what
	 * happened.  We leave it to lightningd to decide if it wants to try
	 * again. */
	msg = towire_connectd_connect_failed(NULL, id, errcode, errmsg,
					     addrhint);
	daemon_conn_send(daemon->master, take(msg));
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
	connect->conn = NULL;
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
		/* DNS should have been resolved before */
		assert(addr->u.wireaddr.wireaddr.type != ADDR_TYPE_DNS);
		/* If it was a Tor address, we wouldn't be here. */
		assert(!is_toraddr((char*)addr->u.wireaddr.wireaddr.addr));
		ai = wireaddr_to_addrinfo(tmpctx, &addr->u.wireaddr.wireaddr);
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
		host = fmt_wireaddr_without_port(tmpctx, &addr->u.wireaddr.wireaddr);
		port = addr->u.wireaddr.wireaddr.port;
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
	bool use_proxy = connect->daemon->always_use_proxy;
	const struct wireaddr_internal *addr = &connect->addrs[connect->addrnum];
	struct io_conn *conn;
	bool use_dns = connect->daemon->use_dns;
	struct addrinfo hints, *ais, *aii;
	struct wireaddr_internal addrhint;
	int gai_err;
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;

	assert(!connect->conn);

	/* Out of addresses? */
	if (connect->addrnum == tal_count(connect->addrs)) {
		connect_failed(connect->daemon, &connect->id,
			       connect->addrhint, CONNECT_ALL_ADDRESSES_FAILED,
			       "All addresses failed: %s",
			       connect->errors);
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
		switch (addr->u.wireaddr.wireaddr.type) {
		case ADDR_TYPE_TOR_V2_REMOVED:
			af = -1;
			break;
		case ADDR_TYPE_TOR_V3:
			use_proxy = true;
			break;
		case ADDR_TYPE_IPV4:
			af = AF_INET;
			break;
		case ADDR_TYPE_IPV6:
			af = AF_INET6;
			break;
		case ADDR_TYPE_DNS:
			if (use_proxy) /* hand it to the proxy */
				break;
			if (!use_dns) {  /* ignore DNS when we can't use it */
				tal_append_fmt(&connect->errors,
					       "%s: dns disabled. ",
					       type_to_string(tmpctx,
							      struct wireaddr_internal,
							      addr));
				goto next;
			}
			/* Resolve with getaddrinfo */
			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_family = AF_UNSPEC;
			hints.ai_protocol = 0;
			hints.ai_flags = AI_ADDRCONFIG;
			gai_err = getaddrinfo((char *)addr->u.wireaddr.wireaddr.addr,
					      tal_fmt(tmpctx, "%d",
						      addr->u.wireaddr.wireaddr.port),
					      &hints, &ais);
			if (gai_err != 0) {
				tal_append_fmt(&connect->errors,
					       "%s: getaddrinfo error '%s'. ",
					       type_to_string(tmpctx,
							      struct wireaddr_internal,
							      addr),
					       gai_strerror(gai_err));
				goto next;
			}
			/* create new addrhints on-the-fly per result ... */
			for (aii = ais; aii; aii = aii->ai_next) {
				addrhint.itype = ADDR_INTERNAL_WIREADDR;
				addrhint.u.wireaddr.is_websocket = false;
				if (aii->ai_family == AF_INET) {
					sa4 = (struct sockaddr_in *) aii->ai_addr;
					wireaddr_from_ipv4(&addrhint.u.wireaddr.wireaddr,
							   &sa4->sin_addr,
							   addr->u.wireaddr.wireaddr.port);
				} else if (aii->ai_family == AF_INET6) {
					sa6 = (struct sockaddr_in6 *) aii->ai_addr;
					wireaddr_from_ipv6(&addrhint.u.wireaddr.wireaddr,
							   &sa6->sin6_addr,
							   addr->u.wireaddr.wireaddr.port);
				} else {
					/* skip unsupported ai_family */
					continue;
				}
				tal_arr_expand(&connect->addrs, addrhint);
				/* don't forget to update convenience pointer */
				addr = &connect->addrs[connect->addrnum];
			}
			freeaddrinfo(ais);
			goto next;
		}
	}

	/* If we have to use proxy but we don't have one, we fail. */
	if (use_proxy) {
		if (!connect->daemon->proxyaddr) {
			tal_append_fmt(&connect->errors,
				       "%s: need a proxy. ",
				       type_to_string(tmpctx,
						      struct wireaddr_internal,
						      addr));
			goto next;
		}
		af = connect->daemon->proxyaddr->ai_family;
	}

	if (af == -1) {
		tal_append_fmt(&connect->errors,
			       "%s: not supported. ",
			       type_to_string(tmpctx, struct wireaddr_internal,
					      addr));
		goto next;
	}

	fd = socket(af, SOCK_STREAM, 0);
	if (fd < 0) {
		tal_append_fmt(&connect->errors,
			       "%s: opening %i socket gave %s. ",
			       type_to_string(tmpctx, struct wireaddr_internal,
					      addr),
			       af, strerror(errno));
		goto next;
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

	return;

next:
	/* This causes very limited recursion. */
	connect->addrnum++;
	try_connect_one_addr(connect);
}

/*~ connectd is responsible for incoming connections, but it's the process of
 * setting up the listening ports which gives us information we need for startup
 * (such as our own address).  So we perform setup in two phases: first we bind
 * the sockets according to the command line arguments (if any), then we start
 * listening for connections to them once lightningd is ready.
 *
 * This stores the fds we're going to listen on: */
struct listen_fd {
	/* This is usually an IPv4/v6 address, but we also support local
	 * domain sockets (i.e. filesystem) */
	struct wireaddr_internal wi;
	/* The actual fd, ready to listen() on */
	int fd;
	/* If we bind() IPv6 then IPv4 to same port, we *may* fail to listen()
	 * on the IPv4 socket: under Linux, by default, the IPv6 listen()
	 * covers IPv4 too.  Normally we'd consider failing to listen on a
	 * port to be fatal, so we note this when setting up addresses. */
	bool mayfail;
	/* Is this a websocket? */
	enum is_websocket is_websocket;
};

static struct listen_fd *listen_fd_new(const tal_t *ctx,
				       const struct wireaddr_internal *wi,
				       int fd, bool mayfail,
				       enum is_websocket is_websocket)
{
	struct listen_fd *l = tal(ctx, struct listen_fd);

	l->wi = *wi;
	l->fd = fd;
	l->mayfail = mayfail;
	l->is_websocket = is_websocket;
	return l;
}

/*~ Helper routine to create and bind a socket of a given type; like many
 * daemons we set it SO_REUSEADDR so we won't have to wait 2 minutes to reuse
 * it on restart.
 *
 * Note that it's generally an antipattern to have a function which
 * returns an allocated object without an explicit tal ctx so the
 * caller is aware. */
static struct listen_fd *make_listen_fd(const tal_t *ctx,
					const struct wireaddr_internal *wi,
					int domain, void *addr, socklen_t len,
					bool listen_mayfail,
					enum is_websocket is_websocket,
					char **errstr)
{
	int fd = socket(domain, SOCK_STREAM, 0);
	int on = 1;

	if (fd < 0) {
		const char *es = strerror(errno);
		*errstr = tal_fmt(ctx, "Failed to create socket for %s%s: %s",
				  is_websocket ? "websocket " : "",
				  type_to_string(tmpctx,
						 struct wireaddr_internal,
						 wi),
				  es);
		status_debug("Failed to create %u socket: %s", domain, es);
		return NULL;
	}

	/* Re-use, please.. */
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
		status_unusual("Failed setting socket reuse: %s",
			       strerror(errno));

	if (bind(fd, addr, len) != 0) {
		const char *es = strerror(errno);
		*errstr = tal_fmt(ctx, "Failed to bind socket for %s%s: %s",
				  is_websocket ? "websocket " : "",
				  type_to_string(tmpctx,
						 struct wireaddr_internal,
						 wi),
				  es);
		status_debug("Failed to bind %u socket: %s", domain, es);
		goto fail;
	}

	*errstr = NULL;
	status_debug("Created %slistener on %s",
		     is_websocket ? "websocket ": "",
		     type_to_string(tmpctx, struct wireaddr_internal, wi));
	return listen_fd_new(ctx, wi, fd, listen_mayfail, is_websocket);

fail:
	/*~ ccan/noerr contains convenient routines which don't clobber the
	 * errno global; in this case, the caller can report errno. */
	close_noerr(fd);
	return NULL;
}

/* Return true if it created socket successfully.  If errstr is non-NULL,
 * allocate off ctx if return false, otherwise it implies it's OK to fail. */
static struct listen_fd *handle_wireaddr_listen(const tal_t *ctx,
						const struct wireaddr_internal *wi,
						bool listen_mayfail,
						char **errstr)
{
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	const struct wireaddr *wireaddr;
	bool is_websocket = wi->u.wireaddr.is_websocket;

	assert(wi->itype == ADDR_INTERNAL_WIREADDR);
	wireaddr = &wi->u.wireaddr.wireaddr;

	/* Note the use of a switch() over enum here, even though it must be
	 * IPv4 or IPv6 here; that will catch future changes. */
	switch (wireaddr->type) {
	case ADDR_TYPE_IPV4:
		wireaddr_to_ipv4(wireaddr, &addr);
		/* We might fail if IPv6 bound to port first */
		return make_listen_fd(ctx, wi, AF_INET, &addr, sizeof(addr),
				      listen_mayfail, is_websocket, errstr);
	case ADDR_TYPE_IPV6:
		wireaddr_to_ipv6(wireaddr, &addr6);
		return make_listen_fd(ctx, wi, AF_INET6, &addr6, sizeof(addr6),
				      listen_mayfail, is_websocket, errstr);
	/* Handle specially by callers. */
	case ADDR_TYPE_TOR_V2_REMOVED:
	case ADDR_TYPE_TOR_V3:
	case ADDR_TYPE_DNS:
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

static void add_announceable(struct wireaddr **announceable,
			     const struct wireaddr *addr)
{
	/*~ utils.h contains a convenience macro tal_arr_expand which
	 * reallocates a tal_arr to make it one longer, then returns a pointer
	 * to the (new) last element. */
	tal_arr_expand(announceable, *addr);
}

/* We need to have a bound address we can tell Tor to connect to */
static const struct wireaddr *
find_local_address(const struct listen_fd **listen_fds)
{
	for (size_t i = 0; i < tal_count(listen_fds); i++) {
		if (listen_fds[i]->wi.itype != ADDR_INTERNAL_WIREADDR)
			continue;
		if (listen_fds[i]->wi.u.wireaddr.is_websocket)
			continue;
		if (listen_fds[i]->wi.u.wireaddr.wireaddr.type != ADDR_TYPE_IPV4
		    && listen_fds[i]->wi.u.wireaddr.wireaddr.type != ADDR_TYPE_IPV6)
			continue;
		return &listen_fds[i]->wi.u.wireaddr.wireaddr;
	}
	return NULL;
}

static bool want_tor(const struct wireaddr_internal *proposed_wireaddr)
{
	for (size_t i = 0; i < tal_count(proposed_wireaddr); i++) {
		if (proposed_wireaddr[i].itype == ADDR_INTERNAL_STATICTOR
		    || proposed_wireaddr[i].itype == ADDR_INTERNAL_AUTOTOR)
			return true;
	}
	return false;
}

/*~ The user can specify three kinds of addresses: ones we bind to but don't
 * announce, ones we announce but don't bind to, and ones we bind to and
 * announce if they seem to be public addresses.
 *
 * This routine sorts out the mess: it populates the *announceable array,
 * and returns the addresses we bound to (by convention, return is allocated
 * off `ctx` argument).
 *
 * Note the important difference between returning a zero-element array, and
 * returning NULL!  The latter means failure here, the former simply means
 * we don't want to listen to anything.
 */
static const struct listen_fd **
setup_listeners(const tal_t *ctx,
		struct daemon *daemon,
		/* The proposed address. */
		const struct wireaddr_internal *proposed_wireaddr,
		/* For each one, listen, announce or both */
		const enum addr_listen_announce *proposed_listen_announce,
		const char *tor_password,
		struct wireaddr **announceable,
		char **errstr)
{
	struct sockaddr_un addrun;
	const struct listen_fd **listen_fds, *lfd;
	const char *blob = NULL;
	struct secret random;
	struct pubkey pb;
	struct wireaddr *toraddr;
	const struct wireaddr *localaddr;

	/* Start with empty arrays, for tal_arr_expand() */
	listen_fds = tal_arr(ctx, const struct listen_fd *, 0);
	*announceable = tal_arr(ctx, struct wireaddr, 0);

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
		add_announceable(announceable, &wa.u.wireaddr.wireaddr);
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
			lfd = make_listen_fd(ctx, &wa, AF_UNIX,
					     &addrun, sizeof(addrun),
					     false, NORMAL_SOCKET,
					     errstr);
			/* Don't bother freeing here; we'll exit */
			if (!lfd)
				return NULL;
			/* We don't announce socket names, though we allow
			 * them to lazily specify --addr=/socket. */
			tal_arr_expand(&listen_fds, tal_steal(listen_fds, lfd));
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
			wa.u.wireaddr.wireaddr.port = wa.u.allproto.port;
			wa.u.wireaddr.is_websocket = wa.u.allproto.is_websocket;

			/* First, create wildcard IPv6 address. */
			wa.u.wireaddr.wireaddr.type = ADDR_TYPE_IPV6;
			wa.u.wireaddr.wireaddr.addrlen = 16;
			memset(wa.u.wireaddr.wireaddr.addr, 0,
			       sizeof(wa.u.wireaddr.wireaddr.addr));

			/* This may fail due to no IPv6 support. */
			lfd = handle_wireaddr_listen(ctx, &wa, false, errstr);
			if (lfd) {
				tal_arr_expand(&listen_fds,
					       tal_steal(listen_fds, lfd));
				if (announce
				    && public_address(daemon, &wa.u.wireaddr.wireaddr))
					add_announceable(announceable,
							 &wa.u.wireaddr.wireaddr);
			}
			ipv6_ok = (lfd != NULL);

			/* Now, create wildcard IPv4 address. */
			wa.u.wireaddr.wireaddr.type = ADDR_TYPE_IPV4;
			wa.u.wireaddr.wireaddr.addrlen = 4;
			memset(wa.u.wireaddr.wireaddr.addr, 0,
			       sizeof(wa.u.wireaddr.wireaddr.addr));
			/* This listen *may* fail, as long as IPv6 succeeds! */
			lfd = handle_wireaddr_listen(ctx, &wa, ipv6_ok, errstr);
			if (lfd) {
				tal_arr_expand(&listen_fds,
					       tal_steal(listen_fds, lfd));
				if (announce
				    && public_address(daemon, &wa.u.wireaddr.wireaddr))
					add_announceable(announceable,
							&wa.u.wireaddr.wireaddr);
			} else if (!ipv6_ok) {
				/* Both failed, return now, errstr set. */
				return NULL;
			}
			continue;
		}
		/* This is a vanilla wireaddr as per BOLT #7 */
		case ADDR_INTERNAL_WIREADDR:
			lfd = handle_wireaddr_listen(ctx, &wa, false, errstr);
			if (!lfd)
				return NULL;
			tal_arr_expand(&listen_fds, tal_steal(listen_fds, lfd));
			if (announce && public_address(daemon, &wa.u.wireaddr.wireaddr))
				add_announceable(announceable, &wa.u.wireaddr.wireaddr);
			continue;
		case ADDR_INTERNAL_FORPROXY:
			break;
		}
		/* Shouldn't happen. */
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Invalid listener address type %u",
			      proposed_wireaddr[i].itype);
	}

	/* Make sure we have at least one non-websocket address to send to,
	 * for Tor */
	localaddr = find_local_address(listen_fds);
	if (want_tor(proposed_wireaddr) && !localaddr) {
		*errstr = "Need to bind at least one local address,"
			" to send Tor connections to";
		return NULL;
	}

	/* If we want websockets to match IPv4/v6, set it up now. */
	if (daemon->websocket_port) {
		bool announced_some = false;
		struct wireaddr_internal addr;
		/* Only consider bindings added before this! */
		size_t num_nonws_listens = tal_count(listen_fds);

		for (size_t i = 0; i < num_nonws_listens; i++) {
			/* Ignore UNIX sockets */
			if (listen_fds[i]->wi.itype != ADDR_INTERNAL_WIREADDR)
				continue;

			/* Override with websocket port */
			addr = listen_fds[i]->wi;
			addr.u.wireaddr.is_websocket = true;
			addr.u.wireaddr.wireaddr.port = daemon->websocket_port;

			/* We set mayfail on all but the first websocket;
			 * it's quite common to have multple overlapping
			 * addresses. */
			lfd = handle_wireaddr_listen(ctx, &addr, announced_some,
						     errstr);
			if (!lfd)
				continue;

			announced_some = true;
			tal_arr_expand(&listen_fds, tal_steal(listen_fds, lfd));
		}

		/* If none of those was possible, it's a configuration error? */
		if (tal_count(listen_fds) == num_nonws_listens) {
			*errstr = "Cannot listen on websocket: not listening on any IPv4/6 addresses";
			return NULL;
		}
	}

	/* FIXME: Websocket over Tor (difficult for autotor, since we need
	 * to use the same onion addr!) */

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
					  localaddr);

		if (!(proposed_listen_announce[i] & ADDR_ANNOUNCE)) {
			continue;
		};
		add_announceable(announceable, toraddr);
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
					    localaddr,
					    0);
		/* get rid of blob data on our side of tor and add jitter */
		randombytes_buf((void * const)proposed_wireaddr[i].u.torservice.blob, TOR_V3_BLOBLEN);

		if (!(proposed_listen_announce[i] & ADDR_ANNOUNCE)) {
				continue;
		};
		add_announceable(announceable, toraddr);
	}

	/*~ The spec used to ban more than one address of each type, but
	 * nobody could remember exactly why, so now that's allowed. */
	/* BOLT #7:
	 *
	 * The origin node:
	 *...
	 *   - MUST place address descriptors in ascending order.
	 */
	asort(*announceable, tal_count(*announceable), wireaddr_cmp_type, NULL);

	*errstr = NULL;
	return listen_fds;
}


/*~ Parse the incoming connect init message from lightningd ("master") and
 * assign config variables to the daemon; it should be the first message we
 * get. */
static void connect_init(struct daemon *daemon, const u8 *msg)
{
	struct wireaddr *proxyaddr;
	struct wireaddr_internal *binding;
	struct wireaddr_internal *proposed_wireaddr;
	enum addr_listen_announce *proposed_listen_announce;
	struct wireaddr *announceable;
	char *tor_password;
	bool dev_fast_gossip;
	bool dev_disconnect, dev_no_ping_timer;
	char *errstr;

	/* Fields which require allocation are allocated off daemon */
	if (!fromwire_connectd_init(
		daemon, msg,
		&chainparams,
		&daemon->our_features,
		&daemon->id,
		&proposed_wireaddr,
		&proposed_listen_announce,
		&proxyaddr, &daemon->always_use_proxy,
		&daemon->dev_allow_localhost, &daemon->use_dns,
		&tor_password,
		&daemon->timeout_secs,
		&daemon->websocket_helper,
		&daemon->websocket_port,
		&daemon->announce_websocket,
		&dev_fast_gossip,
		&dev_disconnect,
		&dev_no_ping_timer)) {
		/* This is a helper which prints the type expected and the actual
		 * message, then exits (it should never be called!). */
		master_badmsg(WIRE_CONNECTD_INIT, msg);
	}

#if DEVELOPER
	/*~ Clearly mark these as developer-only flags! */
	daemon->dev_fast_gossip = dev_fast_gossip;
	daemon->dev_no_ping_timer = dev_no_ping_timer;
	daemon->dev_suppress_gossip = false;
#endif

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
	daemon->listen_fds = setup_listeners(daemon, daemon,
					     proposed_wireaddr,
					     proposed_listen_announce,
					     tor_password,
					     &announceable,
					     &errstr);

	/* Free up old allocations */
	tal_free(proposed_wireaddr);
	tal_free(proposed_listen_announce);
	tal_free(tor_password);

	/* Create binding array to send to lightningd */
	binding = tal_arr(tmpctx, struct wireaddr_internal, 0);
	for (size_t i = 0; i < tal_count(daemon->listen_fds); i++) {
		/* FIXME: Tell it about websockets! */
		if (daemon->listen_fds[i]->is_websocket)
			continue;
		tal_arr_expand(&binding, daemon->listen_fds[i]->wi);
	}

	/* Tell it we're ready, handing it the addresses we have. */
	daemon_conn_send(daemon->master,
			 take(towire_connectd_init_reply(NULL,
							 binding,
							 announceable,
							 errstr)));
	/*~ Who cares about a little once-off memory leak?  Turns out we do!
	 * We have a memory leak checker which scans for allocated memory
	 * with no pointers to it (a tell-tale leak sign, though with tal it's
	 * not always a real problem), and this would (did!) trigger it. */
	tal_free(announceable);

#if DEVELOPER
	if (dev_disconnect) {
		daemon->dev_disconnect_fd = 5;
		dev_disconnect_init(5);
	} else {
		daemon->dev_disconnect_fd = -1;
	}
#endif
}

/* Returning functions in C is ugly! */
static struct io_plan *(*get_in_cb(enum is_websocket is_websocket))(struct io_conn *, struct daemon *)

{
	/*~ This switch and fall pattern serves a specific purpose:
	 * gcc will warn if we don't handle every case! */
	switch (is_websocket) {
	case WEBSOCKET:
		return websocket_connection_in;
	case NORMAL_SOCKET:
		return connection_in;
	}
	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "Invalid is_websocket %u", is_websocket);
}

/*~ lightningd tells us to go! */
static void connect_activate(struct daemon *daemon, const u8 *msg)
{
	bool do_listen;
	char *errmsg = NULL;

	if (!fromwire_connectd_activate(msg, &do_listen))
		master_badmsg(WIRE_CONNECTD_ACTIVATE, msg);

	/* If we're --offline, lightningd tells us not to actually listen. */
	if (do_listen) {
		for (size_t i = 0; i < tal_count(daemon->listen_fds); i++) {
			if (listen(daemon->listen_fds[i]->fd, 64) != 0) {
				if (daemon->listen_fds[i]->mayfail) {
					close(daemon->listen_fds[i]->fd);
					continue;
				}
				errmsg = tal_fmt(tmpctx,
						 "Failed to listen on socket %s: %s",
						 type_to_string(tmpctx,
								struct wireaddr_internal,
								&daemon->listen_fds[i]->wi),
						 strerror(errno));
				break;
			}
			/* Add to listeners array */
			tal_arr_expand(&daemon->listeners,
				       io_new_listener(daemon,
						       daemon->listen_fds[i]->fd,
						       get_in_cb(daemon->listen_fds[i]
								 ->is_websocket),
						       daemon));
		}
	}

	/* Free, with NULL assignment just as an extra sanity check. */
	daemon->listen_fds = tal_free(daemon->listen_fds);

	/* OK, we're ready! */
	daemon_conn_send(daemon->master,
			 take(towire_connectd_activate_reply(NULL, errmsg)));
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
	bech32_encode(bech32, "ln", data, tal_count(data), sizeof(bech32),
		      BECH32_ENCODING_BECH32);
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
		new_addrs = wireaddr_from_hostname(tmpctx, hostnames[i], chainparams_get_ln_port(chainparams),
		                                   NULL, broken_reply, NULL);
		if (new_addrs) {
			for (size_t j = 0; j < tal_count(new_addrs); j++) {
				if (new_addrs[j].type == ADDR_TYPE_DNS)
					continue;
				struct wireaddr_internal a;
				a.itype = ADDR_INTERNAL_WIREADDR;
				a.u.wireaddr.is_websocket = false;
				a.u.wireaddr.wireaddr = new_addrs[j];
				status_peer_debug(id, "Resolved %s to %s", hostnames[i],
						  type_to_string(tmpctx, struct wireaddr,
								 &a.u.wireaddr.wireaddr));
				tal_arr_expand(addrs, a);
			}
			/* Other seeds will likely have the same information. */
			return;
		} else
			status_peer_debug(id, "Could not resolve %s", hostnames[i]);
	}
}

/*~ Adds just one address type.
 *
 * Ignores deprecated and the `addrhint`. */
static void add_gossip_addrs_bytypes(struct wireaddr_internal **addrs,
				     const struct wireaddr *normal_addrs,
				     const struct wireaddr *addrhint,
				     u64 types)
{
	for (size_t i = 0; i < tal_count(normal_addrs); i++) {
		if (addrhint && wireaddr_eq(addrhint, &normal_addrs[i]))
			continue;
		/* I guess this is possible in future! */
		if (normal_addrs[i].type > 63)
			continue;
		if (((u64)1 << normal_addrs[i].type) & types) {
			struct wireaddr_internal addr;
			addr.itype = ADDR_INTERNAL_WIREADDR;
			addr.u.wireaddr.is_websocket = false;
			addr.u.wireaddr.wireaddr = normal_addrs[i];
			tal_arr_expand(addrs, addr);
		}
	}

}


/*~ Orders the addresses which lightningd gave us.
 *
 * Ignores deprecated protocols and the `addrhint` that is assumed to be
 * already added first. Adds all IPv6 addresses, followed by IPv4 and then TOR.
 * This ensures we are modern and use IPv6 when possible, falling back to
 * direct (faster) IPv4 and finally (less stable) TOR connections. */
static void add_gossip_addrs(struct wireaddr_internal **addrs,
			     const struct wireaddr *normal_addrs,
			     const struct wireaddr *addrhint)
{
	u64 types[] = { 0, 0, 0 };

	/* Note gratuitous use of switch() means we'll know if a new one
	 * appears! */
	for (size_t i = ADDR_TYPE_IPV4; i <= ADDR_TYPE_DNS; i++) {
		switch ((enum wire_addr_type)i) {
		/* First priority */
		case ADDR_TYPE_IPV6:
		case ADDR_TYPE_DNS:
			types[0] |= ((u64)1 << i);
			break;
		/* Second priority */
		case ADDR_TYPE_IPV4:
			types[1] |= ((u64)1 << i);
			break;
		case ADDR_TYPE_TOR_V3:
		/* Third priority */
			types[2] |= ((u64)1 << i);
			break;
		/* We can't use these to connect to! */
		case ADDR_TYPE_TOR_V2_REMOVED:
			break;
		}
		/* Other results returned are possible, but we don't understand
		 * them anyway! */
	}

	/* Add in priority order */
	for (size_t i = 0; i < ARRAY_SIZE(types); i++)
		add_gossip_addrs_bytypes(addrs, normal_addrs, addrhint, types[i]);
}

/*~ Consumes addrhint if not NULL.
 *
 * That's a pretty ugly interface: we should use TAKEN, but we only have one
 * caller so it's marginal. */
static void try_connect_peer(struct daemon *daemon,
			     const struct node_id *id,
			     struct wireaddr *gossip_addrs,
			     struct wireaddr_internal *addrhint STEALS,
			     bool dns_fallback)
{
	struct wireaddr_internal *addrs;
	bool use_proxy = daemon->always_use_proxy;
	struct connecting *connect;

	/* Already existing?  Must have crossed over, it'll know soon. */
	if (peer_htable_get(daemon->peers, id))
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
	/* We add this first so its tried first by connectd */
	if (addrhint)
		tal_arr_expand(&addrs, *addrhint);

	/* Tell it to omit the existing hint (if that's a wireaddr itself) */
	add_gossip_addrs(&addrs, gossip_addrs,
			 addrhint
			 && addrhint->itype == ADDR_INTERNAL_WIREADDR
			 && !addrhint->u.wireaddr.is_websocket
			 ? &addrhint->u.wireaddr.wireaddr : NULL);

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
				                         chainparams_get_ln_port(chainparams));
				tal_arr_expand(&addrs, unresolved);
			}
		} else if (daemon->use_dns && dns_fallback) {
			add_seed_addrs(&addrs, id,
			               daemon->broken_resolver_response);
		}
	}

	/* Still no address?  Fail immediately.  Lightningd can still choose
	* to retry; an address may get gossiped or appear on the DNS seed. */
	if (tal_count(addrs) == 0) {
		connect_failed(daemon, id, addrhint,
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
	connect->addrhint = tal_steal(connect, addrhint);
	connect->errors = tal_strdup(connect, "");
	connect->conn = NULL;
	list_add_tail(&daemon->connecting, &connect->list);
	tal_add_destructor(connect, destroy_connecting);

	/* Now we kick it off by recursively trying connect->addrs[connect->addrnum] */
	try_connect_one_addr(connect);
}

/* lightningd tells us to connect to a peer by id, with optional addr hint. */
static void connect_to_peer(struct daemon *daemon, const u8 *msg)
{
	struct node_id id;
	struct wireaddr_internal *addrhint;
	struct wireaddr *addrs;
	bool dns_fallback;

	if (!fromwire_connectd_connect_to_peer(tmpctx, msg,
					       &id, &addrs, &addrhint,
					       &dns_fallback))
		master_badmsg(WIRE_CONNECTD_CONNECT_TO_PEER, msg);

	try_connect_peer(daemon, &id, addrs, addrhint, dns_fallback);
}

/* lightningd tells us a peer should be disconnected. */
static void peer_discard(struct daemon *daemon, const u8 *msg)
{
	struct node_id id;
	u64 counter;
	struct peer *peer;

	if (!fromwire_connectd_discard_peer(msg, &id, &counter))
		master_badmsg(WIRE_CONNECTD_DISCARD_PEER, msg);

	/* We should stay in sync with lightningd, but this can happen
	 * under stress. */
	peer = peer_htable_get(daemon->peers, &id);
	if (!peer)
		return;
	/* If it's reconnected already, it will learn soon. */
	if (peer->counter != counter)
		return;
	status_peer_debug(&id, "discard_peer");
	tal_free(peer);
}

static void start_shutdown(struct daemon *daemon, const u8 *msg)
{
	if (!fromwire_connectd_start_shutdown(msg))
		master_badmsg(WIRE_CONNECTD_START_SHUTDOWN, msg);

	daemon->shutting_down = true;

	/* No more incoming connections! */
	daemon->listeners = tal_free(daemon->listeners);

	daemon_conn_send(daemon->master,
			 take(towire_connectd_start_shutdown_reply(NULL)));
}

/* lightningd tells us to send a msg and disconnect. */
static void peer_final_msg(struct io_conn *conn,
			   struct daemon *daemon, const u8 *msg)
{
	struct peer *peer;
	struct node_id id;
	u64 counter;
	u8 *finalmsg;

	if (!fromwire_connectd_peer_final_msg(tmpctx, msg, &id, &counter,
					      &finalmsg))
		master_badmsg(WIRE_CONNECTD_PEER_FINAL_MSG, msg);

	/* This can happen if peer hung up on us (or wrong counter
	 * if it reconnected). */
	peer = peer_htable_get(daemon->peers, &id);
	if (peer && peer->counter == counter)
		multiplex_final_msg(peer, take(finalmsg));
}

static void dev_connect_memleak(struct daemon *daemon, const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	memtable = memleak_start(tmpctx);
	memleak_ptr(memtable, msg);

	/* Now delete daemon and those which it has pointers to. */
	memleak_scan_obj(memtable, daemon);
	memleak_scan_htable(memtable, &daemon->peers->raw);

	found_leak = dump_memleak(memtable, memleak_status_broken);
	daemon_conn_send(daemon->master,
			 take(towire_connectd_dev_memleak_reply(NULL,
							      found_leak)));
}

#if DEVELOPER
static void dev_suppress_gossip(struct daemon *daemon, const u8 *msg)
{
	daemon->dev_suppress_gossip = true;
}

static const char *addr2name(const tal_t *ctx,
			     const struct sockaddr_storage *sa,
			     socklen_t addrlen)
{
	const struct sockaddr_in *in = (struct sockaddr_in *)sa;
	const struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)sa;
	const struct sockaddr_un *un = (struct sockaddr_un *)sa;
	char addr[1000];

	switch (sa->ss_family) {
	case AF_UNIX:
		if (addrlen == sizeof(un->sun_family))
			return tal_fmt(ctx, "unix socket <unnamed>");
		else
			return tal_fmt(ctx, "unix socket %s", un->sun_path);
	case AF_INET:
		if (!inet_ntop(sa->ss_family, &in->sin_addr, addr, sizeof(addr)))
			return tal_fmt(ctx, "IPv4 socket <badaddr>");
		else
			return tal_fmt(ctx, "IPv4 socket %s:%u",
				       addr, ntohs(in->sin_port));
	case AF_INET6:
		if (!inet_ntop(sa->ss_family, &in6->sin6_addr, addr, sizeof(addr)))
			return tal_fmt(ctx, "IPv6 socket <badaddr>");
		else
			return tal_fmt(ctx, "IPv6 socket %s:%u",
				       addr, ntohs(in6->sin6_port));
	default:
		return tal_fmt(ctx, "unknown family %u (**BROKEN**)",
			       (unsigned)sa->ss_family);
	}
}

static void describe_fd(int fd)
{
	struct sockaddr_storage sa;
	socklen_t addrlen = sizeof(sa);

	if (getsockname(fd, (void *)&sa, &addrlen) != 0) {
		status_broken("dev_report_fds: %i cannot get sockname (%s)",
			      fd, strerror(errno));
		return;
	}
	status_info("dev_report_fds: %i name %s", fd, addr2name(tmpctx, &sa, addrlen));

	if (getpeername(fd, (void *)&sa, &addrlen) != 0)
		return;
	status_info("dev_report_fds: %i peer %s", fd, addr2name(tmpctx, &sa, addrlen));
}

static const char *io_plan_status_str(enum io_plan_status status)
{
	switch (status) {
	case IO_UNSET: return "IO_UNSET";
	case IO_POLLING_NOTSTARTED: return "IO_POLLING_NOTSTARTED";
	case IO_POLLING_STARTED: return "IO_POLLING_STARTED";
	case IO_WAITING: return "IO_WAITING";
	case IO_ALWAYS: return "IO_ALWAYS";
	}
	return "INVALID-STATUS";
}

/* Stupid and slow, but machines are fast! */
static const tal_t *find_tal_ptr(const tal_t *root, const tal_t *p)
{
	if (root == p)
		return root;

	for (tal_t *t = tal_first(root); t; t = tal_next(t)) {
		const tal_t *ret = find_tal_ptr(t, p);
		if (ret)
			return ret;
	}
	return NULL;
}

/* Looks up ptr in hash tree, to try to find name */
static const char *try_tal_name(const tal_t *ctx, const void *p)
{
	const tal_t *t = find_tal_ptr(NULL, p);
	if (t)
		return tal_name(t);
	return tal_fmt(ctx, "%p", p);
}

static void dev_report_fds(struct daemon *daemon, const u8 *msg)
{
	for (int fd = 3; fd < 4096; fd++) {
		bool listener;
		const struct io_conn *c;
		const struct io_listener *l;
		if (!isatty(fd) && errno == EBADF)
			continue;
		if (fd == HSM_FD) {
			status_info("dev_report_fds: %i -> hsm fd", fd);
			continue;
		}
		if (fd == GOSSIPCTL_FD) {
			status_info("dev_report_fds: %i -> gossipd fd", fd);
			continue;
		}
#if DEVELOPER
		if (fd == daemon->dev_disconnect_fd) {
			status_info("dev_report_fds: %i -> dev_disconnect_fd", fd);
			continue;
		}
#endif
		if (fd == daemon->gossip_store_fd) {
			status_info("dev_report_fds: %i -> gossip_store", fd);
			continue;
		}
		c = io_have_fd(fd, &listener);
		if (!c) {
			status_broken("dev_report_fds: %i open but unowned?", fd);
			continue;
		} else if (listener) {
			l = (void *)c;
			status_info("dev_report_fds: %i -> listener (%s)", fd,
				    backtrace_symname(tmpctx, l->init));
		} else {
			status_info("dev_report_fds: %i -> IN=%s:%s+%s(%s), OUT=%s:%s+%s(%s)",
				    fd,
				    io_plan_status_str(c->plan[IO_IN].status),
				    backtrace_symname(tmpctx, c->plan[IO_IN].io),
				    backtrace_symname(tmpctx, c->plan[IO_IN].next),
				    try_tal_name(tmpctx, c->plan[IO_IN].next_arg),
				    io_plan_status_str(c->plan[IO_OUT].status),
				    backtrace_symname(tmpctx, c->plan[IO_OUT].io),
				    backtrace_symname(tmpctx, c->plan[IO_OUT].next),
				    try_tal_name(tmpctx, c->plan[IO_OUT].next_arg));
		}
		describe_fd(fd);
	}
}
#endif /* DEVELOPER */

static struct io_plan *recv_peer_connect_subd(struct io_conn *conn,
					      const u8 *msg,
					      int fd,
					      struct daemon *daemon)
{
	peer_connect_subd(daemon, msg, fd);
	return daemon_conn_read_next(conn, daemon->master);
}

static struct io_plan *recv_req(struct io_conn *conn,
				const u8 *msg,
				struct daemon *daemon)
{
	enum connectd_wire t = fromwire_peektype(msg);

	/* Demux requests from lightningd: we expect INIT then ACTIVATE, then
	 * connect requests and disconnected messages. */
	switch (t) {
	case WIRE_CONNECTD_INIT:
		connect_init(daemon, msg);
		goto out;

	case WIRE_CONNECTD_ACTIVATE:
		connect_activate(daemon, msg);
		goto out;

	case WIRE_CONNECTD_CONNECT_TO_PEER:
		connect_to_peer(daemon, msg);
		goto out;

	case WIRE_CONNECTD_DISCARD_PEER:
		peer_discard(daemon, msg);
		goto out;

	case WIRE_CONNECTD_PEER_FINAL_MSG:
		peer_final_msg(conn, daemon, msg);
		goto out;

	case WIRE_CONNECTD_PING:
		send_manual_ping(daemon, msg);
		goto out;

	case WIRE_CONNECTD_SEND_ONIONMSG:
		onionmsg_req(daemon, msg);
		goto out;

	case WIRE_CONNECTD_CUSTOMMSG_OUT:
		send_custommsg(daemon, msg);
		goto out;

	case WIRE_CONNECTD_PEER_CONNECT_SUBD:
		/* This comes with an fd */
		return daemon_conn_read_with_fd(conn, daemon->master,
						recv_peer_connect_subd, daemon);

	case WIRE_CONNECTD_START_SHUTDOWN:
		start_shutdown(daemon, msg);
		goto out;

	case WIRE_CONNECTD_DEV_MEMLEAK:
		if (daemon->developer) {
			dev_connect_memleak(daemon, msg);
			goto out;
		}
		/* Fall thru */
	case WIRE_CONNECTD_DEV_SUPPRESS_GOSSIP:
#if DEVELOPER
		dev_suppress_gossip(daemon, msg);
		goto out;
#endif
	case WIRE_CONNECTD_DEV_REPORT_FDS:
#if DEVELOPER
		dev_report_fds(daemon, msg);
		goto out;
#endif
	/* We send these, we don't receive them */
	case WIRE_CONNECTD_INIT_REPLY:
	case WIRE_CONNECTD_ACTIVATE_REPLY:
	case WIRE_CONNECTD_PEER_CONNECTED:
	case WIRE_CONNECTD_PEER_SPOKE:
	case WIRE_CONNECTD_CONNECT_FAILED:
	case WIRE_CONNECTD_DEV_MEMLEAK_REPLY:
	case WIRE_CONNECTD_PING_REPLY:
	case WIRE_CONNECTD_GOT_ONIONMSG_TO_US:
	case WIRE_CONNECTD_CUSTOMMSG_IN:
	case WIRE_CONNECTD_PEER_DISCONNECT_DONE:
	case WIRE_CONNECTD_START_SHUTDOWN_REPLY:
		break;
	}

	/* Master shouldn't give bad requests. */
	status_failed(STATUS_FAIL_MASTER_IO, "%i: %s",
		      t, tal_hex(tmpctx, msg));

out:
	/* Read the next message. */
	return daemon_conn_read_next(conn, daemon->master);
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

/*~ gossipd sends us gossip to send to the peers. */
static struct io_plan *recv_gossip(struct io_conn *conn,
				   const u8 *msg,
				   struct daemon *daemon)
{
	struct node_id dst;
	u8 *gossip_msg;
	struct peer *peer;

	if (!fromwire_gossipd_send_gossip(msg, msg, &dst, &gossip_msg))
		status_failed(STATUS_FAIL_GOSSIP_IO, "Unknown msg %i",
			      fromwire_peektype(msg));

	peer = peer_htable_get(daemon->peers, &dst);
	if (peer)
		inject_peer_msg(peer, take(gossip_msg));

	return daemon_conn_read_next(conn, daemon->gossipd);
}

/*~ This is a hook used by the memleak code: it can't see pointers
 * inside hash tables, so we give it a hint here. */
static void memleak_daemon_cb(struct htable *memtable, struct daemon *daemon)
{
	memleak_scan_htable(memtable, &daemon->peers->raw);
}

static void gossipd_failed(struct daemon_conn *gossipd)
{
	status_failed(STATUS_FAIL_GOSSIP_IO, "gossipd exited?");
}

int main(int argc, char *argv[])
{
	struct daemon *daemon;
	bool developer;

	setup_locale();

	/* Common subdaemon setup code. */
	developer = subdaemon_setup(argc, argv);

	/* Allocate and set up our simple top-level structure. */
	daemon = tal(NULL, struct daemon);
	daemon->developer = developer;
	daemon->connection_counter = 1;
	daemon->peers = tal(daemon, struct peer_htable);
	daemon->listeners = tal_arr(daemon, struct io_listener *, 0);
	peer_htable_init(daemon->peers);
	memleak_add_helper(daemon, memleak_daemon_cb);
	list_head_init(&daemon->connecting);
	timers_init(&daemon->timers, time_mono());
	daemon->gossip_store_fd = -1;
	daemon->shutting_down = false;

	/* stdin == control */
	daemon->master = daemon_conn_new(daemon, STDIN_FILENO, recv_req, NULL,
					 daemon);
	tal_add_destructor(daemon->master, master_gone);

	/* This tells the status_* subsystem to use this connection to send
	 * our status_ and failed messages. */
	status_setup_async(daemon->master);

	/* Don't leave around websocketd zombies.  Technically not portable,
	 * but OK for Linux and BSD, so... */
	signal(SIGCHLD, SIG_IGN);

	/* This streams gossip to and from gossipd */
	daemon->gossipd = daemon_conn_new(daemon, GOSSIPCTL_FD,
					  recv_gossip, NULL,
					  daemon);
	tal_add_destructor(daemon->gossipd, gossipd_failed);

	/* Set up ecdh() function so it uses our HSM fd, and calls
	 * status_failed on error. */
	ecdh_hsmd_setup(HSM_FD, status_failed);

	for (;;) {
		struct timer *expired;
		io_loop(&daemon->timers, &expired);
		timer_expired(expired);
	}
}

/*~ Getting bored?  This was a pretty simple daemon!
 *
 * The good news is that the next daemon gossipd/gossipd.c is the most complex
 * global daemon we have!
 */
