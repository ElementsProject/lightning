#include "lightningd.h"
#include "peer_control.h"
#include "subdaemon.h"
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <daemon/dns.h>
#include <daemon/jsonrpc.h>
#include <daemon/log.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/gossip/gen_gossip_control_wire.h>
#include <lightningd/gossip/gen_gossip_status_wire.h>
#include <lightningd/handshake/gen_handshake_control_wire.h>
#include <lightningd/handshake/gen_handshake_status_wire.h>
#include <lightningd/hsm/gen_hsm_control_wire.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->ld->peers, &peer->list);
	if (peer->fd >= 0)
		close(peer->fd);
	if (peer->connect_cmd)
		command_fail(peer->connect_cmd, "Failed after %s",
			     peer->condition);
}

void peer_set_condition(struct peer *peer, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	tal_free(peer->condition);
	peer->condition = tal_vfmt(peer, fmt, ap);
	va_end(ap);
	log_info(peer->log, "condition: %s", peer->condition);
}

static struct peer *new_peer(struct lightningd *ld,
			     struct io_conn *conn,
			     const char *in_or_out,
			     struct command *cmd)
{
	static u64 id_counter;
	struct peer *peer = tal(ld, struct peer);
	const char *netname;

	peer->ld = ld;
	peer->unique_id = id_counter++;
	peer->owner = NULL;
	peer->id = NULL;
	peer->fd = io_conn_fd(conn);
	peer->connect_cmd = cmd;
	/* Max 128k per peer. */
	peer->log_book = new_log_book(peer, 128*1024, LOG_UNUSUAL);
	peer->log = new_log(peer, peer->log_book,
			    "peer %"PRIu64":", peer->unique_id);

	/* FIXME: Don't assume protocol here! */
	if (!netaddr_from_fd(peer->fd, SOCK_STREAM, IPPROTO_TCP,
			     &peer->netaddr)) {
		log_unusual(ld->log, "Failed to get netaddr for outgoing: %s",
			    strerror(errno));
		return tal_free(peer);
	}
	netname = netaddr_name(peer, &peer->netaddr);
	peer->condition = tal_fmt(peer, "%s %s", in_or_out, netname);
	tal_free(netname);
	list_add_tail(&ld->peers, &peer->list);
	tal_add_destructor(peer, destroy_peer);
	return peer;
}

struct peer *peer_by_unique_id(struct lightningd *ld, u64 unique_id)
{
	struct peer *p;

	list_for_each(&ld->peers, p, list)
		if (p->unique_id == unique_id)
			return p;
	return NULL;
}

static void handshake_succeeded(struct subdaemon *hs, const u8 *msg,
				struct peer *peer)
{
	struct crypto_state *cs;

	if (!peer->id) {
		struct pubkey id;

		if (!fromwire_handshake_responder_resp(msg, msg, NULL, &id, &cs))
			goto err;
		peer->id = tal_dup(peer, struct pubkey, &id);
		log_info_struct(hs->log, "Peer in from %s",
				struct pubkey, peer->id);
	} else {
		if (!fromwire_handshake_initiator_resp(msg, msg, NULL, &cs))
			goto err;
		log_info_struct(hs->log, "Peer out to %s",
				struct pubkey, peer->id);
	}

	/* FIXME: Look for peer duplicates! */

	/* Tell handshaked to exit. */
	subdaemon_req(peer->owner, take(towire_handshake_exit_req(msg)),
		      -1, NULL, NULL, NULL);

	peer->owner = peer->ld->gossip;
	tal_steal(peer->owner, peer);
	peer_set_condition(peer, "Beginning gossip");

	/* Tell gossip to handle it now. */
	msg = towire_gossipctl_new_peer(msg, peer->unique_id, cs);
	subdaemon_req(peer->ld->gossip, msg, peer->fd, &peer->fd, NULL, NULL);

	/* Peer struct longer owns fd. */
	peer->fd = -1;

	return;

err:
	log_broken(hs->log, "Malformed resp: %s", tal_hex(peer, msg));
	close(peer->fd);
	tal_free(peer);
}

static void peer_got_hsmfd(struct subdaemon *hsm, const u8 *msg,
			   struct peer *peer)
{
	const u8 *req;

	if (!fromwire_hsmctl_hsmfd_ecdh_response(msg, NULL)) {
		log_unusual(peer->ld->log, "Malformed hsmfd response: %s",
			    tal_hex(peer, msg));
		goto error;
	}

	/* Give handshake daemon the hsm fd. */
	peer->owner = new_subdaemon(peer, peer->ld,
				    "lightningd_handshake",
				    handshake_status_wire_type_name,
				    handshake_control_wire_type_name,
				    NULL, NULL,
				    peer->hsmfd, peer->fd, -1);
	if (!peer->owner) {
		log_unusual(peer->ld->log, "Could not subdaemon handshake: %s",
			    strerror(errno));
		peer_set_condition(peer, "Failed to subdaemon handshake");
		goto error;
	}

	/* Peer struct longer owns fd. */
	peer->fd = -1;

	/* Now handshake owns peer: until it succeeds, peer vanishes
	 * when it does. */
	tal_steal(peer->owner, peer);

	if (peer->id) {
		req = towire_handshake_initiator_req(peer, &peer->ld->dstate.id,
						     peer->id);
		peer_set_condition(peer, "Starting handshake as initiator");
	} else {
		req = towire_handshake_responder_req(peer, &peer->ld->dstate.id);
		peer_set_condition(peer, "Starting handshake as responder");
	}

	/* Now hand peer request to the handshake daemon: hands it
	 * back on success */
	subdaemon_req(peer->owner, take(req), -1, &peer->fd,
		      handshake_succeeded, peer);
	return;

error:
	tal_free(peer);
}

/* FIXME: timeout handshake if taking too long? */
static struct io_plan *peer_in(struct io_conn *conn, struct lightningd *ld)
{
	struct peer *peer = new_peer(ld, conn, "Incoming from", NULL);

	if (!peer)
		return io_close(conn);

	/* Get HSM fd for this peer. */
	subdaemon_req(ld->hsm,
		      take(towire_hsmctl_hsmfd_ecdh(ld, peer->unique_id)),
		      -1, &peer->hsmfd, peer_got_hsmfd, peer);

	/* We don't need conn, we'll pass fd to handshaked. */
	return io_close_taken_fd(conn);
}

static int make_listen_fd(struct lightningd *ld,
			  int domain, void *addr, socklen_t len)
{
	int fd = socket(domain, SOCK_STREAM, 0);
	if (fd < 0) {
		log_debug(ld->log, "Failed to create %u socket: %s",
			  domain, strerror(errno));
		return -1;
	}

	if (addr) {
		int on = 1;

		/* Re-use, please.. */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)))
			log_unusual(ld->log, "Failed setting socket reuse: %s",
				    strerror(errno));

		if (bind(fd, addr, len) != 0) {
			log_unusual(ld->log, "Failed to bind on %u socket: %s",
				    domain, strerror(errno));
			goto fail;
		}
	}

	if (listen(fd, 5) != 0) {
		log_unusual(ld->log, "Failed to listen on %u socket: %s",
			    domain, strerror(errno));
		goto fail;
	}
	return fd;

fail:
	close_noerr(fd);
	return -1;
}

void setup_listeners(struct lightningd *ld)
{
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	socklen_t len;
	int fd1, fd2;

	if (!ld->dstate.portnum) {
		log_debug(ld->log, "Zero portnum, not listening for incoming");
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(ld->dstate.portnum);

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr = in6addr_any;
	addr6.sin6_port = htons(ld->dstate.portnum);

	/* IPv6, since on Linux that (usually) binds to IPv4 too. */
	fd1 = make_listen_fd(ld, AF_INET6, &addr6, sizeof(addr6));
	if (fd1 >= 0) {
		struct sockaddr_in6 in6;

		len = sizeof(in6);
		if (getsockname(fd1, (void *)&in6, &len) != 0) {
			log_unusual(ld->log, "Failed get IPv6 sockname: %s",
				    strerror(errno));
			close_noerr(fd1);
			fd1 = -1;
		} else {
			addr.sin_port = in6.sin6_port;
			assert(ld->dstate.portnum == ntohs(addr.sin_port));
			log_debug(ld->log, "Creating IPv6 listener on port %u",
				  ld->dstate.portnum);
			io_new_listener(ld, fd1, peer_in, ld);
		}
	}

	/* Just in case, aim for the same port... */
	fd2 = make_listen_fd(ld, AF_INET, &addr, sizeof(addr));
	if (fd2 >= 0) {
		len = sizeof(addr);
		if (getsockname(fd2, (void *)&addr, &len) != 0) {
			log_unusual(ld->log, "Failed get IPv4 sockname: %s",
				    strerror(errno));
			close_noerr(fd2);
			fd2 = -1;
		} else {
			assert(ld->dstate.portnum == ntohs(addr.sin_port));
			log_debug(ld->log, "Creating IPv4 listener on port %u",
				  ld->dstate.portnum);
			io_new_listener(ld, fd2, peer_in, ld);
		}
	}

	if (fd1 < 0 && fd2 < 0)
		fatal("Could not bind to a network address on port %u",
		      ld->dstate.portnum);
}

struct json_connecting {
	/* This owns us, so we're freed after command_fail or command_success */
	struct command *cmd;
	const char *name, *port;
	struct pubkey id;
};

/* FIXME: timeout handshake if taking too long? */
static struct io_plan *peer_out(struct io_conn *conn,
				struct lightningd_state *dstate,
				struct json_connecting *jc)
{
	struct lightningd *ld = ld_from_dstate(jc->cmd->dstate);
	struct peer *peer = new_peer(ld, conn, "Outgoing to", jc->cmd);

	if (!peer)
		return io_close(conn);

	/* We already know ID we're trying to reach. */
	peer->id = tal_dup(peer, struct pubkey, &jc->id);

	/* Get HSM fd for this peer. */
	subdaemon_req(ld->hsm,
		      take(towire_hsmctl_hsmfd_ecdh(ld, peer->unique_id)),
		      -1, &peer->hsmfd, peer_got_hsmfd, peer);

	/* We don't need conn, we'll pass fd to handshaked. */
	return io_close_taken_fd(conn);
}

static void connect_failed(struct lightningd_state *dstate,
			   struct json_connecting *connect)
{
	/* FIXME: Better diagnostics! */
	command_fail(connect->cmd, "Failed to connect to peer %s:%s",
		     connect->name, connect->port);
}

static void json_connect(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct json_connecting *connect;
	jsmntok_t *host, *port, *idtok;
	const tal_t *tmpctx = tal_tmpctx(cmd);

	if (!json_get_params(buffer, params,
			     "host", &host,
			     "port", &port,
			     "id", &idtok,
			     NULL)) {
		command_fail(cmd, "Need host, port and id to connect");
		return;
	}

	connect = tal(cmd, struct json_connecting);
	connect->cmd = cmd;
	connect->name = tal_strndup(connect, buffer + host->start,
				    host->end - host->start);
	connect->port = tal_strndup(connect, buffer + port->start,
				    port->end - port->start);

	if (!pubkey_from_hexstr(buffer + idtok->start,
				idtok->end - idtok->start, &connect->id)) {
		command_fail(cmd, "id %.*s not valid",
			     idtok->end - idtok->start,
			     buffer + idtok->start);
		return;
	}

	if (!dns_resolve_and_connect(cmd->dstate, connect->name, connect->port,
				     peer_out, connect_failed, connect)) {
		command_fail(cmd, "DNS failed");
		return;
	}

	tal_free(tmpctx);
}

static const struct json_command connect_command = {
	"connect",
	json_connect,
	"Connect to a {host} at {port} expecting node {id}",
	"Returns the {id} on success (once channel established)"
};
AUTODATA(json_command, &connect_command);

struct log_info {
	enum log_level level;
	struct json_result *response;
};

/* FIXME: Share this with jsonrpc.c's code! */
static void log_to_json(unsigned int skipped,
			struct timerel diff,
			enum log_level level,
			const char *prefix,
			const char *log,
			struct log_info *info)
{
	if (level < info->level)
		return;

	if (level != LOG_IO)
		json_add_string(info->response, NULL, log);
}

static void json_getpeers(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct lightningd *ld = ld_from_dstate(cmd->dstate);
	struct peer *p;
	struct json_result *response = new_json_result(cmd);
	jsmntok_t *leveltok;
	struct log_info info;

	json_get_params(buffer, params, "?level", &leveltok, NULL);

	if (!leveltok)
		;
	else if (json_tok_streq(buffer, leveltok, "debug"))
		info.level = LOG_DBG;
	else if (json_tok_streq(buffer, leveltok, "info"))
		info.level = LOG_INFORM;
	else if (json_tok_streq(buffer, leveltok, "unusual"))
		info.level = LOG_UNUSUAL;
	else if (json_tok_streq(buffer, leveltok, "broken"))
		info.level = LOG_BROKEN;
	else {
		command_fail(cmd, "Invalid level param");
		return;
	}

	json_object_start(response, NULL);
	json_array_start(response, "peers");
	list_for_each(&ld->peers, p, list) {
		json_object_start(response, NULL);
		json_add_u64(response, "unique_id", p->unique_id);
		json_add_string(response, "condition", p->condition);
		json_add_string(response, "netaddr",
				netaddr_name(response, &p->netaddr));
		if (p->id)
			json_add_pubkey(response, "peerid", p->id);
		if (p->owner)
			json_add_string(response, "owner", p->owner->name);

		if (leveltok) {
			info.response = response;
			json_array_start(response, "log");
			log_each_line(p->log_book, log_to_json, &info);
			json_array_end(response);
		}
		json_object_end(response);
	}
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command getpeers_command = {
	"getpeers",
	json_getpeers,
	"List the current peers, if {level} is set, include {log}s",
	"Returns a 'peers' array"
};
AUTODATA(json_command, &getpeers_command);
