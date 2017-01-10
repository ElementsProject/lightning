#include "lightningd.h"
#include "peer_control.h"
#include "subdaemon.h"
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/take/take.h>
#include <daemon/log.h>
#include <errno.h>
#include <lightningd/handshake/gen_handshake_control_wire.h>
#include <lightningd/handshake/gen_handshake_status_wire.h>
#include <lightningd/hsm/gen_hsm_control_wire.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

struct peer {
	struct lightningd *ld;

	/* Inside ld->peers. */
	struct list_node list;

	/* What stage is this in? */
	struct subdaemon *owner;

	/* ID of peer (NULL before initial handshake). */
	struct pubkey *id;

	/* Our fd to the peer. */
	int fd;

	/* HSM connection for this peer. */
	int hsmfd;
};

static void destroy_peer(struct peer *peer)
{
	list_del_from(&peer->ld->peers, &peer->list);
	if (peer->fd >= 0)
		close(peer->fd);
}

static struct peer *new_peer(const tal_t *ctx, struct lightningd *ld, int fd)
{
	struct peer *peer = tal(ctx, struct peer);
	peer->ld = ld;
	peer->owner = NULL;
	peer->id = NULL;
	peer->fd = fd;
	list_add_tail(&ld->peers, &peer->list);
	tal_add_destructor(peer, destroy_peer);
	return peer;
}

static void handshake_responder_succeeded(struct subdaemon *hs, const u8 *msg,
					  struct peer *peer)
{
	struct crypto_state *cs;
	struct pubkey id;

	if (!fromwire_handshake_responder_resp(msg, msg, NULL, &id, &cs)) {
		log_broken(hs->log, "Malformed responder resp: %s",
			   tal_hex(peer, msg));
		tal_free(peer);
		return;
	}

	/* FIXME: Look for peer duplicates! */

	/* Peer is now a full-fledged citizen. */
	peer->id = tal_dup(peer, struct pubkey, &id);

	log_info_struct(hs->log, "Peer in from %s", struct pubkey, peer->id);

	/* Tell handshaked to exit. */
	subdaemon_req(peer->owner, take(towire_handshake_exit_req(msg)),
		      -1, NULL, NULL, NULL);

	/* FIXME: start lightningd_connect */
	peer->owner = NULL;
}

static void peer_got_hsmfd(struct subdaemon *hsm, const u8 *msg,
			   struct peer *peer)
{
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
				    NULL,
				    peer->hsmfd, -1);
	if (!peer->owner) {
		log_unusual(peer->ld->log, "Could not subdaemon handshake: %s",
			    strerror(errno));
		goto error;
	}

	/* Now handshake owns peer: until it succeeds, peer vanishes
	 * when it does. */
	tal_steal(peer->owner, peer);

	/* Now hand peer fd to the handshake daemon, it hand back on success */
	subdaemon_req(peer->owner,
		      take(towire_handshake_responder_req(peer,
							  &peer->ld->dstate.id)),
		      peer->fd, &peer->fd,
		      handshake_responder_succeeded, peer);

	/* Peer struct longer owns fd. */
	peer->fd = -1;
	return;

error:
	tal_free(peer);
}

/* FIXME: timeout handshake if taking too long? */
static struct io_plan *peer_in(struct io_conn *conn, struct lightningd *ld)
{
	struct peer *peer = new_peer(ld, ld, io_conn_fd(conn));

	/* Get HSM fd for this peer. */
	/* FIXME: We use pointer as ID. */
	subdaemon_req(ld->hsm, take(towire_hsmctl_hsmfd_ecdh(ld, (u64)peer)),
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
