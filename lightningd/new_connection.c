#include <ccan/fdpass/fdpass.h>
#include <ccan/tal/str/str.h>
#include <daemon/jsonrpc.h>
#include <daemon/log.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/cryptomsg.h>
#include <lightningd/handshake/gen_handshake_wire.h>
#include <lightningd/hsm/gen_hsm_wire.h>
#include <lightningd/hsm_control.h>
#include <lightningd/lightningd.h>
#include <lightningd/new_connection.h>
#include <lightningd/peer_control.h>
#include <lightningd/status.h>
#include <lightningd/subd.h>
#include <unistd.h>
#include <wire/wire_sync.h>

/* Before we have identified the peer, we just have a connection object. */
struct connection {
	/* Lightning daemon, for when we're handed through callbacks. */
	struct lightningd *ld;

	/* Where we connected to/from. */
	struct netaddr netaddr;

	/* Unique identifier for handshaked. */
	u64 unique_id;

	/* Json command which made us connect (if any) */
	struct command *cmd;

	/* If we are initiating, we known their id.  Otherwise NULL. */
	struct pubkey *known_id;
};

static void connection_destroy(struct connection *c)
{
	/* FIXME: better diagnostics. */
	if (c->cmd)
		command_fail(c->cmd, "Failed to connect to peer");
}

static void set_blocking(int fd, bool block)
{
	int flags = fcntl(fd, F_GETFL);

	if (block)
		flags &= ~O_NONBLOCK;
	else
		flags |= O_NONBLOCK;

	fcntl(fd, F_SETFL, flags);
}

static void
PRINTF_FMT(3,4) connection_failed(struct connection *c, struct log *log,
				  const char *fmt, ...)
{
	const char *msg;
	va_list ap;

	va_start(ap, fmt);
	msg = tal_vfmt(c, fmt, ap);
	va_end(ap);
	log_info(log, "%s", msg);
	if (c->cmd) {
		command_fail(c->cmd, "%s", msg);
		/* Don't fail in destructor, too. */
		c->cmd = NULL;
	}
	tal_free(c);
}

struct connection *new_connection(const tal_t *ctx,
				  struct lightningd *ld,
				  struct command *cmd,
				  const struct pubkey *known_id)
{
	static u64 id_counter;
	struct connection *c = tal(ctx, struct connection);

	c->ld = ld;
	c->unique_id = id_counter++;
	c->cmd = cmd;
	if (known_id)
		c->known_id = tal_dup(c, struct pubkey, known_id);
	else
		c->known_id = NULL;
	tal_add_destructor(c, connection_destroy);

	return c;
}

static bool has_even_bit(const u8 *bitmap)
{
	size_t len = tal_count(bitmap);

	while (len) {
		if (*bitmap & 0xAA)
			return true;
		len--;
		bitmap++;
	}
	return false;
}

static bool handshake_succeeded(struct subd *handshaked,
				const u8 *msg, const int *fds,
				struct connection *c)
{
	struct crypto_state cs;
	struct pubkey *id;
	u8 *globalfeatures, *localfeatures;

	assert(tal_count(fds) == 1);

	/* FIXME: Look for peer duplicates! */

	if (!c->known_id) {
		id = tal(msg, struct pubkey);
		if (!fromwire_handshake_responder_reply(c, msg, NULL, id, &cs,
							&globalfeatures,
							&localfeatures))
			goto err;
		log_info_struct(handshaked->log, "Peer in from %s",
				struct pubkey, id);
	} else {
		id = c->known_id;
		if (!fromwire_handshake_initiator_reply(c, msg, NULL, &cs,
							&globalfeatures,
							&localfeatures))
			goto err;
		log_info_struct(handshaked->log, "Peer out to %s",
				struct pubkey, id);
	}

	/* BOLT #1:
	 *
	 * For unknown feature bits which are non-zero, the receiver
	 * MUST ignore the bit if the bit number is odd, and MUST fail
	 * the connection if the bit number is even.
	 */
	if (has_even_bit(globalfeatures)) {
		connection_failed(c, handshaked->log,
				  "peer %s: bad globalfeatures: %s",
				  type_to_string(c, struct pubkey, id),
				  tal_hex(msg, globalfeatures));
		return true;
	}

	if (has_even_bit(localfeatures)) {
		connection_failed(c, handshaked->log,
				  "peer %s: bad localfeatures: %s",
				  type_to_string(c, struct pubkey, id),
				  tal_hex(msg, localfeatures));
		return true;
	}

	if (c->cmd) {
		struct json_result *response;
		response = new_json_result(c->cmd);

		json_object_start(response, NULL);
		json_add_pubkey(response, "id", id);
		json_object_end(response);
		command_success(c->cmd, response);
		c->cmd = NULL;
	}

	add_peer(handshaked->ld, c->unique_id, fds[0], id, &cs);
	/* Now shut handshaked down (frees c as well) */
	return false;

err:
	log_broken(handshaked->log, "Malformed resp: %s", tal_hex(c, msg));
	close(fds[0]);
	return false;
}

/* Same path for connecting in vs connecting out. */
static struct io_plan *hsm_then_handshake(struct io_conn *conn,
					  struct lightningd *ld,
					  struct connection *c)
{
	const tal_t *tmpctx = tal_tmpctx(conn);
	int connfd = io_conn_fd(conn), hsmfd;
	struct subd *handshaked;
	u8 *msg;

	/* Get HSM fd for this peer. */
	msg = towire_hsmctl_hsmfd_ecdh(tmpctx, c->unique_id);
	if (!wire_sync_write(ld->hsm_fd, msg))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = hsm_sync_read(tmpctx, ld);
	if (!fromwire_hsmctl_hsmfd_ecdh_fd_reply(msg, NULL))
		fatal("Malformed hsmfd response: %s", tal_hex(msg, msg));

	hsmfd = fdpass_recv(ld->hsm_fd);
	if (hsmfd < 0)
		fatal("Could not read fd from HSM: %s", strerror(errno));

	/* Make sure connection fd is blocking */
	set_blocking(connfd, true);

	/* Give handshake daemon the hsm fd. */
	handshaked = new_subd(ld, ld,
			      "lightningd_handshake", NULL,
			      handshake_wire_type_name,
			      NULL, NULL,
			      take(&hsmfd), take(&connfd), NULL);
	if (!handshaked) {
		log_unusual(ld->log, "Could not subdaemon handshake: %s",
			    strerror(errno));
		goto error;
	}

	/* If handshake daemon fails, we just drop connection. */
	tal_steal(handshaked, c);

	if (c->known_id) {
		msg = towire_handshake_initiator(tmpctx, &ld->dstate.id,
						 c->known_id);
	} else {
		msg = towire_handshake_responder(tmpctx, &ld->dstate.id);
	}

	/* Now hand peer request to the handshake daemon: hands it
	 * back on success */
	subd_req(c, handshaked, take(msg), -1, 1, handshake_succeeded, c);

	tal_free(tmpctx);

	/* We don't need conn, we've passed fd to handshaked. */
	return io_close_taken_fd(conn);

error:
	close(hsmfd);
	tal_free(tmpctx);
	return io_close(conn);
}

struct io_plan *connection_out(struct io_conn *conn,
			       struct lightningd_state *dstate,
			       const struct netaddr *netaddr,
			       struct connection *c)
{
	c->netaddr = *netaddr;
	return hsm_then_handshake(conn, ld_from_dstate(dstate), c);
}

struct io_plan *connection_in(struct io_conn *conn, struct lightningd *ld)
{
	struct connection *c = new_connection(ld, ld, NULL, NULL);

	/* FIXME: Don't assume TCP here. */
	if (!netaddr_from_fd(io_conn_fd(conn), SOCK_STREAM, IPPROTO_TCP,
			     &c->netaddr)) {
		log_unusual(ld->log, "Could not get address of incoming fd");
		return io_close(conn);
	}
	return hsm_then_handshake(conn, ld, c);
}

const struct pubkey *connection_known_id(const struct connection *c)
{
	return c->known_id;
}
