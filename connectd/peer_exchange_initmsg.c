#include <ccan/io/io.h>
#include <common/cryptomsg.h>
#include <common/dev_disconnect.h>
#include <common/features.h>
#include <common/status.h>
#include <common/wire_error.h>
#include <connectd/connectd.h>
#include <connectd/gen_connect_wire.h>
#include <connectd/peer_exchange_initmsg.h>
#include <wire/peer_wire.h>

/* Temporary structure for us to read peer message in */
struct peer {
	struct daemon *daemon;

	/* The ID of the peer */
	struct pubkey id;

	/* Where it's connected to/from. */
	struct wireaddr_internal addr;

	/* Crypto state for writing/reading peer initmsg */
	struct crypto_state cs;

	/* Buffer for reading/writing message. */
	u8 *msg;
};

/* Here in case we need to read another message. */
static struct io_plan *read_init(struct io_conn *conn, struct peer *peer);

static struct io_plan *peer_init_received(struct io_conn *conn,
					  struct peer *peer)
{
	u8 *msg = cryptomsg_decrypt_body(peer, &peer->cs, peer->msg);
	u8 *globalfeatures, *localfeatures;

	if (!msg)
		return io_close(conn);

	status_peer_io(LOG_IO_IN, msg);

	/* BOLT #1:
	 *
	 * A receiving node:
	 *   - upon receiving a message of _odd_, unknown type:
	 *     - MUST ignore the received message.
	 */
	if (unlikely(is_unknown_msg_discardable(msg)))
		return read_init(conn, peer);

	if (!fromwire_init(peer, msg, &globalfeatures, &localfeatures)) {
		status_trace("peer %s bad fromwire_init '%s', closing",
			     type_to_string(tmpctx, struct pubkey, &peer->id),
			     tal_hex(tmpctx, msg));
		return io_close(conn);
	}

	/* BOLT #1:
	 *
	 * The receiving node:
	 * ...
	 *  - upon receiving unknown _odd_ feature bits that are non-zero:
	 *    - MUST ignore the bit.
	 *  - upon receiving unknown _even_ feature bits that are non-zero:
	 *    - MUST fail the connection.
	 */
	if (!features_supported(globalfeatures, localfeatures)) {
		const u8 *our_globalfeatures = get_offered_globalfeatures(msg);
		const u8 *our_localfeatures = get_offered_localfeatures(msg);
		msg = towire_errorfmt(NULL, NULL, "Unsupported features %s/%s:"
				      " we only offer globalfeatures %s"
				      " and localfeatures %s",
				      tal_hex(msg, globalfeatures),
				      tal_hex(msg, localfeatures),
				      tal_hex(msg, our_globalfeatures),
				      tal_hex(msg, our_localfeatures));
		msg = cryptomsg_encrypt_msg(NULL, &peer->cs, take(msg));
		return io_write(conn, msg, tal_count(msg), io_close_cb, NULL);
	}

	/* Create message to tell master peer has connected. */
	msg = towire_connect_peer_connected(NULL, &peer->id, &peer->addr,
					    &peer->cs,
					    globalfeatures, localfeatures);

	/* Usually return io_close_taken_fd, but may wait for old peer to
	 * be disconnected if it's a reconnect. */
	return peer_connected(conn, peer->daemon, &peer->id,
			      take(msg), take(localfeatures));
}

static struct io_plan *peer_init_hdr_received(struct io_conn *conn,
					      struct peer *peer)
{
	u16 len;

	if (!cryptomsg_decrypt_header(&peer->cs, peer->msg, &len))
		return io_close(conn);

	tal_free(peer->msg);
	peer->msg = tal_arr(peer, u8, (u32)len + CRYPTOMSG_BODY_OVERHEAD);
	return io_read(conn, peer->msg, tal_count(peer->msg),
		       peer_init_received, peer);
}

static struct io_plan *read_init(struct io_conn *conn, struct peer *peer)
{
	/* Free our sent init msg. */
	tal_free(peer->msg);

	/* BOLT #1:
	 *
	 * The receiving node:
	 *  - MUST wait to receive `init` before sending any other messages.
	 */
	peer->msg = tal_arr(peer, u8, CRYPTOMSG_HDR_SIZE);
	return io_read(conn, peer->msg, tal_bytelen(peer->msg),
		       peer_init_hdr_received, peer);
}

#if DEVELOPER
static struct io_plan *peer_write_postclose(struct io_conn *conn,
					    struct peer *peer)
{
	dev_sabotage_fd(io_conn_fd(conn));
	return read_init(conn, peer);
}
#endif

struct io_plan *peer_exchange_initmsg(struct io_conn *conn,
				      struct daemon *daemon,
				      const struct crypto_state *cs,
				      const struct pubkey *id,
				      const struct wireaddr_internal *addr)
{
	/* If conn is closed, forget peer */
	struct peer *peer = tal(conn, struct peer);
	struct io_plan *(*next)(struct io_conn *, struct peer *);

	peer->daemon = daemon;
	peer->id = *id;
	peer->addr = *addr;
	peer->cs = *cs;

	/* BOLT #1:
	 *
	 * The sending node:
	 *   - MUST send `init` as the first Lightning message for any
	 *     connection.
	 */
	peer->msg = towire_init(NULL,
				get_offered_globalfeatures(tmpctx),
				get_offered_localfeatures(tmpctx));
	status_peer_io(LOG_IO_OUT, peer->msg);
	peer->msg = cryptomsg_encrypt_msg(peer, &peer->cs, take(peer->msg));

	next = read_init;
#if DEVELOPER
	switch (dev_disconnect(WIRE_INIT)) {
	case DEV_DISCONNECT_BEFORE:
		dev_sabotage_fd(io_conn_fd(conn));
		break;
	case DEV_DISCONNECT_DROPPKT:
		peer->msg = tal_free(peer->msg); /* FALL THRU */
	case DEV_DISCONNECT_AFTER:
		next = peer_write_postclose;
		break;
	case DEV_DISCONNECT_BLACKHOLE:
		dev_blackhole_fd(io_conn_fd(conn));
		break;
	case DEV_DISCONNECT_NORMAL:
		break;
	}
#endif /* DEVELOPER */

	return io_write(conn, peer->msg, tal_bytelen(peer->msg), next, peer);
}
