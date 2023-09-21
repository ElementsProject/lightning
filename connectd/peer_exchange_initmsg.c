#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/io/io.h>
#include <common/dev_disconnect.h>
#include <common/memleak.h>
#include <common/status.h>
#include <common/wire_error.h>
#include <connectd/connectd.h>
#include <connectd/connectd_wiregen.h>
#include <connectd/netaddress.h>
#include <connectd/peer_exchange_initmsg.h>
#include <wire/peer_wire.h>

/* Temporary structure for us to read peer message in */
struct early_peer {
	struct daemon *daemon;

	/* The ID of the peer */
	struct node_id id;

	/* Where it's connected to/from. */
	struct wireaddr_internal addr;

	/* Crypto state for writing/reading peer initmsg */
	struct crypto_state cs;

	/* Buffer for reading/writing message. */
	u8 *msg;

	/* Are we connected via a websocket? */
	enum is_websocket is_websocket;

	bool incoming;
};

static bool contains_common_chain(struct bitcoin_blkid *chains)
{
	for (size_t i = 0; i < tal_count(chains); i++) {
		if (bitcoin_blkid_eq(&chains[i], &chainparams->genesis_blockhash))
			return true;
	}
	return false;
}

/* Here in case we need to read another message. */
static struct io_plan *read_init(struct io_conn *conn, struct early_peer *peer);

static struct io_plan *peer_init_received(struct io_conn *conn,
					  struct early_peer *peer)
{
	u8 *msg = cryptomsg_decrypt_body(tmpctx, &peer->cs, peer->msg);
	u8 *globalfeatures, *features;
	struct tlv_init_tlvs *tlvs;
	struct wireaddr *remote_addr;

	if (!msg)
		return io_close(conn);

	status_peer_io(LOG_IO_IN, &peer->id, msg);

	/* BOLT #1:
	 *
	 * A receiving node:
	 *   - upon receiving a message of _odd_, unknown type:
	 *     - MUST ignore the received message.
	 */
	if (unlikely(is_unknown_msg_discardable(msg)))
		return read_init(conn, peer);

	if (!fromwire_init(tmpctx, msg, &globalfeatures, &features, &tlvs)) {
		status_peer_debug(&peer->id,
				  "bad fromwire_init '%s', closing",
				  tal_hex(tmpctx, msg));
		return io_close(conn);
	}

	/* BOLT #1:
	 * The receiving node:
	 * ...
	 *  - upon receiving `networks` containing no common chains
	 *    - MAY close the connection.
	 */
	if (tlvs->networks) {
		if (!contains_common_chain(tlvs->networks)) {
			status_peer_debug(&peer->id,
			                  "No common chain with this peer '%s', closing",
			                  tal_hex(tmpctx, msg));
			msg = towire_warningfmt(NULL, NULL, "No common network");
			msg = cryptomsg_encrypt_msg(NULL, &peer->cs, take(msg));
			return io_write(conn, msg, tal_count(msg), io_close_cb, NULL);
		}
	}

	/* fetch optional tlv `remote_addr` */
	remote_addr = NULL;

	/* BOLT #1:
	 * The receiving node:
	 * ...
	 *  - MAY use the `remote_addr` to update its `node_announcement`
	 */
	if (tlvs->remote_addr) {
		const u8 *cursor = tlvs->remote_addr;
		size_t len = tal_bytelen(tlvs->remote_addr);

		remote_addr = tal(peer, struct wireaddr);
		if (fromwire_wireaddr(&cursor, &len, remote_addr)) {
			switch (remote_addr->type) {
			case ADDR_TYPE_IPV4:
			case ADDR_TYPE_IPV6:
				/* Drop non-public addresses when not testing */
				if (!address_routable(remote_addr,
						      peer->daemon->dev_allow_localhost))
					remote_addr = tal_free(remote_addr);
				break;
			/* We are only interested in IP addresses */
			case ADDR_TYPE_TOR_V2_REMOVED:
			case ADDR_TYPE_TOR_V3:
			case ADDR_TYPE_DNS:
				remote_addr = tal_free(remote_addr);
				break;
			}
		} else
			remote_addr = tal_free(remote_addr);
	}

	/* The globalfeatures field is now unused, but there was a
	 * window where it was: combine the two. */
	features = featurebits_or(tmpctx, take(features), globalfeatures);

	/* We can dispose of peer after next call. */
	tal_steal(tmpctx, peer);

	/* Usually return io_close_taken_fd, but may wait for old peer to
	 * be disconnected if it's a reconnect. */
	return peer_connected(conn, peer->daemon, &peer->id,
			      &peer->addr,
			      remote_addr,
			      &peer->cs,
			      take(features),
			      peer->is_websocket,
			      peer->incoming);
}

static struct io_plan *peer_init_hdr_received(struct io_conn *conn,
					      struct early_peer *peer)
{
	u16 len;

	if (!cryptomsg_decrypt_header(&peer->cs, peer->msg, &len))
		return io_close(conn);

	tal_free(peer->msg);
	peer->msg = tal_arr(peer, u8, (u32)len + CRYPTOMSG_BODY_OVERHEAD);
	return io_read(conn, peer->msg, tal_count(peer->msg),
		       peer_init_received, peer);
}

static struct io_plan *read_init(struct io_conn *conn, struct early_peer *peer)
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

static struct io_plan *dev_peer_write_postclose(struct io_conn *conn,
						struct early_peer *peer)
{
	dev_sabotage_fd(io_conn_fd(conn), true);
	return read_init(conn, peer);
}

static struct io_plan *dev_peer_write_post_sabotage(struct io_conn *conn,
						    struct early_peer *peer)
{
	dev_sabotage_fd(io_conn_fd(conn), false);
	return read_init(conn, peer);
}

struct io_plan *peer_exchange_initmsg(struct io_conn *conn,
				      struct daemon *daemon,
				      const struct feature_set *our_features,
				      const struct crypto_state *cs,
				      const struct node_id *id,
				      const struct wireaddr_internal *addr,
				      struct oneshot *timeout,
				      enum is_websocket is_websocket,
				      bool incoming)
{
	/* If conn is closed, forget peer */
	struct early_peer *peer = tal(conn, struct early_peer);
	struct io_plan *(*next)(struct io_conn *, struct early_peer *);
	struct tlv_init_tlvs *tlvs;

	peer->daemon = daemon;
	peer->id = *id;
	peer->addr = *addr;
	peer->cs = *cs;
	peer->incoming = incoming;
	peer->is_websocket = is_websocket;

	/* Attach timer to early peer, so it gets freed with it. */
	notleak(tal_steal(peer, timeout));

	/* BOLT #1:
	 *
	 * The sending node:
	 *   - MUST send `init` as the first Lightning message for any
	 *     connection.
	 *  ...
	 *   - SHOULD set `networks` to all chains it will gossip or open
	 *     channels for.
	 */
	tlvs = tlv_init_tlvs_new(tmpctx);
	tlvs->networks = tal_dup_arr(tlvs, struct bitcoin_blkid,
				     &chainparams->genesis_blockhash, 1, 0);

	/* set optional tlv `remote_addr` on incoming IP connections */
	tlvs->remote_addr = NULL;

	/* BOLT #1:
	 * The sending node:
	 * ...
	 *  - SHOULD set `remote_addr` to reflect the remote IP address (and port) of an
	 *    incoming connection, if the node is the receiver and the connection was done
	 *    via IP.
	 */
	if (incoming
	    && addr->itype == ADDR_INTERNAL_WIREADDR
	    && !addr->u.wireaddr.is_websocket
	    && address_routable(&addr->u.wireaddr.wireaddr, true)) {
		switch (addr->u.wireaddr.wireaddr.type) {
		case ADDR_TYPE_IPV4:
		case ADDR_TYPE_IPV6:
			tlvs->remote_addr = tal_arr(tlvs, u8, 0);
			towire_wireaddr(&tlvs->remote_addr, &addr->u.wireaddr.wireaddr);
			break;
		/* Only report IP addresses back for now */
		case ADDR_TYPE_TOR_V2_REMOVED:
		case ADDR_TYPE_TOR_V3:
		case ADDR_TYPE_DNS:
			break;
		}
	}

	/* Initially, there were two sets of feature bits: global and local.
	 * Local affected peer nodes only, global affected everyone.  Both were
	 * sent in the `init` message, but node_announcement only advertized
	 * globals.
	 *
	 * But we didn't have any globals for a long time, and it turned out
	 * that people wanted us to broadcast local features so they could do
	 * peer selection.  We agreed that the number spaces should be distinct,
	 * but debate still raged on how to handle them.
	 *
	 * Meanwhile, we finally added a global bit to the spec, so now it
	 * matters.  And LND v0.8 decided to make option_static_remotekey a
	 * GLOBAL bit, not a local bit, so we need to send that as a global
	 * bit here.
	 *
	 * Finally, we agreed that bits below 13 could be put in both, but
	 * from now on they'll all go in initfeatures. */
	peer->msg = towire_init(NULL,
				our_features->bits[GLOBAL_INIT_FEATURE],
				our_features->bits[INIT_FEATURE],
				tlvs);
	status_peer_io(LOG_IO_OUT, &peer->id, peer->msg);
	peer->msg = cryptomsg_encrypt_msg(peer, &peer->cs, take(peer->msg));

	next = read_init;
	switch (dev_disconnect(&peer->id, WIRE_INIT)) {
	case DEV_DISCONNECT_BEFORE:
		dev_sabotage_fd(io_conn_fd(conn), true);
		break;
	case DEV_DISCONNECT_AFTER:
		next = dev_peer_write_postclose;
		break;
	case DEV_DISCONNECT_BLACKHOLE:
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Blackhole not supported during handshake");
		break;
	case DEV_DISCONNECT_NORMAL:
		break;
	case DEV_DISCONNECT_DISABLE_AFTER:
		next = dev_peer_write_post_sabotage;
		break;
	}

	return io_write(conn, peer->msg, tal_bytelen(peer->msg), next, peer);
}
