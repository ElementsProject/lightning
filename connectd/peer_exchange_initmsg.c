#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/io/io.h>
#include <common/dev_disconnect.h>
#include <common/status.h>
#include <common/wire_error.h>
#include <connectd/connectd.h>
#include <connectd/connectd_wiregen.h>
#include <connectd/peer_exchange_initmsg.h>
#include <wire/peer_wire.h>

/* Temporary structure for us to read peer message in */
struct peer {
	struct daemon *daemon;

	/* The ID of the peer */
	struct node_id id;

	/* Where it's connected to/from. */
	struct wireaddr_internal addr;

	/* Crypto state for writing/reading peer initmsg */
	struct crypto_state cs;

	/* Buffer for reading/writing message. */
	u8 *msg;

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
static struct io_plan *read_init(struct io_conn *conn, struct peer *peer);

static struct io_plan *peer_init_received(struct io_conn *conn,
					  struct peer *peer)
{
	u8 *msg = cryptomsg_decrypt_body(tmpctx, &peer->cs, peer->msg);
	u8 *globalfeatures, *features;
	struct tlv_init_tlvs *tlvs = tlv_init_tlvs_new(msg);

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

	if (!fromwire_init(tmpctx, msg, &globalfeatures, &features, tlvs)) {
		status_peer_debug(&peer->id,
				  "bad fromwire_init '%s', closing",
				  tal_hex(tmpctx, msg));
		return io_close(conn);
	}

	/* BOLT #1:
	 * The receiving node:
	 * ...
	 *  - upon receiving `networks` containing no common chains
	 *    - MAY fail the connection.
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

	/* The globalfeatures field is now unused, but there was a
	 * window where it was: combine the two. */
	features = featurebits_or(tmpctx, take(features), globalfeatures);

	/* Usually return io_close_taken_fd, but may wait for old peer to
	 * be disconnected if it's a reconnect. */
	return peer_connected(conn, peer->daemon, &peer->id,
			      &peer->addr, &peer->cs,
			      take(features),
			      peer->incoming);
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
	dev_sabotage_fd(io_conn_fd(conn), true);
	return read_init(conn, peer);
}

static struct io_plan *peer_write_post_sabotage(struct io_conn *conn,
						struct peer *peer)
{
	dev_sabotage_fd(io_conn_fd(conn), false);
	return read_init(conn, peer);
}
#endif

struct io_plan *peer_exchange_initmsg(struct io_conn *conn,
				      struct daemon *daemon,
				      const struct feature_set *our_features,
				      const struct crypto_state *cs,
				      const struct node_id *id,
				      const struct wireaddr_internal *addr,
				      bool incoming)
{
	/* If conn is closed, forget peer */
	struct peer *peer = tal(conn, struct peer);
	struct io_plan *(*next)(struct io_conn *, struct peer *);
	struct tlv_init_tlvs *tlvs;

	peer->daemon = daemon;
	peer->id = *id;
	peer->addr = *addr;
	peer->cs = *cs;
	peer->incoming = incoming;

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
#if DEVELOPER
	switch (dev_disconnect(WIRE_INIT)) {
	case DEV_DISCONNECT_BEFORE:
		dev_sabotage_fd(io_conn_fd(conn), true);
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
	case DEV_DISCONNECT_DISABLE_AFTER:
		next = peer_write_post_sabotage;
		break;
	}
#endif /* DEVELOPER */

	return io_write(conn, peer->msg, tal_bytelen(peer->msg), next, peer);
}
