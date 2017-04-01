#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/structeq/structeq.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <daemon/routing.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/channel.h>
#include <lightningd/channel/gen_channel_wire.h>
#include <lightningd/commit_tx.h>
#include <lightningd/crypto_sync.h>
#include <lightningd/cryptomsg.h>
#include <lightningd/daemon_conn.h>
#include <lightningd/debug.h>
#include <lightningd/derive_basepoints.h>
#include <lightningd/key_derive.h>
#include <lightningd/msg_queue.h>
#include <lightningd/peer_failed.h>
#include <lightningd/status.h>
#include <secp256k1.h>
#include <signal.h>
#include <stdio.h>
#include <type_to_string.h>
#include <version.h>
#include <wire/gen_onion_wire.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

/* stdin == requests, 3 == peer, 4 = gossip */
#define REQ_FD STDIN_FILENO
#define PEER_FD 3
#define GOSSIP_FD 4

struct peer {
	struct peer_crypto_state pcs;
	struct channel_config conf[NUM_SIDES];
	struct pubkey next_per_commit[NUM_SIDES];
	bool funding_locked[NUM_SIDES];

	/* Their sig for current commit. */
	secp256k1_ecdsa_signature their_commit_sig;

	/* Secret keys and basepoint secrets. */
	struct secrets our_secrets;

	/* Our shaseed for generating per-commitment-secrets. */
	struct sha256 shaseed;

	/* BOLT #2:
	 *
	 * A sending node MUST set `id` to 0 for the first HTLC it offers, and
	 * increase the value by 1 for each successive offer.
	 */
	u64 htlc_id;

	struct channel_id channel_id;
	struct channel *channel;

	struct msg_queue peer_out;
	struct io_conn *peer_conn;

	struct daemon_conn gossip_client;
	struct daemon_conn master;

	/* Announcement related information */
	struct pubkey node_ids[NUM_SIDES];
	struct short_channel_id short_channel_ids[NUM_SIDES];
	secp256k1_ecdsa_signature announcement_node_sigs[NUM_SIDES];
	secp256k1_ecdsa_signature announcement_bitcoin_sigs[NUM_SIDES];

	/* Which direction of the channel do we control? */
	u16 channel_direction;
};

static struct io_plan *gossip_client_recv(struct io_conn *conn,
					  struct daemon_conn *dc)
{
	u8 *msg = dc->msg_in;
	struct peer *peer = container_of(dc, struct peer, gossip_client);
	u16 type = fromwire_peektype(msg);

	if (type == WIRE_CHANNEL_ANNOUNCEMENT || type == WIRE_CHANNEL_UPDATE ||
	    type == WIRE_NODE_ANNOUNCEMENT)
		msg_enqueue(&peer->peer_out, msg);

	return daemon_conn_read_next(conn, dc);
}

static void send_announcement_signatures(struct peer *peer)
{
	tal_t *tmpctx = tal_tmpctx(peer);
	u8 *msg;
	// TODO(cdecker) Use the HSM to generate this signature
	secp256k1_ecdsa_signature *sig =
	    talz(tmpctx, secp256k1_ecdsa_signature);

	msg = towire_announcement_signatures(tmpctx, &peer->channel_id,
					     &peer->short_channel_ids[LOCAL],
					     sig, sig);
	msg_enqueue(&peer->peer_out, take(msg));
	tal_free(tmpctx);
}

static void send_channel_update(struct peer *peer, bool disabled)
{
	tal_t *tmpctx = tal_tmpctx(peer);
	u32 timestamp = time_now().ts.tv_sec;
	u16 flags;
	u8 *cupdate;
	// TODO(cdecker) Create a real signature for this update
	secp256k1_ecdsa_signature *sig =
	    talz(tmpctx, secp256k1_ecdsa_signature);

	flags = peer->channel_direction | (disabled << 1);
	cupdate = towire_channel_update(
	    tmpctx, sig, &peer->short_channel_ids[LOCAL], timestamp, flags, 36,
	    1, 10, peer->channel->view[LOCAL].feerate_per_kw);

	daemon_conn_send(&peer->gossip_client, take(cupdate));

	msg_enqueue(&peer->peer_out, cupdate);
	tal_free(tmpctx);
}

/* Now that we have a working channel, tell the world. */
static void send_channel_announcement(struct peer *peer)
{
	tal_t *tmpctx = tal_tmpctx(peer);
	int first, second;
	u8 *cannounce, *features = tal_arr(peer, u8, 0);

	if (peer->channel_direction == 0) {
		first = LOCAL;
		second = REMOTE;
	} else {
		first = REMOTE;
		second = LOCAL;
	}

	cannounce = towire_channel_announcement(
	    tmpctx, &peer->announcement_node_sigs[first],
	    &peer->announcement_node_sigs[second],
	    &peer->announcement_bitcoin_sigs[first],
	    &peer->announcement_bitcoin_sigs[second],
	    &peer->short_channel_ids[LOCAL], &peer->node_ids[first],
	    &peer->node_ids[second], &peer->channel->funding_pubkey[first],
	    &peer->channel->funding_pubkey[second], features);

	msg_enqueue(&peer->peer_out, cannounce);
	daemon_conn_send(&peer->gossip_client, take(cannounce));
	tal_free(tmpctx);
}

static struct io_plan *peer_out(struct io_conn *conn, struct peer *peer)
{
	const u8 *out = msg_dequeue(&peer->peer_out);
	if (!out)
		return msg_queue_wait(conn, &peer->peer_out, peer_out, peer);

	return peer_write_message(conn, &peer->pcs, out, peer_out);
}

static void handle_peer_funding_locked(struct peer *peer, const u8 *msg)
{
	struct channel_id chanid;

	if (!fromwire_funding_locked(msg, NULL, &chanid,
				     &peer->next_per_commit[REMOTE]))
		status_failed(WIRE_CHANNEL_PEER_BAD_MESSAGE,
			      "Bad funding_locked %s", tal_hex(msg, msg));

	if (!structeq(&chanid, &peer->channel_id))
		status_failed(WIRE_CHANNEL_PEER_BAD_MESSAGE,
			      "Wrong channel id in %s", tal_hex(trc, msg));
	if (peer->funding_locked[REMOTE])
		status_failed(WIRE_CHANNEL_PEER_BAD_MESSAGE,
			      "Funding locked twice");

	peer->funding_locked[REMOTE] = true;
	daemon_conn_send(&peer->master,
			 take(towire_channel_received_funding_locked(peer)));

	if (peer->funding_locked[LOCAL]) {
		daemon_conn_send(&peer->master,
				 take(towire_channel_normal_operation(peer)));
	}
}

static void handle_peer_announcement_signatures(struct peer *peer, const u8 *msg)
{
	struct channel_id chanid;

	if (!fromwire_announcement_signatures(msg, NULL,
					      &chanid,
					      &peer->short_channel_ids[REMOTE],
					      &peer->announcement_node_sigs[REMOTE],
					      &peer->announcement_bitcoin_sigs[REMOTE]))
		status_failed(WIRE_CHANNEL_PEER_BAD_MESSAGE,
			      "Bad announcement_signatures %s",
			      tal_hex(msg, msg));

	/* Make sure we agree on the channel ids */
	/* FIXME: Check short_channel_id */
	if (!structeq(&chanid, &peer->channel_id)) {
		status_failed(WIRE_CHANNEL_PEER_BAD_MESSAGE,
			      "Wrong channel_id or short_channel_id in %s or %s",
			      tal_hexstr(trc, &chanid, sizeof(struct channel_id)),
			      tal_hexstr(trc, &peer->short_channel_ids[REMOTE],
					 sizeof(struct short_channel_id)));
	}

	if (peer->funding_locked[LOCAL]) {
		send_channel_announcement(peer);
		send_channel_update(peer, false);
	}
}

static void handle_peer_add_htlc(struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 id;
	u32 amount_msat;
	u32 cltv_expiry;
	struct sha256 payment_hash;
	u8 onion_routing_packet[1254];
	enum channel_add_err add_err;

	if (!fromwire_update_add_htlc(msg, NULL, &channel_id, &id, &amount_msat,
				      &cltv_expiry, &payment_hash,
				      onion_routing_packet))
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad peer_add_htlc %s", tal_hex(msg, msg));

	add_err = channel_add_htlc(peer->channel, REMOTE, id, amount_msat,
				   cltv_expiry, &payment_hash,
				   onion_routing_packet);
	if (add_err != CHANNEL_ERR_ADD_OK)
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad peer_add_htlc: %u", add_err);
}

static struct io_plan *peer_in(struct io_conn *conn, struct peer *peer, u8 *msg)
{
	enum wire_type type = fromwire_peektype(msg);

	/* Must get funding_locked before almost anything. */
	if (!peer->funding_locked[REMOTE]) {
		/* We can get gossup before funging, too */
		if (type != WIRE_FUNDING_LOCKED
		    && type != WIRE_CHANNEL_ANNOUNCEMENT
		    && type != WIRE_CHANNEL_UPDATE
		    && type != WIRE_NODE_ANNOUNCEMENT) {
			peer_failed(io_conn_fd(peer->peer_conn),
				    &peer->pcs.cs,
				    &peer->channel_id,
				    WIRE_CHANNEL_PEER_BAD_MESSAGE,
				    "%s (%u) before funding locked",
				    wire_type_name(type), type);
		}
	}

	switch (type) {
	case WIRE_FUNDING_LOCKED:
		handle_peer_funding_locked(peer, msg);
		goto done;
	case WIRE_ANNOUNCEMENT_SIGNATURES:
		handle_peer_announcement_signatures(peer, msg);
		goto done;
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
	case WIRE_NODE_ANNOUNCEMENT:
		/* Forward to gossip daemon */
		daemon_conn_send(&peer->gossip_client, msg);
		goto done;

	case WIRE_UPDATE_ADD_HTLC:
		handle_peer_add_htlc(peer, msg);
		goto done;

	case WIRE_INIT:
	case WIRE_ERROR:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
		goto badmessage;

	case WIRE_SHUTDOWN:
	case WIRE_CLOSING_SIGNED:
	case WIRE_UPDATE_FULFILL_HTLC:
	case WIRE_UPDATE_FAIL_HTLC:
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
	case WIRE_COMMITMENT_SIGNED:
	case WIRE_REVOKE_AND_ACK:
	case WIRE_UPDATE_FEE:
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Unimplemented message %u (%s)",
			    type, wire_type_name(type));
	}

badmessage:
	peer_failed(io_conn_fd(peer->peer_conn),
		    &peer->pcs.cs,
		    &peer->channel_id,
		    WIRE_CHANNEL_PEER_BAD_MESSAGE,
		    "Peer sent unknown message %u (%s)",
		    type, wire_type_name(type));

done:
	return peer_read_message(conn, &peer->pcs, peer_in);
}

static struct io_plan *setup_peer_conn(struct io_conn *conn, struct peer *peer)
{
	return io_duplex(conn, peer_read_message(conn, &peer->pcs, peer_in),
			 peer_out(conn, peer));
}

static void peer_conn_broken(struct io_conn *conn, struct peer *peer)
{
	send_channel_update(peer, true);
	/* Make sure gossipd actually gets this message before dying */
	daemon_conn_sync_flush(&peer->gossip_client);
	status_failed(WIRE_CHANNEL_PEER_READ_FAILED,
		      "peer connection broken: %s", strerror(errno));
}

static void init_channel(struct peer *peer, const u8 *msg)
{
	struct privkey seed;
	struct basepoints points[NUM_SIDES];
	u32 feerate;
	u64 funding_satoshi, push_msat;
	u16 funding_txout;
	struct pubkey funding_pubkey[NUM_SIDES];
	struct sha256_double funding_txid;
	bool am_funder;

	if (!fromwire_channel_init(msg, NULL,
				   &funding_txid, &funding_txout,
				   &peer->conf[LOCAL], &peer->conf[REMOTE],
				   &peer->their_commit_sig,
				   &peer->pcs.cs,
				   &funding_pubkey[REMOTE],
				   &points[REMOTE].revocation,
				   &points[REMOTE].payment,
				   &points[REMOTE].delayed_payment,
				   &peer->next_per_commit[REMOTE],
				   &am_funder,
				   &feerate, &funding_satoshi, &push_msat,
				   &seed,
				   &peer->node_ids[LOCAL],
				   &peer->node_ids[REMOTE]))
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "%s",
			      tal_hex(msg, msg));

	/* We derive everything from the one secret seed. */
	derive_basepoints(&seed, &funding_pubkey[LOCAL], &points[LOCAL],
			  &peer->our_secrets, &peer->shaseed,
			  &peer->next_per_commit[LOCAL], 1);

	peer->channel = new_channel(peer, &funding_txid, funding_txout,
				    funding_satoshi, push_msat, feerate,
				    &peer->conf[LOCAL], &peer->conf[REMOTE],
				    &points[LOCAL], &points[REMOTE],
				    &funding_pubkey[LOCAL],
				    &funding_pubkey[REMOTE],
				    am_funder ? LOCAL : REMOTE);

	peer->channel_direction = get_channel_direction(
	    &peer->node_ids[LOCAL], &peer->node_ids[REMOTE]);

	/* OK, now we can process peer messages. */
	peer->peer_conn = io_new_conn(peer, PEER_FD, setup_peer_conn, peer);
	io_set_finish(peer->peer_conn, peer_conn_broken, peer);
}

static void handle_funding_locked(struct peer *peer, const u8 *msg)
{
	if (!fromwire_channel_funding_locked(msg, NULL,
					     &peer->short_channel_ids[LOCAL]))
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "%s", tal_hex(msg, msg));

	msg = towire_funding_locked(peer,
				    &peer->channel_id,
				    &peer->next_per_commit[LOCAL]);
	msg_enqueue(&peer->peer_out, take(msg));
	peer->funding_locked[LOCAL] = true;

	if (peer->funding_locked[REMOTE]) {
		send_channel_announcement(peer);
		send_channel_update(peer, false);
		daemon_conn_send(&peer->master,
				 take(towire_channel_normal_operation(peer)));
	}
}

static void handle_funding_announce_depth(struct peer *peer, const u8 *msg)
{
	status_trace("Exchanging announcement signatures.");
	send_announcement_signatures(peer);
}

static void start_commit_timer(struct peer *peer)
{
	/* FIXME! */
}

static void handle_offer_htlc(struct peer *peer, const u8 *inmsg)
{
	u8 *msg;
	u32 amount_msat, cltv_expiry;
	struct sha256 payment_hash;
	u8 onion_routing_packet[1254];
	enum onion_type failcode;
	/* Subtle: must be tal_arr since we marshal using tal_len() */
	const char *failmsg;

	if (!peer->funding_locked[LOCAL] || !peer->funding_locked[REMOTE])
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "funding not locked");

	if (!fromwire_channel_offer_htlc(inmsg, NULL, &amount_msat,
					 &cltv_expiry, &payment_hash,
					 onion_routing_packet))
		status_failed(WIRE_CHANNEL_BAD_COMMAND,
			      "bad offer_htlc message %s",
			      tal_hex(inmsg, inmsg));

	switch (channel_add_htlc(peer->channel, LOCAL, peer->htlc_id,
				 amount_msat, cltv_expiry, &payment_hash,
				 onion_routing_packet)) {
	case CHANNEL_ERR_ADD_OK:
		/* Tell the peer. */
		msg = towire_update_add_htlc(peer, &peer->channel_id,
					     peer->htlc_id, amount_msat,
					     cltv_expiry, &payment_hash,
					     onion_routing_packet);
		msg_enqueue(&peer->peer_out, take(msg));
		peer->funding_locked[LOCAL] = true;
		start_commit_timer(peer);
		/* Tell the master. */
		msg = towire_channel_offer_htlc_reply(inmsg, peer->htlc_id,
						      0, NULL);
		daemon_conn_send(&peer->master, take(msg));
		peer->htlc_id++;
		return;
	case CHANNEL_ERR_INVALID_EXPIRY:
		failcode = WIRE_INCORRECT_CLTV_EXPIRY;
		failmsg = tal_fmt(inmsg, "Invalid cltv_expiry %u", cltv_expiry);
		goto failed;
	case CHANNEL_ERR_DUPLICATE:
	case CHANNEL_ERR_DUPLICATE_ID_DIFFERENT:
		status_failed(WIRE_CHANNEL_BAD_COMMAND,
			      "Duplicate HTLC %"PRIu64, peer->htlc_id);

	/* FIXME: Fuzz the boundaries a bit to avoid probing? */
	case CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED:
		/* FIXME: We should advertise this? */
		failcode = WIRE_TEMPORARY_CHANNEL_FAILURE;
		failmsg = tal_fmt(inmsg, "Maximum value exceeded");
		goto failed;
	case CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED:
		failcode = WIRE_TEMPORARY_CHANNEL_FAILURE;
		failmsg = tal_fmt(inmsg, "Capacity exceeded");
		goto failed;
	case CHANNEL_ERR_HTLC_BELOW_MINIMUM:
		failcode = WIRE_AMOUNT_BELOW_MINIMUM;
		failmsg = tal_fmt(inmsg, "HTLC too small (%u minimum)",
				  htlc_minimum_msat(peer->channel, REMOTE));
		goto failed;
	case CHANNEL_ERR_TOO_MANY_HTLCS:
		failcode = WIRE_TEMPORARY_CHANNEL_FAILURE;
		failmsg = tal_fmt(inmsg, "Too many HTLCs");
		goto failed;
	}
	/* Shouldn't return anything else! */
	abort();

failed:
	msg = towire_channel_offer_htlc_reply(inmsg, 0, failcode, (u8*)failmsg);
	daemon_conn_send(&peer->master, take(msg));
}

static void handle_preimage(struct peer *peer, const u8 *inmsg)
{
	u8 *msg;
	u64 id;
	struct preimage preimage;

	if (!fromwire_channel_fulfill_htlc(inmsg, NULL, &id, &preimage))
		status_failed(WIRE_CHANNEL_BAD_COMMAND,
			      "Invalid channel_fulfill_htlc");

	switch (channel_fulfill_htlc(peer->channel, REMOTE, id, &preimage)) {
	case CHANNEL_ERR_REMOVE_OK:
		msg = towire_update_fulfill_htlc(peer, &peer->channel_id,
						 id, &preimage);
		msg_enqueue(&peer->peer_out, take(msg));
		start_commit_timer(peer);
		return;
	/* These shouldn't happen, because any offered HTLC (which would give
	 * us the preimage) should have timed out long before.  If we
	 * were to get preimages from other sources, this could happen. */
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		status_failed(WIRE_CHANNEL_BAD_COMMAND,
			      "HTLC %"PRIu64" preimage failed", id);
	}
	abort();
}

static void handle_fail(struct peer *peer, const u8 *inmsg)
{
	u8 *msg;
	u64 id;
	u8 *errpkt;

	if (!fromwire_channel_fail_htlc(inmsg, inmsg, NULL, &id, &errpkt))
		status_failed(WIRE_CHANNEL_BAD_COMMAND,
			      "Invalid channel_fail_htlc");

	switch (channel_fail_htlc(peer->channel, REMOTE, id)) {
	case CHANNEL_ERR_REMOVE_OK:
		msg = towire_update_fail_htlc(peer, &peer->channel_id,
					      id, errpkt);
		msg_enqueue(&peer->peer_out, take(msg));
		start_commit_timer(peer);
		return;
	/* These shouldn't happen, because any offered HTLC (which would give
	 * us the preimage) should have timed out long before.  If we
	 * were to get preimages from other sources, this could happen. */
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		status_failed(WIRE_CHANNEL_BAD_COMMAND,
			      "HTLC %"PRIu64" preimage failed", id);
	}
	abort();
}

static struct io_plan *req_in(struct io_conn *conn, struct daemon_conn *master)
{
	struct peer *peer = container_of(master, struct peer, master);

	if (!peer->channel)
		init_channel(peer, master->msg_in);
	else {
		enum channel_wire_type t = fromwire_peektype(master->msg_in);

		switch (t) {
		case WIRE_CHANNEL_FUNDING_LOCKED:
			handle_funding_locked(peer, master->msg_in);
			goto out;
		case WIRE_CHANNEL_FUNDING_ANNOUNCE_DEPTH:
			handle_funding_announce_depth(peer, master->msg_in);
			goto out;
		case WIRE_CHANNEL_OFFER_HTLC:
			handle_offer_htlc(peer, master->msg_in);
			goto out;
		case WIRE_CHANNEL_FULFILL_HTLC:
			handle_preimage(peer, master->msg_in);
			goto out;
		case WIRE_CHANNEL_FAIL_HTLC:
			handle_fail(peer, master->msg_in);
			goto out;

		case WIRE_CHANNEL_BAD_COMMAND:
		case WIRE_CHANNEL_HSM_FAILED:
		case WIRE_CHANNEL_PEER_WRITE_FAILED:
		case WIRE_CHANNEL_PEER_READ_FAILED:
		case WIRE_CHANNEL_RECEIVED_FUNDING_LOCKED:
		case WIRE_CHANNEL_NORMAL_OPERATION:
		case WIRE_CHANNEL_INIT:
		case WIRE_CHANNEL_OFFER_HTLC_REPLY:
		case WIRE_CHANNEL_ACCEPTED_HTLC:
		case WIRE_CHANNEL_FULFILLED_HTLC:
		case WIRE_CHANNEL_FAILED_HTLC:
		case WIRE_CHANNEL_MALFORMED_HTLC:
		case WIRE_CHANNEL_PEER_BAD_MESSAGE:
			break;
		}
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "%s", strerror(errno));
	}

out:
	return daemon_conn_read_next(conn, master);
}

#ifndef TESTING
int main(int argc, char *argv[])
{
	struct peer *peer = tal(NULL, struct peer);

	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	subdaemon_debug(argc, argv);

	/* We handle write returning errors! */
	signal(SIGCHLD, SIG_IGN);
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	daemon_conn_init(peer, &peer->master, REQ_FD, req_in);
	peer->channel = NULL;
	peer->htlc_id = 0;

	status_setup_async(&peer->master);
	msg_queue_init(&peer->peer_out, peer);

	daemon_conn_init(peer, &peer->gossip_client, GOSSIP_FD,
			 gossip_client_recv);

	init_peer_crypto_state(peer, &peer->pcs);
	peer->funding_locked[LOCAL] = peer->funding_locked[REMOTE] = false;

	/* We don't expect to exit here. */
	io_loop(NULL, NULL);
	tal_free(peer);
	return 0;
}
#endif /* TESTING */
