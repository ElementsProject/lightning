#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/structeq/structeq.h>
#include <ccan/take/take.h>
#include <ccan/time/time.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/channel.h>
#include <lightningd/channel/gen_channel_wire.h>
#include <lightningd/commit_tx.h>
#include <lightningd/connection.h>
#include <lightningd/crypto_sync.h>
#include <lightningd/cryptomsg.h>
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
	struct pubkey funding_pubkey[NUM_SIDES];

	/* Their sig for current commit. */
	secp256k1_ecdsa_signature their_commit_sig;

	/* Secret keys and basepoint secrets. */
	struct secrets our_secrets;

	/* Our shaseed for generating per-commitment-secrets. */
	struct sha256 shaseed;

	struct channel_id channel_id;
	struct channel *channel;

	struct msg_queue peer_out;

	struct daemon_conn gossip_client;
	struct daemon_conn master;

	/* Announcement related information */
	struct pubkey node_ids[NUM_SIDES];
	struct short_channel_id short_channel_ids[NUM_SIDES];
	secp256k1_ecdsa_signature announcement_node_sigs[NUM_SIDES];
	secp256k1_ecdsa_signature announcement_bitcoin_sigs[NUM_SIDES];
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

static void announce_channel(struct peer *peer)
{
	tal_t *tmpctx = tal_tmpctx(peer);
	u8 local_der[33], remote_der[33];
	int first, second;
	u32 timestamp = time_now().ts.tv_sec;
	u8 *cannounce, *cupdate, *features = tal_arr(peer, u8, 0);
	u16 flags;

	/* Find out in which order we have to list the endpoints */
	pubkey_to_der(local_der, &peer->node_ids[LOCAL]);
	pubkey_to_der(remote_der, &peer->node_ids[REMOTE]);
	if (memcmp(local_der, remote_der, sizeof(local_der)) < 0) {
		first = LOCAL;
		second = REMOTE;
	} else {
		first = REMOTE;
		second = LOCAL;
	}

	/* Now that we have a working channel, tell the world. */
	cannounce = towire_channel_announcement(
	    tmpctx, &peer->announcement_node_sigs[first],
	    &peer->announcement_node_sigs[second],
	    &peer->announcement_bitcoin_sigs[first],
	    &peer->announcement_bitcoin_sigs[second],
	    &peer->short_channel_ids[LOCAL], &peer->node_ids[first],
	    &peer->node_ids[second], &peer->funding_pubkey[first],
	    &peer->funding_pubkey[second], features);

	// TODO(cdecker) Create a real signature for this update
	secp256k1_ecdsa_signature *sig =
	    talz(tmpctx, secp256k1_ecdsa_signature);

	flags = first == LOCAL;
	cupdate = towire_channel_update(
	    tmpctx, sig, &peer->short_channel_ids[LOCAL], timestamp, flags, 36,
	    1, 10, peer->channel->view[LOCAL].feerate_per_kw);

	msg_enqueue(&peer->peer_out, cannounce);
	msg_enqueue(&peer->peer_out, cupdate);

	daemon_conn_send(&peer->gossip_client, take(cannounce));
	daemon_conn_send(&peer->gossip_client, take(cupdate));

	tal_free(tmpctx);
}

static struct io_plan *peer_out(struct io_conn *conn, struct peer *peer)
{
	const u8 *out = msg_dequeue(&peer->peer_out);
	if (!out)
		return msg_queue_wait(conn, &peer->peer_out, peer_out, peer);

	return peer_write_message(conn, &peer->pcs, out, peer_out);
}

static struct io_plan *peer_in(struct io_conn *conn, struct peer *peer, u8 *msg)
{
	struct channel_id chanid;
	int type = fromwire_peektype(msg);

	if (fromwire_funding_locked(msg, NULL, &chanid,
				    &peer->next_per_commit[REMOTE])) {
		if (!structeq(&chanid, &peer->channel_id))
			status_failed(WIRE_CHANNEL_PEER_BAD_MESSAGE,
				      "Wrong channel id in %s",
				      tal_hex(trc, msg));
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
	} else if (type == WIRE_ANNOUNCEMENT_SIGNATURES) {
		fromwire_announcement_signatures(
		    msg, NULL, &chanid, &peer->short_channel_ids[REMOTE],
		    &peer->announcement_node_sigs[REMOTE],
		    &peer->announcement_bitcoin_sigs[REMOTE]);

		/* Make sure we agree on the channel ids */
		if (!structeq(&chanid, &peer->channel_id)) {
			status_failed(
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Wrong channel_id or short_channel_id in %s or %s",
			    tal_hexstr(trc, &chanid, sizeof(struct channel_id)),
			    tal_hexstr(trc, &peer->short_channel_ids[REMOTE],
				       sizeof(struct short_channel_id)));
		}
		if (peer->funding_locked[LOCAL]) {
			announce_channel(peer);
		}
	} else if (type == WIRE_CHANNEL_ANNOUNCEMENT ||
		   type == WIRE_CHANNEL_UPDATE ||
		   type == WIRE_NODE_ANNOUNCEMENT) {
		daemon_conn_send(&peer->gossip_client, msg);
	}

	return peer_read_message(conn, &peer->pcs, peer_in);
}


static struct io_plan *setup_peer_conn(struct io_conn *conn, struct peer *peer)
{
	return io_duplex(conn, peer_read_message(conn, &peer->pcs, peer_in),
			 peer_out(conn, peer));
}

static void peer_conn_broken(struct io_conn *conn, struct peer *peer)
{
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
	struct sha256_double funding_txid;
	bool am_funder;

	if (!fromwire_channel_init(msg, NULL,
				   &funding_txid, &funding_txout,
				   &peer->conf[LOCAL], &peer->conf[REMOTE],
				   &peer->their_commit_sig,
				   &peer->pcs.cs,
				   &peer->funding_pubkey[REMOTE],
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
	derive_basepoints(&seed, &peer->funding_pubkey[LOCAL], &points[LOCAL],
			  &peer->our_secrets, &peer->shaseed,
			  &peer->next_per_commit[LOCAL], 1);

	peer->channel = new_channel(peer, &funding_txid, funding_txout,
				    funding_satoshi, push_msat, feerate,
				    &peer->conf[LOCAL], &peer->conf[REMOTE],
				    &points[LOCAL], &points[REMOTE],
				    am_funder ? LOCAL : REMOTE);

	/* OK, now we can process peer messages. */
	io_set_finish(io_new_conn(peer, PEER_FD, setup_peer_conn, peer),
		      peer_conn_broken, peer);
}

static struct io_plan *req_in(struct io_conn *conn, struct daemon_conn *master)
{
	struct peer *peer = container_of(master, struct peer, master);

	if (!peer->channel)
		init_channel(peer, master->msg_in);
	else if (fromwire_channel_funding_locked(master->msg_in, NULL,
						 &peer->short_channel_ids[LOCAL])) {
		u8 *msg = towire_funding_locked(peer,
						&peer->channel_id,
						&peer->next_per_commit[LOCAL]);
		msg_enqueue(&peer->peer_out, take(msg));
		peer->funding_locked[LOCAL] = true;
		send_announcement_signatures(peer);

		if (peer->funding_locked[REMOTE]) {
			announce_channel(peer);
			daemon_conn_send(master,
				 take(towire_channel_normal_operation(peer)));
		}
	} else
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "%s", strerror(errno));

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
