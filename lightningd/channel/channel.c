#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/structeq/structeq.h>
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
#include <secp256k1.h>
#include <signal.h>
#include <status.h>
#include <stdio.h>
#include <type_to_string.h>
#include <version.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

/* stdin == requests, 3 == peer */
#define REQ_FD STDIN_FILENO
#define PEER_FD 3

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

	struct channel_id channel_id;
	struct channel *channel;

	u8 *req_in;

	struct msg_queue peer_out;

	int gossip_client_fd;
	struct daemon_conn gossip_client;
};

static void queue_pkt(struct peer *peer, const u8 *msg)
{
	msg_enqueue(&peer->peer_out, msg);
	io_wake(peer);
}

static struct io_plan *gossip_client_recv(struct io_conn *conn,
					  struct daemon_conn *dc)
{
	u8 *msg = dc->msg_in;
	struct peer *peer = container_of(dc, struct peer, gossip_client);
	u16 type = fromwire_peektype(msg);

	if (type == WIRE_CHANNEL_ANNOUNCEMENT || type == WIRE_CHANNEL_UPDATE ||
	    type == WIRE_NODE_ANNOUNCEMENT)
		queue_pkt(peer, tal_dup_arr(dc->ctx, u8, msg, tal_len(msg), 0));

	return daemon_conn_read_next(conn, dc);
}

static struct io_plan *peer_out(struct io_conn *conn, struct peer *peer)
{
	const u8 *out = msg_dequeue(&peer->peer_out);
	if (!out)
		return io_out_wait(conn, peer, peer_out, peer);

	return peer_write_message(conn, &peer->pcs, out, peer_out);
}

static struct io_plan *peer_in(struct io_conn *conn, struct peer *peer, u8 *msg)
{
	struct channel_id chanid;
	int type = fromwire_peektype(msg);

	status_trace("Received %s from peer", wire_type_name(type));


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
		status_send(towire_channel_received_funding_locked(peer));

		if (peer->funding_locked[LOCAL])
			status_send(towire_channel_normal_operation(peer));
	}

	if (type == WIRE_CHANNEL_ANNOUNCEMENT || type == WIRE_CHANNEL_UPDATE ||
	    type == WIRE_NODE_ANNOUNCEMENT) {
		daemon_conn_send(&peer->gossip_client, msg);
	}

	return peer_read_message(conn, &peer->pcs, peer_in);
}

static struct io_plan *req_in(struct io_conn *conn, struct peer *peer)
{
	if (fromwire_channel_funding_locked(peer->req_in, NULL)) {
		u8 *msg = towire_funding_locked(peer,
						&peer->channel_id,
						&peer->next_per_commit[LOCAL]);
		queue_pkt(peer, msg);
		peer->funding_locked[LOCAL] = true;

		if (peer->funding_locked[REMOTE])
			status_send(towire_channel_normal_operation(peer));
	} else
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "%s", strerror(errno));

	return io_read_wire(conn, peer, &peer->req_in, req_in, peer);
}

static struct io_plan *setup_req_in(struct io_conn *conn, struct peer *peer)
{
	return io_read_wire(conn, peer, &peer->req_in, req_in, peer);
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

#ifndef TESTING
int main(int argc, char *argv[])
{
	u8 *msg;
	struct peer *peer = tal(NULL, struct peer);
	struct privkey seed;
	struct basepoints points[NUM_SIDES];
	struct pubkey funding_pubkey[NUM_SIDES];
	u32 feerate;
	u64 funding_satoshi, push_msat;
	u16 funding_txout;
	struct sha256_double funding_txid;
	bool am_funder;

	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	subdaemon_debug(argc, argv);

	/* We handle write returning errors! */
	signal(SIGCHLD, SIG_IGN);
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);
	status_setup(REQ_FD);
	msg_queue_init(&peer->peer_out, peer);
	init_peer_crypto_state(peer, &peer->pcs);
	peer->funding_locked[LOCAL] = peer->funding_locked[REMOTE] = false;

	msg = wire_sync_read(peer, REQ_FD);
	if (!msg)
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "%s", strerror(errno));

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
				   &seed))
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "%s",
			      tal_hex(msg, msg));
	tal_free(msg);
	peer->gossip_client_fd = fdpass_recv(REQ_FD);

	daemon_conn_init(peer, &peer->gossip_client, peer->gossip_client_fd,
			 gossip_client_recv);

	if (peer->gossip_client_fd == -1)
		status_failed(
		    WIRE_CHANNEL_BAD_COMMAND,
		    "Did not receive a valid client socket to gossipd");

	/* We derive everything from the one secret seed. */
	derive_basepoints(&seed, &funding_pubkey[LOCAL], &points[LOCAL],
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
	io_new_conn(peer, REQ_FD, setup_req_in, peer);

	/* We don't expect to exit here. */
	io_loop(NULL, NULL);
	tal_free(peer);
	return 0;
}
#endif /* TESTING */
