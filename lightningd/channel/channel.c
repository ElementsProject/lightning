#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/mem/mem.h>
#include <ccan/structeq/structeq.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <daemon/routing.h>
#include <daemon/timeout.h>
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
#include <lightningd/hsm/gen_hsm_client_wire.h>
#include <lightningd/htlc_tx.h>
#include <lightningd/key_derive.h>
#include <lightningd/msg_queue.h>
#include <lightningd/peer_failed.h>
#include <lightningd/ping.h>
#include <lightningd/sphinx.h>
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

/* stdin == requests, 3 == peer, 4 = gossip, 5 = HSM */
#define REQ_FD STDIN_FILENO
#define PEER_FD 3
#define GOSSIP_FD 4
#define HSM_FD 5

struct peer {
	struct peer_crypto_state pcs;
	struct channel_config conf[NUM_SIDES];
	struct pubkey old_per_commit[NUM_SIDES];
	struct pubkey current_per_commit[NUM_SIDES];
	bool funding_locked[NUM_SIDES];
	u64 commit_index[NUM_SIDES];

	/* Their sig for current commit. */
	secp256k1_ecdsa_signature their_commit_sig;

	/* Secret keys and basepoint secrets. */
	struct secrets our_secrets;

	/* Our shaseed for generating per-commitment-secrets. */
	struct sha256 shaseed;

	/* Their shachain. */
	struct shachain their_shachain;

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

	struct timers timers;
	struct oneshot *commit_timer;
	u32 commit_msec;

	/* Don't accept a pong we didn't ping for. */
	size_t num_pings_outstanding;

	/* Announcement related information */
	struct pubkey node_ids[NUM_SIDES];
	struct short_channel_id short_channel_ids[NUM_SIDES];
	secp256k1_ecdsa_signature announcement_node_sigs[NUM_SIDES];
	secp256k1_ecdsa_signature announcement_bitcoin_sigs[NUM_SIDES];
	bool have_sigs[NUM_SIDES];

	/* Which direction of the channel do we control? */
	u16 channel_direction;

	/* CLTV delta to announce to peers */
	u16 cltv_delta;
	u32 fee_base;
	u32 fee_per_satoshi;
};

static u8 *create_channel_announcement(const tal_t *ctx, struct peer *peer);

static struct io_plan *gossip_client_recv(struct io_conn *conn,
					  struct daemon_conn *dc)
{
	u8 *msg = dc->msg_in;
	struct peer *peer = container_of(dc, struct peer, gossip_client);
	u16 type = fromwire_peektype(msg);

	if (type == WIRE_CHANNEL_ANNOUNCEMENT || type == WIRE_CHANNEL_UPDATE ||
	    type == WIRE_NODE_ANNOUNCEMENT)
		msg_enqueue(&peer->peer_out, msg);
	else
		status_failed(WIRE_CHANNEL_GOSSIP_BAD_MESSAGE,
			      "Got bad message from gossipd: %d", type);

	return daemon_conn_read_next(conn, dc);
}

static void send_announcement_signatures(struct peer *peer)
{
	/* First 2 + 256 byte are the signatures and msg type, skip them */
	size_t offset = 258;
	const tal_t *tmpctx = tal_tmpctx(peer);
	struct sha256_double hash;
	u8 *msg;
	u8 *ca = create_channel_announcement(tmpctx, peer);
	u8 *req = towire_hsm_cannouncement_sig_req(tmpctx,
						   &peer->channel->funding_pubkey[LOCAL],
						   ca);

	if (!wire_sync_write(HSM_FD, req))
		status_failed(WIRE_CHANNEL_HSM_FAILED,
			      "Writing cannouncement_sig_req");

	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg || !fromwire_hsm_cannouncement_sig_reply(msg, NULL,
					  &peer->announcement_node_sigs[LOCAL]))
		status_failed(WIRE_CHANNEL_HSM_FAILED,
			      "Reading cannouncement_sig_resp");

	/* Double-check that HSM gave a valid signature. */
	sha256_double(&hash, ca + offset, tal_len(ca) - offset);
	if (!check_signed_hash(&hash, &peer->announcement_node_sigs[LOCAL],
			       &peer->node_ids[LOCAL])) {
		/* It's ok to fail here, the channel announcement is
		 * unique, unlike the channel update which may have
		 * been replaced in the meantime. */
		status_failed(WIRE_CHANNEL_HSM_FAILED,
			      "HSM returned an invalid signature");
	}

	/* TODO(cdecker) Move this to the HSM once we store the
	 * funding_privkey there */
	sign_hash(&peer->our_secrets.funding_privkey, &hash,
		  &peer->announcement_bitcoin_sigs[LOCAL]);

	peer->have_sigs[LOCAL] = true;

	msg = towire_announcement_signatures(
	    tmpctx, &peer->channel_id, &peer->short_channel_ids[LOCAL],
	    &peer->announcement_node_sigs[LOCAL],
	    &peer->announcement_bitcoin_sigs[LOCAL]);
	msg_enqueue(&peer->peer_out, take(msg));
	tal_free(tmpctx);
}

static void send_channel_update(struct peer *peer, bool disabled)
{
	tal_t *tmpctx = tal_tmpctx(peer);
	u32 timestamp = time_now().ts.tv_sec;
	u16 flags;
	u8 *cupdate, *msg;

	/* Set the signature to empty so that valgrind doesn't complain */
	secp256k1_ecdsa_signature *sig =
	    talz(tmpctx, secp256k1_ecdsa_signature);

	flags = peer->channel_direction | (disabled << 1);
	cupdate = towire_channel_update(
	    tmpctx, sig, &peer->short_channel_ids[LOCAL], timestamp, flags,
	    peer->cltv_delta, peer->fee_base, peer->fee_per_satoshi,
	    peer->channel->view[LOCAL].feerate_per_kw);

	msg = towire_hsm_cupdate_sig_req(tmpctx, cupdate);

	if (!wire_sync_write(HSM_FD, msg))
		status_failed(WIRE_CHANNEL_HSM_FAILED,
			      "Writing cupdate_sig_req");

	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg || !fromwire_hsm_cupdate_sig_reply(tmpctx, msg, NULL, &cupdate))
		status_failed(WIRE_CHANNEL_HSM_FAILED,
			      "Reading cupdate_sig_req");

	daemon_conn_send(&peer->gossip_client, cupdate);
	msg_enqueue(&peer->peer_out, cupdate);
	tal_free(tmpctx);
}

/* Tentatively create a channel_announcement, possibly with invalid
 * signatures. The signatures need to be collected first, by asking
 * the HSM and by exchanging announcement_signature messages. */
static u8 *create_channel_announcement(const tal_t *ctx, struct peer *peer)
{
	int first, second;
	u8 *cannounce, *features = tal_arr(ctx, u8, 0);

	if (peer->channel_direction == 0) {
		first = LOCAL;
		second = REMOTE;
	} else {
		first = REMOTE;
		second = LOCAL;
	}

	cannounce = towire_channel_announcement(
	    ctx, &peer->announcement_node_sigs[first],
	    &peer->announcement_node_sigs[second],
	    &peer->announcement_bitcoin_sigs[first],
	    &peer->announcement_bitcoin_sigs[second],
	    &peer->short_channel_ids[LOCAL], &peer->node_ids[first],
	    &peer->node_ids[second], &peer->channel->funding_pubkey[first],
	    &peer->channel->funding_pubkey[second], features);
	tal_free(features);
	return cannounce;
}

static void send_channel_announcement(struct peer *peer)
{
	u8 *msg = create_channel_announcement(peer, peer);
	/* Makes a copy */
	msg_enqueue(&peer->peer_out, msg);
	/* Takes ownership */
	daemon_conn_send(&peer->gossip_client, take(msg));
}

static struct io_plan *peer_out(struct io_conn *conn, struct peer *peer)
{
	const u8 *out = msg_dequeue(&peer->peer_out);
	if (!out)
		return msg_queue_wait(conn, &peer->peer_out, peer_out, peer);

	status_trace("peer_out %s", wire_type_name(fromwire_peektype(out)));
	return peer_write_message(conn, &peer->pcs, out, peer_out);
}

static struct io_plan *peer_in(struct io_conn *conn, struct peer *peer, u8 *msg);

static struct io_plan *handle_peer_funding_locked(struct io_conn *conn,
						  struct peer *peer,
						  const u8 *msg)
{
	struct channel_id chanid;

	if (!fromwire_funding_locked(msg, NULL, &chanid,
				     &peer->current_per_commit[REMOTE]))
		status_failed(WIRE_CHANNEL_PEER_BAD_MESSAGE,
			      "Bad funding_locked %s", tal_hex(msg, msg));

	if (!structeq(&chanid, &peer->channel_id))
		status_failed(WIRE_CHANNEL_PEER_BAD_MESSAGE,
			      "Wrong channel id in %s", tal_hex(trc, msg));
	if (peer->funding_locked[REMOTE])
		status_failed(WIRE_CHANNEL_PEER_BAD_MESSAGE,
			      "Funding locked twice");

	peer->funding_locked[REMOTE] = true;

	if (peer->funding_locked[LOCAL]) {
		daemon_conn_send(&peer->master,
				 take(towire_channel_normal_operation(peer)));
	}

	return peer_read_message(conn, &peer->pcs, peer_in);
}

static struct io_plan *handle_peer_announcement_signatures(struct io_conn *conn,
							   struct peer *peer,
							   const u8 *msg)
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

	peer->have_sigs[REMOTE] = true;

	/* We have the remote sigs, do we have the local ones as well? */
	if (peer->funding_locked[LOCAL] && peer->have_sigs[LOCAL]) {
		send_channel_announcement(peer);
		send_channel_update(peer, false);
		/* Tell the master that we just announced the channel,
		 * so it may announce the node */
		daemon_conn_send(&peer->master, take(towire_channel_announced(msg)));
	}

	return peer_read_message(conn, &peer->pcs, peer_in);
}

static struct io_plan *handle_peer_add_htlc(struct io_conn *conn,
					    struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 id;
	u64 amount_msat;
	u32 cltv_expiry;
	struct sha256 payment_hash;
	u8 onion_routing_packet[TOTAL_PACKET_SIZE];
	enum channel_add_err add_err;

	if (!fromwire_update_add_htlc(msg, NULL, &channel_id, &id, &amount_msat,
				      &payment_hash, &cltv_expiry,
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
	return peer_read_message(conn, &peer->pcs, peer_in);
}

static void send_commit(struct peer *peer)
{
	tal_t *tmpctx = tal_tmpctx(peer);
	u8 *msg;
	secp256k1_ecdsa_signature commit_sig, *htlc_sigs;
	size_t i;
	struct bitcoin_tx **txs;
	const u8 **wscripts;
	const struct htlc **htlc_map;
	struct pubkey localkey;
	struct privkey local_secretkey;

	/* Timer has expired. */
	peer->commit_timer = NULL;

	/* FIXME: Document this requirement in BOLT 2! */
	/* We can't send two commits in a row. */
	if (channel_awaiting_revoke_and_ack(peer->channel)) {
		status_trace("Can't send commit: waiting for revoke_and_ack");
		tal_free(tmpctx);
		return;
	}

	/* BOLT #2:
	 *
	 * A node MUST NOT send a `commitment_signed` message which does not
	 * include any updates.
	 */
	if (!channel_sending_commit(peer->channel, NULL)) {
		status_trace("Can't send commit: nothing to send");
		tal_free(tmpctx);
		return;
	}

	if (!derive_simple_privkey(&peer->our_secrets.payment_basepoint_secret,
				   &peer->channel->basepoints[LOCAL].payment,
				   &peer->current_per_commit[REMOTE],
				   &local_secretkey))
		status_failed(WIRE_CHANNEL_CRYPTO_FAILED,
			      "Deriving local_secretkey");

	if (!derive_simple_key(&peer->channel->basepoints[LOCAL].payment,
			       &peer->current_per_commit[REMOTE],
			       &localkey))
		status_failed(WIRE_CHANNEL_CRYPTO_FAILED,
			      "Deriving localkey");

	txs = channel_txs(tmpctx, &htlc_map, &wscripts, peer->channel,
			  &peer->current_per_commit[REMOTE], REMOTE);

	sign_tx_input(txs[0], 0, NULL,
		      wscripts[0],
		      &peer->our_secrets.funding_privkey,
		      &peer->channel->funding_pubkey[LOCAL],
		      &commit_sig);

	status_trace("Creating commit_sig signature %s for tx %s wscript %s key %s",
		     type_to_string(trc, secp256k1_ecdsa_signature,
				    &commit_sig),
		     type_to_string(trc, struct bitcoin_tx, txs[0]),
		     tal_hex(trc, wscripts[0]),
		     type_to_string(trc, struct pubkey,
				    &peer->channel->funding_pubkey[LOCAL]));

	/* BOLT #2:
	 *
	 * A node MUST include one `htlc_signature` for every HTLC transaction
	 * corresponding to BIP69 lexicographic ordering of the commitment
	 * transaction.
	 */
	htlc_sigs = tal_arr(tmpctx, secp256k1_ecdsa_signature,
			    tal_count(txs) - 1);

	for (i = 0; i < tal_count(htlc_sigs); i++) {
		sign_tx_input(txs[1 + i], 0,
			      NULL,
			      wscripts[1 + i],
			      &local_secretkey, &localkey,
			      &htlc_sigs[i]);
		status_trace("Creating HTLC signature %s for tx %s wscript %s key %s",
			     type_to_string(trc, secp256k1_ecdsa_signature,
					    &htlc_sigs[i]),
			     type_to_string(trc, struct bitcoin_tx, txs[1+i]),
			     tal_hex(trc, wscripts[1+i]),
			     type_to_string(trc, struct pubkey, &localkey));
		assert(check_tx_sig(txs[1+i], 0, NULL, wscripts[1+i],
				    &localkey, &htlc_sigs[i]));
	}
	status_trace("Sending commit_sig with %zu htlc sigs",
		     tal_count(htlc_sigs));
	msg = towire_commitment_signed(tmpctx, &peer->channel_id,
				       &commit_sig, htlc_sigs);
	msg_enqueue(&peer->peer_out, take(msg));
	tal_free(tmpctx);
}

static void start_commit_timer(struct peer *peer)
{
	/* Already armed? */
	if (peer->commit_timer)
		return;

	peer->commit_timer = new_reltimer(&peer->timers, peer,
					  time_from_msec(peer->commit_msec),
					  send_commit, peer);
}

static struct io_plan *handle_peer_commit_sig(struct io_conn *conn,
					      struct peer *peer, const u8 *msg)
{
	tal_t *tmpctx = tal_tmpctx(peer);
	struct sha256 old_commit_secret;
	struct channel_id channel_id;
	secp256k1_ecdsa_signature commit_sig, *htlc_sigs;
	struct pubkey remotekey;
	struct bitcoin_tx **txs;
	const struct htlc **htlc_map, **changed_htlcs;
	const u8 **wscripts;
	size_t i;

	changed_htlcs = tal_arr(msg, const struct htlc *, 0);
	if (!channel_rcvd_commit(peer->channel, &changed_htlcs)) {
		/* BOLT #2:
		 *
		 * A node MUST NOT send a `commitment_signed` message which
		 * does not include any updates.
		 */
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "commit_sig with no changes");
	}

	if (!fromwire_commitment_signed(tmpctx, msg, NULL,
					&channel_id, &commit_sig, &htlc_sigs))
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad commit_sig %s", tal_hex(msg, msg));

	txs = channel_txs(tmpctx, &htlc_map, &wscripts, peer->channel,
			  &peer->current_per_commit[LOCAL], LOCAL);

	if (!derive_simple_key(&peer->channel->basepoints[REMOTE].payment,
			       &peer->current_per_commit[LOCAL],
			       &remotekey))
		status_failed(WIRE_CHANNEL_CRYPTO_FAILED,
			      "Deriving remotekey");

	/* BOLT #2:
	 *
	 * A receiving node MUST fail the channel if `signature` is not valid
	 * for its local commitment transaction once all pending updates are
	 * applied.
	 */
	if (!check_tx_sig(txs[0], 0, NULL, wscripts[0],
			  &peer->channel->funding_pubkey[REMOTE], &commit_sig))
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad commit_sig signature %s for tx %s wscript %s key %s",
			    type_to_string(msg, secp256k1_ecdsa_signature,
					   &commit_sig),
			    type_to_string(msg, struct bitcoin_tx, txs[0]),
			    tal_hex(msg, wscripts[0]),
			    type_to_string(msg, struct pubkey,
					   &peer->channel->funding_pubkey
					   [REMOTE]));

	/* BOLT #2:
	 *
	 * A receiving node MUST fail the channel if `num_htlcs` is not equal
	 * to the number of HTLC outputs in the local commitment transaction
	 * once all pending updates are applied.
	 */
	if (tal_count(htlc_sigs) != tal_count(txs) - 1)
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Expected %zu htlc sigs, not %zu",
			    tal_count(txs) - 1, tal_count(htlc_sigs));

	/* BOLT #2:
	 *
	 * A receiving node MUST fail
	 * the channel if any `htlc_signature` is not valid for the
	 * corresponding HTLC transaction.
	 */
	for (i = 0; i < tal_count(htlc_sigs); i++) {
		if (!check_tx_sig(txs[1+i], 0, NULL, wscripts[1+i],
				  &remotekey, &htlc_sigs[i]))
			peer_failed(io_conn_fd(peer->peer_conn),
				    &peer->pcs.cs,
				    &peer->channel_id,
				    WIRE_CHANNEL_PEER_BAD_MESSAGE,
				    "Bad commit_sig signature %s for htlc %s wscript %s key %s",
				    type_to_string(msg, secp256k1_ecdsa_signature, &htlc_sigs[i]),
				    type_to_string(msg, struct bitcoin_tx, txs[1+i]),
				    tal_hex(msg, wscripts[1+i]),
				    type_to_string(msg, struct pubkey, &remotekey));
	}

	status_trace("Received commit_sig with %zu htlc sigs",
		     tal_count(htlc_sigs));

	struct pubkey oldpoint = peer->old_per_commit[LOCAL], test;
	status_trace("Sending secret for point %"PRIu64" %s",
		     peer->commit_index[LOCAL]-1,
		     type_to_string(trc, struct pubkey,
				    &peer->old_per_commit[LOCAL]));

	peer->old_per_commit[LOCAL] = peer->current_per_commit[LOCAL];
	if (!next_per_commit_point(&peer->shaseed, &old_commit_secret,
				   &peer->current_per_commit[LOCAL],
				   peer->commit_index[LOCAL]))
		status_failed(WIRE_CHANNEL_CRYPTO_FAILED,
			      "Deriving next commit_point");

	pubkey_from_privkey((struct privkey *)&old_commit_secret, &test);
	if (!pubkey_eq(&test, &oldpoint))
		status_failed(WIRE_CHANNEL_CRYPTO_FAILED,
			      "Invalid secret %s for commit_point",
			      tal_hexstr(msg, &old_commit_secret,
					 sizeof(old_commit_secret)));

	peer->commit_index[LOCAL]++;

	/* If this queues more changes on the other end, send commit. */
	if (channel_sending_revoke_and_ack(peer->channel)) {
		status_trace("revoke_and_ack made pending: commit timer");
		start_commit_timer(peer);
	}

	msg = towire_revoke_and_ack(msg, &channel_id, &old_commit_secret,
				    &peer->current_per_commit[LOCAL]);
	msg_enqueue(&peer->peer_out, take(msg));
	tal_free(tmpctx);

	return peer_read_message(conn, &peer->pcs, peer_in);
}

static void their_htlc_locked(const struct htlc *htlc, struct peer *peer)
{
	tal_t *tmpctx = tal_tmpctx(peer);
	u8 *msg;
	struct onionpacket *op;
	struct sha256 bad_onion_sha;
	struct secret ss;
	enum onion_type failcode;
	enum channel_remove_err rerr;
	struct pubkey ephemeral;

	status_trace("their htlc %"PRIu64" locked", htlc->id);

	/* We unwrap the onion now. */
	/* FIXME: We could do this earlier and call HSM async, for speed. */
	op = parse_onionpacket(tmpctx, htlc->routing, TOTAL_PACKET_SIZE);
	if (!op) {
		/* FIXME: could be bad version, bad key. */
		failcode = WIRE_INVALID_ONION_VERSION;
		goto bad_onion;
	}

	/* Because wire takes struct pubkey. */
	ephemeral.pubkey = op->ephemeralkey;
	msg = towire_hsm_ecdh_req(tmpctx, &ephemeral);
	if (!wire_sync_write(HSM_FD, msg))
		status_failed(WIRE_CHANNEL_HSM_FAILED, "Writing ecdh req");
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg || !fromwire_hsm_ecdh_resp(msg, NULL, &ss))
		status_failed(WIRE_CHANNEL_HSM_FAILED, "Reading ecdh response");

	if (memeqzero(&ss, sizeof(ss))) {
		failcode = WIRE_INVALID_ONION_KEY;
		goto bad_onion;
	}

	/* Tell master to deal with it. */
	msg = towire_channel_accepted_htlc(tmpctx, htlc->id, htlc->msatoshi,
					   abs_locktime_to_blocks(&htlc->expiry),
					   &htlc->rhash,
					   &ss,
					   htlc->routing);
	daemon_conn_send(&peer->master, take(msg));
	tal_free(tmpctx);
	return;

bad_onion:
	sha256(&bad_onion_sha, htlc->routing, TOTAL_PACKET_SIZE);
	msg = towire_update_fail_malformed_htlc(tmpctx, &peer->channel_id,
						htlc->id, &bad_onion_sha,
						failcode);
	msg_enqueue(&peer->peer_out, take(msg));

	status_trace("htlc %"PRIu64" %s", htlc->id, onion_type_name(failcode));
	rerr = channel_fail_htlc(peer->channel, REMOTE, htlc->id);
	if (rerr != CHANNEL_ERR_REMOVE_OK)
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_INTERNAL_ERROR,
			    "Could not fail malformed htlc %"PRIu64": %u",
			    htlc->id, rerr);
	start_commit_timer(peer);
	tal_free(tmpctx);
}

static struct io_plan *handle_peer_revoke_and_ack(struct io_conn *conn,
						  struct peer *peer,
						  const u8 *msg)
{
	struct sha256 old_commit_secret;
	struct privkey privkey;
	struct channel_id channel_id;
	struct pubkey per_commit_point, next_per_commit;
	const struct htlc **changed_htlcs = tal_arr(msg, const struct htlc *, 0);

	if (!fromwire_revoke_and_ack(msg, NULL, &channel_id, &old_commit_secret,
				     &next_per_commit)) {
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad revoke_and_ack %s", tal_hex(msg, msg));
	}

	/* BOLT #2:
	 *
	 * A receiving node MUST check that `per_commitment_secret` generates
	 * the previous `per_commitment_point`, and MUST fail if it does
	 * not.
	 */
	memcpy(&privkey, &old_commit_secret, sizeof(privkey));
	if (!pubkey_from_privkey(&privkey, &per_commit_point)) {
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad privkey %s",
			    type_to_string(msg, struct privkey, &privkey));
	}
	if (!pubkey_eq(&per_commit_point, &peer->old_per_commit[REMOTE])) {
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Wrong privkey %s for %s",
			    type_to_string(msg, struct privkey, &privkey),
			    type_to_string(msg, struct pubkey,
					   &peer->old_per_commit[REMOTE]));
	}

	/* BOLT #2:
	 *
	 * A receiving node MAY fail if the `per_commitment_secret` was not
	 * generated by the protocol in [BOLT #3]
	 */
	if (!shachain_add_hash(&peer->their_shachain,
			       shachain_index(peer->commit_index[REMOTE]),
			       &old_commit_secret)) {
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad shachain for privkey %"PRIu64" %s ",
			    peer->commit_index[REMOTE],
			    type_to_string(msg, struct privkey, &privkey));
	}
	peer->commit_index[REMOTE]++;
	peer->old_per_commit[REMOTE] = peer->current_per_commit[REMOTE];
	peer->current_per_commit[REMOTE] = next_per_commit;

	/* We start timer even if this returns false: we might have delayed
	 * commit because we were waiting for this! */
	if (channel_rcvd_revoke_and_ack(peer->channel, &changed_htlcs))
		status_trace("Commits outstanding after recv revoke_and_ack");
	else
		status_trace("No commits outstanding after recv revoke_and_ack");

	/* Tell master about locked-in htlcs. */
	for (size_t i = 0; i < tal_count(changed_htlcs); i++) {
		if (changed_htlcs[i]->state == RCVD_ADD_ACK_REVOCATION) {
			their_htlc_locked(changed_htlcs[i], peer);
		}
	}

	start_commit_timer(peer);
	return peer_read_message(conn, &peer->pcs, peer_in);
}

static struct io_plan *handle_peer_fulfill_htlc(struct io_conn *conn,
						struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 id;
	struct preimage preimage;
	enum channel_remove_err e;

	if (!fromwire_update_fulfill_htlc(msg, NULL, &channel_id,
					  &id, &preimage)) {
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad update_fulfill_htlc %s", tal_hex(msg, msg));
	}

	e = channel_fulfill_htlc(peer->channel, LOCAL, id, &preimage);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK:
		msg = towire_channel_fulfilled_htlc(msg, id, &preimage);
		daemon_conn_send(&peer->master, take(msg));
		start_commit_timer(peer);
		return peer_read_message(conn, &peer->pcs, peer_in);
	/* These shouldn't happen, because any offered HTLC (which would give
	 * us the preimage) should have timed out long before.  If we
	 * were to get preimages from other sources, this could happen. */
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad update_fulfill_htlc: failed to fulfill %"
			    PRIu64 " error %u", id, e);
	}
	abort();
}

static struct io_plan *handle_peer_fail_htlc(struct io_conn *conn,
					     struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 id;
	enum channel_remove_err e;
	u8 *reason;

	if (!fromwire_update_fail_htlc(msg, msg, NULL,
				       &channel_id, &id, &reason)) {
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad update_fulfill_htlc %s", tal_hex(msg, msg));
	}

	e = channel_fail_htlc(peer->channel, LOCAL, id);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK:
		msg = towire_channel_failed_htlc(msg, id, reason);
		daemon_conn_send(&peer->master, take(msg));
		start_commit_timer(peer);
		return peer_read_message(conn, &peer->pcs, peer_in);
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad update_fail_htlc: failed to remove %"
			    PRIu64 " error %u", id, e);
	}
	abort();
}

static struct io_plan *handle_peer_fail_malformed_htlc(struct io_conn *conn,
						       struct peer *peer,
						       const u8 *msg)
{
	struct channel_id channel_id;
	u64 id;
	enum channel_remove_err e;
	struct sha256 sha256_of_onion;
	u16 failcode;

	if (!fromwire_update_fail_malformed_htlc(msg, NULL, &channel_id, &id,
						 &sha256_of_onion, &failcode)) {
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad update_fail_malformed_htlc %s",
			    tal_hex(msg, msg));
	}

	e = channel_fail_htlc(peer->channel, LOCAL, id);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK:
		msg = towire_channel_malformed_htlc(msg, id, &sha256_of_onion,
						    failcode);
		daemon_conn_send(&peer->master, take(msg));
		start_commit_timer(peer);
		return peer_read_message(conn, &peer->pcs, peer_in);
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad update_fail_malformed_htlc: failed to remove %"
			    PRIu64 " error %u", id, e);
	}
	abort();
}

static struct io_plan *handle_ping(struct io_conn *conn,
				   struct peer *peer, const u8 *msg)
{
	u8 *pong;

	if (!check_ping_make_pong(peer, msg, &pong))
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad ping");

	status_trace("Got ping, sending %s", pong ?
		     wire_type_name(fromwire_peektype(pong))
		     : "nothing");

	if (pong)
		msg_enqueue(&peer->peer_out, take(pong));
	return peer_read_message(conn, &peer->pcs, peer_in);
}

static struct io_plan *handle_pong(struct io_conn *conn,
				   struct peer *peer, const u8 *pong)
{
	u8 *ignored;

	status_trace("Got pong!");
	if (!fromwire_pong(pong, pong, NULL, &ignored))
		status_failed(WIRE_CHANNEL_PEER_READ_FAILED, "Bad pong");

	if (!peer->num_pings_outstanding)
		status_failed(WIRE_CHANNEL_PEER_READ_FAILED, "Unexpected pong");

	peer->num_pings_outstanding--;
	daemon_conn_send(&peer->master,
			 take(towire_channel_ping_reply(pong, tal_len(pong))));
	return peer_read_message(conn, &peer->pcs, peer_in);
}

static struct io_plan *peer_in(struct io_conn *conn, struct peer *peer, u8 *msg)
{
	enum wire_type type = fromwire_peektype(msg);
	status_trace("peer_in %s", wire_type_name(type));

	/* Must get funding_locked before almost anything. */
	if (!peer->funding_locked[REMOTE]) {
		/* We can get gossip before funding, too */
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
		return handle_peer_funding_locked(conn, peer, msg);
	case WIRE_ANNOUNCEMENT_SIGNATURES:
		return handle_peer_announcement_signatures(conn, peer, msg);
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
	case WIRE_NODE_ANNOUNCEMENT:
		/* Forward to gossip daemon */
		daemon_conn_send(&peer->gossip_client, msg);
		return peer_read_message(conn, &peer->pcs, peer_in);
	case WIRE_UPDATE_ADD_HTLC:
		return handle_peer_add_htlc(conn, peer, msg);
	case WIRE_COMMITMENT_SIGNED:
		return handle_peer_commit_sig(conn, peer, msg);
	case WIRE_REVOKE_AND_ACK:
		return handle_peer_revoke_and_ack(conn, peer, msg);
	case WIRE_UPDATE_FULFILL_HTLC:
		return handle_peer_fulfill_htlc(conn, peer, msg);
	case WIRE_UPDATE_FAIL_HTLC:
		return handle_peer_fail_htlc(conn, peer, msg);
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
		return handle_peer_fail_malformed_htlc(conn, peer, msg);
	case WIRE_PING:
		return handle_ping(conn, peer, msg);
	case WIRE_PONG:
		return handle_pong(conn, peer, msg);

	case WIRE_INIT:
	case WIRE_ERROR:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_CHANNEL_REESTABLISH:
		goto badmessage;

	case WIRE_SHUTDOWN:
	case WIRE_CLOSING_SIGNED:
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
}

static struct io_plan *setup_peer_conn(struct io_conn *conn, struct peer *peer)
{
	return io_duplex(conn, peer_read_message(conn, &peer->pcs, peer_in),
			 peer_out(conn, peer));
}

static void peer_conn_broken(struct io_conn *conn, struct peer *peer)
{
	/* If we have signatures, send an update to say we're disabled. */
	if (peer->have_sigs[LOCAL] && peer->have_sigs[REMOTE]) {
		send_channel_update(peer, true);

		/* Make sure gossipd actually gets this message before dying */
		daemon_conn_sync_flush(&peer->gossip_client);
	}
	status_failed(WIRE_CHANNEL_PEER_READ_FAILED,
		      "peer connection broken: %s", strerror(errno));
}

static void init_channel(struct peer *peer, const u8 *msg)
{
	struct privkey seed;
	struct basepoints points[NUM_SIDES];
	u64 funding_satoshi, push_msat;
	u16 funding_txout;
	struct pubkey funding_pubkey[NUM_SIDES];
	struct sha256_double funding_txid;
	bool am_funder;
	u8 *funding_signed;

	if (!fromwire_channel_init(msg, msg, NULL,
				   &funding_txid, &funding_txout,
				   &peer->conf[LOCAL], &peer->conf[REMOTE],
				   &peer->their_commit_sig,
				   &peer->pcs.cs,
				   &funding_pubkey[REMOTE],
				   &points[REMOTE].revocation,
				   &points[REMOTE].payment,
				   &points[REMOTE].delayed_payment,
				   &peer->old_per_commit[REMOTE],
				   &am_funder,
				   &peer->fee_base,
				   &peer->fee_per_satoshi,
				   &funding_satoshi, &push_msat,
				   &seed,
				   &peer->node_ids[LOCAL],
				   &peer->node_ids[REMOTE],
				   &peer->commit_msec,
				   &peer->cltv_delta,
				   &funding_signed))
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "Init: %s",
			      tal_hex(msg, msg));

	/* channel_id is set from funding txout */
	derive_channel_id(&peer->channel_id, &funding_txid, funding_txout);

	/* We derive everything from the one secret seed. */
	derive_basepoints(&seed, &funding_pubkey[LOCAL], &points[LOCAL],
			  &peer->our_secrets, &peer->shaseed,
			  &peer->old_per_commit[LOCAL],
			  peer->commit_index[LOCAL]);
	status_trace("First per_commit_point = %s",
		     type_to_string(trc, struct pubkey,
				    &peer->old_per_commit[LOCAL]));

	peer->channel = new_channel(peer, &funding_txid, funding_txout,
				    funding_satoshi, push_msat, peer->fee_base,
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

	/* If we have a funding_signed message, we send that immediately */
	if (tal_len(funding_signed) != 0)
		msg_enqueue(&peer->peer_out, take(funding_signed));
}

static void handle_funding_locked(struct peer *peer, const u8 *msg)
{
	if (!fromwire_channel_funding_locked(msg, NULL,
					     &peer->short_channel_ids[LOCAL]))
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "%s", tal_hex(msg, msg));

	next_per_commit_point(&peer->shaseed, NULL,
			      &peer->current_per_commit[LOCAL],
			      peer->commit_index[LOCAL]++);

	msg = towire_funding_locked(peer,
				    &peer->channel_id,
				    &peer->current_per_commit[LOCAL]);
	msg_enqueue(&peer->peer_out, take(msg));
	peer->funding_locked[LOCAL] = true;

	if (peer->funding_locked[REMOTE]) {
		daemon_conn_send(&peer->master,
				 take(towire_channel_normal_operation(peer)));
	}
}

static void handle_funding_announce_depth(struct peer *peer, const u8 *msg)
{
	status_trace("Exchanging announcement signatures.");
	send_announcement_signatures(peer);

	/* Only send the announcement and update if the other end gave
	 * us its sig */
	if (peer->have_sigs[REMOTE]) {
		send_channel_announcement(peer);
		send_channel_update(peer, false);
		/* Tell the master that we just announced the channel,
		 * so it may announce the node */
		daemon_conn_send(&peer->master, take(towire_channel_announced(msg)));
	}
}

static void handle_offer_htlc(struct peer *peer, const u8 *inmsg)
{
	u8 *msg;
	u32 cltv_expiry;
	u64 amount_msat;
	struct sha256 payment_hash;
	u8 onion_routing_packet[TOTAL_PACKET_SIZE];
	enum channel_add_err e;
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

	e = channel_add_htlc(peer->channel, LOCAL, peer->htlc_id,
			     amount_msat, cltv_expiry, &payment_hash,
			     onion_routing_packet);
	status_trace("Adding HTLC %"PRIu64" gave %i", peer->htlc_id, e);

	switch (e) {
	case CHANNEL_ERR_ADD_OK:
		/* Tell the peer. */
		msg = towire_update_add_htlc(peer, &peer->channel_id,
					     peer->htlc_id, amount_msat,
					     &payment_hash, cltv_expiry,
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
	enum channel_remove_err e;

	if (!fromwire_channel_fail_htlc(inmsg, inmsg, NULL, &id, &errpkt))
		status_failed(WIRE_CHANNEL_BAD_COMMAND,
			      "Invalid channel_fail_htlc");

	e = channel_fail_htlc(peer->channel, REMOTE, id);
	switch (e) {
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
			      "HTLC %"PRIu64" removal failed: %i", id, e);
	}
	abort();
}

static void handle_ping_cmd(struct peer *peer, const u8 *inmsg)
{
	u16 num_pong_bytes, ping_len;
	u8 *ping;

	if (!fromwire_channel_ping(inmsg, NULL, &num_pong_bytes, &ping_len))
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "Bad channel_ping");

	ping = make_ping(peer, num_pong_bytes, ping_len);
	if (tal_len(ping) > 65535)
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "Oversize channel_ping");

	msg_enqueue(&peer->peer_out, take(ping));

	status_trace("sending ping expecting %sresponse",
		     num_pong_bytes >= 65532 ? "no " : "");

	/* BOLT #1:
	 *
	 * if `num_pong_bytes` is less than 65532 it MUST respond by sending a
	 * `pong` message with `byteslen` equal to `num_pong_bytes`, otherwise
	 * it MUST ignore the `ping`.
	 */
	if (num_pong_bytes >= 65532)
		daemon_conn_send(&peer->master,
				 take(towire_channel_ping_reply(peer, 0)));
	else
		peer->num_pings_outstanding++;
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
		case WIRE_CHANNEL_PING:
			handle_ping_cmd(peer, master->msg_in);
			goto out;

		case WIRE_CHANNEL_BAD_COMMAND:
		case WIRE_CHANNEL_HSM_FAILED:
		case WIRE_CHANNEL_CRYPTO_FAILED:
		case WIRE_CHANNEL_GOSSIP_BAD_MESSAGE:
		case WIRE_CHANNEL_INTERNAL_ERROR:
		case WIRE_CHANNEL_PEER_WRITE_FAILED:
		case WIRE_CHANNEL_PEER_READ_FAILED:
		case WIRE_CHANNEL_NORMAL_OPERATION:
		case WIRE_CHANNEL_INIT:
		case WIRE_CHANNEL_OFFER_HTLC_REPLY:
		case WIRE_CHANNEL_ACCEPTED_HTLC:
		case WIRE_CHANNEL_FULFILLED_HTLC:
		case WIRE_CHANNEL_FAILED_HTLC:
		case WIRE_CHANNEL_MALFORMED_HTLC:
		case WIRE_CHANNEL_PING_REPLY:
		case WIRE_CHANNEL_PEER_BAD_MESSAGE:
		case WIRE_CHANNEL_ANNOUNCED:
			break;
		}
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "%u %s", t,
			      channel_wire_type_name(t));
	}

out:
	return daemon_conn_read_next(conn, master);
}

#ifndef TESTING
static void master_gone(struct io_conn *unused, struct daemon_conn *dc)
{
	/* Can't tell master, it's gone. */
	exit(2);
}

static void gossip_gone(struct io_conn *unused, struct daemon_conn *dc)
{
	status_failed(WIRE_CHANNEL_GOSSIP_BAD_MESSAGE,
		      "Gossip connection closed");
}

int main(int argc, char *argv[])
{
	struct peer *peer = tal(NULL, struct peer);
	int i;

	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	subdaemon_debug(argc, argv);

	/* We handle write returning errors! */
	signal(SIGCHLD, SIG_IGN);
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	daemon_conn_init(peer, &peer->master, REQ_FD, req_in, master_gone);
	peer->channel = NULL;
	peer->htlc_id = 0;
	peer->num_pings_outstanding = 0;
	timers_init(&peer->timers, time_mono());
	peer->commit_timer = NULL;
	peer->commit_index[LOCAL] = peer->commit_index[REMOTE] = 0;
	peer->have_sigs[LOCAL] = peer->have_sigs[REMOTE] = false;

	/* We send these to HSM to get real signatures; don't have valgrind
	 * complain. */
	for (i = 0; i < NUM_SIDES; i++) {
		memset(&peer->announcement_node_sigs[i], 0,
		       sizeof(peer->announcement_node_sigs[i]));
		memset(&peer->announcement_bitcoin_sigs[i], 0,
		       sizeof(peer->announcement_bitcoin_sigs[i]));
	}

	shachain_init(&peer->their_shachain);

	status_setup_async(&peer->master);
	msg_queue_init(&peer->peer_out, peer);

	daemon_conn_init(peer, &peer->gossip_client, GOSSIP_FD,
			 gossip_client_recv, gossip_gone);

	init_peer_crypto_state(peer, &peer->pcs);
	peer->funding_locked[LOCAL] = peer->funding_locked[REMOTE] = false;

	for (;;) {
		struct timer *expired = NULL;
		io_loop(&peer->timers, &expired);

		if (!expired)
			break;
		timer_expired(peer, expired);
	}

	tal_free(peer);
	return 0;
}
#endif /* TESTING */
