#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/cast/cast.h>
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
#include <wire/peer_wire.h>
#include <wire/wire.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

/* stdin == requests, 3 == peer, 4 = gossip, 5 = HSM */
#define REQ_FD STDIN_FILENO
#define PEER_FD 3
#define GOSSIP_FD 4
#define HSM_FD 5

struct commit_sigs {
	struct peer *peer;
	secp256k1_ecdsa_signature commit_sig;
	secp256k1_ecdsa_signature *htlc_sigs;
};

struct peer {
	struct peer_crypto_state pcs;
	struct channel_config conf[NUM_SIDES];
	bool funding_locked[NUM_SIDES];
	u64 next_index[NUM_SIDES];

	/* Remote's current per-commit point. */
	struct pubkey remote_per_commit;

	/* Remotes's last per-commitment point: we keep this to check
	 * revoke_and_ack's `per_commitment_secret` is correct. */
	struct pubkey old_remote_per_commit;

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

	/* If we're waiting for a specific reply, defer other messages. */
	enum channel_wire_type master_reply_type;
	void (*handle_master_reply)(struct peer *peer, const u8 *msg);
	struct msg_queue master_deferred;

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

	/* We save calculated commit sigs while waiting for master approval */
	struct commit_sigs *next_commit_sigs;

	/* If master told us to shut down, this contains scriptpubkey until
	 * we're ready to send it. */
	u8 *unsent_shutdown_scriptpubkey;

	/* Information used for reestablishment. */
	bool last_was_revoke;
	struct changed_htlc *last_sent_commit;
	u64 revocations_received;
};

static u8 *create_channel_announcement(const tal_t *ctx, struct peer *peer);
static void start_commit_timer(struct peer *peer);

/* Returns a pointer to the new end */
static void *tal_arr_append_(void **p, size_t size)
{
	size_t n = tal_len(*p) / size;
	tal_resize_(p, size, n+1, false);
	return (char *)(*p) + n * size;
}
#define tal_arr_append(p) tal_arr_append_((void **)(p), sizeof(**(p)))

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

	/* BOLT #2:
	 *
	 * On reconnection, a node MUST ignore a redundant `funding_locked` if
	 * it receives one.
	 */
	if (peer->funding_locked[REMOTE])
		return peer_read_message(conn, &peer->pcs, peer_in);

	peer->old_remote_per_commit = peer->remote_per_commit;
	if (!fromwire_funding_locked(msg, NULL, &chanid,
				     &peer->remote_per_commit))
		status_failed(WIRE_CHANNEL_PEER_BAD_MESSAGE,
			      "Bad funding_locked %s", tal_hex(msg, msg));

	if (!structeq(&chanid, &peer->channel_id))
		status_failed(WIRE_CHANNEL_PEER_BAD_MESSAGE,
			      "Wrong channel id in %s", tal_hex(trc, msg));

	peer->funding_locked[REMOTE] = true;
	daemon_conn_send(&peer->master,
			 take(towire_channel_got_funding_locked(peer,
						&peer->remote_per_commit)));

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

static struct changed_htlc *changed_htlc_arr(const tal_t *ctx,
					     const struct htlc **changed_htlcs)
{
	struct changed_htlc *changed;
	size_t i;

	changed = tal_arr(ctx, struct changed_htlc, tal_count(changed_htlcs));
	for (i = 0; i < tal_count(changed_htlcs); i++) {
		changed[i].id = changed_htlcs[i]->id;
		changed[i].newstate = changed_htlcs[i]->state;
	}
	return changed;
}

static u8 *sending_commitsig_msg(const tal_t *ctx,
				 u64 remote_commit_index,
				 const struct htlc **changed_htlcs,
				 const secp256k1_ecdsa_signature *commit_sig,
				 const secp256k1_ecdsa_signature *htlc_sigs)
{
	const tal_t *tmpctx = tal_tmpctx(ctx);
	struct changed_htlc *changed;
	u8 *msg;

	/* We tell master what (of our) HTLCs peer will now be
	 * committed to. */
	changed = changed_htlc_arr(tmpctx, changed_htlcs);
	msg = towire_channel_sending_commitsig(ctx, remote_commit_index,
					       changed, commit_sig, htlc_sigs);
	tal_free(tmpctx);
	return msg;
}

/* BOLT #2:
 *
 * A node MUST NOT send a `shutdown` if there are updates pending on
 * the receiving node's commitment transaction.
 */
/* So we only call this after reestablish or immediately after sending commit */
static void maybe_send_shutdown(struct peer *peer)
{
	u8 *msg;

	if (!peer->unsent_shutdown_scriptpubkey)
		return;

	msg = towire_shutdown(peer, &peer->channel_id,
			      peer->unsent_shutdown_scriptpubkey);
	msg_enqueue(&peer->peer_out, take(msg));
	peer->unsent_shutdown_scriptpubkey
		= tal_free(peer->unsent_shutdown_scriptpubkey);
}

/* Master has acknowledged that we're sending commitment, so send it. */
static void handle_sending_commitsig_reply(struct peer *peer, const u8 *msg)
{
	status_trace("Sending commit_sig with %zu htlc sigs",
		     tal_count(peer->next_commit_sigs->htlc_sigs));

	peer->next_index[REMOTE]++;

	msg = towire_commitment_signed(peer, &peer->channel_id,
				       &peer->next_commit_sigs->commit_sig,
				       peer->next_commit_sigs->htlc_sigs);
	msg_enqueue(&peer->peer_out, take(msg));
	peer->next_commit_sigs = tal_free(peer->next_commit_sigs);

	maybe_send_shutdown(peer);

	/* Timer now considered expired, you can add a new one. */
	peer->commit_timer = NULL;
	start_commit_timer(peer);
}

/* This blocks other traffic from the master until we get reply. */
static void master_sync_reply(struct peer *peer, const u8 *msg,
			      enum channel_wire_type replytype,
			      void (*handle)(struct peer *peer, const u8 *msg))
{
	assert(!peer->handle_master_reply);

	peer->handle_master_reply = handle;
	peer->master_reply_type = replytype;

	daemon_conn_send(&peer->master, msg);
}

static struct commit_sigs *calc_commitsigs(const tal_t *ctx,
					   const struct peer *peer,
					   u64 commit_index)
{
	const tal_t *tmpctx = tal_tmpctx(ctx);
	size_t i;
	struct bitcoin_tx **txs;
	const u8 **wscripts;
	const struct htlc **htlc_map;
	struct pubkey localkey;
	struct privkey local_secretkey;
	struct commit_sigs *commit_sigs = tal(ctx, struct commit_sigs);

	if (!derive_simple_privkey(&peer->our_secrets.payment_basepoint_secret,
				   &peer->channel->basepoints[LOCAL].payment,
				   &peer->remote_per_commit,
				   &local_secretkey))
		status_failed(WIRE_CHANNEL_CRYPTO_FAILED,
			      "Deriving local_secretkey");

	if (!derive_simple_key(&peer->channel->basepoints[LOCAL].payment,
			       &peer->remote_per_commit,
			       &localkey))
		status_failed(WIRE_CHANNEL_CRYPTO_FAILED,
			      "Deriving localkey");

	status_trace("Derived key %s from basepoint %s, point %s",
		     type_to_string(trc, struct pubkey, &localkey),
		     type_to_string(trc, struct pubkey,
				    &peer->channel->basepoints[LOCAL].payment),
		     type_to_string(trc, struct pubkey,
				    &peer->remote_per_commit));

	txs = channel_txs(tmpctx, &htlc_map, &wscripts, peer->channel,
			  &peer->remote_per_commit,
			  commit_index,
			  REMOTE);

	sign_tx_input(txs[0], 0, NULL,
		      wscripts[0],
		      &peer->our_secrets.funding_privkey,
		      &peer->channel->funding_pubkey[LOCAL],
		      &commit_sigs->commit_sig);

	status_trace("Creating commit_sig signature %"PRIu64" %s for tx %s wscript %s key %s",
		     commit_index,
		     type_to_string(trc, secp256k1_ecdsa_signature,
				    &commit_sigs->commit_sig),
		     type_to_string(trc, struct bitcoin_tx, txs[0]),
		     tal_hex(trc, wscripts[0]),
		     type_to_string(trc, struct pubkey,
				    &peer->channel->funding_pubkey[LOCAL]));
	dump_htlcs(peer->channel, "Sending commit_sig");

	/* BOLT #2:
	 *
	 * A node MUST include one `htlc_signature` for every HTLC transaction
	 * corresponding to BIP69 lexicographic ordering of the commitment
	 * transaction.
	 */
	commit_sigs->htlc_sigs = tal_arr(commit_sigs, secp256k1_ecdsa_signature,
					 tal_count(txs) - 1);

	for (i = 0; i < tal_count(commit_sigs->htlc_sigs); i++) {
		sign_tx_input(txs[1 + i], 0,
			      NULL,
			      wscripts[1 + i],
			      &local_secretkey, &localkey,
			      &commit_sigs->htlc_sigs[i]);
		status_trace("Creating HTLC signature %s for tx %s wscript %s key %s",
			     type_to_string(trc, secp256k1_ecdsa_signature,
					    &commit_sigs->htlc_sigs[i]),
			     type_to_string(trc, struct bitcoin_tx, txs[1+i]),
			     tal_hex(trc, wscripts[1+i]),
			     type_to_string(trc, struct pubkey, &localkey));
		assert(check_tx_sig(txs[1+i], 0, NULL, wscripts[1+i],
				    &localkey, &commit_sigs->htlc_sigs[i]));
	}

	tal_free(tmpctx);
	return commit_sigs;
}

static void send_commit(struct peer *peer)
{
	tal_t *tmpctx = tal_tmpctx(peer);
	u8 *msg;
	const struct htlc **changed_htlcs;

	/* FIXME: Document this requirement in BOLT 2! */
	/* We can't send two commits in a row. */
	if (channel_awaiting_revoke_and_ack(peer->channel)
	    || peer->handle_master_reply) {
		status_trace("Can't send commit: waiting for revoke_and_ack %s",
			     peer->handle_master_reply ? "processing" : "reply");
		/* Mark this as done and try again. */
		peer->commit_timer = NULL;
		start_commit_timer(peer);
		tal_free(tmpctx);
		return;
	}

	/* BOLT #2:
	 *
	 * A node MUST NOT send a `commitment_signed` message which does not
	 * include any updates.
	 */
	changed_htlcs = tal_arr(tmpctx, const struct htlc *, 0);
	if (!channel_sending_commit(peer->channel, &changed_htlcs)) {
		status_trace("Can't send commit: nothing to send");

		/* Covers the case where we've just been told to shutdown. */
		maybe_send_shutdown(peer);

		peer->commit_timer = NULL;
		tal_free(tmpctx);
		return;
	}

	peer->next_commit_sigs = calc_commitsigs(peer, peer,
						 peer->next_index[REMOTE]);

	status_trace("Telling master we're about to commit...");
	/* Tell master to save this next commit to database, then wait. */
	msg = sending_commitsig_msg(tmpctx, peer->next_index[REMOTE],
				    changed_htlcs,
				    &peer->next_commit_sigs->commit_sig,
				    peer->next_commit_sigs->htlc_sigs);
	master_sync_reply(peer, take(msg),
			  WIRE_CHANNEL_SENDING_COMMITSIG_REPLY,
			  handle_sending_commitsig_reply);
	tal_free(tmpctx);
}

static void start_commit_timer(struct peer *peer)
{
	/* Already armed? */
	if (peer->commit_timer) {
		status_trace("Commit timer already running...");
		return;
	}

	peer->commit_timer = new_reltimer(&peer->timers, peer,
					  time_from_msec(peer->commit_msec),
					  send_commit, peer);
}

static u8 *make_revocation_msg(const struct peer *peer, u64 revoke_index)
{
	struct pubkey oldpoint, point;
	struct sha256 old_commit_secret;

	/* Get secret. */
	per_commit_secret(&peer->shaseed, &old_commit_secret, revoke_index);

	/* Sanity check that it corresponds to the point we sent. */
	pubkey_from_privkey((struct privkey *)&old_commit_secret, &point);
	if (!per_commit_point(&peer->shaseed, &oldpoint, revoke_index))
		status_failed(WIRE_CHANNEL_CRYPTO_FAILED,
			      "Invalid point %"PRIu64" for commit_point",
			      revoke_index);

	status_trace("Sending revocation #%"PRIu64" for %s",
		     revoke_index,
		     type_to_string(trc, struct pubkey, &oldpoint));

	if (!pubkey_eq(&point, &oldpoint))
		status_failed(WIRE_CHANNEL_CRYPTO_FAILED,
			      "Invalid secret %s for commit_point",
			      tal_hexstr(trc, &old_commit_secret,
					 sizeof(old_commit_secret)));

	/* We're revoking N-1th commit, sending N+1th point. */
	if (!per_commit_point(&peer->shaseed, &point, revoke_index+2))
		status_failed(WIRE_CHANNEL_CRYPTO_FAILED,
			      "Deriving next commit_point");

	return towire_revoke_and_ack(peer, &peer->channel_id, &old_commit_secret,
				     &point);
}

/* We come back here once master has acked the commit_sig we received */
static struct io_plan *send_revocation(struct io_conn *conn, struct peer *peer)
{
	/* Revoke previous commit. */
	u8 *msg = make_revocation_msg(peer, peer->next_index[LOCAL]-1);

	/* From now on we apply changes to the next commitment */
	peer->next_index[LOCAL]++;

	/* If this queues more changes on the other end, send commit. */
	if (channel_sending_revoke_and_ack(peer->channel)) {
		status_trace("revoke_and_ack made pending: commit timer");
		start_commit_timer(peer);
	}

	msg_enqueue(&peer->peer_out, take(msg));

	return peer_read_message(conn, &peer->pcs, peer_in);
}

/* FIXME: We could do this earlier and call HSM async, for speed. */
static void get_shared_secret(const struct htlc *htlc,
			      struct secret *shared_secret)
{
	tal_t *tmpctx = tal_tmpctx(htlc);
	struct pubkey ephemeral;
	struct onionpacket *op;
	u8 *msg;

	/* We unwrap the onion now. */
	op = parse_onionpacket(tmpctx, htlc->routing, TOTAL_PACKET_SIZE);
	if (!op) {
		/* Return an invalid shared secret. */
		memset(shared_secret, 0, sizeof(*shared_secret));
		tal_free(tmpctx);
		return;
	}

	/* Because wire takes struct pubkey. */
	ephemeral.pubkey = op->ephemeralkey;
	msg = towire_hsm_ecdh_req(tmpctx, &ephemeral);
	if (!wire_sync_write(HSM_FD, msg))
		status_failed(WIRE_CHANNEL_HSM_FAILED, "Writing ecdh req");
	msg = wire_sync_read(tmpctx, HSM_FD);
	/* Gives all-zero shares_secret if it was invalid. */
	if (!msg || !fromwire_hsm_ecdh_resp(msg, NULL, shared_secret))
		status_failed(WIRE_CHANNEL_HSM_FAILED, "Reading ecdh response");
	tal_free(tmpctx);
}

static u8 *got_commitsig_msg(const tal_t *ctx,
			     u64 local_commit_index,
			     const secp256k1_ecdsa_signature *commit_sig,
			     const secp256k1_ecdsa_signature *htlc_sigs,
			     const struct htlc **changed_htlcs)
{
	const tal_t *tmpctx = tal_tmpctx(ctx);
	struct changed_htlc *changed;
	struct fulfilled_htlc *fulfilled;
	struct failed_htlc *failed;
	struct added_htlc *added;
	struct secret *shared_secret;
	u8 *msg;

	changed = tal_arr(tmpctx, struct changed_htlc, 0);
	added = tal_arr(tmpctx, struct added_htlc, 0);
	shared_secret = tal_arr(tmpctx, struct secret, 0);
	failed = tal_arr(tmpctx, struct failed_htlc, 0);
	fulfilled = tal_arr(tmpctx, struct fulfilled_htlc, 0);

	for (size_t i = 0; i < tal_count(changed_htlcs); i++) {
		const struct htlc *htlc = changed_htlcs[i];
		if (htlc->state == RCVD_ADD_COMMIT) {
			struct added_htlc *a = tal_arr_append(&added);
			struct secret *s = tal_arr_append(&shared_secret);
			a->id = htlc->id;
			a->amount_msat = htlc->msatoshi;
			a->payment_hash = htlc->rhash;
			a->cltv_expiry = abs_locktime_to_blocks(&htlc->expiry);
			memcpy(a->onion_routing_packet,
			       htlc->routing,
			       sizeof(a->onion_routing_packet));
			get_shared_secret(htlc, s);
		} else if (htlc->state == RCVD_REMOVE_COMMIT) {
			if (htlc->r) {
				struct fulfilled_htlc *f;
				assert(!htlc->fail);
				f = tal_arr_append(&fulfilled);
				f->id = htlc->id;
				f->payment_preimage = *htlc->r;
			} else {
				struct failed_htlc *f;
				assert(htlc->fail);
				f = tal_arr_append(&failed);
				f->id = htlc->id;
				f->malformed = htlc->malformed;
				f->failreason = cast_const(u8 *, htlc->fail);
			}
		} else {
			struct changed_htlc *c = tal_arr_append(&changed);
			assert(htlc->state == RCVD_REMOVE_ACK_COMMIT
			       || htlc->state == RCVD_ADD_ACK_COMMIT);

			c->id = htlc->id;
			c->newstate = htlc->state;
		}
	}

	msg = towire_channel_got_commitsig(ctx, local_commit_index,
					   commit_sig,
					   htlc_sigs,
					   added,
					   shared_secret,
					   fulfilled,
					   failed,
					   changed);
	tal_free(tmpctx);
	return msg;
}

/* Tell peer to continue now master has replied. */
static void handle_reply_wake_peer(struct peer *peer, const u8 *msg)
{
	io_wake(peer);
}

static struct io_plan *handle_peer_commit_sig(struct io_conn *conn,
					      struct peer *peer, const u8 *msg)
{
	const tal_t *tmpctx = tal_tmpctx(peer);
	struct channel_id channel_id;
	secp256k1_ecdsa_signature commit_sig, *htlc_sigs;
	struct pubkey remotekey, point;
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

	if (!per_commit_point(&peer->shaseed, &point,
			      peer->next_index[LOCAL]))
		status_failed(WIRE_CHANNEL_CRYPTO_FAILED,
			      "Deriving per_commit_point for %"PRIu64,
			      peer->next_index[LOCAL]);

	txs = channel_txs(tmpctx, &htlc_map, &wscripts, peer->channel,
			  &point, peer->next_index[LOCAL], LOCAL);

	if (!derive_simple_key(&peer->channel->basepoints[REMOTE].payment,
			       &point, &remotekey))
		status_failed(WIRE_CHANNEL_CRYPTO_FAILED,
			      "Deriving remotekey");
	status_trace("Derived key %s from basepoint %s, point %s",
		     type_to_string(trc, struct pubkey, &remotekey),
		     type_to_string(trc, struct pubkey,
				    &peer->channel->basepoints[REMOTE].payment),
		     type_to_string(trc, struct pubkey, &point));
	/* BOLT #2:
	 *
	 * A receiving node MUST fail the channel if `signature` is not valid
	 * for its local commitment transaction once all pending updates are
	 * applied.
	 */
	if (!check_tx_sig(txs[0], 0, NULL, wscripts[0],
			  &peer->channel->funding_pubkey[REMOTE], &commit_sig)) {
		dump_htlcs(peer->channel, "receiving commit_sig");
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad commit_sig signature %"PRIu64" %s for tx %s wscript %s key %s",
			    peer->next_index[LOCAL],
			    type_to_string(msg, secp256k1_ecdsa_signature,
					   &commit_sig),
			    type_to_string(msg, struct bitcoin_tx, txs[0]),
			    tal_hex(msg, wscripts[0]),
			    type_to_string(msg, struct pubkey,
					   &peer->channel->funding_pubkey
					   [REMOTE]));
	}

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

	/* Tell master daemon, then wait for ack. */
	msg = got_commitsig_msg(tmpctx, peer->next_index[LOCAL], &commit_sig,
				htlc_sigs, changed_htlcs);

	master_sync_reply(peer, take(msg),
			  WIRE_CHANNEL_GOT_COMMITSIG_REPLY,
			  handle_reply_wake_peer);

	/* And peer waits for reply. */
	return io_wait(conn, peer, send_revocation, peer);
}

static u8 *got_revoke_msg(const tal_t *ctx, u64 revoke_num,
			  const struct sha256 *per_commitment_secret,
			  const struct pubkey *next_per_commit_point,
			  const struct htlc **changed_htlcs)
{
	tal_t *tmpctx = tal_tmpctx(ctx);
	u8 *msg;
	struct changed_htlc *changed = tal_arr(tmpctx, struct changed_htlc, 0);

	for (size_t i = 0; i < tal_count(changed_htlcs); i++) {
		struct changed_htlc *c = tal_arr_append(&changed);
		const struct htlc *htlc = changed_htlcs[i];

		status_trace("HTLC %"PRIu64"[%s] => %s",
			     htlc->id, side_to_str(htlc_owner(htlc)),
			     htlc_state_name(htlc->state));

		c->id = changed_htlcs[i]->id;
		c->newstate = changed_htlcs[i]->state;
	}

	msg = towire_channel_got_revoke(ctx, revoke_num, per_commitment_secret,
					next_per_commit_point, changed);
	tal_free(tmpctx);
	return msg;
}

/* We come back here once master has acked the revoke_and_ack we received */
static struct io_plan *accepted_revocation(struct io_conn *conn,
					   struct peer *peer)
{
	start_commit_timer(peer);
	return peer_read_message(conn, &peer->pcs, peer_in);
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
	if (!pubkey_eq(&per_commit_point, &peer->old_remote_per_commit)) {
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Wrong privkey %s for %"PRIu64" %s",
			    type_to_string(msg, struct privkey, &privkey),
			    peer->next_index[LOCAL]-2,
			    type_to_string(msg, struct pubkey,
					   &peer->old_remote_per_commit));
	}

	/* We start timer even if this returns false: we might have delayed
	 * commit because we were waiting for this! */
	if (channel_rcvd_revoke_and_ack(peer->channel, &changed_htlcs))
		status_trace("Commits outstanding after recv revoke_and_ack");
	else
		status_trace("No commits outstanding after recv revoke_and_ack");

	/* Tell master about things this locks in, wait for response */
	msg = got_revoke_msg(msg, peer->next_index[REMOTE] - 2,
			     &old_commit_secret, &next_per_commit,
			     changed_htlcs);
	master_sync_reply(peer, take(msg),
			  WIRE_CHANNEL_GOT_REVOKE_REPLY,
			  handle_reply_wake_peer);

	peer->old_remote_per_commit = peer->remote_per_commit;
	peer->remote_per_commit = next_per_commit;
	status_trace("revoke_and_ack %s: remote_per_commit = %s, old_remote_per_commit = %s",
		     side_to_str(peer->channel->funder),
		     type_to_string(trc, struct pubkey,
				    &peer->remote_per_commit),
		     type_to_string(trc, struct pubkey,
				    &peer->old_remote_per_commit));

	/* And peer waits for reply. */
	return io_wait(conn, peer, accepted_revocation, peer);
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
		/* FIXME: We could send preimages to master immediately. */
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
	struct htlc *htlc;

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
		/* Save reason for when we tell master. */
		htlc = channel_get_htlc(peer->channel, LOCAL, id);
		htlc->fail = tal_steal(htlc, reason);
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
	u16 failure_code;
	struct htlc *htlc;
	u8 *fail;

	if (!fromwire_update_fail_malformed_htlc(msg, NULL, &channel_id, &id,
						 &sha256_of_onion,
						 &failure_code)) {
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad update_fail_malformed_htlc %s",
			    tal_hex(msg, msg));
	}

	/* BOLT #2:
	 *
	 * A receiving node MUST fail the channel if the `BADONION` bit in
	 * `failure_code` is not set for `update_fail_malformed_htlc`.
	 */
	if (!(failure_code & BADONION)) {
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "Bad update_fail_malformed_htlc failure code %u",
			    failure_code);
	}

	e = channel_fail_htlc(peer->channel, LOCAL, id);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK:
		htlc = channel_get_htlc(peer->channel, LOCAL, id);
		/* FIXME: Do this! */
		/* BOLT #2:
		 *
		 * A receiving node MAY check the `sha256_of_onion`
		 * in `update_fail_malformed_htlc` and MAY retry or choose an
		 * alternate error response if it does not match the onion it
		 * sent.
		 */

		/* BOLT #2:
		 *
		 * Otherwise, a receiving node which has an outgoing HTLC
		 * canceled by `update_fail_malformed_htlc` MUST return an
		 * error in the `update_fail_htlc` sent to the link which
		 * originally sent the HTLC using the `failure_code` given and
		 * setting the data to `sha256_of_onion`.
		 */
		fail = tal_arr(htlc, u8, 0);
		towire_u16(&fail, failure_code);
		towire_sha256(&fail, &sha256_of_onion);
		/* FIXME: Make htlc->fail a u8 *! */
		htlc->fail = fail;
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

static struct io_plan *handle_peer_shutdown(struct io_conn *conn,
					    struct peer *peer,
					    const u8 *shutdown)
{
	struct channel_id channel_id;
	u8 *scriptpubkey;

	if (!fromwire_shutdown(peer, shutdown, NULL, &channel_id, &scriptpubkey))
		status_failed(WIRE_CHANNEL_PEER_READ_FAILED, "Bad shutdown");

	/* Tell master, it will tell us what to send. */
	daemon_conn_send(&peer->master,
			 take(towire_channel_got_shutdown(peer, scriptpubkey)));
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
	case WIRE_SHUTDOWN:
		return handle_peer_shutdown(conn, peer, msg);

	case WIRE_INIT:
	case WIRE_ERROR:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_CHANNEL_REESTABLISH:
		goto badmessage;

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

static void resend_revoke(struct peer *peer)
{
	/* Current commit is peer->next_index[LOCAL]-1, revoke prior */
	u8 *msg = make_revocation_msg(peer, peer->next_index[LOCAL]-2);
	msg_enqueue(&peer->peer_out, take(msg));
}

static void send_fail_or_fulfill(struct peer *peer, const struct htlc *h)
{
	u8 *msg;
	if (h->malformed) {
		struct sha256 sha256_of_onion;
		sha256(&sha256_of_onion, h->routing, tal_len(h->routing));

		msg = towire_update_fail_malformed_htlc(peer, &peer->channel_id,
							h->id, &sha256_of_onion,
							h->malformed);
	} else if (h->fail) {
		msg = towire_update_fail_htlc(peer, &peer->channel_id, h->id,
					      h->fail);
	} else if (h->r) {
		msg = towire_update_fulfill_htlc(peer, &peer->channel_id, h->id,
						 h->r);
	} else
		peer_failed(io_conn_fd(peer->peer_conn),
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "HTLC %"PRIu64" state %s not failed/fulfilled",
			    h->id, htlc_state_name(h->state));
	msg_enqueue(&peer->peer_out, take(msg));
}

static void resend_commitment(struct peer *peer, const struct changed_htlc *last)
{
	size_t i;
	struct commit_sigs *commit_sigs;
	u8 *msg;

	/* BOLT #2:
	 *
	 * If `next_local_commitment_number` is equal to the commitment number
	 * of the last `commitment_signed` message the receiving node has
	 * sent, it MUST reuse the same commitment number for its next
	 * `commitment_signed`
	 */
	/* In our case, we consider ourselves already committed to this, so
	 * retransmission is simplest. */
	for (i = 0; i < tal_count(last); i++) {
		const struct htlc *h;

		h = channel_get_htlc(peer->channel,
				     htlc_state_owner(last[i].newstate),
				     last[i].id);

		/* I think this can happen if we actually received revoke_and_ack
		 * then they asked for a retransmit */
		if (!h)
			peer_failed(io_conn_fd(peer->peer_conn),
				    &peer->pcs.cs,
				    &peer->channel_id,
				    WIRE_CHANNEL_PEER_BAD_MESSAGE,
				    "Can't find HTLC %"PRIu64" to resend",
				    last[i].id);

		if (h->state == SENT_ADD_COMMIT) {
			u8 *msg = towire_update_add_htlc(peer, &peer->channel_id,
							 h->id, h->msatoshi,
							 &h->rhash,
							 abs_locktime_to_blocks(
								 &h->expiry),
							 h->routing);
			msg_enqueue(&peer->peer_out, take(msg));
		} else if (h->state == SENT_REMOVE_COMMIT) {
			send_fail_or_fulfill(peer, h);
		}
	}

	/* Re-send the commitment_signed itself. */
	commit_sigs = calc_commitsigs(peer, peer, peer->next_index[REMOTE]-1);
	msg = towire_commitment_signed(peer, &peer->channel_id,
				       &commit_sigs->commit_sig,
				       commit_sigs->htlc_sigs);
	msg_enqueue(&peer->peer_out, take(msg));
	tal_free(commit_sigs);
}

static void peer_reconnect(struct peer *peer)
{
	struct channel_id channel_id;
	/* Note: BOLT #2 uses these names, which are sender-relative! */
	u64 next_local_commitment_number, next_remote_revocation_number;
	bool retransmit_revoke_and_ack;
	struct htlc_map_iter it;
	const struct htlc *htlc;
	u8 *msg;

	/* BOLT #2:
	 *
	 * On reconnection, a node MUST transmit `channel_reestablish` for
	 * each channel, and MUST wait for to receive the other node's
	 * `channel_reestablish` message before sending any other messages for
	 * that channel.
	 *
	 * The sending node MUST set `next_local_commitment_number` to the
	 * commitment number of the next `commitment_signed` it expects to
	 * receive, and MUST set `next_remote_revocation_number` to the
	 * commitment number of the next `revoke_and_ack` message it expects
	 * to receive.
	 */
	msg = towire_channel_reestablish(peer, &peer->channel_id,
					 peer->next_index[LOCAL],
					 peer->revocations_received);
	if (!sync_crypto_write(&peer->pcs.cs, PEER_FD, take(msg)))
		status_failed(WIRE_CHANNEL_PEER_WRITE_FAILED,
			      "Failed writing reestablish: %s", strerror(errno));

again:
	msg = sync_crypto_read(peer, &peer->pcs.cs, PEER_FD);
	if (!msg)
		status_failed(WIRE_CHANNEL_PEER_READ_FAILED,
			      "Failed reading reestablish: %s", strerror(errno));

	if (is_gossip_msg(msg)) {
		/* Forward to gossip daemon */
		daemon_conn_send(&peer->gossip_client, msg);
		goto again;
	}

	if (!fromwire_channel_reestablish(msg, NULL, &channel_id,
					  &next_local_commitment_number,
					  &next_remote_revocation_number)) {
		status_failed(WIRE_CHANNEL_PEER_READ_FAILED,
			      "bad reestablish msg: %s %s",
			      wire_type_name(fromwire_peektype(msg)),
			      tal_hex(msg, msg));
	}

	status_trace("Got reestablish commit=%"PRIu64" revoke=%"PRIu64,
		     next_local_commitment_number,
		     next_remote_revocation_number);

	/* BOLT #2:
	 *
	 * If `next_local_commitment_number` is 1 in both the
	 * `channel_reestablish` it sent and received, then the node MUST
	 * retransmit `funding_locked`, otherwise it MUST NOT.
	 */
	if (peer->funding_locked[LOCAL]
	    && peer->next_index[LOCAL] == 1
	    && next_local_commitment_number == 1) {
		u8 *msg;
		struct pubkey next_per_commit_point;

		/* Contains per commit point #1, for first post-opening commit */
		per_commit_point(&peer->shaseed, &next_per_commit_point, 1);
		msg = towire_funding_locked(peer,
					    &peer->channel_id,
					    &next_per_commit_point);
		msg_enqueue(&peer->peer_out, take(msg));
	}

	/* Note: next_index is the index of the current commit we're working
	 * on, but BOLT #2 refers to the *last* commit index, so we -1 where
	 * required. */

	/* BOLT #2:
	 *
	 * If `next_remote_revocation_number` is equal to the commitment
	 * number of the last `revoke_and_ack` the receiving node has sent, it
	 * MUST re-send the `revoke_and_ack`, otherwise if
	 * `next_remote_revocation_number` is not equal to one greater than
	 * the commitment number of the last `revoke_and_ack` the receiving
	 * node has sent (or equal to zero if none have been sent), it SHOULD
	 * fail the channel.
	 */
	if (next_remote_revocation_number == peer->next_index[LOCAL] - 2) {
		/* Don't try to retransmit revocation index -1! */
		if (peer->next_index[LOCAL] < 2) {
			status_failed(WIRE_CHANNEL_PEER_READ_FAILED,
				      "bad reestablish revocation_number: %"
				      PRIu64,
				      next_remote_revocation_number);
		}
		retransmit_revoke_and_ack = true;
	} else if (next_remote_revocation_number != peer->next_index[LOCAL] - 1) {
		status_failed(WIRE_CHANNEL_PEER_READ_FAILED,
			      "bad reestablish revocation_number: %"PRIu64
			      " vs %"PRIu64,
			      next_remote_revocation_number,
			      peer->next_index[LOCAL]);
	} else
		retransmit_revoke_and_ack = false;

	/* We have to re-send in the same order we sent originally:
	 * revoke_and_ack (usually) alters our next commitment. */
	if (retransmit_revoke_and_ack && !peer->last_was_revoke)
		resend_revoke(peer);

	/* BOLT #2:
	 *
	 * If `next_local_commitment_number` is equal to the commitment number
	 * of the last `commitment_signed` message the receiving node has
	 * sent, it MUST reuse the same commitment number for its next
	 * `commitment_signed`
	 */
	if (next_local_commitment_number == peer->next_index[REMOTE] - 1) {
		/* We completed opening, we don't re-transmit that one! */
		if (next_local_commitment_number == 0)
			status_failed(WIRE_CHANNEL_PEER_READ_FAILED,
				      "bad reestablish commitment_number: %"
				      PRIu64,
				      next_local_commitment_number);

		resend_commitment(peer, peer->last_sent_commit);

	/* BOLT #2:
	 *
	 * ... otherwise if `next_local_commitment_number` is not one greater
	 * than the commitment number of the last `commitment_signed` message
	 * the receiving node has sent, it SHOULD fail the channel.
	 */
	} else if (next_local_commitment_number != peer->next_index[REMOTE])
		peer_failed(PEER_FD,
			    &peer->pcs.cs,
			    &peer->channel_id,
			    WIRE_CHANNEL_PEER_BAD_MESSAGE,
			    "bad reestablish commitment_number: %"PRIu64
			    " vs %"PRIu64,
			    next_local_commitment_number,
			    peer->next_index[REMOTE]);

	/* This covers the case where we sent revoke after commit. */
	if (retransmit_revoke_and_ack && peer->last_was_revoke)
		resend_revoke(peer);

	/* BOLT #2:
	 *
	 * On reconnection if the node has sent a previous `shutdown` it MUST
	 * retransmit it
	 */
	maybe_send_shutdown(peer);

	/* Start commit timer: if we sent revoke we might need it. */
	start_commit_timer(peer);

	/* Now, re-send any that we're supposed to be failing. */
	for (htlc = htlc_map_first(&peer->channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(&peer->channel->htlcs, &it)) {
		if (htlc->state == SENT_REMOVE_HTLC)
			send_fail_or_fulfill(peer, htlc);
	}
}

/* We do this synchronously. */
static void init_channel(struct peer *peer)
{
	struct privkey seed;
	struct basepoints points[NUM_SIDES];
	u64 funding_satoshi;
	u16 funding_txout;
	u64 local_msatoshi;
	struct pubkey funding_pubkey[NUM_SIDES];
	struct sha256_double funding_txid;
	bool am_funder;
	enum htlc_state *hstates;
	struct fulfilled_htlc *fulfilled;
	enum side *fulfilled_sides;
	struct failed_htlc *failed;
	enum side *failed_sides;
	struct added_htlc *htlcs;
	bool reconnected;
	u8 *funding_signed;
	u8 *msg;

	msg = wire_sync_read(peer, REQ_FD);
	if (!fromwire_channel_init(peer, msg, NULL,
				   &funding_txid, &funding_txout,
				   &funding_satoshi,
				   &peer->conf[LOCAL], &peer->conf[REMOTE],
				   &peer->their_commit_sig,
				   &peer->pcs.cs,
				   &funding_pubkey[REMOTE],
				   &points[REMOTE].revocation,
				   &points[REMOTE].payment,
				   &points[REMOTE].delayed_payment,
				   &peer->remote_per_commit,
				   &peer->old_remote_per_commit,
				   &am_funder,
				   &peer->fee_base,
				   &peer->fee_per_satoshi,
				   &local_msatoshi,
				   &seed,
				   &peer->node_ids[LOCAL],
				   &peer->node_ids[REMOTE],
				   &peer->commit_msec,
				   &peer->cltv_delta,
				   &peer->last_was_revoke,
				   &peer->last_sent_commit,
				   &peer->next_index[LOCAL],
				   &peer->next_index[REMOTE],
				   &peer->revocations_received,
				   &peer->htlc_id,
				   &htlcs,
				   &hstates,
				   &fulfilled,
				   &fulfilled_sides,
				   &failed,
				   &failed_sides,
				   &peer->funding_locked[LOCAL],
				   &peer->funding_locked[REMOTE],
				   &peer->short_channel_ids[LOCAL],
				   &reconnected,
				   &peer->unsent_shutdown_scriptpubkey,
				   &funding_signed))
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "Init: %s",
			      tal_hex(msg, msg));

	status_trace("init %s: remote_per_commit = %s, old_remote_per_commit = %s"
		     " next_idx_local = %"PRIu64
		     " next_idx_remote = %"PRIu64
		     " revocations_received = %"PRIu64,
		     am_funder ? "LOCAL" : "REMOTE",
		     type_to_string(trc, struct pubkey,
				    &peer->remote_per_commit),
		     type_to_string(trc, struct pubkey,
				    &peer->old_remote_per_commit),
		     peer->next_index[LOCAL], peer->next_index[REMOTE],
		     peer->revocations_received);

	/* First commit is used for opening: if we've sent 0, we're on
	 * index 1. */
	assert(peer->next_index[LOCAL] > 0);
	assert(peer->next_index[REMOTE] > 0);

	/* channel_id is set from funding txout */
	derive_channel_id(&peer->channel_id, &funding_txid, funding_txout);

	/* We derive everything from the one secret seed. */
	derive_basepoints(&seed, &funding_pubkey[LOCAL], &points[LOCAL],
			  &peer->our_secrets, &peer->shaseed);

	peer->channel = new_channel(peer, &funding_txid, funding_txout,
				    funding_satoshi,
				    local_msatoshi,
				    peer->fee_base,
				    &peer->conf[LOCAL], &peer->conf[REMOTE],
				    &points[LOCAL], &points[REMOTE],
				    &funding_pubkey[LOCAL],
				    &funding_pubkey[REMOTE],
				    am_funder ? LOCAL : REMOTE);

	if (!channel_force_htlcs(peer->channel, htlcs, hstates,
				 fulfilled, fulfilled_sides,
				 failed, failed_sides))
		status_failed(WIRE_CHANNEL_BAD_COMMAND,
			      "Could not restore HTLCs");

	peer->channel_direction = get_channel_direction(
	    &peer->node_ids[LOCAL], &peer->node_ids[REMOTE]);

	/* OK, now we can process peer messages. */
	if (reconnected)
		peer_reconnect(peer);

	peer->peer_conn = io_new_conn(peer, PEER_FD, setup_peer_conn, peer);
	io_set_finish(peer->peer_conn, peer_conn_broken, peer);

	/* If we have a funding_signed message, send that immediately */
	if (funding_signed)
		msg_enqueue(&peer->peer_out, take(funding_signed));

	tal_free(msg);
}

static void handle_funding_locked(struct peer *peer, const u8 *msg)
{
	struct pubkey next_per_commit_point;

	if (!fromwire_channel_funding_locked(msg, NULL,
					     &peer->short_channel_ids[LOCAL]))
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "%s", tal_hex(msg, msg));

	per_commit_point(&peer->shaseed,
			 &next_per_commit_point, peer->next_index[LOCAL]);

	status_trace("funding_locked: sending commit index %"PRIu64": %s",
		     peer->next_index[LOCAL],
		     type_to_string(trc, struct pubkey, &next_per_commit_point));
	msg = towire_funding_locked(peer,
				    &peer->channel_id, &next_per_commit_point);
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
	u16 malformed;
	enum channel_remove_err e;

	if (!fromwire_channel_fail_htlc(inmsg, inmsg, NULL, &id, &malformed,
					&errpkt))
		status_failed(WIRE_CHANNEL_BAD_COMMAND,
			      "Invalid channel_fail_htlc");

	if (malformed && !(malformed & BADONION))
		status_failed(WIRE_CHANNEL_BAD_COMMAND,
			      "Invalid channel_fail_htlc: bad malformed 0x%x",
			      malformed);

	e = channel_fail_htlc(peer->channel, REMOTE, id);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK:
		if (malformed) {
			struct htlc *h;
			struct sha256 sha256_of_onion;
			status_trace("Failing %"PRIu64" with code %u",
				     id, malformed);
			h = channel_get_htlc(peer->channel, REMOTE, id);
			sha256(&sha256_of_onion, h->routing,
			       tal_len(h->routing));
			msg = towire_update_fail_malformed_htlc(peer,
							&peer->channel_id,
							id, &sha256_of_onion,
							malformed);
		} else {
			msg = towire_update_fail_htlc(peer, &peer->channel_id,
						      id, errpkt);
		}
		msg_enqueue(&peer->peer_out, take(msg));
		start_commit_timer(peer);
		return;
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

static void handle_shutdown_cmd(struct peer *peer, const u8 *inmsg)
{
	u8 *scriptpubkey;

	if (!fromwire_channel_send_shutdown(peer, inmsg, NULL, &scriptpubkey))
		status_failed(WIRE_CHANNEL_BAD_COMMAND, "Bad send_shutdown");

	/* We can't send this until commit (if any) is done, so start timer<. */
	peer->unsent_shutdown_scriptpubkey = scriptpubkey;
	start_commit_timer(peer);
}

static struct io_plan *req_in(struct io_conn *conn, struct daemon_conn *master)
{
	struct peer *peer = container_of(master, struct peer, master);
	enum channel_wire_type t = fromwire_peektype(master->msg_in);

	/* Waiting for something specific?  Defer others. */
	if (peer->handle_master_reply) {
		void (*handle)(struct peer *peer, const u8 *msg);

		if (t != peer->master_reply_type) {
			msg_enqueue(&peer->master_deferred,
				    take(master->msg_in));
			master->msg_in = NULL;
			goto out_next;
		}

		/* Just in case it resets this. */
		handle = peer->handle_master_reply;
		peer->handle_master_reply = NULL;

		handle(peer, master->msg_in);
		goto out;
	}

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
	case WIRE_CHANNEL_SEND_SHUTDOWN:
		handle_shutdown_cmd(peer, master->msg_in);
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
	case WIRE_CHANNEL_PING_REPLY:
	case WIRE_CHANNEL_PEER_BAD_MESSAGE:
	case WIRE_CHANNEL_ANNOUNCED:
	case WIRE_CHANNEL_SENDING_COMMITSIG:
	case WIRE_CHANNEL_GOT_COMMITSIG:
	case WIRE_CHANNEL_GOT_REVOKE:
	case WIRE_CHANNEL_SENDING_COMMITSIG_REPLY:
	case WIRE_CHANNEL_GOT_COMMITSIG_REPLY:
	case WIRE_CHANNEL_GOT_REVOKE_REPLY:
	case WIRE_CHANNEL_GOT_FUNDING_LOCKED:
	case WIRE_CHANNEL_GOT_SHUTDOWN:
		break;
	}
	status_failed(WIRE_CHANNEL_BAD_COMMAND, "%u %s", t,
		      channel_wire_type_name(t));

out:
	/* In case we've now processed reply, process packet backlog. */
	if (!peer->handle_master_reply) {
		const u8 *msg = msg_dequeue(&peer->master_deferred);
		if (msg) {
			/* Free old packet exactly like daemon_conn_read_next */
			master->msg_in = tal_free(master->msg_in);
			master->msg_in = cast_const(u8 *, tal_steal(master,msg));
			return req_in(conn, master);
		}
	}

out_next:
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
	status_setup_async(&peer->master);

	peer->num_pings_outstanding = 0;
	timers_init(&peer->timers, time_mono());
	peer->commit_timer = NULL;
	peer->have_sigs[LOCAL] = peer->have_sigs[REMOTE] = false;
	peer->handle_master_reply = NULL;
	peer->master_reply_type = 0;
	msg_queue_init(&peer->master_deferred, peer);
	msg_queue_init(&peer->peer_out, peer);
	peer->next_commit_sigs = NULL;
	peer->unsent_shutdown_scriptpubkey = NULL;

	/* We send these to HSM to get real signatures; don't have valgrind
	 * complain. */
	for (i = 0; i < NUM_SIDES; i++) {
		memset(&peer->announcement_node_sigs[i], 0,
		       sizeof(peer->announcement_node_sigs[i]));
		memset(&peer->announcement_bitcoin_sigs[i], 0,
		       sizeof(peer->announcement_bitcoin_sigs[i]));
	}

	daemon_conn_init(peer, &peer->gossip_client, GOSSIP_FD,
			 gossip_client_recv, gossip_gone);

	init_peer_crypto_state(peer, &peer->pcs);
	peer->funding_locked[LOCAL] = peer->funding_locked[REMOTE] = false;

	/* Read init_channel message sync. */
	init_channel(peer);

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
