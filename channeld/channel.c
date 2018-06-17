/* Main channel operation daemon: runs from funding_locked to shutdown_complete.
 *
 * We're fairly synchronous: our main loop looks for gossip, master or
 * peer requests and services them synchronously.
 *
 * The exceptions are:
 * 1. When we've asked the master something: in that case, we queue
 *    non-response packets for later processing while we await the reply.
 * 2. We queue and send non-blocking responses to peers: if both peers were
 *    reading and writing synchronously we could deadlock if we hit buffer
 *    limits, unlikely as that is.
 */
#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/cast/cast.h>
#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/mem/mem.h>
#include <ccan/structeq/structeq.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <channeld/commit_tx.h>
#include <channeld/full_channel.h>
#include <channeld/gen_channel_wire.h>
#include <common/crypto_sync.h>
#include <common/derive_basepoints.h>
#include <common/dev_disconnect.h>
#include <common/htlc_tx.h>
#include <common/key_derive.h>
#include <common/msg_queue.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/ping.h>
#include <common/read_peer_msg.h>
#include <common/sphinx.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/version.h>
#include <common/wire_error.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gen_gossip_wire.h>
#include <gossipd/gossip_constants.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <secp256k1.h>
#include <stdio.h>
#include <wire/gen_onion_wire.h>
#include <wire/peer_wire.h>
#include <wire/wire.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

/* stdin == requests, 3 == peer, 4 = gossip, 5 = HSM */
#define MASTER_FD STDIN_FILENO
#define PEER_FD 3
#define GOSSIP_FD 4
#define HSM_FD 5

struct commit_sigs {
	struct peer *peer;
	secp256k1_ecdsa_signature commit_sig;
	secp256k1_ecdsa_signature *htlc_sigs;
};

struct peer {
	struct crypto_state cs;
	struct channel_config conf[NUM_SIDES];
	bool funding_locked[NUM_SIDES];
	u64 next_index[NUM_SIDES];

	/* Tolerable amounts for feerate (only relevant for fundee). */
	u32 feerate_min, feerate_max;

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
	 * A sending node:
	 *...
	 *  - for the first HTLC it offers:
	 *    - MUST set `id` to 0.
	 */
	u64 htlc_id;

	struct bitcoin_blkid chain_hash;
	struct channel_id channel_id;
	struct channel *channel;

	/* Pending msgs to send (not encrypted) */
	struct msg_queue peer_out;

	/* Current msg to send, and offset (encrypted) */
	const u8 *peer_outmsg;
	size_t peer_outoff;

	/* Messages from master / gossipd: we queue them since we
	 * might be waiting for a specific reply. */
	struct msg_queue from_master, from_gossipd;

	struct timers timers;
	struct oneshot *commit_timer;
	u64 commit_timer_attempts;
	u32 commit_msec;

	/* Don't accept a pong we didn't ping for. */
	size_t num_pings_outstanding;

	/* The feerate we want. */
	u32 desired_feerate;

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

	/* The scriptpubkey to use for shutting down. */
	u8 *final_scriptpubkey;

	/* If master told us to shut down */
	bool send_shutdown;
	/* Has shutdown been sent by each side? */
	bool shutdown_sent[NUM_SIDES];

	/* Information used for reestablishment. */
	bool last_was_revoke;
	struct changed_htlc *last_sent_commit;
	u64 revocations_received;
	u8 channel_flags;

	bool announce_depth_reached;
	bool channel_local_active;

	/* Make sure timestamps move forward. */
	u32 last_update_timestamp;
};

static u8 *create_channel_announcement(const tal_t *ctx, struct peer *peer);
static void start_commit_timer(struct peer *peer);

static void billboard_update(const struct peer *peer)
{
	const char *funding_status, *announce_status, *shutdown_status;

	if (peer->funding_locked[LOCAL] && peer->funding_locked[REMOTE])
		funding_status = "Funding transaction locked.";
	else if (!peer->funding_locked[LOCAL] && !peer->funding_locked[REMOTE])
		/* FIXME: Say how many blocks to go! */
		funding_status = "Funding needs more confirmations.";
	else if (peer->funding_locked[LOCAL] && !peer->funding_locked[REMOTE])
		funding_status = "We've confirmed funding, they haven't yet.";
	else if (!peer->funding_locked[LOCAL] && peer->funding_locked[REMOTE])
		funding_status = "They've confirmed funding, we haven't yet.";

	if (peer->have_sigs[LOCAL] && peer->have_sigs[REMOTE])
		announce_status = " Channel announced.";
	else if (peer->have_sigs[LOCAL] && !peer->have_sigs[REMOTE])
		announce_status = " Waiting for their announcement signatures.";
	else if (!peer->have_sigs[LOCAL] && peer->have_sigs[REMOTE])
		announce_status = " They need our announcement signatures.";
	else if (!peer->have_sigs[LOCAL] && !peer->have_sigs[REMOTE])
		announce_status = "";

	if (!peer->shutdown_sent[LOCAL] && !peer->shutdown_sent[REMOTE])
		shutdown_status = "";
	else if (!peer->shutdown_sent[LOCAL] && peer->shutdown_sent[REMOTE])
		shutdown_status = " We've send shutdown, waiting for theirs";
	else if (peer->shutdown_sent[LOCAL] && !peer->shutdown_sent[REMOTE])
		shutdown_status = " They've sent shutdown, waiting for ours";
	else if (peer->shutdown_sent[LOCAL] && peer->shutdown_sent[REMOTE]) {
		size_t num_htlcs = num_channel_htlcs(peer->channel);
		if (num_htlcs)
			shutdown_status = tal_fmt(tmpctx,
						  " Shutdown messages exchanged,"
						  " waiting for %zu HTLCs to complete.",
						  num_htlcs);
		else
			shutdown_status = tal_fmt(tmpctx,
						  " Shutdown messages exchanged.");
	}
	peer_billboard(false, "%s%s%s", funding_status,
		       announce_status, shutdown_status);
}

/* Returns a pointer to the new end */
static void *tal_arr_append_(void **p, size_t size)
{
	size_t n = tal_len(*p) / size;
	tal_resize_(p, size, n+1, false);
	return (char *)(*p) + n * size;
}
#define tal_arr_append(p) tal_arr_append_((void **)(p), sizeof(**(p)))

static void do_peer_write(struct peer *peer)
{
	int r;
	size_t len = tal_len(peer->peer_outmsg);

	r = write(PEER_FD, peer->peer_outmsg + peer->peer_outoff,
		  len - peer->peer_outoff);
	if (r < 0)
		peer_failed_connection_lost();

	peer->peer_outoff += r;
	if (peer->peer_outoff == len)
		peer->peer_outmsg = tal_free(peer->peer_outmsg);
}

static bool peer_write_pending(struct peer *peer)
{
	const u8 *msg;

	if (peer->peer_outmsg)
		return true;

	msg = msg_dequeue(&peer->peer_out);
	if (!msg)
		return false;

	status_peer_io(LOG_IO_OUT, msg);
	peer->peer_outmsg = cryptomsg_encrypt_msg(peer, &peer->cs, take(msg));
	peer->peer_outoff = 0;
	return true;
}

/* Synchronous flush of all pending packets. */
static void flush_peer_out(struct peer *peer)
{
	while (peer_write_pending(peer))
		do_peer_write(peer);
}

static void enqueue_peer_msg(struct peer *peer, const u8 *msg TAKES)
{
#if DEVELOPER
	enum dev_disconnect d = dev_disconnect(fromwire_peektype(msg));

	/* We want to effect this exact packet, so flush any pending. */
	if (d != DEV_DISCONNECT_NORMAL)
		flush_peer_out(peer);

	switch (d) {
	case DEV_DISCONNECT_BEFORE:
		/* Fail immediately. */
		dev_sabotage_fd(PEER_FD);
		msg_enqueue(&peer->peer_out, msg);
		flush_peer_out(peer);
		/* Should not return */
		abort();
	case DEV_DISCONNECT_DROPPKT:
		tal_free(msg);
		/* Fail next time we try to do something. */
		dev_sabotage_fd(PEER_FD);
		return;
	case DEV_DISCONNECT_AFTER:
		msg_enqueue(&peer->peer_out, msg);
		flush_peer_out(peer);
		dev_sabotage_fd(PEER_FD);
		return;
	case DEV_DISCONNECT_BLACKHOLE:
		msg_enqueue(&peer->peer_out, msg);
		dev_blackhole_fd(PEER_FD);
		return;
	case DEV_DISCONNECT_NORMAL:
		break;
	}
#endif
	msg_enqueue(&peer->peer_out, msg);
}

/* Create and send channel_update to gossipd (and maybe peer) */
static void send_channel_update(struct peer *peer, int disable_flag)
{
	u8 *msg;

	assert(disable_flag == 0 || disable_flag == ROUTING_FLAGS_DISABLED);

	/* Only send an update if we told gossipd */
	if (!peer->channel_local_active)
		return;

	assert(peer->short_channel_ids[LOCAL].u64);

	msg = towire_gossip_local_channel_update(NULL,
						 &peer->short_channel_ids[LOCAL],
						 disable_flag
						 == ROUTING_FLAGS_DISABLED,
						 peer->cltv_delta,
						 peer->conf[REMOTE].htlc_minimum_msat,
						 peer->fee_base,
						 peer->fee_per_satoshi);
	wire_sync_write(GOSSIP_FD, take(msg));
}

/**
 * Add a channel locally and send a channel update to the peer
 *
 * Send a local_add_channel message to gossipd in order to make the channel
 * usable locally, and also tell our peer about our parameters via a
 * channel_update message. The peer may accept the update and use the contained
 * information to route incoming payments through the channel. The
 * channel_update is not preceeded by a channel_announcement and won't make much
 * sense to other nodes, so we don't tell gossipd about it.
 */
static void make_channel_local_active(struct peer *peer)
{
	u8 *msg;

	/* Tell gossipd about local channel. */
	msg = towire_gossip_local_add_channel(NULL,
					      &peer->short_channel_ids[LOCAL],
					      &peer->node_ids[REMOTE]);
 	wire_sync_write(GOSSIP_FD, take(msg));

	/* Tell gossipd and the other side what parameters we expect should
	 * they route through us */
	send_channel_update(peer, 0);
}

static void send_announcement_signatures(struct peer *peer)
{
	/* First 2 + 256 byte are the signatures and msg type, skip them */
	size_t offset = 258;
	struct sha256_double hash;
	u8 *msg, *ca, *req;

	status_trace("Exchanging announcement signatures.");
	ca = create_channel_announcement(tmpctx, peer);
	req = towire_hsm_cannouncement_sig_req(
	    tmpctx, &peer->channel->funding_pubkey[LOCAL], ca);


	if (!wire_sync_write(HSM_FD, req))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Writing cannouncement_sig_req: %s",
			      strerror(errno));

	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg || !fromwire_hsm_cannouncement_sig_reply(msg,
					  &peer->announcement_node_sigs[LOCAL]))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading cannouncement_sig_resp: %s",
			      strerror(errno));

	/* Double-check that HSM gave a valid signature. */
	sha256_double(&hash, ca + offset, tal_len(ca) - offset);
	if (!check_signed_hash(&hash, &peer->announcement_node_sigs[LOCAL],
			       &peer->node_ids[LOCAL])) {
		/* It's ok to fail here, the channel announcement is
		 * unique, unlike the channel update which may have
		 * been replaced in the meantime. */
		status_failed(STATUS_FAIL_HSM_IO,
			      "HSM returned an invalid signature");
	}

	/* TODO(cdecker) Move this to the HSM once we store the
	 * funding_privkey there */
	sign_hash(&peer->our_secrets.funding_privkey, &hash,
		  &peer->announcement_bitcoin_sigs[LOCAL]);

	msg = towire_announcement_signatures(
	    NULL, &peer->channel_id, &peer->short_channel_ids[LOCAL],
	    &peer->announcement_node_sigs[LOCAL],
	    &peer->announcement_bitcoin_sigs[LOCAL]);
	enqueue_peer_msg(peer, take(msg));
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
	    features,
	    &peer->chain_hash,
	    &peer->short_channel_ids[LOCAL], &peer->node_ids[first],
	    &peer->node_ids[second], &peer->channel->funding_pubkey[first],
	    &peer->channel->funding_pubkey[second]);
	tal_free(features);
	return cannounce;
}

/* Once we have both, we'd better make sure we agree what they are! */
static void check_short_ids_match(struct peer *peer)
{
	assert(peer->have_sigs[LOCAL]);
	assert(peer->have_sigs[REMOTE]);

	if (!structeq(&peer->short_channel_ids[LOCAL],
		      &peer->short_channel_ids[REMOTE]))
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "We disagree on short_channel_ids:"
			    " I have %s, you say %s",
			    type_to_string(peer, struct short_channel_id,
					   &peer->short_channel_ids[LOCAL]),
			    type_to_string(peer, struct short_channel_id,
					   &peer->short_channel_ids[REMOTE]));
}

static void announce_channel(struct peer *peer)
{
	u8 *cannounce;

	check_short_ids_match(peer);

	cannounce = create_channel_announcement(tmpctx, peer);

	wire_sync_write(GOSSIP_FD, cannounce);
	send_channel_update(peer, 0);
}

static void channel_announcement_negotiate(struct peer *peer)
{
	/* Don't do any announcement work if we're shutting down */
	if (peer->shutdown_sent[LOCAL])
		return;

	/* Can't do anything until funding is locked. */
	if (!peer->funding_locked[LOCAL] || !peer->funding_locked[REMOTE])
		return;

	if (!peer->channel_local_active) {
		peer->channel_local_active = true;
		make_channel_local_active(peer);
	}
	/* BOLT #7:
	 *
	 *      - MUST NOT send `announcement_signatures` messages until
	 *      `funding_locked` has been sent AND the funding transaction has
	 *      at least six confirmations.
	 */
	if (peer->announce_depth_reached && !peer->have_sigs[LOCAL]) {
		send_announcement_signatures(peer);
		peer->have_sigs[LOCAL] = true;
		billboard_update(peer);
	}

	/* If we've completed the signature exchange, we can send a real
	 * announcement, otherwise we send a temporary one */
	if (peer->have_sigs[LOCAL] && peer->have_sigs[REMOTE])
		announce_channel(peer);
}

static void handle_peer_funding_locked(struct peer *peer, const u8 *msg)
{
	struct channel_id chanid;

	/* BOLT #2:
	 *
	 * A node:
	 *...
	 *  - upon reconnection:
	 *    - MUST ignore any redundant `funding_locked` it receives.
	 */
	if (peer->funding_locked[REMOTE])
		return;

	/* Too late, we're shutting down! */
	if (peer->shutdown_sent[LOCAL])
		return;

	peer->old_remote_per_commit = peer->remote_per_commit;
	if (!fromwire_funding_locked(msg, &chanid,
				     &peer->remote_per_commit))
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad funding_locked %s", tal_hex(msg, msg));

	if (!structeq(&chanid, &peer->channel_id))
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Wrong channel id in %s (expected %s)",
			    tal_hex(tmpctx, msg),
			    type_to_string(msg, struct channel_id,
					   &peer->channel_id));

	peer->funding_locked[REMOTE] = true;
	wire_sync_write(MASTER_FD,
			take(towire_channel_got_funding_locked(NULL,
						&peer->remote_per_commit)));

	channel_announcement_negotiate(peer);
	billboard_update(peer);
}

static void handle_peer_announcement_signatures(struct peer *peer, const u8 *msg)
{
	struct channel_id chanid;

	if (!fromwire_announcement_signatures(msg,
					      &chanid,
					      &peer->short_channel_ids[REMOTE],
					      &peer->announcement_node_sigs[REMOTE],
					      &peer->announcement_bitcoin_sigs[REMOTE]))
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad announcement_signatures %s",
			    tal_hex(msg, msg));

	/* Make sure we agree on the channel ids */
	if (!structeq(&chanid, &peer->channel_id)) {
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Wrong channel_id: expected %s, got %s",
			    type_to_string(tmpctx, struct channel_id,
					   &peer->channel_id),
			    type_to_string(tmpctx, struct channel_id, &chanid));
	}

	peer->have_sigs[REMOTE] = true;
	billboard_update(peer);

	channel_announcement_negotiate(peer);
}

static bool get_shared_secret(const struct htlc *htlc,
			      struct secret *shared_secret)
{
	struct pubkey ephemeral;
	struct onionpacket *op;
	u8 *msg;

	/* We unwrap the onion now. */
	op = parse_onionpacket(tmpctx, htlc->routing, TOTAL_PACKET_SIZE);
	if (!op) {
		/* Return an invalid shared secret. */
		memset(shared_secret, 0, sizeof(*shared_secret));
		return false;
	}

	/* Because wire takes struct pubkey. */
	ephemeral.pubkey = op->ephemeralkey;
	msg = towire_hsm_ecdh_req(tmpctx, &ephemeral);
	if (!wire_sync_write(HSM_FD, msg))
		status_failed(STATUS_FAIL_HSM_IO, "Writing ecdh req");
	msg = wire_sync_read(tmpctx, HSM_FD);
	/* Gives all-zero shares_secret if it was invalid. */
	if (!msg || !fromwire_hsm_ecdh_resp(msg, shared_secret))
		status_failed(STATUS_FAIL_HSM_IO, "Reading ecdh response");

	return !memeqzero(shared_secret, sizeof(*shared_secret));
}

static void handle_peer_add_htlc(struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 id;
	u64 amount_msat;
	u32 cltv_expiry;
	struct sha256 payment_hash;
	u8 onion_routing_packet[TOTAL_PACKET_SIZE];
	enum channel_add_err add_err;
	struct htlc *htlc;

	if (!fromwire_update_add_htlc(msg, &channel_id, &id, &amount_msat,
				      &payment_hash, &cltv_expiry,
				      onion_routing_packet))
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad peer_add_htlc %s", tal_hex(msg, msg));

	add_err = channel_add_htlc(peer->channel, REMOTE, id, amount_msat,
				   cltv_expiry, &payment_hash,
				   onion_routing_packet, &htlc);
	if (add_err != CHANNEL_ERR_ADD_OK)
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad peer_add_htlc: %s",
			    channel_add_err_name(add_err));

	/* If this is wrong, we don't complain yet; when it's confirmed we'll
	 * send it to the master which handles all HTLC failures. */
	htlc->shared_secret = tal(htlc, struct secret);
	get_shared_secret(htlc, htlc->shared_secret);
}

static void handle_peer_feechange(struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u32 feerate;

	if (!fromwire_update_fee(msg, &channel_id, &feerate)) {
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad update_fee %s", tal_hex(msg, msg));
	}

	/* BOLT #2:
	 *
	 * A receiving node:
	 *...
	 *  - if the sender is not responsible for paying the Bitcoin fee:
	 *    - MUST fail the channel.
	 */
	if (peer->channel->funder != REMOTE)
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "update_fee from non-funder?");

	status_trace("update_fee %u, range %u-%u",
		     feerate, peer->feerate_min, peer->feerate_max);

	/* BOLT #2:
	 *
	 * A receiving node:
	 *   - if the `update_fee` is too low for timely processing, OR is
	 *     unreasonably large:
	 *     - SHOULD fail the channel.
	 */
	if (feerate < peer->feerate_min || feerate > peer->feerate_max)
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "update_fee %u outside range %u-%u",
			    feerate, peer->feerate_min, peer->feerate_max);

	/* BOLT #2:
	 *
	 *  - if the sender cannot afford the new fee rate on the receiving
	 *    node's current commitment transaction:
	 *    - SHOULD fail the channel,
	 *      - but MAY delay this check until the `update_fee` is committed.
	 */
	if (!channel_update_feerate(peer->channel, feerate))
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "update_fee %u unaffordable",
			    feerate);

	status_trace("peer updated fee to %u", feerate);
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
				 u32 remote_feerate,
				 const struct htlc **changed_htlcs,
				 const secp256k1_ecdsa_signature *commit_sig,
				 const secp256k1_ecdsa_signature *htlc_sigs)
{
	struct changed_htlc *changed;
	u8 *msg;

	/* We tell master what (of our) HTLCs peer will now be
	 * committed to. */
	changed = changed_htlc_arr(tmpctx, changed_htlcs);
	msg = towire_channel_sending_commitsig(ctx, remote_commit_index,
					       remote_feerate,
					       changed, commit_sig, htlc_sigs);
	return msg;
}

static bool shutdown_complete(const struct peer *peer)
{
	return peer->shutdown_sent[LOCAL]
		&& peer->shutdown_sent[REMOTE]
		&& num_channel_htlcs(peer->channel) == 0
		/* We could be awaiting revoke-and-ack for a feechange */
		&& peer->revocations_received == peer->next_index[REMOTE] - 1;

}

/* BOLT #2:
 *
 * A sending node:
 *...
 *  - if there are updates pending on the receiving node's commitment
 *    transaction:
 *     - MUST NOT send a `shutdown`.
 */
/* So we only call this after reestablish or immediately after sending commit */
static void maybe_send_shutdown(struct peer *peer)
{
	u8 *msg;

	if (!peer->send_shutdown)
		return;

	/* Send a disable channel_update so others don't try to route
	 * over us */
	send_channel_update(peer, ROUTING_FLAGS_DISABLED);

	msg = towire_shutdown(NULL, &peer->channel_id, peer->final_scriptpubkey);
	enqueue_peer_msg(peer, take(msg));
	peer->send_shutdown = false;
	peer->shutdown_sent[LOCAL] = true;
	billboard_update(peer);
}

/* This queues other traffic from the fd until we get reply. */
static u8 *wait_sync_reply(const tal_t *ctx,
			   const u8 *msg,
			   int replytype,
			   int fd,
			   struct msg_queue *queue,
			   const char *who)
{
	u8 *reply;

	status_trace("Sending %s %u", who, fromwire_peektype(msg));

	if (!wire_sync_write(fd, msg))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not set sync write to %s: %s",
			      who, strerror(errno));

	status_trace("... , awaiting %u", replytype);

	for (;;) {
		reply = wire_sync_read(ctx, fd);
		if (!reply)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not set sync read from %s: %s",
				      who, strerror(errno));
		if (fromwire_peektype(reply) == replytype) {
			status_trace("Got it!");
			break;
		}

		status_trace("Nope, got %u instead", fromwire_peektype(reply));
		msg_enqueue(queue, take(reply));
	}

	return reply;
}

static u8 *master_wait_sync_reply(const tal_t *ctx,
				  struct peer *peer, const u8 *msg,
				  enum channel_wire_type replytype)
{
	return wait_sync_reply(ctx, msg, replytype,
			       MASTER_FD, &peer->from_master, "master");
}

static u8 *gossipd_wait_sync_reply(const tal_t *ctx,
				   struct peer *peer, const u8 *msg,
				   enum gossip_wire_type replytype)
{
	return wait_sync_reply(ctx, msg, replytype,
			       GOSSIP_FD, &peer->from_gossipd, "gossipd");
}

static struct commit_sigs *calc_commitsigs(const tal_t *ctx,
					   const struct peer *peer,
					   u64 commit_index)
{
	size_t i;
	struct bitcoin_tx **txs;
	const u8 **wscripts;
	const struct htlc **htlc_map;
	struct pubkey local_htlckey;
	struct privkey local_htlcsecretkey;
	struct commit_sigs *commit_sigs = tal(ctx, struct commit_sigs);

	if (!derive_simple_privkey(&peer->our_secrets.htlc_basepoint_secret,
				   &peer->channel->basepoints[LOCAL].htlc,
				   &peer->remote_per_commit,
				   &local_htlcsecretkey))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving local_htlcsecretkey");

	if (!derive_simple_key(&peer->channel->basepoints[LOCAL].htlc,
			       &peer->remote_per_commit,
			       &local_htlckey))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving local_htlckey");

	status_trace("Derived key %s from basepoint %s, point %s",
		     type_to_string(tmpctx, struct pubkey, &local_htlckey),
		     type_to_string(tmpctx, struct pubkey,
				    &peer->channel->basepoints[LOCAL].htlc),
		     type_to_string(tmpctx, struct pubkey,
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
		     type_to_string(tmpctx, secp256k1_ecdsa_signature,
				    &commit_sigs->commit_sig),
		     type_to_string(tmpctx, struct bitcoin_tx, txs[0]),
		     tal_hex(tmpctx, wscripts[0]),
		     type_to_string(tmpctx, struct pubkey,
				    &peer->channel->funding_pubkey[LOCAL]));
	dump_htlcs(peer->channel, "Sending commit_sig");

	/* BOLT #2:
	 *
	 * A sending node:
	 *...
	 *  - MUST include one `htlc_signature` for every HTLC transaction
	 *    corresponding to BIP69 lexicographic ordering of the commitment
	 *    transaction.
	 */
	commit_sigs->htlc_sigs = tal_arr(commit_sigs, secp256k1_ecdsa_signature,
					 tal_count(txs) - 1);

	for (i = 0; i < tal_count(commit_sigs->htlc_sigs); i++) {
		sign_tx_input(txs[1 + i], 0,
			      NULL,
			      wscripts[1 + i],
			      &local_htlcsecretkey, &local_htlckey,
			      &commit_sigs->htlc_sigs[i]);
		status_trace("Creating HTLC signature %s for tx %s wscript %s key %s",
			     type_to_string(tmpctx, secp256k1_ecdsa_signature,
					    &commit_sigs->htlc_sigs[i]),
			     type_to_string(tmpctx, struct bitcoin_tx, txs[1+i]),
			     tal_hex(tmpctx, wscripts[1+i]),
			     type_to_string(tmpctx, struct pubkey,
					    &local_htlckey));
		assert(check_tx_sig(txs[1+i], 0, NULL, wscripts[1+i],
				    &local_htlckey,
				    &commit_sigs->htlc_sigs[i]));
	}

	return commit_sigs;
}

static void send_commit(struct peer *peer)
{
	u8 *msg;
	const struct htlc **changed_htlcs;

#if DEVELOPER
	/* Hack to suppress all commit sends if dev_disconnect says to */
	if (dev_suppress_commit) {
		peer->commit_timer = NULL;
		return;
	}
#endif

	/* FIXME: Document this requirement in BOLT 2! */
	/* We can't send two commits in a row. */
	if (peer->revocations_received != peer->next_index[REMOTE] - 1) {
		assert(peer->revocations_received
		       == peer->next_index[REMOTE] - 2);
		peer->commit_timer_attempts++;
		/* Only report this in extreme cases */
		if (peer->commit_timer_attempts % 100 == 0)
			status_trace("Can't send commit:"
				     " waiting for revoke_and_ack with %"
				     PRIu64" attempts",
				     peer->commit_timer_attempts);
		/* Mark this as done and try again. */
		peer->commit_timer = NULL;
		start_commit_timer(peer);
		return;
	}

	/* BOLT #2:
	 *
	 *   - if no HTLCs remain in either commitment transaction:
	 *	- MUST NOT send any `update` message after a `shutdown`.
	 */
	if (peer->shutdown_sent[LOCAL] && !num_channel_htlcs(peer->channel)) {
		status_trace("Can't send commit: final shutdown phase");

		peer->commit_timer = NULL;
		return;
	}

	/* If we wanted to update fees, do it now. */
	if (peer->channel->funder == LOCAL
	    && peer->desired_feerate != channel_feerate(peer->channel, REMOTE)) {
		u8 *msg;
		u32 feerate, max = approx_max_feerate(peer->channel);

		feerate = peer->desired_feerate;

		/* FIXME: We should avoid adding HTLCs until we can meet this
		 * feerate! */
		if (feerate > max)
			feerate = max;

		if (!channel_update_feerate(peer->channel, feerate))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not afford feerate %u"
				      " (vs max %u)",
				      feerate, max);

		msg = towire_update_fee(NULL, &peer->channel_id, feerate);
		enqueue_peer_msg(peer, take(msg));
	}

	/* BOLT #2:
	 *
	 * A sending node:
	 *   - MUST NOT send a `commitment_signed` message that does not include
	 *     any updates.
	 */
	changed_htlcs = tal_arr(tmpctx, const struct htlc *, 0);
	if (!channel_sending_commit(peer->channel, &changed_htlcs)) {
		status_trace("Can't send commit: nothing to send");

		/* Covers the case where we've just been told to shutdown. */
		maybe_send_shutdown(peer);

		peer->commit_timer = NULL;
		return;
	}

	peer->next_commit_sigs = calc_commitsigs(peer, peer,
						 peer->next_index[REMOTE]);

	status_trace("Telling master we're about to commit...");
	/* Tell master to save this next commit to database, then wait. */
	msg = sending_commitsig_msg(NULL, peer->next_index[REMOTE],
				    channel_feerate(peer->channel, REMOTE),
				    changed_htlcs,
				    &peer->next_commit_sigs->commit_sig,
				    peer->next_commit_sigs->htlc_sigs);
	/* Message is empty; receiving it is the point. */
	master_wait_sync_reply(tmpctx, peer, take(msg),
			       WIRE_CHANNEL_SENDING_COMMITSIG_REPLY);

	status_trace("Sending commit_sig with %zu htlc sigs",
		     tal_count(peer->next_commit_sigs->htlc_sigs));

	peer->next_index[REMOTE]++;

	msg = towire_commitment_signed(NULL, &peer->channel_id,
				       &peer->next_commit_sigs->commit_sig,
				       peer->next_commit_sigs->htlc_sigs);
	enqueue_peer_msg(peer, take(msg));
	peer->next_commit_sigs = tal_free(peer->next_commit_sigs);

	maybe_send_shutdown(peer);

	/* Timer now considered expired, you can add a new one. */
	peer->commit_timer = NULL;
	start_commit_timer(peer);
}

static void start_commit_timer(struct peer *peer)
{
	/* Already armed? */
	if (peer->commit_timer)
		return;

	peer->commit_timer_attempts = 0;
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
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Invalid point %"PRIu64" for commit_point",
			      revoke_index);

	status_trace("Sending revocation #%"PRIu64" for %s",
		     revoke_index,
		     type_to_string(tmpctx, struct pubkey, &oldpoint));

	if (!pubkey_eq(&point, &oldpoint))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Invalid secret %s for commit_point",
			      tal_hexstr(tmpctx, &old_commit_secret,
					 sizeof(old_commit_secret)));

	/* We're revoking N-1th commit, sending N+1th point. */
	if (!per_commit_point(&peer->shaseed, &point, revoke_index+2))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving next commit_point");

	return towire_revoke_and_ack(peer, &peer->channel_id, &old_commit_secret,
				     &point);
}

static void send_revocation(struct peer *peer)
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

	enqueue_peer_msg(peer, take(msg));
}

static u8 *got_commitsig_msg(const tal_t *ctx,
			     u64 local_commit_index,
			     u32 local_feerate,
			     const secp256k1_ecdsa_signature *commit_sig,
			     const secp256k1_ecdsa_signature *htlc_sigs,
			     const struct htlc **changed_htlcs,
			     const struct bitcoin_tx *committx)
{
	struct changed_htlc *changed;
	struct fulfilled_htlc *fulfilled;
	const struct failed_htlc **failed;
	struct added_htlc *added;
	struct secret *shared_secret;
	u8 *msg;

	changed = tal_arr(tmpctx, struct changed_htlc, 0);
	added = tal_arr(tmpctx, struct added_htlc, 0);
	shared_secret = tal_arr(tmpctx, struct secret, 0);
	failed = tal_arr(tmpctx, const struct failed_htlc *, 0);
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
			*s = *htlc->shared_secret;
		} else if (htlc->state == RCVD_REMOVE_COMMIT) {
			if (htlc->r) {
				struct fulfilled_htlc *f;
				assert(!htlc->fail);
				f = tal_arr_append(&fulfilled);
				f->id = htlc->id;
				f->payment_preimage = *htlc->r;
			} else {
				struct failed_htlc **f;
				assert(htlc->fail);
				f = tal_arr_append(&failed);
				*f = tal(failed, struct failed_htlc);
				(*f)->id = htlc->id;
				(*f)->malformed = htlc->malformed;
				(*f)->failreason = cast_const(u8 *, htlc->fail);
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
					   local_feerate,
					   commit_sig,
					   htlc_sigs,
					   added,
					   shared_secret,
					   fulfilled,
					   failed,
					   changed,
					   committx);
	return msg;
}

static void handle_peer_commit_sig(struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	secp256k1_ecdsa_signature commit_sig, *htlc_sigs;
	struct pubkey remote_htlckey, point;
	struct bitcoin_tx **txs;
	const struct htlc **htlc_map, **changed_htlcs;
	const u8 **wscripts;
	size_t i;

	changed_htlcs = tal_arr(msg, const struct htlc *, 0);
	if (!channel_rcvd_commit(peer->channel, &changed_htlcs)) {
		/* BOLT #2:
		 *
		 * A sending node:
		 *   - MUST NOT send a `commitment_signed` message that does not
		 *     include any updates.
		 */
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "commit_sig with no changes");
	}

	/* We were supposed to check this was affordable as we go. */
	if (peer->channel->funder == REMOTE)
		assert(can_funder_afford_feerate(peer->channel,
						 peer->channel->view[LOCAL]
						 .feerate_per_kw));

	if (!fromwire_commitment_signed(tmpctx, msg,
					&channel_id, &commit_sig, &htlc_sigs))
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad commit_sig %s", tal_hex(msg, msg));

	if (!per_commit_point(&peer->shaseed, &point,
			      peer->next_index[LOCAL]))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving per_commit_point for %"PRIu64,
			      peer->next_index[LOCAL]);

	txs = channel_txs(tmpctx, &htlc_map, &wscripts, peer->channel,
			  &point, peer->next_index[LOCAL], LOCAL);

	if (!derive_simple_key(&peer->channel->basepoints[REMOTE].htlc,
			       &point, &remote_htlckey))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving remote_htlckey");
	status_trace("Derived key %s from basepoint %s, point %s",
		     type_to_string(tmpctx, struct pubkey, &remote_htlckey),
		     type_to_string(tmpctx, struct pubkey,
				    &peer->channel->basepoints[REMOTE].htlc),
		     type_to_string(tmpctx, struct pubkey, &point));
	/* BOLT #2:
	 *
	 * A receiving node:
	 *  - once all pending updates are applied:
	 *    - if `signature` is not valid for its local commitment transaction:
	 *      - MUST fail the channel.
	 */
	if (!check_tx_sig(txs[0], 0, NULL, wscripts[0],
			  &peer->channel->funding_pubkey[REMOTE], &commit_sig)) {
		dump_htlcs(peer->channel, "receiving commit_sig");
		peer_failed(&peer->cs,
			    &peer->channel_id,
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
	 * A receiving node:
	 *...
	 *    - if `num_htlcs` is not equal to the number of HTLC outputs in the
	 * local commitment transaction:
	 *      - MUST fail the channel.
	 */
	if (tal_count(htlc_sigs) != tal_count(txs) - 1)
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Expected %zu htlc sigs, not %zu",
			    tal_count(txs) - 1, tal_count(htlc_sigs));

	/* BOLT #2:
	 *
	 *   - if any `htlc_signature` is not valid for the corresponding HTLC
	 *     transaction:
	 *     - MUST fail the channel.
	 */
	for (i = 0; i < tal_count(htlc_sigs); i++) {
		if (!check_tx_sig(txs[1+i], 0, NULL, wscripts[1+i],
				  &remote_htlckey, &htlc_sigs[i]))
			peer_failed(&peer->cs,
				    &peer->channel_id,
				    "Bad commit_sig signature %s for htlc %s wscript %s key %s",
				    type_to_string(msg, secp256k1_ecdsa_signature, &htlc_sigs[i]),
				    type_to_string(msg, struct bitcoin_tx, txs[1+i]),
				    tal_hex(msg, wscripts[1+i]),
				    type_to_string(msg, struct pubkey,
						   &remote_htlckey));
	}

	status_trace("Received commit_sig with %zu htlc sigs",
		     tal_count(htlc_sigs));

	/* Tell master daemon, then wait for ack. */
	msg = got_commitsig_msg(NULL, peer->next_index[LOCAL],
				channel_feerate(peer->channel, LOCAL),
				&commit_sig, htlc_sigs, changed_htlcs, txs[0]);

	master_wait_sync_reply(tmpctx, peer, take(msg),
			       WIRE_CHANNEL_GOT_COMMITSIG_REPLY);
	return send_revocation(peer);
}

static u8 *got_revoke_msg(const tal_t *ctx, u64 revoke_num,
			  const struct sha256 *per_commitment_secret,
			  const struct pubkey *next_per_commit_point,
			  const struct htlc **changed_htlcs)
{
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
	return msg;
}

static void handle_peer_revoke_and_ack(struct peer *peer, const u8 *msg)
{
	struct sha256 old_commit_secret;
	struct privkey privkey;
	struct channel_id channel_id;
	struct pubkey per_commit_point, next_per_commit;
	const struct htlc **changed_htlcs = tal_arr(msg, const struct htlc *, 0);

	if (!fromwire_revoke_and_ack(msg, &channel_id, &old_commit_secret,
				     &next_per_commit)) {
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad revoke_and_ack %s", tal_hex(msg, msg));
	}

	if (peer->revocations_received != peer->next_index[REMOTE] - 2) {
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Unexpected revoke_and_ack");
	}

	/* BOLT #2:
	 *
	 * A receiving node:
	 *  - if `per_commitment_secret` does not generate the previous
	 *   `per_commitment_point`:
	 *    - MUST fail the channel.
	 */
	memcpy(&privkey, &old_commit_secret, sizeof(privkey));
	if (!pubkey_from_privkey(&privkey, &per_commit_point)) {
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad privkey %s",
			    type_to_string(msg, struct privkey, &privkey));
	}
	if (!pubkey_eq(&per_commit_point, &peer->old_remote_per_commit)) {
		peer_failed(&peer->cs,
			    &peer->channel_id,
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
	msg = got_revoke_msg(NULL, peer->revocations_received++,
			     &old_commit_secret, &next_per_commit,
			     changed_htlcs);
	master_wait_sync_reply(tmpctx, peer, take(msg),
			       WIRE_CHANNEL_GOT_REVOKE_REPLY);

	peer->old_remote_per_commit = peer->remote_per_commit;
	peer->remote_per_commit = next_per_commit;
	status_trace("revoke_and_ack %s: remote_per_commit = %s, old_remote_per_commit = %s",
		     side_to_str(peer->channel->funder),
		     type_to_string(tmpctx, struct pubkey,
				    &peer->remote_per_commit),
		     type_to_string(tmpctx, struct pubkey,
				    &peer->old_remote_per_commit));

	start_commit_timer(peer);
}

static void handle_peer_fulfill_htlc(struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 id;
	struct preimage preimage;
	enum channel_remove_err e;

	if (!fromwire_update_fulfill_htlc(msg, &channel_id,
					  &id, &preimage)) {
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad update_fulfill_htlc %s", tal_hex(msg, msg));
	}

	e = channel_fulfill_htlc(peer->channel, LOCAL, id, &preimage);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK:
		/* FIXME: We could send preimages to master immediately. */
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
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad update_fulfill_htlc: failed to fulfill %"
			    PRIu64 " error %s", id, channel_remove_err_name(e));
	}
	abort();
}

static void handle_peer_fail_htlc(struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 id;
	enum channel_remove_err e;
	u8 *reason;
	struct htlc *htlc;

	if (!fromwire_update_fail_htlc(msg, msg,
				       &channel_id, &id, &reason)) {
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad update_fulfill_htlc %s", tal_hex(msg, msg));
	}

	e = channel_fail_htlc(peer->channel, LOCAL, id, NULL);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK:
		/* Save reason for when we tell master. */
		htlc = channel_get_htlc(peer->channel, LOCAL, id);
		htlc->fail = tal_steal(htlc, reason);
		start_commit_timer(peer);
		return;
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad update_fail_htlc: failed to remove %"
			    PRIu64 " error %s", id,
			    channel_remove_err_name(e));
	}
	abort();
}

static void handle_peer_fail_malformed_htlc(struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 id;
	enum channel_remove_err e;
	struct sha256 sha256_of_onion;
	u16 failure_code;
	struct htlc *htlc;
	u8 *fail;

	if (!fromwire_update_fail_malformed_htlc(msg, &channel_id, &id,
						 &sha256_of_onion,
						 &failure_code)) {
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad update_fail_malformed_htlc %s",
			    tal_hex(msg, msg));
	}

	/* BOLT #2:
	 *
	 *   - if the `BADONION` bit in `failure_code` is not set for
	 *    `update_fail_malformed_htlc`:
	 *      - MUST fail the channel.
	 */
	if (!(failure_code & BADONION)) {
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad update_fail_malformed_htlc failure code %u",
			    failure_code);
	}

	e = channel_fail_htlc(peer->channel, LOCAL, id, &htlc);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK:
		/* FIXME: Do this! */
		/* BOLT #2:
		 *
		 *   - if the `sha256_of_onion` in `update_fail_malformed_htlc`
		 *     doesn't match the onion it sent:
		 *    - MAY retry or choose an alternate error response.
		 */

		/* BOLT #2:
		 *
		 *  - otherwise, a receiving node which has an outgoing HTLC
		 * canceled by `update_fail_malformed_htlc`:
		 *
		 *    - MUST return an error in the `update_fail_htlc` sent to
		 *      the link which originally sent the HTLC, using the
		 *      `failure_code` given and setting the data to
		 *      `sha256_of_onion`.
		 */
		fail = tal_arr(htlc, u8, 0);
		towire_u16(&fail, failure_code);
		towire_sha256(&fail, &sha256_of_onion);
		htlc->fail = fail;
		start_commit_timer(peer);
		return;
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad update_fail_malformed_htlc: failed to remove %"
			    PRIu64 " error %s", id, channel_remove_err_name(e));
	}
	abort();
}

static void handle_pong(struct peer *peer, const u8 *pong)
{
	const char *err = got_pong(pong, &peer->num_pings_outstanding);
	if (err)
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "%s", err);

	wire_sync_write(MASTER_FD,
			take(towire_channel_ping_reply(NULL, tal_len(pong))));
}

static void handle_peer_shutdown(struct peer *peer, const u8 *shutdown)
{
	struct channel_id channel_id;
	u8 *scriptpubkey;

	/* Disable the channel. */
	send_channel_update(peer, ROUTING_FLAGS_DISABLED);

	if (!fromwire_shutdown(peer, shutdown, &channel_id, &scriptpubkey))
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "Bad shutdown %s", tal_hex(peer, shutdown));

	/* Tell master: we don't have to wait because on reconnect other end
	 * will re-send anyway. */
	wire_sync_write(MASTER_FD,
			take(towire_channel_got_shutdown(NULL, scriptpubkey)));

	peer->shutdown_sent[REMOTE] = true;
	/* BOLT #2:
	 *
	 * A receiving node:
	 * ...
	 * - once there are no outstanding updates on the peer, UNLESS
	 *   it has already sent a `shutdown`:
	 *    - MUST reply to a `shutdown` message with a `shutdown`
	 */
	if (!peer->shutdown_sent[LOCAL]) {
		peer->send_shutdown = true;
		start_commit_timer(peer);
	}
	billboard_update(peer);
}

/* Note: msg came from read_peer_msg() which handles pings, gossip,
 * wrong channel, errors */
static void peer_in(struct peer *peer, const u8 *msg)
{
	enum wire_type type = fromwire_peektype(msg);

	/* Must get funding_locked before almost anything. */
	if (!peer->funding_locked[REMOTE]) {
		if (type != WIRE_FUNDING_LOCKED
		    && type != WIRE_PONG
		    && type != WIRE_SHUTDOWN) {
			peer_failed(&peer->cs,
				    &peer->channel_id,
				    "%s (%u) before funding locked",
				    wire_type_name(type), type);
		}
	}

	switch (type) {
	case WIRE_FUNDING_LOCKED:
		handle_peer_funding_locked(peer, msg);
		return;
	case WIRE_ANNOUNCEMENT_SIGNATURES:
		handle_peer_announcement_signatures(peer, msg);
		return;
	case WIRE_UPDATE_ADD_HTLC:
		handle_peer_add_htlc(peer, msg);
		return;
	case WIRE_COMMITMENT_SIGNED:
		handle_peer_commit_sig(peer, msg);
		return;
	case WIRE_UPDATE_FEE:
		handle_peer_feechange(peer, msg);
		return;
	case WIRE_REVOKE_AND_ACK:
		handle_peer_revoke_and_ack(peer, msg);
		return;
	case WIRE_UPDATE_FULFILL_HTLC:
		handle_peer_fulfill_htlc(peer, msg);
		return;
	case WIRE_UPDATE_FAIL_HTLC:
		handle_peer_fail_htlc(peer, msg);
		return;
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
		handle_peer_fail_malformed_htlc(peer, msg);
		return;
	case WIRE_PONG:
		handle_pong(peer, msg);
		return;
	case WIRE_SHUTDOWN:
		handle_peer_shutdown(peer, msg);
		return;

	case WIRE_INIT:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_CHANNEL_REESTABLISH:
	case WIRE_CLOSING_SIGNED:
		break;

	/* These are all swallowed by read_peer_msg */
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
	case WIRE_QUERY_CHANNEL_RANGE:
	case WIRE_REPLY_CHANNEL_RANGE:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
	case WIRE_PING:
	case WIRE_ERROR:
		abort();
	}

	peer_failed(&peer->cs,
		    &peer->channel_id,
		    "Peer sent unknown message %u (%s)",
		    type, wire_type_name(type));
}

static void peer_conn_broken(struct peer *peer)
{
	/* If we have signatures, send an update to say we're disabled. */
	send_channel_update(peer, ROUTING_FLAGS_DISABLED);
	peer_failed_connection_lost();
}

static void resend_revoke(struct peer *peer)
{
	/* Current commit is peer->next_index[LOCAL]-1, revoke prior */
	u8 *msg = make_revocation_msg(peer, peer->next_index[LOCAL]-2);
	enqueue_peer_msg(peer, take(msg));
}

static void send_fail_or_fulfill(struct peer *peer, const struct htlc *h)
{
	u8 *msg;
	if (h->malformed) {
		struct sha256 sha256_of_onion;
		sha256(&sha256_of_onion, h->routing, tal_len(h->routing));

		msg = towire_update_fail_malformed_htlc(NULL, &peer->channel_id,
							h->id, &sha256_of_onion,
							h->malformed);
	} else if (h->fail) {
		msg = towire_update_fail_htlc(NULL, &peer->channel_id, h->id,
					      h->fail);
	} else if (h->r) {
		msg = towire_update_fulfill_htlc(NULL, &peer->channel_id, h->id,
						 h->r);
	} else
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "HTLC %"PRIu64" state %s not failed/fulfilled",
			    h->id, htlc_state_name(h->state));
	enqueue_peer_msg(peer, take(msg));
}

static void resend_commitment(struct peer *peer, const struct changed_htlc *last)
{
	size_t i;
	struct commit_sigs *commit_sigs;
	u8 *msg;

	/* BOLT #2:
	 *
	 *   - if `next_local_commitment_number` is equal to the commitment
	 *     number of the last `commitment_signed` message the receiving node
	 *     has sent:
	 *     - MUST reuse the same commitment number for its next
	 *       `commitment_signed`.
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
			peer_failed(&peer->cs,
				    &peer->channel_id,
				    "Can't find HTLC %"PRIu64" to resend",
				    last[i].id);

		if (h->state == SENT_ADD_COMMIT) {
			u8 *msg = towire_update_add_htlc(peer, &peer->channel_id,
							 h->id, h->msatoshi,
							 &h->rhash,
							 abs_locktime_to_blocks(
								 &h->expiry),
							 h->routing);
			enqueue_peer_msg(peer, take(msg));
		} else if (h->state == SENT_REMOVE_COMMIT) {
			send_fail_or_fulfill(peer, h);
		}
	}

	/* Make sure they have the correct fee. */
	if (peer->channel->funder == LOCAL) {
		msg = towire_update_fee(NULL, &peer->channel_id,
					channel_feerate(peer->channel, REMOTE));
		enqueue_peer_msg(peer, take(msg));
	}

	/* Re-send the commitment_signed itself. */
	commit_sigs = calc_commitsigs(peer, peer, peer->next_index[REMOTE]-1);
	msg = towire_commitment_signed(NULL, &peer->channel_id,
				       &commit_sigs->commit_sig,
				       commit_sigs->htlc_sigs);
	enqueue_peer_msg(peer, take(msg));
	tal_free(commit_sigs);

	/* If we have already received the revocation for the previous, the
	 * other side shouldn't be asking for a retransmit! */
	if (peer->revocations_received != peer->next_index[REMOTE] - 2)
		status_unusual("Retransmitted commitment_signed %"PRIu64
			       " but they already send revocation %"PRIu64"?",
			       peer->next_index[REMOTE]-1,
			       peer->revocations_received);
}

/* Our local wrapper around read_peer_msg */
static void channeld_io_error(struct peer *peer)
{
	peer_conn_broken(peer);
}

static bool channeld_send_reply(struct crypto_state *cs UNUSED,
			    int peer_fd UNUSED,
			    const u8 *msg UNUSED,
			    struct peer *peer)
{
	enqueue_peer_msg(peer, msg);
	return true;
}

static u8 *channeld_read_peer_msg(struct peer *peer)
{
	return read_peer_msg(peer, &peer->cs,
			     &peer->channel_id,
			     channeld_send_reply,
			     channeld_io_error,
			     peer);
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
	 *   - upon reconnection:
	 *     - if a channel is in an error state:
	 *       - SHOULD retransmit the error packet and ignore any other packets for
	 *        that channel.
	 *     - otherwise:
	 *       - MUST transmit `channel_reestablish` for each channel.
	 *       - MUST wait to receive the other node's `channel_reestablish`
	 *         message before sending any other messages for that channel.
	 *
	 * The sending node:
	 *   - MUST set `next_local_commitment_number` to the commitment number
	 *     of the next `commitment_signed` it expects to receive.
	 *   - MUST set `next_remote_revocation_number` to the commitment number
	 *     of the next `revoke_and_ack` message it expects to receive.
	 */
	msg = towire_channel_reestablish(NULL, &peer->channel_id,
					 peer->next_index[LOCAL],
					 peer->revocations_received);
	if (!sync_crypto_write(&peer->cs, PEER_FD, take(msg)))
		peer_failed_connection_lost();

	peer_billboard(false, "Sent reestablish, waiting for theirs");

	/* Read until they say something interesting */
	while ((msg = channeld_read_peer_msg(peer)) == NULL)
		clean_tmpctx();

	if (!fromwire_channel_reestablish(msg, &channel_id,
					  &next_local_commitment_number,
					  &next_remote_revocation_number)) {
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "bad reestablish msg: %s %s",
			    wire_type_name(fromwire_peektype(msg)),
			    tal_hex(msg, msg));
	}

	status_trace("Got reestablish commit=%"PRIu64" revoke=%"PRIu64,
		     next_local_commitment_number,
		     next_remote_revocation_number);

	/* BOLT #2:
	 *
	 *   - if `next_local_commitment_number` is 1 in both the
	 *    `channel_reestablish` it sent and received:
	 *     - MUST retransmit `funding_locked`.
	 *   - otherwise:
	 *     - MUST NOT retransmit `funding_locked`.
	 */
	if (peer->funding_locked[LOCAL]
	    && peer->next_index[LOCAL] == 1
	    && next_local_commitment_number == 1) {
		u8 *msg;
		struct pubkey next_per_commit_point;

		/* Contains per commit point #1, for first post-opening commit */
		per_commit_point(&peer->shaseed, &next_per_commit_point, 1);
		msg = towire_funding_locked(NULL,
					    &peer->channel_id,
					    &next_per_commit_point);
		enqueue_peer_msg(peer, take(msg));
	}

	/* Note: next_index is the index of the current commit we're working
	 * on, but BOLT #2 refers to the *last* commit index, so we -1 where
	 * required. */

	/* BOLT #2:
	 *
	 *   - if `next_local_commitment_number` is equal to the commitment
	 *     number of the last `commitment_signed` message the receiving node
	 *     has sent:
	 *     - MUST reuse the same commitment number for its next
	 *      `commitment_signed`.
	 *   - otherwise:
	 *     - if `next_local_commitment_number` is not 1 greater than the
	 *       commitment number of the last `commitment_signed` message the
	 *       receiving node has sent:
	 *       - SHOULD fail the channel.
	 */
	if (next_remote_revocation_number == peer->next_index[LOCAL] - 2) {
		/* Don't try to retransmit revocation index -1! */
		if (peer->next_index[LOCAL] < 2) {
			peer_failed(&peer->cs,
				    &peer->channel_id,
				    "bad reestablish revocation_number: %"
				    PRIu64,
				    next_remote_revocation_number);
		}
		retransmit_revoke_and_ack = true;
	} else if (next_remote_revocation_number != peer->next_index[LOCAL] - 1) {
		peer_failed(&peer->cs,
			    &peer->channel_id,
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
	 *   - if `next_local_commitment_number` is equal to the commitment
	 *     number of the last `commitment_signed` message the receiving node
	 *     has sent:
	 *     - MUST reuse the same commitment number for its next
	 *       `commitment_signed`.
	 */
	if (next_local_commitment_number == peer->next_index[REMOTE] - 1) {
		/* We completed opening, we don't re-transmit that one! */
		if (next_local_commitment_number == 0)
			peer_failed(&peer->cs,
				    &peer->channel_id,
				    "bad reestablish commitment_number: %"
				    PRIu64,
				    next_local_commitment_number);

		resend_commitment(peer, peer->last_sent_commit);

	/* BOLT #2:
	 *
	 *   - otherwise:
	 *     - if `next_local_commitment_number` is not 1 greater than the
	 *       commitment number of the last `commitment_signed` message the
	 *       receiving node has sent:
	 *       - SHOULD fail the channel.
	 */
	} else if (next_local_commitment_number != peer->next_index[REMOTE])
		peer_failed(&peer->cs,
			    &peer->channel_id,
			    "bad reestablish commitment_number: %"PRIu64
			    " vs %"PRIu64,
			    next_local_commitment_number,
			    peer->next_index[REMOTE]);

	/* This covers the case where we sent revoke after commit. */
	if (retransmit_revoke_and_ack && peer->last_was_revoke)
		resend_revoke(peer);

	/* BOLT #2:
	 *
	 *   - upon reconnection:
	 *     - if it has sent a previous `shutdown`:
	 *       - MUST retransmit `shutdown`.
	 */
	/* (If we had sent `closing_signed`, we'd be in closingd). */
	maybe_send_shutdown(peer);

	/* Corner case: we didn't send shutdown before because update_add_htlc
	 * pending, but now they're cleared by restart, and we're actually
	 * complete.  In that case, their `shutdown` will trigger us. */

	/* Start commit timer: if we sent revoke we might need it. */
	start_commit_timer(peer);

	/* Now, re-send any that we're supposed to be failing. */
	for (htlc = htlc_map_first(peer->channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(peer->channel->htlcs, &it)) {
		if (htlc->state == SENT_REMOVE_HTLC)
			send_fail_or_fulfill(peer, htlc);
	}

	/* Reenable channel by sending a channel_update without the
	 * disable flag */
	channel_announcement_negotiate(peer);

	/* Corner case: we will get upset with them if they send
	 * commitment_signed with no changes.  But it could be that we sent a
	 * feechange, they acked, and now they want to commit it; we can't
	 * even tell by seeing if fees are different (short of saving full fee
	 * state in database) since it could be a tiny feechange, or two
	 * feechanges which cancelled out. */
	if (peer->channel->funder == LOCAL)
		peer->channel->changes_pending[LOCAL] = true;

	peer_billboard(true, "Reconnected, and reestablished.");
}

/* Funding has locked in, and reached depth. */
static void handle_funding_locked(struct peer *peer, const u8 *msg)
{
	unsigned int depth;

	if (!fromwire_channel_funding_locked(msg,
					     &peer->short_channel_ids[LOCAL],
					     &depth))
		master_badmsg(WIRE_CHANNEL_FUNDING_LOCKED, msg);

	/* Too late, we're shutting down! */
	if (peer->shutdown_sent[LOCAL])
		return;

	if (!peer->funding_locked[LOCAL]) {
		struct pubkey next_per_commit_point;

		per_commit_point(&peer->shaseed,
				 &next_per_commit_point,
				 peer->next_index[LOCAL]);

		status_trace("funding_locked: sending commit index %"PRIu64": %s",
			     peer->next_index[LOCAL],
			     type_to_string(tmpctx, struct pubkey, &next_per_commit_point));
		msg = towire_funding_locked(NULL,
					    &peer->channel_id, &next_per_commit_point);
		enqueue_peer_msg(peer, take(msg));
		peer->funding_locked[LOCAL] = true;
	}

	peer->announce_depth_reached = (depth >= ANNOUNCE_MIN_DEPTH);

	/* Send temporary or final announcements */
	channel_announcement_negotiate(peer);

	billboard_update(peer);
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
		status_failed(STATUS_FAIL_MASTER_IO,
			      "funding not locked for offer_htlc");

	if (!fromwire_channel_offer_htlc(inmsg, &amount_msat,
					 &cltv_expiry, &payment_hash,
					 onion_routing_packet))
		master_badmsg(WIRE_CHANNEL_OFFER_HTLC, inmsg);

	e = channel_add_htlc(peer->channel, LOCAL, peer->htlc_id,
			     amount_msat, cltv_expiry, &payment_hash,
			     onion_routing_packet, NULL);
	status_trace("Adding HTLC %"PRIu64" msat=%"PRIu64" cltv=%u gave %s",
		     peer->htlc_id, amount_msat, cltv_expiry,
		     channel_add_err_name(e));

	switch (e) {
	case CHANNEL_ERR_ADD_OK:
		/* Tell the peer. */
		msg = towire_update_add_htlc(NULL, &peer->channel_id,
					     peer->htlc_id, amount_msat,
					     &payment_hash, cltv_expiry,
					     onion_routing_packet);
		enqueue_peer_msg(peer, take(msg));
		start_commit_timer(peer);
		/* Tell the master. */
		msg = towire_channel_offer_htlc_reply(NULL, peer->htlc_id,
						      0, NULL);
		wire_sync_write(MASTER_FD, take(msg));
		peer->htlc_id++;
		return;
	case CHANNEL_ERR_INVALID_EXPIRY:
		failcode = WIRE_INCORRECT_CLTV_EXPIRY;
		failmsg = tal_fmt(inmsg, "Invalid cltv_expiry %u", cltv_expiry);
		goto failed;
	case CHANNEL_ERR_DUPLICATE:
	case CHANNEL_ERR_DUPLICATE_ID_DIFFERENT:
		status_failed(STATUS_FAIL_MASTER_IO,
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
	/* Note: tal_fmt doesn't set tal_len() to exact length, so fix here. */
	tal_resize(&failmsg, strlen(failmsg)+1);
	msg = towire_channel_offer_htlc_reply(NULL, 0, failcode, (u8*)failmsg);
	wire_sync_write(MASTER_FD, take(msg));
}

static void handle_feerates(struct peer *peer, const u8 *inmsg)
{
	u32 feerate;

	if (!fromwire_channel_feerates(inmsg, &feerate,
				       &peer->feerate_min,
				       &peer->feerate_max))
		master_badmsg(WIRE_CHANNEL_FEERATES, inmsg);

	/* BOLT #2:
	 *
	 * The node _responsible_ for paying the Bitcoin fee:
	 *   - SHOULD send `update_fee` to ensure the current fee rate is
	 *    sufficient (by a significant margin) for timely processing of the
	 *     commitment transaction.
	 */
	if (peer->channel->funder == LOCAL) {
		peer->desired_feerate = feerate;
		start_commit_timer(peer);
	} else {
		/* BOLT #2:
		 *
		 * The node _not responsible_ for paying the Bitcoin fee:
		 *  - MUST NOT send `update_fee`.
		 */
		/* FIXME: We could drop to chain if fees are too low, but
		 * that's fraught too. */
	}
}

static void handle_preimage(struct peer *peer, const u8 *inmsg)
{
	u8 *msg;
	u64 id;
	struct preimage preimage;

	if (!fromwire_channel_fulfill_htlc(inmsg, &id, &preimage))
		master_badmsg(WIRE_CHANNEL_FULFILL_HTLC, inmsg);

	switch (channel_fulfill_htlc(peer->channel, REMOTE, id, &preimage)) {
	case CHANNEL_ERR_REMOVE_OK:
		msg = towire_update_fulfill_htlc(NULL, &peer->channel_id,
						 id, &preimage);
		enqueue_peer_msg(peer, take(msg));
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
		status_failed(STATUS_FAIL_MASTER_IO,
			      "HTLC %"PRIu64" preimage failed", id);
	}
	abort();
}

static u8 *foreign_channel_update(const tal_t *ctx,
				  struct peer *peer,
				  const struct short_channel_id *scid)
{
	u8 *msg, *update;

	msg = towire_gossip_get_update(NULL, scid);
	msg = gossipd_wait_sync_reply(tmpctx, peer, take(msg),
				      WIRE_GOSSIP_GET_UPDATE_REPLY);
	if (!fromwire_gossip_get_update_reply(ctx, msg, &update))
		status_failed(STATUS_FAIL_GOSSIP_IO,
			      "Invalid update reply");
	return update;
}

static u8 *make_failmsg(const tal_t *ctx,
			struct peer *peer,
			const struct htlc *htlc,
			enum onion_type failcode,
			const struct short_channel_id *scid)
{
	u8 *msg, *channel_update = NULL;
	u32 cltv_expiry = abs_locktime_to_blocks(&htlc->expiry);

	switch (failcode) {
	case WIRE_INVALID_REALM:
		msg = towire_invalid_realm(ctx);
		goto done;
	case WIRE_TEMPORARY_NODE_FAILURE:
		msg = towire_temporary_node_failure(ctx);
		goto done;
	case WIRE_PERMANENT_NODE_FAILURE:
		msg = towire_permanent_node_failure(ctx);
		goto done;
	case WIRE_REQUIRED_NODE_FEATURE_MISSING:
		msg = towire_required_node_feature_missing(ctx);
		goto done;
	case WIRE_TEMPORARY_CHANNEL_FAILURE:
		channel_update = foreign_channel_update(ctx, peer, scid);
		msg = towire_temporary_channel_failure(ctx, channel_update);
		goto done;
	case WIRE_CHANNEL_DISABLED:
		msg = towire_channel_disabled(ctx);
		goto done;
	case WIRE_PERMANENT_CHANNEL_FAILURE:
		msg = towire_permanent_channel_failure(ctx);
		goto done;
	case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
		msg = towire_required_channel_feature_missing(ctx);
		goto done;
	case WIRE_UNKNOWN_NEXT_PEER:
		msg = towire_unknown_next_peer(ctx);
		goto done;
	case WIRE_AMOUNT_BELOW_MINIMUM:
		channel_update = foreign_channel_update(ctx, peer, scid);
		msg = towire_amount_below_minimum(ctx, htlc->msatoshi,
						  channel_update);
		goto done;
	case WIRE_FEE_INSUFFICIENT:
		channel_update = foreign_channel_update(ctx, peer, scid);
		msg = towire_fee_insufficient(ctx, htlc->msatoshi,
					      channel_update);
		goto done;
	case WIRE_INCORRECT_CLTV_EXPIRY:
		channel_update = foreign_channel_update(ctx, peer, scid);
		msg = towire_incorrect_cltv_expiry(ctx, cltv_expiry,
						   channel_update);
		goto done;
	case WIRE_EXPIRY_TOO_SOON:
		channel_update = foreign_channel_update(ctx, peer, scid);
		msg = towire_expiry_too_soon(ctx, channel_update);
		goto done;
	case WIRE_EXPIRY_TOO_FAR:
		msg = towire_expiry_too_far(ctx);
		goto done;
	case WIRE_UNKNOWN_PAYMENT_HASH:
		msg = towire_unknown_payment_hash(ctx);
		goto done;
	case WIRE_INCORRECT_PAYMENT_AMOUNT:
		msg = towire_incorrect_payment_amount(ctx);
		goto done;
	case WIRE_FINAL_EXPIRY_TOO_SOON:
		msg = towire_final_expiry_too_soon(ctx);
		goto done;
	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
		msg = towire_final_incorrect_cltv_expiry(ctx, cltv_expiry);
		goto done;
	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
		msg = towire_final_incorrect_htlc_amount(ctx, htlc->msatoshi);
		goto done;
	case WIRE_INVALID_ONION_VERSION:
	case WIRE_INVALID_ONION_HMAC:
	case WIRE_INVALID_ONION_KEY:
		break;
	}
	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "Asked to create failmsg %u (%s)",
		      failcode, onion_type_name(failcode));

done:
	tal_free(channel_update);
	return msg;
}

static void handle_fail(struct peer *peer, const u8 *inmsg)
{
	u8 *msg;
	u64 id;
	u8 *errpkt;
	u16 failcode;
	struct short_channel_id scid;
	enum channel_remove_err e;
	struct htlc *h;

	if (!fromwire_channel_fail_htlc(inmsg, inmsg, &id, &errpkt,
					&failcode, &scid))
		master_badmsg(WIRE_CHANNEL_FAIL_HTLC, inmsg);

	if (failcode && tal_len(errpkt))
		status_failed(STATUS_FAIL_MASTER_IO,
			      "Invalid channel_fail_htlc: %s with errpkt?",
			      onion_type_name(failcode));

	e = channel_fail_htlc(peer->channel, REMOTE, id, &h);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK:
		if (failcode & BADONION) {
			struct sha256 sha256_of_onion;
			status_trace("Failing %"PRIu64" with code %u",
				     id, failcode);
			sha256(&sha256_of_onion, h->routing,
			       tal_len(h->routing));
			msg = towire_update_fail_malformed_htlc(peer,
							&peer->channel_id,
							id, &sha256_of_onion,
							failcode);
		} else {
			u8 *reply;

			if (failcode) {
				u8 *failmsg = make_failmsg(inmsg, peer, h,
							   failcode, &scid);
				errpkt = create_onionreply(inmsg,
							   h->shared_secret,
							   failmsg);
			}

			reply = wrap_onionreply(inmsg, h->shared_secret,
						errpkt);
			msg = towire_update_fail_htlc(peer, &peer->channel_id,
						      id, reply);
		}
		enqueue_peer_msg(peer, take(msg));
		start_commit_timer(peer);
		return;
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		status_failed(STATUS_FAIL_MASTER_IO,
			      "HTLC %"PRIu64" removal failed: %s", id,
			      channel_remove_err_name(e));
	}
	abort();
}

static void handle_ping_cmd(struct peer *peer, const u8 *inmsg)
{
	u16 num_pong_bytes, ping_len;
	u8 *ping;

	if (!fromwire_channel_ping(inmsg, &num_pong_bytes, &ping_len))
		master_badmsg(WIRE_CHANNEL_PING, inmsg);

	ping = make_ping(NULL, num_pong_bytes, ping_len);
	if (tal_len(ping) > 65535)
		status_failed(STATUS_FAIL_MASTER_IO, "Oversize channel_ping");

	enqueue_peer_msg(peer, take(ping));

	status_trace("sending ping expecting %sresponse",
		     num_pong_bytes >= 65532 ? "no " : "");

	/* BOLT #1:
	 *
	 *   - if `num_pong_bytes` is less than 65532:
	 *     - MUST respond by sending a `pong` message, with `byteslen` equal
	 *       to `num_pong_bytes`.
	 *   - otherwise (`num_pong_bytes` is **not** less than 65532):
	 *     - MUST ignore the `ping`.
	 */
	if (num_pong_bytes >= 65532)
		wire_sync_write(MASTER_FD,
				take(towire_channel_ping_reply(NULL, 0)));
	else
		peer->num_pings_outstanding++;
}

static void handle_shutdown_cmd(struct peer *peer, const u8 *inmsg)
{
	if (!fromwire_channel_send_shutdown(inmsg))
		master_badmsg(WIRE_CHANNEL_SEND_SHUTDOWN, inmsg);

	/* We can't send this until commit (if any) is done, so start timer. */
	peer->send_shutdown = true;
	start_commit_timer(peer);
}

#if DEVELOPER
static void handle_dev_reenable_commit(struct peer *peer)
{
	dev_suppress_commit = false;
	start_commit_timer(peer);
	status_trace("dev_reenable_commit");
	wire_sync_write(MASTER_FD,
			take(towire_channel_dev_reenable_commit_reply(NULL)));
}
#endif

static void req_in(struct peer *peer, const u8 *msg)
{
	enum channel_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CHANNEL_FUNDING_LOCKED:
		handle_funding_locked(peer, msg);
		return;
	case WIRE_CHANNEL_OFFER_HTLC:
		handle_offer_htlc(peer, msg);
		return;
	case WIRE_CHANNEL_FEERATES:
		handle_feerates(peer, msg);
		return;
	case WIRE_CHANNEL_FULFILL_HTLC:
		handle_preimage(peer, msg);
		return;
	case WIRE_CHANNEL_FAIL_HTLC:
		handle_fail(peer, msg);
		return;
	case WIRE_CHANNEL_PING:
		handle_ping_cmd(peer, msg);
		return;
	case WIRE_CHANNEL_SEND_SHUTDOWN:
		handle_shutdown_cmd(peer, msg);
		return;
	case WIRE_CHANNEL_DEV_REENABLE_COMMIT:
#if DEVELOPER
		handle_dev_reenable_commit(peer);
		return;
#endif /* DEVELOPER */
	case WIRE_CHANNEL_INIT:
	case WIRE_CHANNEL_OFFER_HTLC_REPLY:
	case WIRE_CHANNEL_PING_REPLY:
	case WIRE_CHANNEL_SENDING_COMMITSIG:
	case WIRE_CHANNEL_GOT_COMMITSIG:
	case WIRE_CHANNEL_GOT_REVOKE:
	case WIRE_CHANNEL_SENDING_COMMITSIG_REPLY:
	case WIRE_CHANNEL_GOT_COMMITSIG_REPLY:
	case WIRE_CHANNEL_GOT_REVOKE_REPLY:
	case WIRE_CHANNEL_GOT_FUNDING_LOCKED:
	case WIRE_CHANNEL_GOT_SHUTDOWN:
	case WIRE_CHANNEL_SHUTDOWN_COMPLETE:
	case WIRE_CHANNEL_DEV_REENABLE_COMMIT_REPLY:
		break;
	}
	master_badmsg(-1, msg);
}

static void init_shared_secrets(struct channel *channel,
				const struct added_htlc *htlcs,
				const enum htlc_state *hstates)
{
	for (size_t i = 0; i < tal_count(htlcs); i++) {
		struct htlc *htlc;

		/* We only derive this for HTLCs *they* added. */
		if (htlc_state_owner(hstates[i]) != REMOTE)
			continue;

		htlc = channel_get_htlc(channel, REMOTE, htlcs[i].id);
		htlc->shared_secret = tal(htlc, struct secret);
		get_shared_secret(htlc, htlc->shared_secret);
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
	struct bitcoin_txid funding_txid;
	enum side funder;
	enum htlc_state *hstates;
	struct fulfilled_htlc *fulfilled;
	enum side *fulfilled_sides;
	struct failed_htlc **failed;
	enum side *failed_sides;
	struct added_htlc *htlcs;
	bool reconnected;
	u8 *funding_signed;
	u8 *msg;
	u32 feerate_per_kw[NUM_SIDES];

	assert(!(fcntl(MASTER_FD, F_GETFL) & O_NONBLOCK));

	status_setup_sync(MASTER_FD);

	msg = wire_sync_read(peer, MASTER_FD);
	if (!fromwire_channel_init(peer, msg,
				   &peer->chain_hash,
				   &funding_txid, &funding_txout,
				   &funding_satoshi,
				   &peer->conf[LOCAL], &peer->conf[REMOTE],
				   feerate_per_kw,
				   &peer->feerate_min, &peer->feerate_max,
				   &peer->their_commit_sig,
				   &peer->cs,
				   &funding_pubkey[REMOTE],
				   &points[REMOTE].revocation,
				   &points[REMOTE].payment,
				   &points[REMOTE].htlc,
				   &points[REMOTE].delayed_payment,
				   &peer->remote_per_commit,
				   &peer->old_remote_per_commit,
				   &funder,
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
				   &peer->send_shutdown,
				   &peer->shutdown_sent[REMOTE],
				   &peer->final_scriptpubkey,
				   &peer->channel_flags,
				   &funding_signed,
				   &peer->announce_depth_reached))
		master_badmsg(WIRE_CHANNEL_INIT, msg);

	status_trace("init %s: remote_per_commit = %s, old_remote_per_commit = %s"
		     " next_idx_local = %"PRIu64
		     " next_idx_remote = %"PRIu64
		     " revocations_received = %"PRIu64
		     " feerates %u/%u (range %u-%u)",
		     side_to_str(funder),
		     type_to_string(tmpctx, struct pubkey,
				    &peer->remote_per_commit),
		     type_to_string(tmpctx, struct pubkey,
				    &peer->old_remote_per_commit),
		     peer->next_index[LOCAL], peer->next_index[REMOTE],
		     peer->revocations_received,
		     feerate_per_kw[LOCAL], feerate_per_kw[REMOTE],
		     peer->feerate_min, peer->feerate_max);

	/* First commit is used for opening: if we've sent 0, we're on
	 * index 1. */
	assert(peer->next_index[LOCAL] > 0);
	assert(peer->next_index[REMOTE] > 0);

	/* channel_id is set from funding txout */
	derive_channel_id(&peer->channel_id, &funding_txid, funding_txout);

	/* We derive everything from the one secret seed. */
	derive_basepoints(&seed, &funding_pubkey[LOCAL], &points[LOCAL],
			  &peer->our_secrets, &peer->shaseed);

	peer->channel = new_full_channel(peer, &funding_txid, funding_txout,
					 funding_satoshi,
					 local_msatoshi,
					 feerate_per_kw,
					 &peer->conf[LOCAL], &peer->conf[REMOTE],
					 &points[LOCAL], &points[REMOTE],
					 &funding_pubkey[LOCAL],
					 &funding_pubkey[REMOTE],
					 funder);

	if (!channel_force_htlcs(peer->channel, htlcs, hstates,
				 fulfilled, fulfilled_sides,
				 cast_const2(const struct failed_htlc **,
					     failed),
				 failed_sides))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not restore HTLCs");

	/* We derive shared secrets for each remote HTLC, so we can
	 * create error packet if necessary. */
	init_shared_secrets(peer->channel, htlcs, hstates);

	peer->channel_direction = get_channel_direction(
	    &peer->node_ids[LOCAL], &peer->node_ids[REMOTE]);

	/* Default desired feerate is the feerate we set for them last. */
	if (peer->channel->funder == LOCAL)
		peer->desired_feerate = feerate_per_kw[REMOTE];

	/* OK, now we can process peer messages. */
	if (reconnected)
		peer_reconnect(peer);

	/* If we have a funding_signed message, send that immediately */
	if (funding_signed)
		enqueue_peer_msg(peer, take(funding_signed));

	channel_announcement_negotiate(peer);

	billboard_update(peer);
	tal_free(msg);
}

static void send_shutdown_complete(struct peer *peer)
{
	/* Push out any incomplete messages to peer. */
	flush_peer_out(peer);

	/* Now we can tell master shutdown is complete. */
	wire_sync_write(MASTER_FD,
			take(towire_channel_shutdown_complete(NULL, &peer->cs)));
	fdpass_send(MASTER_FD, PEER_FD);
	fdpass_send(MASTER_FD, GOSSIP_FD);
	close(MASTER_FD);
}

int main(int argc, char *argv[])
{
	setup_locale();

	int i, nfds;
	fd_set fds_in, fds_out;
	struct peer *peer;

	subdaemon_setup(argc, argv);

	peer = tal(NULL, struct peer);
	peer->num_pings_outstanding = 0;
	timers_init(&peer->timers, time_mono());
	peer->commit_timer = NULL;
	peer->have_sigs[LOCAL] = peer->have_sigs[REMOTE] = false;
	peer->announce_depth_reached = false;
	peer->channel_local_active = false;
	msg_queue_init(&peer->from_master, peer);
	msg_queue_init(&peer->from_gossipd, peer);
	msg_queue_init(&peer->peer_out, peer);
	peer->peer_outmsg = NULL;
	peer->peer_outoff = 0;
	peer->next_commit_sigs = NULL;
	peer->shutdown_sent[LOCAL] = false;
	peer->last_update_timestamp = 0;

	/* We send these to HSM to get real signatures; don't have valgrind
	 * complain. */
	for (i = 0; i < NUM_SIDES; i++) {
		memset(&peer->announcement_node_sigs[i], 0,
		       sizeof(peer->announcement_node_sigs[i]));
		memset(&peer->announcement_bitcoin_sigs[i], 0,
		       sizeof(peer->announcement_bitcoin_sigs[i]));
	}

	/* Read init_channel message sync. */
	init_channel(peer);

	FD_ZERO(&fds_in);
	FD_SET(MASTER_FD, &fds_in);
	FD_SET(PEER_FD, &fds_in);
	FD_SET(GOSSIP_FD, &fds_in);

	FD_ZERO(&fds_out);
	FD_SET(PEER_FD, &fds_out);
	nfds = GOSSIP_FD+1;

	while (!shutdown_complete(peer)) {
		struct timemono first;
		fd_set rfds = fds_in, wfds, *wptr;
		struct timeval timeout, *tptr;
		struct timer *expired;
		const u8 *msg;
		struct timemono now = time_mono();

		/* Free any temporary allocations */
		clean_tmpctx();

		/* For simplicity, we process one event at a time. */
		msg = msg_dequeue(&peer->from_master);
		if (msg) {
			status_trace("Now dealing with deferred %s",
				     channel_wire_type_name(
					     fromwire_peektype(msg)));
			req_in(peer, msg);
			tal_free(msg);
			continue;
		}

		expired = timers_expire(&peer->timers, now);
		if (expired) {
			timer_expired(peer, expired);
			continue;
		}

		msg = msg_dequeue(&peer->from_gossipd);
		if (msg) {
			status_trace("Now dealing with deferred gossip %u",
				     fromwire_peektype(msg));
			handle_gossip_msg(take(msg), &peer->cs,
					  channeld_send_reply,
					  channeld_io_error,
					  peer);
			continue;
		}

		if (timer_earliest(&peer->timers, &first)) {
			timeout = timespec_to_timeval(
				timemono_between(first, now).ts);
			tptr = &timeout;
		} else
			tptr = NULL;

		if (peer_write_pending(peer)) {
			wfds = fds_out;
			wptr = &wfds;
		} else
			wptr = NULL;

		if (select(nfds, &rfds, wptr, NULL, tptr) < 0) {
			/* Signals OK, eg. SIGUSR1 */
			if (errno == EINTR)
				continue;
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "select failed: %s", strerror(errno));
		}

		/* Try writing out encrypted packet if any (don't block!) */
		if (wptr && FD_ISSET(PEER_FD, wptr)) {
			if (!io_fd_block(PEER_FD, false))
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "NONBLOCK failed: %s",
					      strerror(errno));
			do_peer_write(peer);
			if (!io_fd_block(PEER_FD, true))
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "NONBLOCK unset failed: %s",
					      strerror(errno));
			continue;
		}

		if (FD_ISSET(MASTER_FD, &rfds)) {
			msg = wire_sync_read(peer, MASTER_FD);

			if (!msg)
				status_failed(STATUS_FAIL_MASTER_IO,
					      "Can't read command: %s",
					      strerror(errno));
			req_in(peer, msg);
		} else if (FD_ISSET(GOSSIP_FD, &rfds)) {
			msg = wire_sync_read(peer, GOSSIP_FD);
			/* Gossipd hangs up on us to kill us when a new
			 * connection comes in. */
			if (!msg)
				peer_conn_broken(peer);
			handle_gossip_msg(msg, &peer->cs,
					  channeld_send_reply,
					  channeld_io_error,
					  peer);
		} else if (FD_ISSET(PEER_FD, &rfds)) {
			/* This could take forever, but who cares? */
			msg = channeld_read_peer_msg(peer);
			if (msg)
				peer_in(peer, msg);
		} else
			msg = NULL;
		tal_free(msg);
	}

	/* We only exit when shutdown is complete. */
	assert(shutdown_complete(peer));
	send_shutdown_complete(peer);
	daemon_shutdown();
	return 0;
}
