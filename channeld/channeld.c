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
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/cast/cast.h>
#include <ccan/container_of/container_of.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/mem/mem.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <channeld/channeld_wiregen.h>
#include <channeld/commit_tx.h>
#include <channeld/full_channel.h>
#include <channeld/watchtower.h>
#include <common/blinding.h>
#include <common/coin_mvt.h>
#include <common/crypto_sync.h>
#include <common/dev_disconnect.h>
#include <common/ecdh_hsmd.h>
#include <common/features.h>
#include <common/gossip_constants.h>
#include <common/gossip_store.h>
#include <common/htlc_tx.h>
#include <common/key_derive.h>
#include <common/memleak.h>
#include <common/msg_queue.h>
#include <common/node_id.h>
#include <common/onionreply.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/ping.h>
#include <common/private_channel_announcement.h>
#include <common/psbt_internal.h>
#include <common/psbt_open.h>
#include <common/read_peer_msg.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/version.h>
#include <common/wire_error.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gossip_store_wiregen.h>
#include <gossipd/gossipd_peerd_wiregen.h>
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>
#include <secp256k1.h>
#include <stdio.h>
#if EXPERIMENTAL_FEATURES
#include <wire/bolt12_exp_wiregen.h>
#endif
#include <wire/common_wiregen.h>
#include <wire/onion_wire.h>
#include <wire/peer_wire.h>
#include <wire/wire.h>
#include <wire/wire_io.h>
#include <wire/wire_sync.h>

/* stdin == requests, 3 == peer, 4 = gossip, 5 = gossip_store, 6 = HSM */
#define MASTER_FD STDIN_FILENO
#define HSM_FD 6

struct peer {
	struct per_peer_state *pps;
	bool funding_locked[NUM_SIDES];
	u64 next_index[NUM_SIDES];

	/* Features peer supports. */
	u8 *their_features;

	/* Features we support. */
	struct feature_set *our_features;

	/* Tolerable amounts for feerate (only relevant for fundee). */
	u32 feerate_min, feerate_max;

	/* Feerate to be used when creating penalty transactions. */
	u32 feerate_penalty;

	/* Local next per-commit point. */
	struct pubkey next_local_per_commit;

	/* Remote's current per-commit point. */
	struct pubkey remote_per_commit;

	/* Remotes's last per-commitment point: we keep this to check
	 * revoke_and_ack's `per_commitment_secret` is correct. */
	struct pubkey old_remote_per_commit;

	/* Their sig for current commit. */
	struct bitcoin_signature their_commit_sig;

	/* BOLT #2:
	 *
	 * A sending node:
	 *...
	 *  - for the first HTLC it offers:
	 *    - MUST set `id` to 0.
	 */
	u64 htlc_id;

	struct channel_id channel_id;
	struct channel *channel;

	/* Messages from master: we queue them since we might be
	 * waiting for a specific reply. */
	struct msg_queue *from_master;

	struct timers timers;
	struct oneshot *commit_timer;
	u64 commit_timer_attempts;
	u32 commit_msec;

	/* Are we expecting a pong? */
	bool expecting_pong;

	/* The feerate we want. */
	u32 desired_feerate;

	/* Announcement related information */
	struct node_id node_ids[NUM_SIDES];
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

	/* Make sure peer is live. */
	struct timeabs last_recv;

	/* Additional confirmations need for local lockin. */
	u32 depth_togo;

	/* Non-empty if they specified a fixed shutdown script */
	u8 *remote_upfront_shutdown_script;

	/* Empty commitments.  Spec violation, but a minor one. */
	u64 last_empty_commitment;

	/* Penalty bases for this channel / peer. */
	struct penalty_base **pbases;

	/* PSBT. For v2 openchannel set until we are waiting
	 * for peer's tx_sigs */
	struct wally_psbt *psbt;
};

static u8 *create_channel_announcement(const tal_t *ctx, struct peer *peer);
static void start_commit_timer(struct peer *peer);

static void billboard_update(const struct peer *peer)
{
	const char *funding_status, *announce_status,
		*shutdown_status COMPILER_WANTS_INIT("gcc 8.3.0");

	if (peer->funding_locked[LOCAL] && peer->funding_locked[REMOTE])
		funding_status = "Funding transaction locked.";
	else if (!peer->funding_locked[LOCAL] && !peer->funding_locked[REMOTE])
		funding_status = tal_fmt(tmpctx,
					"Funding needs %d more confirmations for lockin.",
					peer->depth_togo);
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
	else if (peer->shutdown_sent[LOCAL] && !peer->shutdown_sent[REMOTE])
		shutdown_status = " We've send shutdown, waiting for theirs";
	else if (!peer->shutdown_sent[LOCAL] && peer->shutdown_sent[REMOTE])
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

static const u8 *hsm_req(const tal_t *ctx, const u8 *req TAKES)
{
	u8 *msg;
	int type = fromwire_peektype(req);

	if (!wire_sync_write(HSM_FD, req))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Writing %s to HSM: %s",
			      hsmd_wire_name(type),
			      strerror(errno));

	msg = wire_sync_read(ctx, HSM_FD);
	if (!msg)
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading resp to %s: %s",
			      hsmd_wire_name(type),
			      strerror(errno));

	return msg;
}

static enum tx_role their_tx_role(const struct peer *peer)
{
	return peer->channel->opener == LOCAL ?
		TX_ACCEPTER : TX_INITIATOR;
}

#if EXPERIMENTAL_FEATURES
static enum tx_role our_tx_role(const struct peer *peer)
{
	return peer->channel->opener == LOCAL ?
		TX_INITIATOR : TX_ACCEPTER;
}

static const u8 *psbt_to_tx_sigs_msg(const tal_t *ctx,
				     const struct peer *peer,
				     const struct wally_psbt *psbt)
{
	const struct witness_stack **ws;

	ws = psbt_to_witness_stacks(tmpctx, psbt,
				    our_tx_role(peer));

	return towire_tx_signatures(ctx, &peer->channel->cid,
				   &peer->channel->funding_txid,
				   ws);
}
#endif /* EXPERIMENTAL_FEATURES */

/*
 * The maximum msat that this node will accept for an htlc.
 * It's flagged as an optional field in `channel_update`.
 *
 * We advertize the maximum value possible, defined as the smaller
 * of the remote's maximum in-flight HTLC or the total channel
 * capacity the reserve we have to keep.
 * FIXME: does this need fuzz?
 */
static struct amount_msat advertized_htlc_max(const struct channel *channel)
{
	struct amount_sat lower_bound;
	struct amount_msat lower_bound_msat;

	/* This shouldn't fail */
	if (!amount_sat_sub(&lower_bound, channel->funding,
			    channel->config[REMOTE].channel_reserve)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "funding %s - remote reserve %s?",
			      type_to_string(tmpctx, struct amount_sat,
					     &channel->funding),
			      type_to_string(tmpctx, struct amount_sat,
					     &channel->config[REMOTE]
					     .channel_reserve));
	}

	if (!amount_sat_to_msat(&lower_bound_msat, lower_bound)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "lower_bound %s invalid?",
			      type_to_string(tmpctx, struct amount_sat,
					     &lower_bound));
	}

	if (amount_msat_greater(lower_bound_msat, chainparams->max_payment))
		/* BOLT #7:
		 *
		 * The origin node:
		 * ...
		 *   - if the `htlc_maximum_msat` field is present:
		 * ...
		 *         - for channels with `chain_hash` identifying the Bitcoin blockchain:
		 * 			 - MUST set this to less than 2^32.
		 */
		lower_bound_msat = chainparams->max_payment;

	return lower_bound_msat;
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

	msg = towire_gossipd_local_channel_update(NULL,
						  &peer->short_channel_ids[LOCAL],
						  disable_flag
						  == ROUTING_FLAGS_DISABLED,
						  peer->cltv_delta,
						  peer->channel->config[REMOTE].htlc_minimum,
						  peer->fee_base,
						  peer->fee_per_satoshi,
						  advertized_htlc_max(peer->channel));
	wire_sync_write(peer->pps->gossip_fd, take(msg));
}

/* Get the latest channel update for this channel from gossipd */
static const u8 *get_local_channel_update(const tal_t *ctx, struct peer *peer)
{
	const u8 *msg;

	msg = towire_gossipd_get_update(NULL, &peer->short_channel_ids[LOCAL]);
 	wire_sync_write(peer->pps->gossip_fd, take(msg));

	/* Wait for reply to come back; handle other gossipd msgs meanwhile */
	while ((msg = wire_sync_read(tmpctx, peer->pps->gossip_fd)) != NULL) {
		u8 *update;
		if (fromwire_gossipd_get_update_reply(ctx, msg, &update))
			return update;

		handle_gossip_msg(peer->pps, take(msg));
	}

	/* Gossipd hangs up on us to kill us when a new
	 * connection comes in. */
	peer_failed_connection_lost();
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
	const u8 *ann;
	const u8 *annfeatures = get_agreed_channelfeatures(tmpctx,
							   peer->our_features,
							   peer->their_features);

	ann = private_channel_announcement(tmpctx,
					   &peer->short_channel_ids[LOCAL],
					   &peer->node_ids[LOCAL],
					   &peer->node_ids[REMOTE],
					   annfeatures);

	/* Tell gossipd about local channel. */
	msg = towire_gossip_store_private_channel(NULL,
						  peer->channel->funding, ann);
 	wire_sync_write(peer->pps->gossip_fd, take(msg));

	/* Tell gossipd and the other side what parameters we expect should
	 * they route through us */
	send_channel_update(peer, 0);
}

static void send_announcement_signatures(struct peer *peer)
{
	/* First 2 + 256 byte are the signatures and msg type, skip them */
	size_t offset = 258;
	struct sha256_double hash;
	const u8 *msg, *ca, *req;
	struct pubkey mykey;

	status_debug("Exchanging announcement signatures.");
	ca = create_channel_announcement(tmpctx, peer);
	req = towire_hsmd_cannouncement_sig_req(tmpctx, ca);

	msg = hsm_req(tmpctx, req);
	if (!fromwire_hsmd_cannouncement_sig_reply(msg,
				  &peer->announcement_node_sigs[LOCAL],
				  &peer->announcement_bitcoin_sigs[LOCAL]))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading cannouncement_sig_resp: %s",
			      strerror(errno));

	/* Double-check that HSM gave valid signatures. */
	sha256_double(&hash, ca + offset, tal_count(ca) - offset);
	if (!pubkey_from_node_id(&mykey, &peer->node_ids[LOCAL]))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not convert my id '%s' to pubkey",
			      type_to_string(tmpctx, struct node_id,
					     &peer->node_ids[LOCAL]));
	if (!check_signed_hash(&hash, &peer->announcement_node_sigs[LOCAL],
			       &mykey)) {
		/* It's ok to fail here, the channel announcement is
		 * unique, unlike the channel update which may have
		 * been replaced in the meantime. */
		status_failed(STATUS_FAIL_HSM_IO,
			      "HSM returned an invalid node signature");
	}

	if (!check_signed_hash(&hash, &peer->announcement_bitcoin_sigs[LOCAL],
			       &peer->channel->funding_pubkey[LOCAL])) {
		/* It's ok to fail here, the channel announcement is
		 * unique, unlike the channel update which may have
		 * been replaced in the meantime. */
		status_failed(STATUS_FAIL_HSM_IO,
			      "HSM returned an invalid bitcoin signature");
	}

	msg = towire_announcement_signatures(
	    NULL, &peer->channel_id, &peer->short_channel_ids[LOCAL],
	    &peer->announcement_node_sigs[LOCAL],
	    &peer->announcement_bitcoin_sigs[LOCAL]);
	sync_crypto_write(peer->pps, take(msg));
}

/* Tentatively create a channel_announcement, possibly with invalid
 * signatures. The signatures need to be collected first, by asking
 * the HSM and by exchanging announcement_signature messages. */
static u8 *create_channel_announcement(const tal_t *ctx, struct peer *peer)
{
	int first, second;
	u8 *cannounce, *features
		= get_agreed_channelfeatures(tmpctx, peer->our_features,
					     peer->their_features);

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
	    &chainparams->genesis_blockhash,
	    &peer->short_channel_ids[LOCAL],
	    &peer->node_ids[first],
	    &peer->node_ids[second],
	    &peer->channel->funding_pubkey[first],
	    &peer->channel->funding_pubkey[second]);
	return cannounce;
}

/* Once we have both, we'd better make sure we agree what they are! */
static void check_short_ids_match(struct peer *peer)
{
	assert(peer->have_sigs[LOCAL]);
	assert(peer->have_sigs[REMOTE]);

	if (!short_channel_id_eq(&peer->short_channel_ids[LOCAL],
				 &peer->short_channel_ids[REMOTE]))
		peer_failed(peer->pps,
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

	cannounce = create_channel_announcement(tmpctx, peer);

	wire_sync_write(peer->pps->gossip_fd,
			take(towire_gossipd_local_channel_announcement(NULL,
								       cannounce)));
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
	 * A node:
	 *   - if the `open_channel` message has the `announce_channel` bit set AND a `shutdown` message has not been sent:
	 *     - MUST send the `announcement_signatures` message.
	 *       - MUST NOT send `announcement_signatures` messages until `funding_locked`
	 *       has been sent and received AND the funding transaction has at least six confirmations.
	 *   - otherwise:
	 *     - MUST NOT send the `announcement_signatures` message.
	 */
	if (!(peer->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL))
		return;

	/* BOLT #7:
	 *
	 *      - MUST NOT send `announcement_signatures` messages until `funding_locked`
	 *      has been sent and received AND the funding transaction has at least six confirmations.
 	 */
	if (peer->announce_depth_reached && !peer->have_sigs[LOCAL]) {
		/* When we reenable the channel, we will also send the announcement to remote peer, and
		 * receive the remote announcement reply. But we will rebuild the channel with announcement
		 * from the DB directly, other than waiting for the remote announcement reply.
		 */
		send_announcement_signatures(peer);
		peer->have_sigs[LOCAL] = true;
		billboard_update(peer);
	}

	/* If we've completed the signature exchange, we can send a real
	 * announcement, otherwise we send a temporary one */
	if (peer->have_sigs[LOCAL] && peer->have_sigs[REMOTE]) {
		check_short_ids_match(peer);

		/* After making sure short_channel_ids match, we can send remote
		 * announcement to MASTER. */
		wire_sync_write(MASTER_FD,
			        take(towire_channeld_got_announcement(NULL,
			        &peer->announcement_node_sigs[REMOTE],
			        &peer->announcement_bitcoin_sigs[REMOTE])));

		/* Give other nodes time to notice new block. */
		notleak(new_reltimer(&peer->timers, peer,
				     time_from_sec(GOSSIP_ANNOUNCE_DELAY(dev_fast_gossip)),
				     announce_channel, peer));
	}
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

	if (peer->psbt && !psbt_side_finalized(peer->psbt,
					       their_tx_role(peer)))
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Rcvd `funding_locked` from peer but "
			    "have not received `tx_signatures`");

	peer->old_remote_per_commit = peer->remote_per_commit;
	if (!fromwire_funding_locked(msg, &chanid,
				     &peer->remote_per_commit))
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad funding_locked %s", tal_hex(msg, msg));

	if (!channel_id_eq(&chanid, &peer->channel_id))
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Wrong channel id in %s (expected %s)",
			    tal_hex(tmpctx, msg),
			    type_to_string(msg, struct channel_id,
					   &peer->channel_id));

	peer->funding_locked[REMOTE] = true;
	peer->psbt = tal_free(peer->psbt);
	wire_sync_write(MASTER_FD,
			take(towire_channeld_got_funding_locked(NULL,
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
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad announcement_signatures %s",
			    tal_hex(msg, msg));

	/* Make sure we agree on the channel ids */
	if (!channel_id_eq(&chanid, &peer->channel_id)) {
		peer_failed(peer->pps,
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

static void handle_peer_add_htlc(struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 id;
	struct amount_msat amount;
	u32 cltv_expiry;
	struct sha256 payment_hash;
	u8 onion_routing_packet[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)];
	enum channel_add_err add_err;
	struct htlc *htlc;
#if EXPERIMENTAL_FEATURES
	struct tlv_update_add_tlvs *tlvs = tlv_update_add_tlvs_new(msg);
#endif
	struct pubkey *blinding = NULL;

	if (!fromwire_update_add_htlc(msg, &channel_id, &id, &amount,
				      &payment_hash, &cltv_expiry,
				      onion_routing_packet
#if EXPERIMENTAL_FEATURES
				      , tlvs
#endif
		    ))
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad peer_add_htlc %s", tal_hex(msg, msg));

#if EXPERIMENTAL_FEATURES
	blinding = tlvs->blinding;
#endif
	add_err = channel_add_htlc(peer->channel, REMOTE, id, amount,
				   cltv_expiry, &payment_hash,
				   onion_routing_packet, blinding, &htlc, NULL);
	if (add_err != CHANNEL_ERR_ADD_OK)
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad peer_add_htlc: %s",
			    channel_add_err_name(add_err));
}

static void handle_peer_feechange(struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u32 feerate;

	if (!fromwire_update_fee(msg, &channel_id, &feerate)) {
		peer_failed(peer->pps,
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
	if (peer->channel->opener != REMOTE)
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "update_fee from non-opener?");

	status_debug("update_fee %u, range %u-%u",
		     feerate, peer->feerate_min, peer->feerate_max);

	/* BOLT #2:
	 *
	 * A receiving node:
	 *   - if the `update_fee` is too low for timely processing, OR is
	 *     unreasonably large:
	 *     - SHOULD fail the channel.
	 */
	if (feerate < peer->feerate_min || feerate > peer->feerate_max)
		peer_failed(peer->pps,
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
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "update_fee %u unaffordable",
			    feerate);

	status_debug("peer updated fee to %u", feerate);
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
				 struct penalty_base *pbase,
				 const struct fee_states *fee_states,
				 const struct htlc **changed_htlcs,
				 const struct bitcoin_signature *commit_sig,
				 const struct bitcoin_signature *htlc_sigs)
{
	struct changed_htlc *changed;
	u8 *msg;

	/* We tell master what (of our) HTLCs peer will now be
	 * committed to. */
	changed = changed_htlc_arr(tmpctx, changed_htlcs);
	msg = towire_channeld_sending_commitsig(ctx, remote_commit_index, pbase, fee_states, changed,
					       commit_sig, htlc_sigs);
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
	sync_crypto_write(peer->pps, take(msg));
	peer->send_shutdown = false;
	peer->shutdown_sent[LOCAL] = true;
	billboard_update(peer);
}

/* This queues other traffic from the fd until we get reply. */
static u8 *master_wait_sync_reply(const tal_t *ctx,
				  struct peer *peer,
				  const u8 *msg,
				  int replytype)
{
	u8 *reply;

	status_debug("Sending master %u", fromwire_peektype(msg));

	if (!wire_sync_write(MASTER_FD, msg))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not set sync write to master: %s",
			      strerror(errno));

	status_debug("... , awaiting %u", replytype);

	for (;;) {
		int type;

		reply = wire_sync_read(ctx, MASTER_FD);
		if (!reply)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not set sync read from master: %s",
				      strerror(errno));
		type = fromwire_peektype(reply);
		if (type == replytype) {
			status_debug("Got it!");
			break;
		}

		status_debug("Nope, got %u instead", type);
		msg_enqueue(peer->from_master, take(reply));
	}

	return reply;
}

/* Returns HTLC sigs, sets commit_sig */
static struct bitcoin_signature *calc_commitsigs(const tal_t *ctx,
						  const struct peer *peer,
						  struct bitcoin_tx **txs,
						  const u8 *funding_wscript,
						  const struct htlc **htlc_map,
						  u64 commit_index,
						  struct bitcoin_signature *commit_sig)
{
	size_t i;
	struct pubkey local_htlckey;
	const u8 *msg;
	struct bitcoin_signature *htlc_sigs;

	msg = towire_hsmd_sign_remote_commitment_tx(NULL, txs[0],
						   &peer->channel->funding_pubkey[REMOTE],
						   &peer->remote_per_commit,
						   peer->channel->option_static_remotekey);

	msg = hsm_req(tmpctx, take(msg));
	if (!fromwire_hsmd_sign_tx_reply(msg, commit_sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading sign_remote_commitment_tx reply: %s",
			      tal_hex(tmpctx, msg));

	status_debug("Creating commit_sig signature %"PRIu64" %s for tx %s wscript %s key %s",
		     commit_index,
		     type_to_string(tmpctx, struct bitcoin_signature,
				    commit_sig),
		     type_to_string(tmpctx, struct bitcoin_tx, txs[0]),
		     tal_hex(tmpctx, funding_wscript),
		     type_to_string(tmpctx, struct pubkey,
				    &peer->channel->funding_pubkey[LOCAL]));
	dump_htlcs(peer->channel, "Sending commit_sig");

	if (!derive_simple_key(&peer->channel->basepoints[LOCAL].htlc,
			       &peer->remote_per_commit,
			       &local_htlckey))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving local_htlckey");

	/* BOLT #2:
	 *
	 * A sending node:
	 *...
	 *  - MUST include one `htlc_signature` for every HTLC transaction
	 *    corresponding to the ordering of the commitment transaction
	 */
	htlc_sigs = tal_arr(ctx, struct bitcoin_signature, tal_count(txs) - 1);

	for (i = 0; i < tal_count(htlc_sigs); i++) {
		u8 *wscript;

		wscript = bitcoin_tx_output_get_witscript(tmpctx, txs[0],
							  txs[i+1]->wtx->inputs[0].index);
		msg = towire_hsmd_sign_remote_htlc_tx(NULL, txs[i + 1], wscript,
						     &peer->remote_per_commit,
						     peer->channel->option_anchor_outputs);

		msg = hsm_req(tmpctx, take(msg));
		if (!fromwire_hsmd_sign_tx_reply(msg, &htlc_sigs[i]))
			status_failed(STATUS_FAIL_HSM_IO,
				      "Bad sign_remote_htlc_tx reply: %s",
				      tal_hex(tmpctx, msg));

		status_debug("Creating HTLC signature %s for tx %s wscript %s key %s",
			     type_to_string(tmpctx, struct bitcoin_signature,
					    &htlc_sigs[i]),
			     type_to_string(tmpctx, struct bitcoin_tx, txs[1+i]),
			     tal_hex(tmpctx, wscript),
			     type_to_string(tmpctx, struct pubkey,
					    &local_htlckey));
		assert(check_tx_sig(txs[1+i], 0, NULL, wscript,
				    &local_htlckey,
				    &htlc_sigs[i]));
	}

	return htlc_sigs;
}

/* Have we received something from peer recently? */
static bool peer_recently_active(struct peer *peer)
{
	return time_less(time_between(time_now(), peer->last_recv),
			 time_from_sec(30));
}

static void maybe_send_ping(struct peer *peer)
{
	/* Already have a ping in flight? */
	if (peer->expecting_pong)
		return;

	if (peer_recently_active(peer))
		return;

	/* Send a ping to try to elicit a receive. */
	sync_crypto_write_no_delay(peer->pps, take(make_ping(NULL, 1, 0)));
	peer->expecting_pong = true;
}

/* Peer protocol doesn't want sighash flags. */
static secp256k1_ecdsa_signature *raw_sigs(const tal_t *ctx,
					   const struct bitcoin_signature *sigs)
{
	secp256k1_ecdsa_signature *raw;

	raw = tal_arr(ctx, secp256k1_ecdsa_signature, tal_count(sigs));
	for (size_t i = 0; i < tal_count(sigs); i++)
		raw[i] = sigs[i].s;
	return raw;
}

static struct bitcoin_signature *unraw_sigs(const tal_t *ctx,
					    const secp256k1_ecdsa_signature *raw,
					    bool option_anchor_outputs)
{
	struct bitcoin_signature *sigs;

	sigs = tal_arr(ctx, struct bitcoin_signature, tal_count(raw));
	for (size_t i = 0; i < tal_count(raw); i++) {
		sigs[i].s = raw[i];

		/* BOLT #3:
		 * ## HTLC-Timeout and HTLC-Success Transactions
		 *...
		 * * if `option_anchor_outputs` applies to this commitment
		 *   transaction, `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY` is
		 *   used.
		 */
		if (option_anchor_outputs)
			sigs[i].sighash_type = SIGHASH_SINGLE|SIGHASH_ANYONECANPAY;
		else
			sigs[i].sighash_type = SIGHASH_ALL;
	}
	return sigs;
}

static void send_commit(struct peer *peer)
{
	u8 *msg;
	const struct htlc **changed_htlcs;
	struct bitcoin_signature commit_sig, *htlc_sigs;
	struct bitcoin_tx **txs;
	const u8 *funding_wscript;
	const struct htlc **htlc_map;
	struct wally_tx_output *direct_outputs[NUM_SIDES];
	struct penalty_base *pbase;

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
			status_debug("Can't send commit:"
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
		status_debug("Can't send commit: final shutdown phase");

		peer->commit_timer = NULL;
		return;
	}

	/* If we haven't received a packet for > 30 seconds, delay. */
	if (!peer_recently_active(peer)) {
		/* Mark this as done and try again. */
		peer->commit_timer = NULL;
		start_commit_timer(peer);
		return;
	}

	/* If we wanted to update fees, do it now. */
	if (peer->channel->opener == LOCAL) {
		u32 feerate, max = approx_max_feerate(peer->channel);

		feerate = peer->desired_feerate;

		/* FIXME: We should avoid adding HTLCs until we can meet this
		 * feerate! */
		if (feerate > max)
			feerate = max;

		if (feerate != channel_feerate(peer->channel, REMOTE)) {
			u8 *msg;

			if (!channel_update_feerate(peer->channel, feerate))
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "Could not afford feerate %u"
					      " (vs max %u)",
					      feerate, max);

			msg = towire_update_fee(NULL, &peer->channel_id,
						feerate);
			sync_crypto_write(peer->pps, take(msg));
		}
	}

	/* BOLT #2:
	 *
	 * A sending node:
	 *   - MUST NOT send a `commitment_signed` message that does not include
	 *     any updates.
	 */
	changed_htlcs = tal_arr(tmpctx, const struct htlc *, 0);
	if (!channel_sending_commit(peer->channel, &changed_htlcs)) {
		status_debug("Can't send commit: nothing to send");

		/* Covers the case where we've just been told to shutdown. */
		maybe_send_shutdown(peer);

		peer->commit_timer = NULL;
		return;
	}

	txs = channel_txs(tmpctx, &htlc_map, direct_outputs,
			  &funding_wscript, peer->channel, &peer->remote_per_commit,
			  peer->next_index[REMOTE], REMOTE);

	htlc_sigs =
	    calc_commitsigs(tmpctx, peer, txs, funding_wscript, htlc_map,
			    peer->next_index[REMOTE], &commit_sig);

	if (direct_outputs[LOCAL] != NULL) {
		pbase = penalty_base_new(tmpctx, peer->next_index[REMOTE],
					 txs[0], direct_outputs[LOCAL]);

		/* Add the penalty_base to our in-memory list as well, so we
		 * can find it again later. */
		tal_arr_expand(&peer->pbases, tal_steal(peer, pbase));
	}  else
		pbase = NULL;

	status_debug("Telling master we're about to commit...");
	/* Tell master to save this next commit to database, then wait. */
	msg = sending_commitsig_msg(NULL, peer->next_index[REMOTE],
				    pbase,
				    peer->channel->fee_states,
				    changed_htlcs,
				    &commit_sig,
				    htlc_sigs);
	/* Message is empty; receiving it is the point. */
	master_wait_sync_reply(tmpctx, peer, take(msg),
			       WIRE_CHANNELD_SENDING_COMMITSIG_REPLY);

	status_debug("Sending commit_sig with %zu htlc sigs",
		     tal_count(htlc_sigs));

	peer->next_index[REMOTE]++;

	msg = towire_commitment_signed(NULL, &peer->channel_id,
				       &commit_sig.s,
				       raw_sigs(tmpctx, htlc_sigs));
	sync_crypto_write_no_delay(peer->pps, take(msg));

	maybe_send_shutdown(peer);

	/* Timer now considered expired, you can add a new one. */
	peer->commit_timer = NULL;
	start_commit_timer(peer);
}

static void start_commit_timer(struct peer *peer)
{
	/* We should send a ping now if we need a liveness check. */
	maybe_send_ping(peer);

	/* Already armed? */
	if (peer->commit_timer)
		return;

	peer->commit_timer_attempts = 0;
	peer->commit_timer = new_reltimer(&peer->timers, peer,
					  time_from_msec(peer->commit_msec),
					  send_commit, peer);
}

/* If old_secret is NULL, we don't care, otherwise it is filled in. */
static void get_per_commitment_point(u64 index, struct pubkey *point,
				     struct secret *old_secret)
{
	struct secret *s;
	const u8 *msg;

	msg = hsm_req(tmpctx,
		      take(towire_hsmd_get_per_commitment_point(NULL, index)));

	if (!fromwire_hsmd_get_per_commitment_point_reply(tmpctx, msg,
							 point,
							 &s))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad per_commitment_point reply %s",
			      tal_hex(tmpctx, msg));

	if (old_secret) {
		if (!s)
			status_failed(STATUS_FAIL_HSM_IO,
				      "No secret in per_commitment_point_reply %"
				      PRIu64,
				      index);
		*old_secret = *s;
	}
}

/* revoke_index == current index - 1 (usually; not for retransmission) */
static u8 *make_revocation_msg(const struct peer *peer, u64 revoke_index,
			       struct pubkey *point)
{
	struct secret old_commit_secret;

	get_per_commitment_point(revoke_index+2, point, &old_commit_secret);

	return towire_revoke_and_ack(peer, &peer->channel_id, &old_commit_secret,
				     point);
}

/* Convert changed htlcs into parts which lightningd expects. */
static void marshall_htlc_info(const tal_t *ctx,
			       const struct htlc **changed_htlcs,
			       struct changed_htlc **changed,
			       struct fulfilled_htlc **fulfilled,
			       const struct failed_htlc ***failed,
			       struct added_htlc **added)
{
	*changed = tal_arr(ctx, struct changed_htlc, 0);
	*added = tal_arr(ctx, struct added_htlc, 0);
	*failed = tal_arr(ctx, const struct failed_htlc *, 0);
	*fulfilled = tal_arr(ctx, struct fulfilled_htlc, 0);

	for (size_t i = 0; i < tal_count(changed_htlcs); i++) {
		const struct htlc *htlc = changed_htlcs[i];
		if (htlc->state == RCVD_ADD_COMMIT) {
			struct added_htlc a;

			a.id = htlc->id;
			a.amount = htlc->amount;
			a.payment_hash = htlc->rhash;
			a.cltv_expiry = abs_locktime_to_blocks(&htlc->expiry);
			memcpy(a.onion_routing_packet,
			       htlc->routing,
			       sizeof(a.onion_routing_packet));
			if (htlc->blinding) {
				a.blinding = htlc->blinding;
				ecdh(a.blinding, &a.blinding_ss);
			} else
				a.blinding = NULL;
			tal_arr_expand(added, a);
		} else if (htlc->state == RCVD_REMOVE_COMMIT) {
			if (htlc->r) {
				struct fulfilled_htlc f;
				assert(!htlc->failed);
				f.id = htlc->id;
				f.payment_preimage = *htlc->r;
				tal_arr_expand(fulfilled, f);
			} else {
				assert(!htlc->r);
				tal_arr_expand(failed, htlc->failed);
			}
		} else {
			struct changed_htlc c;
			assert(htlc->state == RCVD_REMOVE_ACK_COMMIT
			       || htlc->state == RCVD_ADD_ACK_COMMIT);

			c.id = htlc->id;
			c.newstate = htlc->state;
			tal_arr_expand(changed, c);
		}
	}
}

static void send_revocation(struct peer *peer,
			    const struct bitcoin_signature *commit_sig,
			    const struct bitcoin_signature *htlc_sigs,
			    const struct htlc **changed_htlcs,
			    const struct bitcoin_tx *committx)
{
	struct changed_htlc *changed;
	struct fulfilled_htlc *fulfilled;
	const struct failed_htlc **failed;
	struct added_htlc *added;
	const u8 *msg_for_master;

	/* Marshall it now before channel_sending_revoke_and_ack changes htlcs */
	/* FIXME: Make infrastructure handle state post-revoke_and_ack! */
	marshall_htlc_info(tmpctx,
			   changed_htlcs,
			   &changed,
			   &fulfilled,
			   &failed,
			   &added);

	/* Revoke previous commit, get new point. */
	u8 *msg = make_revocation_msg(peer, peer->next_index[LOCAL]-1,
				      &peer->next_local_per_commit);

	/* From now on we apply changes to the next commitment */
	peer->next_index[LOCAL]++;

	/* If this queues more changes on the other end, send commit. */
	if (channel_sending_revoke_and_ack(peer->channel)) {
		status_debug("revoke_and_ack made pending: commit timer");
		start_commit_timer(peer);
	}

	/* Tell master daemon about commitsig (and by implication, that we're
	 * sending revoke_and_ack), then wait for it to ack. */
	/* We had to do this after channel_sending_revoke_and_ack, since we
	 * want it to save the fee_states produced there. */
	msg_for_master
		= towire_channeld_got_commitsig(NULL,
					       peer->next_index[LOCAL] - 1,
					       peer->channel->fee_states,
					       commit_sig, htlc_sigs,
					       added,
					       fulfilled,
					       failed,
					       changed,
					       committx);
	master_wait_sync_reply(tmpctx, peer, take(msg_for_master),
			       WIRE_CHANNELD_GOT_COMMITSIG_REPLY);

	/* Now we can finally send revoke_and_ack to peer */
	sync_crypto_write_no_delay(peer->pps, take(msg));
}

static void handle_peer_commit_sig(struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	struct bitcoin_signature commit_sig;
	secp256k1_ecdsa_signature *raw_sigs;
	struct bitcoin_signature *htlc_sigs;
	struct pubkey remote_htlckey;
	struct bitcoin_tx **txs;
	const struct htlc **htlc_map, **changed_htlcs;
	const u8 *funding_wscript;
	size_t i;

	changed_htlcs = tal_arr(msg, const struct htlc *, 0);
	if (!channel_rcvd_commit(peer->channel, &changed_htlcs)) {
		/* BOLT #2:
		 *
		 * A sending node:
		 *   - MUST NOT send a `commitment_signed` message that does not
		 *     include any updates.
		 */
		status_debug("Oh hi LND! Empty commitment at #%"PRIu64,
			     peer->next_index[LOCAL]);
		if (peer->last_empty_commitment == peer->next_index[LOCAL] - 1)
			peer_failed(peer->pps,
				    &peer->channel_id,
				    "commit_sig with no changes (again!)");
		peer->last_empty_commitment = peer->next_index[LOCAL];
	}

	/* We were supposed to check this was affordable as we go. */
	if (peer->channel->opener == REMOTE) {
		status_debug("Feerates are %u/%u",
			     channel_feerate(peer->channel, LOCAL),
			     channel_feerate(peer->channel, REMOTE));
		assert(can_opener_afford_feerate(peer->channel,
						 channel_feerate(peer->channel,
								 LOCAL)));
	}

	if (!fromwire_commitment_signed(tmpctx, msg,
					&channel_id, &commit_sig.s, &raw_sigs))
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad commit_sig %s", tal_hex(msg, msg));
	/* SIGHASH_ALL is implied. */
	commit_sig.sighash_type = SIGHASH_ALL;
	htlc_sigs = unraw_sigs(tmpctx, raw_sigs,
			       peer->channel->option_anchor_outputs);

	txs =
	    channel_txs(tmpctx, &htlc_map, NULL,
			&funding_wscript, peer->channel, &peer->next_local_per_commit,
			peer->next_index[LOCAL], LOCAL);

	/* Set the commit_sig on the commitment tx psbt */
	if (!psbt_input_set_signature(txs[0]->psbt, 0,
				      &peer->channel->funding_pubkey[REMOTE],
				      &commit_sig))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Unable to set signature internally");

	if (!derive_simple_key(&peer->channel->basepoints[REMOTE].htlc,
			       &peer->next_local_per_commit, &remote_htlckey))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving remote_htlckey");
	status_debug("Derived key %s from basepoint %s, point %s",
		     type_to_string(tmpctx, struct pubkey, &remote_htlckey),
		     type_to_string(tmpctx, struct pubkey,
				    &peer->channel->basepoints[REMOTE].htlc),
		     type_to_string(tmpctx, struct pubkey,
				    &peer->next_local_per_commit));
	/* BOLT #2:
	 *
	 * A receiving node:
	 *  - once all pending updates are applied:
	 *    - if `signature` is not valid for its local commitment transaction:
	 *      - MUST fail the channel.
	 */
	if (!check_tx_sig(txs[0], 0, NULL, funding_wscript,
			  &peer->channel->funding_pubkey[REMOTE], &commit_sig)) {
		dump_htlcs(peer->channel, "receiving commit_sig");
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad commit_sig signature %"PRIu64" %s for tx %s wscript %s key %s feerate %u",
			    peer->next_index[LOCAL],
			    type_to_string(msg, struct bitcoin_signature,
					   &commit_sig),
			    type_to_string(msg, struct bitcoin_tx, txs[0]),
			    tal_hex(msg, funding_wscript),
			    type_to_string(msg, struct pubkey,
					   &peer->channel->funding_pubkey
					   [REMOTE]),
			    channel_feerate(peer->channel, LOCAL));
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
		peer_failed(peer->pps,
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
		u8 *wscript;

		wscript = bitcoin_tx_output_get_witscript(tmpctx, txs[0],
							  txs[i+1]->wtx->inputs[0].index);

		if (!check_tx_sig(txs[1+i], 0, NULL, wscript,
				  &remote_htlckey, &htlc_sigs[i]))
			peer_failed(peer->pps,
				    &peer->channel_id,
				    "Bad commit_sig signature %s for htlc %s wscript %s key %s",
				    type_to_string(msg, struct bitcoin_signature, &htlc_sigs[i]),
				    type_to_string(msg, struct bitcoin_tx, txs[1+i]),
				    tal_hex(msg, wscript),
				    type_to_string(msg, struct pubkey,
						   &remote_htlckey));
	}

	status_debug("Received commit_sig with %zu htlc sigs",
		     tal_count(htlc_sigs));

	return send_revocation(peer,
			       &commit_sig, htlc_sigs, changed_htlcs, txs[0]);
}

/* Pops the penalty base for the given commitnum from our internal list. There
 * may not be one, in which case we return NULL and leave the list
 * unmodified. */
static struct penalty_base *
penalty_base_by_commitnum(const tal_t *ctx, struct peer *peer, u64 commitnum)
{
	struct penalty_base *res = NULL;
	for (size_t i = 0; i < tal_count(peer->pbases); i++) {
		if (peer->pbases[i]->commitment_num == commitnum) {
			res = tal_steal(ctx, peer->pbases[i]);
			tal_arr_remove(&peer->pbases, i);
			break;
		}
	}
	return res;
}

static u8 *got_revoke_msg(struct peer *peer, u64 revoke_num,
			  const struct secret *per_commitment_secret,
			  const struct pubkey *next_per_commit_point,
			  const struct htlc **changed_htlcs,
			  const struct fee_states *fee_states)
{
	u8 *msg;
	struct penalty_base *pbase;
	struct changed_htlc *changed = tal_arr(tmpctx, struct changed_htlc, 0);
	const struct bitcoin_tx *ptx = NULL;

	for (size_t i = 0; i < tal_count(changed_htlcs); i++) {
		struct changed_htlc c;
		const struct htlc *htlc = changed_htlcs[i];

		status_debug("HTLC %"PRIu64"[%s] => %s",
			     htlc->id, side_to_str(htlc_owner(htlc)),
			     htlc_state_name(htlc->state));

		c.id = changed_htlcs[i]->id;
		c.newstate = changed_htlcs[i]->state;
		tal_arr_expand(&changed, c);
	}

	pbase = penalty_base_by_commitnum(tmpctx, peer, revoke_num);

	if (pbase) {
		ptx = penalty_tx_create(
		    NULL, peer->channel, peer->feerate_penalty,
		    peer->final_scriptpubkey, per_commitment_secret,
		    &pbase->txid, pbase->outnum, pbase->amount,
		    HSM_FD);
	}

	msg = towire_channeld_got_revoke(peer, revoke_num, per_commitment_secret,
					next_per_commit_point, fee_states,
					changed, pbase, ptx);
	tal_free(ptx);
	return msg;
}

static void handle_peer_revoke_and_ack(struct peer *peer, const u8 *msg)
{
	struct secret old_commit_secret;
	struct privkey privkey;
	struct channel_id channel_id;
	struct pubkey per_commit_point, next_per_commit;
	const struct htlc **changed_htlcs = tal_arr(msg, const struct htlc *, 0);

	if (!fromwire_revoke_and_ack(msg, &channel_id, &old_commit_secret,
				     &next_per_commit)) {
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad revoke_and_ack %s", tal_hex(msg, msg));
	}

	if (peer->revocations_received != peer->next_index[REMOTE] - 2) {
		peer_failed(peer->pps,
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
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad privkey %s",
			    type_to_string(msg, struct privkey, &privkey));
	}
	if (!pubkey_eq(&per_commit_point, &peer->old_remote_per_commit)) {
		peer_failed(peer->pps,
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
		status_debug("Commits outstanding after recv revoke_and_ack");
	else
		status_debug("No commits outstanding after recv revoke_and_ack");

	/* Tell master about things this locks in, wait for response */
	msg = got_revoke_msg(peer, peer->revocations_received++,
			     &old_commit_secret, &next_per_commit,
			     changed_htlcs,
			     peer->channel->fee_states);
	master_wait_sync_reply(tmpctx, peer, take(msg),
			       WIRE_CHANNELD_GOT_REVOKE_REPLY);

	peer->old_remote_per_commit = peer->remote_per_commit;
	peer->remote_per_commit = next_per_commit;
	status_debug("revoke_and_ack %s: remote_per_commit = %s, old_remote_per_commit = %s",
		     side_to_str(peer->channel->opener),
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
	struct htlc *h;

	if (!fromwire_update_fulfill_htlc(msg, &channel_id,
					  &id, &preimage)) {
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad update_fulfill_htlc %s", tal_hex(msg, msg));
	}

	e = channel_fulfill_htlc(peer->channel, LOCAL, id, &preimage, &h);
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
		peer_failed(peer->pps,
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
	struct failed_htlc *f;

	/* reason is not an onionreply because spec doesn't know about that */
	if (!fromwire_update_fail_htlc(msg, msg,
				       &channel_id, &id, &reason)) {
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad update_fail_htlc %s", tal_hex(msg, msg));
	}

	e = channel_fail_htlc(peer->channel, LOCAL, id, &htlc);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK: {
		htlc->failed = f = tal(htlc, struct failed_htlc);
		f->id = id;
		f->sha256_of_onion = NULL;
		f->onion = new_onionreply(f, take(reason));
		start_commit_timer(peer);
		return;
	}
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		peer_failed(peer->pps,
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
	struct failed_htlc *f;

	if (!fromwire_update_fail_malformed_htlc(msg, &channel_id, &id,
						 &sha256_of_onion,
						 &failure_code)) {
		peer_failed(peer->pps,
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
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad update_fail_malformed_htlc failure code %u",
			    failure_code);
	}

	e = channel_fail_htlc(peer->channel, LOCAL, id, &htlc);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK:
		htlc->failed = f = tal(htlc, struct failed_htlc);
		f->id = id;
		f->onion = NULL;
		f->sha256_of_onion = tal_dup(f, struct sha256, &sha256_of_onion);
		f->badonion = failure_code;
		start_commit_timer(peer);
		return;
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad update_fail_malformed_htlc: failed to remove %"
			    PRIu64 " error %s", id, channel_remove_err_name(e));
	}
	abort();
}

static void handle_peer_shutdown(struct peer *peer, const u8 *shutdown)
{
	struct channel_id channel_id;
	u8 *scriptpubkey;

	/* Disable the channel. */
	send_channel_update(peer, ROUTING_FLAGS_DISABLED);

	if (!fromwire_shutdown(tmpctx, shutdown, &channel_id, &scriptpubkey))
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad shutdown %s", tal_hex(peer, shutdown));

	/* BOLT #2:
	 *
	 * - if both nodes advertised the `option_upfront_shutdown_script`
	 * feature, and the receiving node received a non-zero-length
	 * `shutdown_scriptpubkey` in `open_channel` or `accept_channel`, and
	 * that `shutdown_scriptpubkey` is not equal to `scriptpubkey`:
	 *    - MUST fail the connection.
	 */
	/* openingd only sets this if feature was negotiated at opening. */
	if (tal_count(peer->remote_upfront_shutdown_script)
	    && !memeq(scriptpubkey, tal_count(scriptpubkey),
		      peer->remote_upfront_shutdown_script,
		      tal_count(peer->remote_upfront_shutdown_script)))
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "scriptpubkey %s is not as agreed upfront (%s)",
			    tal_hex(peer, scriptpubkey),
			    tal_hex(peer, peer->remote_upfront_shutdown_script));

	/* Tell master: we don't have to wait because on reconnect other end
	 * will re-send anyway. */
	wire_sync_write(MASTER_FD,
			take(towire_channeld_got_shutdown(NULL, scriptpubkey)));

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

/* Try to handle a custommsg Returns true if it was a custom message and has
 * been handled, false if the message was not handled.
 */
static bool channeld_handle_custommsg(const u8 *msg)
{
#if DEVELOPER
	enum peer_wire type = fromwire_peektype(msg);
	if (type % 2 == 1 && !peer_wire_is_defined(type)) {
		/* The message is not part of the messages we know how to
		 * handle. Assuming this is a custommsg, we just forward it to the
		 * master. */
		wire_sync_write(MASTER_FD, take(towire_custommsg_in(NULL, msg)));
		return true;
	} else {
		return false;
	}
#else
	return false;
#endif
}

#if EXPERIMENTAL_FEATURES
static void handle_send_tx_sigs(struct peer *peer, const u8 *msg)
{
	struct wally_psbt *psbt;
	struct bitcoin_txid txid;

	if (!fromwire_channeld_send_tx_sigs(tmpctx, msg, &psbt))
		master_badmsg(WIRE_CHANNELD_SEND_TX_SIGS, msg);

	/* Check that we've got the same / correct PSBT */
	psbt_txid(NULL, psbt, &txid, NULL);
	if (!bitcoin_txid_eq(&txid, &peer->channel->funding_txid))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Txid for passed in PSBT does not match"
			      " funding txid for channel. Expected %s, "
			      "received %s",
			      type_to_string(tmpctx, struct bitcoin_txid,
					     &peer->channel->funding_txid),
			      type_to_string(tmpctx, struct bitcoin_txid,
					     &txid));

	tal_wally_start();
	if (wally_psbt_combine(peer->psbt, psbt) != WALLY_OK) {
		tal_wally_end(tal_free(peer->psbt));
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Unable to combine PSBTs");
	}
	tal_wally_end(tal_steal(peer, peer->psbt));
#if EXPERIMENTAL_FEATURES
	sync_crypto_write(peer->pps,
		take(psbt_to_tx_sigs_msg(NULL, peer, psbt)));
#endif /* EXPERIMENTAL_FEATURES */
}

static void handle_tx_sigs(struct peer *peer, const u8 *msg)
{
	struct channel_id cid;
	struct bitcoin_txid txid;
	const struct witness_stack **ws;

	size_t j = 0;
	enum tx_role their_role = their_tx_role(peer);

	if (!fromwire_tx_signatures(tmpctx, msg, &cid, &txid,
				    cast_const3(
					 struct witness_stack ***,
					 &ws)))
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad tx_signatures %s",
			    tal_hex(msg, msg));

	/* Maybe they didn't get our funding_locked message ? */
	if (peer->funding_locked[LOCAL]) {
		status_broken("Got WIRE_TX_SIGNATURES after funding locked "
			       "for channel %s, ignoring: %s",
			       type_to_string(tmpctx, struct channel_id,
					      &peer->channel_id),
			       tal_hex(tmpctx, msg));
		return;
	}

	if (peer->funding_locked[REMOTE])
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "tx_signatures sent after funding_locked %s",
			    tal_hex(msg, msg));

	if (!peer->psbt) {
		status_broken("Got WIRE_TX_SIGNATURES with no PSBT "
			       "for channel %s, ignoring: %s",
			       type_to_string(tmpctx, struct channel_id,
					      &peer->channel_id),
			       tal_hex(tmpctx, msg));
		return;
	}

	/* This check only works if they've got inputs we need sigs for.
	 * In the case where they send duplicate tx_sigs but have no
	 * sigs, we'll end up re-notifying */
	if (tal_count(ws) && psbt_side_finalized(peer->psbt, their_role)) {
		status_info("Got duplicate WIRE_TX_SIGNATURES, "
			    "already have their sigs. Ignoring");
		return;
	}

	/* We put the PSBT + sigs all together */
	for (size_t i = 0; i < peer->psbt->num_inputs; i++) {
		struct wally_psbt_input *in =
			&peer->psbt->inputs[i];
		u64 in_serial;
		const struct witness_element **elem;

		if (!psbt_get_serial_id(&in->unknowns, &in_serial)) {
			status_broken("PSBT input %zu missing serial_id %s",
				      i, type_to_string(tmpctx,
							struct wally_psbt,
							peer->psbt));
			return;
		}
		if (in_serial % 2 != their_role)
			continue;

		if (j == tal_count(ws))
			peer_failed(peer->pps, &peer->channel_id,
				    "Mismatch witness stack count %s",
				    tal_hex(msg, msg));

		elem = cast_const2(const struct witness_element **,
				   ws[j++]->witness_element);
		psbt_finalize_input(peer->psbt, in, elem);
	}

	/* Send to the peer controller, who will broadcast the funding_tx
	 * as soon as we've got our sigs */
	wire_sync_write(MASTER_FD,
			take(towire_channeld_funding_sigs(NULL, peer->psbt)));
}
#endif /* EXPERIMENTAL_FEATURES */

static void handle_unexpected_reestablish(struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 next_commitment_number;
	u64 next_revocation_number;
	struct secret your_last_per_commitment_secret;
	struct pubkey my_current_per_commitment_point;

	if (!fromwire_channel_reestablish(msg, &channel_id,
					  &next_commitment_number,
					  &next_revocation_number,
					  &your_last_per_commitment_secret,
					  &my_current_per_commitment_point))
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "Bad channel_reestablish %s", tal_hex(peer, msg));

	/* Is it the same as the peer channel ID?  */
	if (channel_id_eq(&channel_id, &peer->channel_id)) {
		/* Log this event as unusual.  */
		status_unusual("Got repeated WIRE_CHANNEL_REESTABLISH "
			       "for channel %s, ignoring: %s",
			       type_to_string(tmpctx, struct channel_id,
					      &peer->channel_id),
			       tal_hex(tmpctx, msg));
		/* This is a mitigation for a known bug in some peer software
		 * that sometimes double-sends a reestablish message.
		 *
		 * Ideally we would send some kind of `error` message to the
		 * peer here, but if we sent an `error` message with the
		 * same channel ID it would cause the peer to drop the
		 * channel unilaterally.
		 * We also cannot use 0x00...00 because that means "all
		 * channels", so a proper peer (like C-lightning) will
		 * unilaterally close all channels we have with it, if we
		 * sent the 0x00...00 channel ID.
		 *
		 * So just do not send an error.
		 */
		return;
	}

	/* We only support one channel here, so the unexpected channel is the
	 * peer getting its wires crossed somewhere.
	 * Fail the channel they sent, not the channel we are actively
	 * handling.  */
	peer_failed(peer->pps, &channel_id,
		    "Peer sent unexpected message %u, (%s) "
		    "for nonexistent channel %s",
		    WIRE_CHANNEL_REESTABLISH, "WIRE_CHANNEL_REESTABLISH",
		    type_to_string(tmpctx, struct channel_id,
				   &channel_id));
}

static void peer_in(struct peer *peer, const u8 *msg)
{
	enum peer_wire type = fromwire_peektype(msg);

	/* Only count soft errors if the channel has locked-in already;
	 * otherwise we can't cancel a channel before it has opened.
	 */
	bool soft_error = peer->funding_locked[REMOTE] || peer->funding_locked[LOCAL];

	peer->last_recv = time_now();

	/* Catch our own ping replies. */
	if (type == WIRE_PONG && peer->expecting_pong) {
		peer->expecting_pong = false;
		return;
	}

	if (channeld_handle_custommsg(msg))
		return;

	/* Since LND seems to send errors which aren't actually fatal events,
	 * we treat errors here as soft. */
	if (handle_peer_gossip_or_error(peer->pps, &peer->channel_id, soft_error, msg))
		return;

	/* Must get funding_locked before almost anything. */
	if (!peer->funding_locked[REMOTE]) {
		if (type != WIRE_FUNDING_LOCKED
		    && type != WIRE_PONG
		    && type != WIRE_SHUTDOWN
#if EXPERIMENTAL_FEATURES
		    /* We expect these for v2 !! */
		    && type != WIRE_TX_SIGNATURES
#endif /* EXPERIMENTAL_FEATURES */
		    /* lnd sends these early; it's harmless. */
		    && type != WIRE_UPDATE_FEE
		    && type != WIRE_ANNOUNCEMENT_SIGNATURES) {
			peer_failed(peer->pps,
				    &peer->channel_id,
				    "%s (%u) before funding locked",
				    peer_wire_name(type), type);
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
	case WIRE_SHUTDOWN:
		handle_peer_shutdown(peer, msg);
		return;
#if EXPERIMENTAL_FEATURES
	case WIRE_TX_SIGNATURES:
		handle_tx_sigs(peer, msg);
		return;
	case WIRE_INIT_RBF:
	/* FIXME: handle this here */
		break;
#endif

	case WIRE_INIT:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_CLOSING_SIGNED:
#if EXPERIMENTAL_FEATURES
	case WIRE_TX_ADD_INPUT:
	case WIRE_TX_REMOVE_INPUT:
	case WIRE_TX_ADD_OUTPUT:
	case WIRE_TX_REMOVE_OUTPUT:
	case WIRE_TX_COMPLETE:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_BLACKLIST_PODLE:
#endif
		break;

	case WIRE_CHANNEL_REESTABLISH:
		handle_unexpected_reestablish(peer, msg);
		return;

	/* These are all swallowed by handle_peer_gossip_or_error */
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
	case WIRE_QUERY_CHANNEL_RANGE:
	case WIRE_REPLY_CHANNEL_RANGE:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
	case WIRE_PING:
	case WIRE_PONG:
	case WIRE_ERROR:
#if EXPERIMENTAL_FEATURES
	case WIRE_ONION_MESSAGE:
#endif
		abort();
	}

	peer_failed(peer->pps,
		    &peer->channel_id,
		    "Peer sent unknown message %u (%s)",
		    type, peer_wire_name(type));
}

static void resend_revoke(struct peer *peer)
{
	struct pubkey point;
	/* Current commit is peer->next_index[LOCAL]-1, revoke prior */
	u8 *msg = make_revocation_msg(peer, peer->next_index[LOCAL]-2, &point);
	sync_crypto_write(peer->pps, take(msg));
}

static void send_fail_or_fulfill(struct peer *peer, const struct htlc *h)
{
	u8 *msg;

	if (h->failed) {
		const struct failed_htlc *f = h->failed;
		if (f->sha256_of_onion) {
			msg = towire_update_fail_malformed_htlc(NULL,
								&peer->channel_id,
								h->id,
								f->sha256_of_onion,
								f->badonion);
		} else {
			msg = towire_update_fail_htlc(peer, &peer->channel_id, h->id,
						      f->onion->contents);
		}
	} else if (h->r) {
		msg = towire_update_fulfill_htlc(NULL, &peer->channel_id, h->id,
						 h->r);
	} else
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "HTLC %"PRIu64" state %s not failed/fulfilled",
			    h->id, htlc_state_name(h->state));
	sync_crypto_write(peer->pps, take(msg));
}

static int cmp_changed_htlc_id(const struct changed_htlc *a,
			       const struct changed_htlc *b,
			       void *unused)
{
	/* ids can be the same (sender and receiver are indep) but in
	 * that case we don't care about order. */
	if (a->id > b->id)
		return 1;
	else if (a->id < b->id)
		return -1;
	return 0;
}

static void resend_commitment(struct peer *peer, struct changed_htlc *last)
{
	size_t i;
	struct bitcoin_signature commit_sig, *htlc_sigs;
	u8 *msg;
	struct bitcoin_tx **txs;
	const u8 *funding_wscript;
	const struct htlc **htlc_map;
	struct wally_tx_output *direct_outputs[NUM_SIDES];

	status_debug("Retransmitting commitment, feerate LOCAL=%u REMOTE=%u",
		     channel_feerate(peer->channel, LOCAL),
		     channel_feerate(peer->channel, REMOTE));

	/* Note that HTLCs must be *added* in order.  Simplest thing to do
	 * is to sort them all into ascending ID order here (we could do
	 * this when we save them in channel_sending_commit, but older versions
	 * won't have them sorted in the db, so doing it here is better). */
	asort(last, tal_count(last), cmp_changed_htlc_id, NULL);

	/* BOLT #2:
	 *
	 *   - if `next_commitment_number` is equal to the commitment
	 *     number of the last `commitment_signed` message the receiving node
	 *     has sent:
	 *     - MUST reuse the same commitment number for its next
	 *       `commitment_signed`.
	 */
	/* In our case, we consider ourselves already committed to this, so
	 * retransmission is simplest. */
	/* We need to send fulfills/failures before adds, so we split them
	 * up into two loops -- this is the 'fulfill/fail' loop */
	for (i = 0; i < tal_count(last); i++) {
		const struct htlc *h;

		h = channel_get_htlc(peer->channel,
				     htlc_state_owner(last[i].newstate),
				     last[i].id);
		/* I think this can happen if we actually received revoke_and_ack
		 * then they asked for a retransmit */
		if (!h)
			peer_failed(peer->pps,
				    &peer->channel_id,
				    "Can't find HTLC %"PRIu64" to resend",
				    last[i].id);

		if (h->state == SENT_REMOVE_COMMIT)
			send_fail_or_fulfill(peer, h);
	}
	/* We need to send fulfills/failures before adds, so we split them
	 * up into two loops -- this is the 'add' loop */
	for (i = 0; i < tal_count(last); i++) {
		const struct htlc *h;

		h = channel_get_htlc(peer->channel,
				     htlc_state_owner(last[i].newstate),
				     last[i].id);

		/* I think this can happen if we actually received revoke_and_ack
		 * then they asked for a retransmit */
		if (!h)
			peer_failed(peer->pps,
				    &peer->channel_id,
				    "Can't find HTLC %"PRIu64" to resend",
				    last[i].id);

		if (h->state == SENT_ADD_COMMIT) {
#if EXPERIMENTAL_FEATURES
			struct tlv_update_add_tlvs *tlvs;
			if (h->blinding) {
				tlvs = tlv_update_add_tlvs_new(tmpctx);
				tlvs->blinding = tal_dup(tlvs, struct pubkey,
							 h->blinding);
			} else
				tlvs = NULL;
#endif
			u8 *msg = towire_update_add_htlc(NULL, &peer->channel_id,
							 h->id, h->amount,
							 &h->rhash,
							 abs_locktime_to_blocks(
								 &h->expiry),
							 h->routing
#if EXPERIMENTAL_FEATURES
							 , tlvs
#endif
				);
			sync_crypto_write(peer->pps, take(msg));
		}
	}

	/* Make sure they have the correct fee. */
	if (peer->channel->opener == LOCAL) {
		msg = towire_update_fee(NULL, &peer->channel_id,
					channel_feerate(peer->channel, REMOTE));
		sync_crypto_write(peer->pps, take(msg));
	}

	/* Re-send the commitment_signed itself. */
	txs = channel_txs(tmpctx, &htlc_map, direct_outputs,
			  &funding_wscript, peer->channel, &peer->remote_per_commit,
			  peer->next_index[REMOTE]-1, REMOTE);

	htlc_sigs = calc_commitsigs(tmpctx, peer, txs, funding_wscript, htlc_map, peer->next_index[REMOTE]-1,
				    &commit_sig);
	msg = towire_commitment_signed(NULL, &peer->channel_id,
				       &commit_sig.s,
				       raw_sigs(tmpctx, htlc_sigs));
	sync_crypto_write(peer->pps, take(msg));

	/* If we have already received the revocation for the previous, the
	 * other side shouldn't be asking for a retransmit! */
	if (peer->revocations_received != peer->next_index[REMOTE] - 2)
		status_unusual("Retransmitted commitment_signed %"PRIu64
			       " but they already send revocation %"PRIu64"?",
			       peer->next_index[REMOTE]-1,
			       peer->revocations_received);
}

/* BOLT #2:
 *
 * A receiving node:
 *  - if `option_static_remotekey` applies to the commitment transaction:
 *    - if `next_revocation_number` is greater than expected above, AND
 *    `your_last_per_commitment_secret` is correct for that
 *    `next_revocation_number` minus 1:
 *...
 *  - otherwise, if it supports `option_data_loss_protect`:
 *    - if `next_revocation_number` is greater than expected above,
 *      AND `your_last_per_commitment_secret` is correct for that
 *     `next_revocation_number` minus 1:
 */
static void check_future_dataloss_fields(struct peer *peer,
			u64 next_revocation_number,
			const struct secret *last_local_per_commit_secret,
			/* This is NULL if option_static_remotekey */
			const struct pubkey *remote_current_per_commitment_point)
{
	const u8 *msg;
	bool correct;

	assert(next_revocation_number > peer->next_index[LOCAL] - 1);

	msg = towire_hsmd_check_future_secret(NULL,
					     next_revocation_number - 1,
					     last_local_per_commit_secret);
	msg = hsm_req(tmpctx, take(msg));
	if (!fromwire_hsmd_check_future_secret_reply(msg, &correct))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad hsm_check_future_secret_reply: %s",
			      tal_hex(tmpctx, msg));

	if (!correct)
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "bad future last_local_per_commit_secret: %"PRIu64
			    " vs %"PRIu64,
			    next_revocation_number,
			    peer->next_index[LOCAL] - 1);

	/* Oh shit, they really are from the future! */
	peer_billboard(true, "They have future commitment number %"PRIu64
		       " vs our %"PRIu64". We must wait for them to close!",
		       next_revocation_number,
		       peer->next_index[LOCAL] - 1);

	/* BOLT #2:
	 * - MUST NOT broadcast its commitment transaction.
	 * - SHOULD fail the channel.
	 * - SHOULD store `my_current_per_commitment_point` to
	 *   retrieve funds should the sending node broadcast its
	 *   commitment transaction on-chain.
	 */
	wire_sync_write(MASTER_FD,
			take(towire_channeld_fail_fallen_behind(NULL,
				       remote_current_per_commitment_point)));

	/* We have to send them an error to trigger dropping to chain. */
	peer_failed(peer->pps, &peer->channel_id, "Awaiting unilateral close");
}

/* BOLT #2:
 *
 * A receiving node:
 *  - if `option_static_remotekey` applies to the commitment transaction:
 * ...
 *  - if `your_last_per_commitment_secret` does not match the expected values:
 *     - SHOULD fail the channel.
 *  - otherwise, if it supports `option_data_loss_protect`:
 *...
 *    - otherwise (`your_last_per_commitment_secret` or
 *     `my_current_per_commitment_point` do not match the expected values):
 *      - SHOULD fail the channel.
 */
static void check_current_dataloss_fields(struct peer *peer,
			u64 next_revocation_number,
			u64 next_commitment_number,
			const struct secret *last_local_per_commit_secret,
			/* NULL if option_static_remotekey */
			const struct pubkey *remote_current_per_commitment_point)
{
	struct secret old_commit_secret;

	/* By the time we're called, we've ensured this is a valid revocation
	 * number. */
	assert(next_revocation_number == peer->next_index[LOCAL] - 2
	       || next_revocation_number == peer->next_index[LOCAL] - 1);

	/* By the time we're called, we've ensured we're within 1 of
	 * their commitment chain */
	assert(next_commitment_number == peer->next_index[REMOTE] ||
	       next_commitment_number == peer->next_index[REMOTE] - 1);

	if (!last_local_per_commit_secret)
		return;

	/* BOLT #2:
	 *    - if `next_revocation_number` equals 0:
	 *      - MUST set `your_last_per_commitment_secret` to all zeroes
	 */

	status_debug("next_revocation_number = %"PRIu64,
		     next_revocation_number);
	if (next_revocation_number == 0)
		memset(&old_commit_secret, 0, sizeof(old_commit_secret));
	else {
		struct pubkey unused;
		/* This gets previous revocation number, since asking for
		 * commitment point N gives secret for N-2 */
		get_per_commitment_point(next_revocation_number+1,
					 &unused, &old_commit_secret);
	}

	if (!secret_eq_consttime(&old_commit_secret,
				 last_local_per_commit_secret))
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "bad reestablish: your_last_per_commitment_secret %"PRIu64
			    ": %s should be %s",
			    next_revocation_number,
			    type_to_string(tmpctx, struct secret,
					   last_local_per_commit_secret),
			    type_to_string(tmpctx, struct secret,
					   &old_commit_secret));

	if (!remote_current_per_commitment_point) {
		status_debug("option_static_remotekey: fields are correct");
		return;
	}

	status_debug("Reestablish, comparing commitments. Remote's next local commitment number"
			" is %"PRIu64". Our next remote is %"PRIu64" with %"PRIu64
			" revocations received",
			next_commitment_number,
			peer->next_index[REMOTE],
			peer->revocations_received);

	/* Either they haven't received our commitment yet, or we're up to date */
	if (next_commitment_number == peer->revocations_received + 1) {
		if (!pubkey_eq(remote_current_per_commitment_point,
				&peer->old_remote_per_commit)) {
			peer_failed(peer->pps,
				    &peer->channel_id,
				    "bad reestablish: remote's "
				    "my_current_per_commitment_point %"PRIu64
				    "is %s; expected %s (new is %s).",
				    next_commitment_number - 1,
				    type_to_string(tmpctx, struct pubkey,
						   remote_current_per_commitment_point),
				    type_to_string(tmpctx, struct pubkey,
						   &peer->old_remote_per_commit),
				    type_to_string(tmpctx, struct pubkey,
						   &peer->remote_per_commit));
		}
	} else {
		/* We've sent a commit sig but haven't gotten a revoke+ack back */
		if (!pubkey_eq(remote_current_per_commitment_point,
				&peer->remote_per_commit)) {
			peer_failed(peer->pps,
				    &peer->channel_id,
				    "bad reestablish: remote's "
				    "my_current_per_commitment_point %"PRIu64
				    "is %s; expected %s (old is %s).",
				    next_commitment_number - 1,
				    type_to_string(tmpctx, struct pubkey,
						   remote_current_per_commitment_point),
				    type_to_string(tmpctx, struct pubkey,
						   &peer->remote_per_commit),
				    type_to_string(tmpctx, struct pubkey,
						   &peer->old_remote_per_commit));
		}
	}

	status_debug("option_data_loss_protect: fields are correct");
}

/* Older LND sometimes sends funding_locked before reestablish! */
/* ... or announcement_signatures.  Sigh, let's handle whatever they send. */
static bool capture_premature_msg(const u8 ***shit_lnd_says, const u8 *msg)
{
	if (fromwire_peektype(msg) == WIRE_CHANNEL_REESTABLISH)
		return false;

	/* Don't allow infinite memory consumption. */
	if (tal_count(*shit_lnd_says) > 10)
		return false;

	status_debug("Stashing early %s msg!",
		     peer_wire_name(fromwire_peektype(msg)));

	tal_arr_expand(shit_lnd_says, tal_steal(*shit_lnd_says, msg));
	return true;
}

static void peer_reconnect(struct peer *peer,
			   const struct secret *last_remote_per_commit_secret)
{
	struct channel_id channel_id;
	/* Note: BOLT #2 uses these names! */
	u64 next_commitment_number, next_revocation_number;
	bool retransmit_revoke_and_ack, retransmit_commitment_signed;
	struct htlc_map_iter it;
	const struct htlc *htlc;
	u8 *msg;
	struct pubkey my_current_per_commitment_point,
		remote_current_per_commitment_point;
	struct secret last_local_per_commitment_secret;
	bool dataloss_protect, check_extra_fields;
	const u8 **premature_msgs = tal_arr(peer, const u8 *, 0);

	dataloss_protect = feature_negotiated(peer->our_features,
					      peer->their_features,
					      OPT_DATA_LOSS_PROTECT);

	/* Both these options give us extra fields to check. */
	check_extra_fields
		= dataloss_protect || peer->channel->option_static_remotekey;

	/* Our current per-commitment point is the commitment point in the last
	 * received signed commitment */
	get_per_commitment_point(peer->next_index[LOCAL] - 1,
				 &my_current_per_commitment_point, NULL);

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
	 *   - MUST set `next_commitment_number` to the commitment number
	 *     of the next `commitment_signed` it expects to receive.
	 *   - MUST set `next_revocation_number` to the commitment number
	 *     of the next `revoke_and_ack` message it expects to receive.
	 *   - if `option_static_remotekey` applies to the commitment transaction:
	 *     - MUST set `my_current_per_commitment_point` to a valid point.
	 *   - otherwise:
	 *     - MUST set `my_current_per_commitment_point` to its commitment
	 *       point for the last signed commitment it received from its
	 *       channel peer (i.e. the commitment_point corresponding to the
	 *       commitment transaction the sender would use to unilaterally
	 *       close).
	 *   - if `next_revocation_number` equals 0:
	 *     - MUST set `your_last_per_commitment_secret` to all zeroes
	 *   - otherwise:
	 *     - MUST set `your_last_per_commitment_secret` to the last
	 *       `per_commitment_secret` it received
	 */
	if (peer->channel->option_static_remotekey) {
		msg = towire_channel_reestablish
			(NULL, &peer->channel_id,
			 peer->next_index[LOCAL],
			 peer->revocations_received,
			 last_remote_per_commit_secret,
			 /* Can send any (valid) point here */
			 &peer->remote_per_commit);
	} else {
		msg = towire_channel_reestablish
			(NULL, &peer->channel_id,
			 peer->next_index[LOCAL],
			 peer->revocations_received,
			 last_remote_per_commit_secret,
			 &my_current_per_commitment_point);
	}

	sync_crypto_write(peer->pps, take(msg));

	peer_billboard(false, "Sent reestablish, waiting for theirs");
	bool soft_error = peer->funding_locked[REMOTE]
		|| peer->funding_locked[LOCAL];

	/* Read until they say something interesting (don't forward
	 * gossip *to* them yet: we might try sending channel_update
	 * before we've reestablished channel). */
	do {
		clean_tmpctx();
		msg = sync_crypto_read(tmpctx, peer->pps);
	} while (channeld_handle_custommsg(msg) ||
		 handle_peer_gossip_or_error(peer->pps, &peer->channel_id, soft_error,
					     msg) ||
		 capture_premature_msg(&premature_msgs, msg));

	if (!fromwire_channel_reestablish(msg,
					&channel_id,
					&next_commitment_number,
					&next_revocation_number,
					&last_local_per_commitment_secret,
					&remote_current_per_commitment_point)) {
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "bad reestablish msg: %s %s",
			    peer_wire_name(fromwire_peektype(msg)),
			    tal_hex(msg, msg));
	}

	status_debug("Got reestablish commit=%"PRIu64" revoke=%"PRIu64,
		     next_commitment_number,
		     next_revocation_number);

#if EXPERIMENTAL_FEATURES
	/* Send our tx_sigs again */
	if (peer->psbt && psbt_side_finalized(peer->psbt,
					      our_tx_role(peer))
		&& !peer->funding_locked[REMOTE])
		sync_crypto_write(peer->pps,
			take(psbt_to_tx_sigs_msg(NULL, peer, peer->psbt)));
#endif /* EXPERIMENTAL_FEATURES */

	/* BOLT #2:
	 *
	 *   - if `next_commitment_number` is 1 in both the
	 *    `channel_reestablish` it sent and received:
	 *     - MUST retransmit `funding_locked`.
	 *   - otherwise:
	 *     - MUST NOT retransmit `funding_locked`.
	 */
	if (peer->funding_locked[LOCAL]
	    && peer->next_index[LOCAL] == 1
	    && next_commitment_number == 1) {
		u8 *msg;

		status_debug("Retransmitting funding_locked for channel %s",
		             type_to_string(tmpctx, struct channel_id, &peer->channel_id));
		/* Contains per commit point #1, for first post-opening commit */
		msg = towire_funding_locked(NULL,
					    &peer->channel_id,
					    &peer->next_local_per_commit);
		sync_crypto_write(peer->pps, take(msg));
	}

	/* Note: next_index is the index of the current commit we're working
	 * on, but BOLT #2 refers to the *last* commit index, so we -1 where
	 * required. */

	/* BOLT #2:
	 *
	 *  - if `next_revocation_number` is equal to the commitment
	 *    number of the last `revoke_and_ack` the receiving node sent, AND
	 *    the receiving node hasn't already received a `closing_signed`:
	 *    - MUST re-send the `revoke_and_ack`.
	 *  - otherwise:
	 *    - if `next_revocation_number` is not equal to 1 greater
	 *      than the commitment number of the last `revoke_and_ack` the
	 *      receiving node has sent:
	 *      - SHOULD fail the channel.
	 *    - if it has not sent `revoke_and_ack`, AND
	 *      `next_revocation_number` is not equal to 0:
	 *      - SHOULD fail the channel.
	 */
	if (next_revocation_number == peer->next_index[LOCAL] - 2) {
		/* Don't try to retransmit revocation index -1! */
		if (peer->next_index[LOCAL] < 2) {
			peer_failed(peer->pps,
				    &peer->channel_id,
				    "bad reestablish revocation_number: %"
				    PRIu64,
				    next_revocation_number);
		}
		retransmit_revoke_and_ack = true;
	} else if (next_revocation_number < peer->next_index[LOCAL] - 1) {
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "bad reestablish revocation_number: %"PRIu64
			    " vs %"PRIu64,
			    next_revocation_number,
			    peer->next_index[LOCAL]);
	} else if (next_revocation_number > peer->next_index[LOCAL] - 1) {
		if (!check_extra_fields)
			/* They don't support option_data_loss_protect or
			 * option_static_remotekey, we fail it due to
			 * unexpected number */
			peer_failed(peer->pps,
				    &peer->channel_id,
				    "bad reestablish revocation_number: %"PRIu64
				    " vs %"PRIu64,
				    next_revocation_number,
				    peer->next_index[LOCAL] - 1);

		/* Remote claims it's ahead of us: can it prove it?
		 * Does not return. */
		check_future_dataloss_fields(peer,
					     next_revocation_number,
					     &last_local_per_commitment_secret,
					     peer->channel->option_static_remotekey ? NULL :
					     &remote_current_per_commitment_point);
 	} else
 		retransmit_revoke_and_ack = false;

	/* BOLT #2:
	 *
	 *   - if `next_commitment_number` is equal to the commitment
	 *     number of the last `commitment_signed` message the receiving node
	 *     has sent:
	 *     - MUST reuse the same commitment number for its next
	 *       `commitment_signed`.
	 */
	if (next_commitment_number == peer->next_index[REMOTE] - 1) {
		/* We completed opening, we don't re-transmit that one! */
		if (next_commitment_number == 0)
			peer_failed(peer->pps,
				    &peer->channel_id,
				    "bad reestablish commitment_number: %"
				    PRIu64,
				    next_commitment_number);

		retransmit_commitment_signed = true;

	/* BOLT #2:
	 *
	 *   - otherwise:
	 *     - if `next_commitment_number` is not 1 greater than the
	 *       commitment number of the last `commitment_signed` message the
	 *       receiving node has sent:
	 *       - SHOULD fail the channel.
	 */
	} else if (next_commitment_number != peer->next_index[REMOTE])
		peer_failed(peer->pps,
			    &peer->channel_id,
			    "bad reestablish commitment_number: %"PRIu64
			    " vs %"PRIu64,
			    next_commitment_number,
			    peer->next_index[REMOTE]);
	else
		retransmit_commitment_signed = false;

	/* After we checked basic sanity, we check dataloss fields if any */
	if (check_extra_fields)
		check_current_dataloss_fields(peer,
					      next_revocation_number,
					      next_commitment_number,
					      &last_local_per_commitment_secret,
					      peer->channel->option_static_remotekey
					      ? NULL
					      : &remote_current_per_commitment_point);

	/* We have to re-send in the same order we sent originally:
	 * revoke_and_ack (usually) alters our next commitment. */
	if (retransmit_revoke_and_ack && !peer->last_was_revoke)
		resend_revoke(peer);

	if (retransmit_commitment_signed)
		resend_commitment(peer, peer->last_sent_commit);

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

	peer_billboard(true, "Reconnected, and reestablished.");

	/* BOLT #2:
	 *   - upon reconnection:
	 *...
	 *       - MUST transmit `channel_reestablish` for each channel.
	 *       - MUST wait to receive the other node's `channel_reestablish`
	 *         message before sending any other messages for that channel.
	 */
	/* LND doesn't wait. */
	for (size_t i = 0; i < tal_count(premature_msgs); i++)
		peer_in(peer, premature_msgs[i]);
	tal_free(premature_msgs);
}

/* ignores the funding_depth unless depth >= minimum_depth
 * (except to update billboard, and set peer->depth_togo). */
static void handle_funding_depth(struct peer *peer, const u8 *msg)
{
	u32 depth;
	struct short_channel_id *scid;

	if (!fromwire_channeld_funding_depth(tmpctx,
					    msg,
					    &scid,
					    &depth))
		master_badmsg(WIRE_CHANNELD_FUNDING_DEPTH, msg);

	/* Too late, we're shutting down! */
	if (peer->shutdown_sent[LOCAL])
		return;

	if (depth < peer->channel->minimum_depth) {
		peer->depth_togo = peer->channel->minimum_depth - depth;

	} else {
		/* We were waiting for them to send us their
		 * `tx_signatures`, but they never did. As a
		 * result we'll still have the psbt */
		if (peer->psbt && !psbt_side_finalized(peer->psbt,
						       their_tx_role(peer))) {
			peer_failed(peer->pps, &peer->channel_id,
				    "Funding tx reached funding depth %d "
				    "but we haven't received peer's "
				    "tx_signatures",
				    depth);
		}

		peer->depth_togo = 0;

		assert(scid);
		peer->short_channel_ids[LOCAL] = *scid;

		if (!peer->funding_locked[LOCAL]) {
			status_debug("funding_locked: sending commit index %"PRIu64": %s",
						peer->next_index[LOCAL],
						type_to_string(tmpctx, struct pubkey,
					&peer->next_local_per_commit));

			msg = towire_funding_locked(NULL,
						    &peer->channel_id,
						    &peer->next_local_per_commit);
			sync_crypto_write(peer->pps, take(msg));

			peer->funding_locked[LOCAL] = true;
		}

		peer->announce_depth_reached = (depth >= ANNOUNCE_MIN_DEPTH);

		/* Send temporary or final announcements */
		channel_announcement_negotiate(peer);
	}

	billboard_update(peer);
}

static void handle_offer_htlc(struct peer *peer, const u8 *inmsg)
{
	u8 *msg;
	u32 cltv_expiry;
	struct amount_msat amount;
	struct sha256 payment_hash;
	u8 onion_routing_packet[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)];
	enum channel_add_err e;
	const u8 *failwiremsg;
	const char *failstr;
	struct amount_sat htlc_fee;
	struct pubkey *blinding;

	if (!peer->funding_locked[LOCAL] || !peer->funding_locked[REMOTE])
		status_failed(STATUS_FAIL_MASTER_IO,
			      "funding not locked for offer_htlc");

	if (!fromwire_channeld_offer_htlc(tmpctx, inmsg, &amount,
					 &cltv_expiry, &payment_hash,
					 onion_routing_packet, &blinding))
		master_badmsg(WIRE_CHANNELD_OFFER_HTLC, inmsg);

#if EXPERIMENTAL_FEATURES
	struct tlv_update_add_tlvs *tlvs;
	if (blinding) {
		tlvs = tlv_update_add_tlvs_new(tmpctx);
		tlvs->blinding = tal_dup(tlvs, struct pubkey, blinding);
	} else
		tlvs = NULL;
#endif

	e = channel_add_htlc(peer->channel, LOCAL, peer->htlc_id,
			     amount, cltv_expiry, &payment_hash,
			     onion_routing_packet, take(blinding), NULL, &htlc_fee);
	status_debug("Adding HTLC %"PRIu64" amount=%s cltv=%u gave %s",
		     peer->htlc_id,
		     type_to_string(tmpctx, struct amount_msat, &amount),
		     cltv_expiry,
		     channel_add_err_name(e));

	switch (e) {
	case CHANNEL_ERR_ADD_OK:
		/* Tell the peer. */
		msg = towire_update_add_htlc(NULL, &peer->channel_id,
					     peer->htlc_id, amount,
					     &payment_hash, cltv_expiry,
					     onion_routing_packet
#if EXPERIMENTAL_FEATURES
					     , tlvs
#endif
			);
		sync_crypto_write(peer->pps, take(msg));
		start_commit_timer(peer);
		/* Tell the master. */
		msg = towire_channeld_offer_htlc_reply(NULL, peer->htlc_id,
						      0, "");
		wire_sync_write(MASTER_FD, take(msg));
		peer->htlc_id++;
		return;
	case CHANNEL_ERR_INVALID_EXPIRY:
		failwiremsg = towire_incorrect_cltv_expiry(inmsg, cltv_expiry, get_local_channel_update(tmpctx, peer));
		failstr = tal_fmt(inmsg, "Invalid cltv_expiry %u", cltv_expiry);
		goto failed;
	case CHANNEL_ERR_DUPLICATE:
	case CHANNEL_ERR_DUPLICATE_ID_DIFFERENT:
		status_failed(STATUS_FAIL_MASTER_IO,
			      "Duplicate HTLC %"PRIu64, peer->htlc_id);

	case CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED:
		failwiremsg = towire_required_node_feature_missing(inmsg);
		failstr = "Mini mode: maximum value exceeded";
		goto failed;
	/* FIXME: Fuzz the boundaries a bit to avoid probing? */
	case CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED:
		failwiremsg = towire_temporary_channel_failure(inmsg, get_local_channel_update(inmsg, peer));
		failstr = tal_fmt(inmsg, "Capacity exceeded - HTLC fee: %s", fmt_amount_sat(inmsg, &htlc_fee));
		goto failed;
	case CHANNEL_ERR_HTLC_BELOW_MINIMUM:
		failwiremsg = towire_amount_below_minimum(inmsg, amount, get_local_channel_update(inmsg, peer));
		failstr = tal_fmt(inmsg, "HTLC too small (%s minimum)",
				  type_to_string(tmpctx,
						 struct amount_msat,
						 &peer->channel->config[REMOTE].htlc_minimum));
		goto failed;
	case CHANNEL_ERR_TOO_MANY_HTLCS:
		failwiremsg = towire_temporary_channel_failure(inmsg, get_local_channel_update(inmsg, peer));
		failstr = "Too many HTLCs";
		goto failed;
	}
	/* Shouldn't return anything else! */
	abort();

failed:
	msg = towire_channeld_offer_htlc_reply(NULL, 0, failwiremsg, failstr);
	wire_sync_write(MASTER_FD, take(msg));
}

static void handle_feerates(struct peer *peer, const u8 *inmsg)
{
	u32 feerate;

	if (!fromwire_channeld_feerates(inmsg, &feerate,
				       &peer->feerate_min,
				       &peer->feerate_max,
				       &peer->feerate_penalty))
		master_badmsg(WIRE_CHANNELD_FEERATES, inmsg);

	/* BOLT #2:
	 *
	 * The node _responsible_ for paying the Bitcoin fee:
	 *   - SHOULD send `update_fee` to ensure the current fee rate is
	 *    sufficient (by a significant margin) for timely processing of the
	 *     commitment transaction.
	 */
	if (peer->channel->opener == LOCAL) {
		peer->desired_feerate = feerate;
		/* Don't do this for the first feerate, wait until something else
		 * happens.  LND seems to get upset in some cases otherwise:
		 * see https://github.com/ElementsProject/lightning/issues/3596 */
		if (peer->next_index[LOCAL] != 1
		    || peer->next_index[REMOTE] != 1)
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

static void handle_specific_feerates(struct peer *peer, const u8 *inmsg)
{
	u32 base_old = peer->fee_base;
	u32 per_satoshi_old = peer->fee_per_satoshi;

	if (!fromwire_channeld_specific_feerates(inmsg,
				       &peer->fee_base,
				       &peer->fee_per_satoshi))
		master_badmsg(WIRE_CHANNELD_SPECIFIC_FEERATES, inmsg);

	/* only send channel updates if values actually changed */
	if (peer->fee_base != base_old || peer->fee_per_satoshi != per_satoshi_old)
		send_channel_update(peer, 0);
}


static void handle_preimage(struct peer *peer, const u8 *inmsg)
{
	struct fulfilled_htlc fulfilled_htlc;
	struct htlc *h;

	if (!fromwire_channeld_fulfill_htlc(inmsg, &fulfilled_htlc))
		master_badmsg(WIRE_CHANNELD_FULFILL_HTLC, inmsg);

	switch (channel_fulfill_htlc(peer->channel, REMOTE,
				     fulfilled_htlc.id,
				     &fulfilled_htlc.payment_preimage,
				     &h)) {
	case CHANNEL_ERR_REMOVE_OK:
		send_fail_or_fulfill(peer, h);
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
			      "HTLC %"PRIu64" preimage failed",
			      fulfilled_htlc.id);
	}
	abort();
}

static void handle_fail(struct peer *peer, const u8 *inmsg)
{
	struct failed_htlc *failed_htlc;
	enum channel_remove_err e;
	struct htlc *h;

	if (!fromwire_channeld_fail_htlc(inmsg, inmsg, &failed_htlc))
		master_badmsg(WIRE_CHANNELD_FAIL_HTLC, inmsg);

	e = channel_fail_htlc(peer->channel, REMOTE, failed_htlc->id, &h);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK:
		h->failed = tal_steal(h, failed_htlc);
		send_fail_or_fulfill(peer, h);
		start_commit_timer(peer);
		return;
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		status_failed(STATUS_FAIL_MASTER_IO,
			      "HTLC %"PRIu64" removal failed: %s",
			      failed_htlc->id,
			      channel_remove_err_name(e));
	}
	abort();
}

static void handle_shutdown_cmd(struct peer *peer, const u8 *inmsg)
{
	u8 *local_shutdown_script;

	if (!fromwire_channeld_send_shutdown(peer, inmsg, &local_shutdown_script))
		master_badmsg(WIRE_CHANNELD_SEND_SHUTDOWN, inmsg);

	tal_free(peer->final_scriptpubkey);
	peer->final_scriptpubkey = local_shutdown_script;

	/* We can't send this until commit (if any) is done, so start timer. */
	peer->send_shutdown = true;
	start_commit_timer(peer);
}

static void handle_send_error(struct peer *peer, const u8 *msg)
{
	char *reason;
	if (!fromwire_channeld_send_error(msg, msg, &reason))
		master_badmsg(WIRE_CHANNELD_SEND_ERROR, msg);
	status_debug("Send error reason: %s", reason);
	sync_crypto_write(peer->pps,
			  take(towire_errorfmt(NULL, &peer->channel_id,
					       "%s", reason)));

	wire_sync_write(MASTER_FD,
			take(towire_channeld_send_error_reply(NULL)));
}

#if DEVELOPER
static void handle_dev_reenable_commit(struct peer *peer)
{
	dev_suppress_commit = false;
	start_commit_timer(peer);
	status_debug("dev_reenable_commit");
	wire_sync_write(MASTER_FD,
			take(towire_channeld_dev_reenable_commit_reply(NULL)));
}

static void handle_dev_memleak(struct peer *peer, const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	memtable = memleak_find_allocations(tmpctx, msg, msg);

	/* Now delete peer and things it has pointers to. */
	memleak_remove_region(memtable, peer, tal_bytelen(peer));

	found_leak = dump_memleak(memtable);
	wire_sync_write(MASTER_FD,
			 take(towire_channeld_dev_memleak_reply(NULL,
							       found_leak)));
}

/* We were told to send a custommsg to the peer by `lightningd`. All the
 * verification is done on the side of `lightningd` so we should be good to
 * just forward it here. */
static void channeld_send_custommsg(struct peer *peer, const u8 *msg)
{
	sync_crypto_write(peer->pps, take(msg));
}
#endif /* DEVELOPER */

static void req_in(struct peer *peer, const u8 *msg)
{
	enum channeld_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CHANNELD_FUNDING_DEPTH:
		handle_funding_depth(peer, msg);
		return;
	case WIRE_CHANNELD_OFFER_HTLC:
		handle_offer_htlc(peer, msg);
		return;
	case WIRE_CHANNELD_FEERATES:
		handle_feerates(peer, msg);
		return;
	case WIRE_CHANNELD_FULFILL_HTLC:
		handle_preimage(peer, msg);
		return;
	case WIRE_CHANNELD_FAIL_HTLC:
		handle_fail(peer, msg);
		return;
	case WIRE_CHANNELD_SPECIFIC_FEERATES:
		handle_specific_feerates(peer, msg);
		return;
	case WIRE_CHANNELD_SEND_SHUTDOWN:
		handle_shutdown_cmd(peer, msg);
		return;
	case WIRE_CHANNELD_SEND_ERROR:
		handle_send_error(peer, msg);
		return;
#if EXPERIMENTAL_FEATURES
	case WIRE_CHANNELD_SEND_TX_SIGS:
		handle_send_tx_sigs(peer, msg);
		return;
#else
	case WIRE_CHANNELD_SEND_TX_SIGS:
		break;
#endif /* !EXPERIMENTAL_FEATURES */
#if DEVELOPER
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT:
		handle_dev_reenable_commit(peer);
		return;
	case WIRE_CHANNELD_DEV_MEMLEAK:
		handle_dev_memleak(peer, msg);
		return;
#else
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT:
	case WIRE_CHANNELD_DEV_MEMLEAK:
#endif /* DEVELOPER */
	case WIRE_CHANNELD_INIT:
	case WIRE_CHANNELD_FUNDING_SIGS:
	case WIRE_CHANNELD_OFFER_HTLC_REPLY:
	case WIRE_CHANNELD_SENDING_COMMITSIG:
	case WIRE_CHANNELD_GOT_COMMITSIG:
	case WIRE_CHANNELD_GOT_REVOKE:
	case WIRE_CHANNELD_SENDING_COMMITSIG_REPLY:
	case WIRE_CHANNELD_GOT_COMMITSIG_REPLY:
	case WIRE_CHANNELD_GOT_REVOKE_REPLY:
	case WIRE_CHANNELD_GOT_FUNDING_LOCKED:
	case WIRE_CHANNELD_GOT_ANNOUNCEMENT:
	case WIRE_CHANNELD_GOT_SHUTDOWN:
	case WIRE_CHANNELD_SHUTDOWN_COMPLETE:
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT_REPLY:
	case WIRE_CHANNELD_FAIL_FALLEN_BEHIND:
	case WIRE_CHANNELD_DEV_MEMLEAK_REPLY:
	case WIRE_CHANNELD_SEND_ERROR_REPLY:
		break;
	}

	/* Now handle common messages. */
	switch ((enum common_wire)t) {
#if DEVELOPER
	case WIRE_CUSTOMMSG_OUT:
		channeld_send_custommsg(peer, msg);
		return;
#else
	case WIRE_CUSTOMMSG_OUT:
#endif
	/* We send these. */
	case WIRE_CUSTOMMSG_IN:
		break;
	}

	master_badmsg(-1, msg);
}

/* We do this synchronously. */
static void init_channel(struct peer *peer)
{
	struct basepoints points[NUM_SIDES];
	struct amount_sat funding;
	u16 funding_txout;
	struct amount_msat local_msat;
	struct pubkey funding_pubkey[NUM_SIDES];
	struct channel_config conf[NUM_SIDES];
	struct bitcoin_txid funding_txid;
	enum side opener;
	struct existing_htlc **htlcs;
	bool reconnected;
	u8 *fwd_msg;
	const u8 *msg;
	struct fee_states *fee_states;
	u32 minimum_depth;
	struct secret last_remote_per_commit_secret;
	secp256k1_ecdsa_signature *remote_ann_node_sig;
	secp256k1_ecdsa_signature *remote_ann_bitcoin_sig;
	bool option_static_remotekey, option_anchor_outputs;
	struct penalty_base *pbases;
#if !DEVELOPER
	bool dev_fail_process_onionpacket; /* Ignored */
#endif

	assert(!(fcntl(MASTER_FD, F_GETFL) & O_NONBLOCK));

	status_setup_sync(MASTER_FD);

	msg = wire_sync_read(tmpctx, MASTER_FD);
	if (!fromwire_channeld_init(peer, msg,
				   &chainparams,
				   &peer->our_features,
				   &peer->channel_id,
				   &funding_txid, &funding_txout,
				   &funding,
				   &minimum_depth,
				   &conf[LOCAL], &conf[REMOTE],
				   &fee_states,
				   &peer->feerate_min,
				   &peer->feerate_max,
				   &peer->feerate_penalty,
				   &peer->their_commit_sig,
				   &peer->pps,
				   &funding_pubkey[REMOTE],
				   &points[REMOTE],
				   &peer->remote_per_commit,
				   &peer->old_remote_per_commit,
				   &opener,
				   &peer->fee_base,
				   &peer->fee_per_satoshi,
				   &local_msat,
				   &points[LOCAL],
				   &funding_pubkey[LOCAL],
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
				   &peer->funding_locked[LOCAL],
				   &peer->funding_locked[REMOTE],
				   &peer->short_channel_ids[LOCAL],
				   &reconnected,
				   &peer->send_shutdown,
				   &peer->shutdown_sent[REMOTE],
				   &peer->final_scriptpubkey,
				   &peer->channel_flags,
				   &fwd_msg,
				   &peer->announce_depth_reached,
				   &last_remote_per_commit_secret,
				   &peer->their_features,
				   &peer->remote_upfront_shutdown_script,
				   &remote_ann_node_sig,
				   &remote_ann_bitcoin_sig,
				   &option_static_remotekey,
				   &option_anchor_outputs,
				   &dev_fast_gossip,
				   &dev_fail_process_onionpacket,
				   &pbases,
				   &peer->psbt)) {
		master_badmsg(WIRE_CHANNELD_INIT, msg);
	}

	/* Keeping an array of pointers is better since it allows us to avoid
	 * extra allocations later. */
	peer->pbases = tal_arr(peer, struct penalty_base *, 0);
	for (size_t i=0; i<tal_count(pbases); i++)
		tal_arr_expand(&peer->pbases,
			       tal_dup(peer, struct penalty_base, &pbases[i]));
	tal_free(pbases);

	/* Once the peer has sent locked, we no longer need to re-send
	 * tx_signatures, hence the PSBT can be free'd */
	if (peer->funding_locked[REMOTE])
		peer->psbt = tal_free(peer->psbt);

	/* stdin == requests, 3 == peer, 4 = gossip, 5 = gossip_store, 6 = HSM */
	per_peer_state_set_fds(peer->pps, 3, 4, 5);

	status_debug("init %s: remote_per_commit = %s, old_remote_per_commit = %s"
		     " next_idx_local = %"PRIu64
		     " next_idx_remote = %"PRIu64
		     " revocations_received = %"PRIu64
		     " feerates %s range %u-%u",
		     side_to_str(opener),
		     type_to_string(tmpctx, struct pubkey,
				    &peer->remote_per_commit),
		     type_to_string(tmpctx, struct pubkey,
				    &peer->old_remote_per_commit),
		     peer->next_index[LOCAL], peer->next_index[REMOTE],
		     peer->revocations_received,
		     type_to_string(tmpctx, struct fee_states, fee_states),
		     peer->feerate_min, peer->feerate_max);

	status_debug("option_static_remotekey = %u", option_static_remotekey);

	if (remote_ann_node_sig && remote_ann_bitcoin_sig) {
		peer->announcement_node_sigs[REMOTE] = *remote_ann_node_sig;
		peer->announcement_bitcoin_sigs[REMOTE] = *remote_ann_bitcoin_sig;
		peer->have_sigs[REMOTE] = true;

		/* Before we store announcement into DB, we have made sure
		 * remote short_channel_id matched the local. Now we initial
		 * it directly!
		 */
		peer->short_channel_ids[REMOTE] = peer->short_channel_ids[LOCAL];
		tal_free(remote_ann_node_sig);
		tal_free(remote_ann_bitcoin_sig);
	}

	/* First commit is used for opening: if we've sent 0, we're on
	 * index 1. */
	assert(peer->next_index[LOCAL] > 0);
	assert(peer->next_index[REMOTE] > 0);

	get_per_commitment_point(peer->next_index[LOCAL],
				 &peer->next_local_per_commit, NULL);

	peer->channel = new_full_channel(peer, &peer->channel_id,
					 &funding_txid,
					 funding_txout,
					 minimum_depth,
					 funding,
					 local_msat,
					 take(fee_states),
					 &conf[LOCAL], &conf[REMOTE],
					 &points[LOCAL], &points[REMOTE],
					 &funding_pubkey[LOCAL],
					 &funding_pubkey[REMOTE],
					 option_static_remotekey,
					 option_anchor_outputs,
					 opener);

	if (!channel_force_htlcs(peer->channel,
			 cast_const2(const struct existing_htlc **, htlcs)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not restore HTLCs");

	/* We don't need these any more, so free them. */
	tal_free(htlcs);

	peer->channel_direction = node_id_idx(&peer->node_ids[LOCAL],
					      &peer->node_ids[REMOTE]);

	/* Default desired feerate is the feerate we set for them last. */
	if (peer->channel->opener == LOCAL)
		peer->desired_feerate = channel_feerate(peer->channel, REMOTE);

	/* from now we need keep watch over WIRE_CHANNELD_FUNDING_DEPTH */
	peer->depth_togo = minimum_depth;

	/* OK, now we can process peer messages. */
	if (reconnected)
		peer_reconnect(peer, &last_remote_per_commit_secret);

	/* If we have a messages to send, send them immediately */
	if (fwd_msg)
		sync_crypto_write(peer->pps, take(fwd_msg));

#if EXPERIMENTAL_FEATURES
	/* peer_reconnect does this if needed */
	if (!reconnected && peer->psbt &&
			psbt_side_finalized(peer->psbt, our_tx_role(peer)))
		sync_crypto_write(peer->pps,
			take(psbt_to_tx_sigs_msg(NULL, peer, peer->psbt)));
#endif /* EXPERIMENTAL_FEATURES */

	/* Reenable channel */
	channel_announcement_negotiate(peer);

	billboard_update(peer);
}

static void send_shutdown_complete(struct peer *peer)
{
	/* Now we can tell master shutdown is complete. */
	wire_sync_write(MASTER_FD,
			take(towire_channeld_shutdown_complete(NULL, peer->pps)));
	per_peer_state_fdpass_send(MASTER_FD, peer->pps);
	close(MASTER_FD);
}

static void try_read_gossip_store(struct peer *peer)
{
	u8 *msg = gossip_store_next(tmpctx, peer->pps);

	if (msg)
		sync_crypto_write(peer->pps, take(msg));
}

int main(int argc, char *argv[])
{
	setup_locale();

	int i, nfds;
	fd_set fds_in, fds_out;
	struct peer *peer;

	subdaemon_setup(argc, argv);

	peer = tal(NULL, struct peer);
	peer->expecting_pong = false;
	timers_init(&peer->timers, time_mono());
	peer->commit_timer = NULL;
	peer->have_sigs[LOCAL] = peer->have_sigs[REMOTE] = false;
	peer->announce_depth_reached = false;
	peer->channel_local_active = false;
	peer->from_master = msg_queue_new(peer);
	peer->shutdown_sent[LOCAL] = false;
	peer->last_update_timestamp = 0;
	/* We actually received it in the previous daemon, but near enough */
	peer->last_recv = time_now();
	peer->last_empty_commitment = 0;

	/* We send these to HSM to get real signatures; don't have valgrind
	 * complain. */
	for (i = 0; i < NUM_SIDES; i++) {
		memset(&peer->announcement_node_sigs[i], 0,
		       sizeof(peer->announcement_node_sigs[i]));
		memset(&peer->announcement_bitcoin_sigs[i], 0,
		       sizeof(peer->announcement_bitcoin_sigs[i]));
	}

	/* Prepare the ecdh() function for use */
	ecdh_hsmd_setup(HSM_FD, status_failed);

	/* Read init_channel message sync. */
	init_channel(peer);

	FD_ZERO(&fds_in);
	FD_SET(MASTER_FD, &fds_in);
	FD_SET(peer->pps->peer_fd, &fds_in);
	FD_SET(peer->pps->gossip_fd, &fds_in);

	FD_ZERO(&fds_out);
	FD_SET(peer->pps->peer_fd, &fds_out);
	nfds = peer->pps->gossip_fd+1;

	while (!shutdown_complete(peer)) {
		struct timemono first;
		fd_set rfds = fds_in;
		struct timeval timeout, *tptr;
		struct timer *expired;
		const u8 *msg;
		struct timerel trel;
		struct timemono now = time_mono();

		/* Free any temporary allocations */
		clean_tmpctx();

		/* For simplicity, we process one event at a time. */
		msg = msg_dequeue(peer->from_master);
		if (msg) {
			status_debug("Now dealing with deferred %s",
				     channeld_wire_name(
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

		if (timer_earliest(&peer->timers, &first)) {
			timeout = timespec_to_timeval(
				timemono_between(first, now).ts);
			tptr = &timeout;
		} else if (time_to_next_gossip(peer->pps, &trel)) {
			timeout = timerel_to_timeval(trel);
			tptr = &timeout;
		} else
			tptr = NULL;

		if (select(nfds, &rfds, NULL, NULL, tptr) < 0) {
			/* Signals OK, eg. SIGUSR1 */
			if (errno == EINTR)
				continue;
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "select failed: %s", strerror(errno));
		}

		if (FD_ISSET(MASTER_FD, &rfds)) {
			msg = wire_sync_read(tmpctx, MASTER_FD);

			if (!msg)
				status_failed(STATUS_FAIL_MASTER_IO,
					      "Can't read command: %s",
					      strerror(errno));
			req_in(peer, msg);
		} else if (FD_ISSET(peer->pps->peer_fd, &rfds)) {
			/* This could take forever, but who cares? */
			msg = sync_crypto_read(tmpctx, peer->pps);
			peer_in(peer, msg);
		} else if (FD_ISSET(peer->pps->gossip_fd, &rfds)) {
			msg = wire_sync_read(tmpctx, peer->pps->gossip_fd);
			/* Gossipd hangs up on us to kill us when a new
			 * connection comes in. */
			if (!msg)
				peer_failed_connection_lost();
			handle_gossip_msg(peer->pps, take(msg));
		} else /* Lowest priority: stream from store. */
			try_read_gossip_store(peer);
	}

	/* We only exit when shutdown is complete. */
	assert(shutdown_complete(peer));
	send_shutdown_complete(peer);
	daemon_shutdown();
	return 0;
}
