/* Main channel operation daemon: runs from funding_locked to shutdown_complete.
 *
 * We're fairly synchronous: our main loop looks for master or
 * peer requests and services them synchronously.
 *
 * The exceptions are:
 * 1. When we've asked the master something: in that case, we queue
 *    non-response packets for later processing while we await the reply.
 * 2. We queue and send non-blocking responses to peers: if both peers were
 *    reading and writing synchronously we could deadlock if we hit buffer
 *    limits, unlikely as that is.
 */
#include "config.h"
#include <ccan/asort/asort.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <channeld/channeld.h>
#include <channeld/channeld_wiregen.h>
#include <channeld/full_channel.h>
#include <channeld/watchtower.h>
#include <common/billboard.h>
#include <common/ecdh_hsmd.h>
#include <common/gossip_store.h>
#include <common/key_derive.h>
#include <common/memleak.h>
#include <common/msg_queue.h>
#include <common/onionreply.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/peer_io.h>
#include <common/per_peer_state.h>
#include <common/private_channel_announcement.h>
#include <common/read_peer_msg.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gossip_store_wiregen.h>
#include <gossipd/gossipd_peerd_wiregen.h>
#include <hsmd/hsmd_wiregen.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

/* stdin == requests, 3 == peer, 4 = HSM */
#define MASTER_FD STDIN_FILENO
#define HSM_FD 4

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

	/* The feerate we want. */
	u32 desired_feerate;

	/* Current blockheight */
	u32 our_blockheight;

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
	/* If master told us to send wrong_funding */
	struct bitcoin_outpoint *shutdown_wrong_funding;

#if EXPERIMENTAL_FEATURES
	/* Do we want quiescence? */
	bool stfu;
	/* Which side is considered the initiator? */
	enum side stfu_initiator;
	/* Has stfu been sent by each side? */
	bool stfu_sent[NUM_SIDES];
	/* Updates master asked, which we've deferred while quiescing */
	struct msg_queue *update_queue;
#endif

#if DEVELOPER
	/* If set, don't fire commit counter when this hits 0 */
	u32 *dev_disable_commit;

	/* If set, send channel_announcement after 1 second, not 30 */
	bool dev_fast_gossip;
#endif
	/* Information used for reestablishment. */
	bool last_was_revoke;
	struct changed_htlc *last_sent_commit;
	u64 revocations_received;
	u8 channel_flags;

	bool announce_depth_reached;
	bool channel_local_active;

	/* Make sure timestamps move forward. */
	u32 last_update_timestamp;

	/* Additional confirmations need for local lockin. */
	u32 depth_togo;

	/* Non-empty if they specified a fixed shutdown script */
	u8 *remote_upfront_shutdown_script;

	/* Empty commitments.  Spec violation, but a minor one. */
	u64 last_empty_commitment;

	/* Penalty bases for this channel / peer. */
	struct penalty_base **pbases;

	/* We allow a 'tx-sigs' message between reconnect + funding_locked */
	bool tx_sigs_allowed;

	/* Most recent channel_update message. */
	u8 *channel_update;
};

static u8 *create_channel_announcement(const tal_t *ctx, struct peer *peer);
static void start_commit_timer(struct peer *peer);

static void billboard_update(const struct peer *peer)
{
	const char *update = billboard_message(tmpctx, peer->funding_locked,
					       peer->have_sigs,
					       peer->shutdown_sent,
					       peer->depth_togo,
					       num_channel_htlcs(peer->channel));

	peer_billboard(false, update);
}

const u8 *hsm_req(const tal_t *ctx, const u8 *req TAKES)
{
	u8 *msg;

	/* hsmd goes away at shutdown.  That's OK. */
	if (!wire_sync_write(HSM_FD, req))
		exit(0);

	msg = wire_sync_read(ctx, HSM_FD);
	if (!msg)
		exit(0);

	return msg;
}

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
	if (!amount_sat_sub(&lower_bound, channel->funding_sats,
			    channel->config[REMOTE].channel_reserve)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "funding %s - remote reserve %s?",
			      type_to_string(tmpctx, struct amount_sat,
					     &channel->funding_sats),
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

	return lower_bound_msat;
}

#if EXPERIMENTAL_FEATURES
static void maybe_send_stfu(struct peer *peer)
{
	if (!peer->stfu)
		return;

	if (!peer->stfu_sent[LOCAL] && !pending_updates(peer->channel, LOCAL, false)) {
		u8 *msg = towire_stfu(NULL, &peer->channel_id,
				      peer->stfu_initiator == LOCAL);
		peer_write(peer->pps, take(msg));
		peer->stfu_sent[LOCAL] = true;
	}

	if (peer->stfu_sent[LOCAL] && peer->stfu_sent[REMOTE]) {
		status_unusual("STFU complete: we are quiescent");
		wire_sync_write(MASTER_FD,
				towire_channeld_dev_quiesce_reply(tmpctx));
	}
}

static void handle_stfu(struct peer *peer, const u8 *stfu)
{
	struct channel_id channel_id;
	u8 remote_initiated;

	if (!fromwire_stfu(stfu, &channel_id, &remote_initiated))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad stfu %s", tal_hex(peer, stfu));

	if (!channel_id_eq(&channel_id, &peer->channel_id)) {
		peer_failed_err(peer->pps, &channel_id,
				"Wrong stfu channel_id: expected %s, got %s",
				type_to_string(tmpctx, struct channel_id,
					       &peer->channel_id),
				type_to_string(tmpctx, struct channel_id,
					       &channel_id));
	}

	/* Sanity check */
	if (pending_updates(peer->channel, REMOTE, false))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "STFU but you still have updates pending?");

	if (!peer->stfu) {
		peer->stfu = true;
		if (!remote_initiated)
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "Unsolicited STFU but you said"
					 " you didn't initiate?");
		peer->stfu_initiator = REMOTE;
	} else {
		/* BOLT-quiescent #2:
		 *
		 * If both sides send `stfu` simultaneously, they will both
		 * set `initiator` to `1`, in which case the "initiator" is
		 * arbitrarily considered to be the channel funder (the sender
		 * of `open_channel`).
		 */
		if (remote_initiated)
			peer->stfu_initiator = peer->channel->opener;
	}

	/* BOLT-quiescent #2:
	 * The receiver of `stfu`:
	 *   - if it has sent `stfu` then:
	 *     - MUST now consider the channel to be quiescent
	 *   - otherwise:
	 *     - SHOULD NOT send any more update messages.
	 *     - MUST reply with `stfu` once it can do so.
	 */
	peer->stfu_sent[REMOTE] = true;

	maybe_send_stfu(peer);
}

/* Returns true if we queued this for later handling (steals if true) */
static bool handle_master_request_later(struct peer *peer, const u8 *msg)
{
	if (peer->stfu) {
		msg_enqueue(peer->update_queue, take(msg));
		return true;
	}
	return false;
}

/* Compare, with false if either is NULL */
static bool match_type(const u8 *t1, const u8 *t2)
{
	/* Missing fields are possible. */
	if (!t1 || !t2)
		return false;

	return featurebits_eq(t1, t2);
}

static void set_channel_type(struct channel *channel, const u8 *type)
{
	const struct channel_type *cur = channel->type;

	if (featurebits_eq(cur->features, type))
		return;

	/* We only allow one upgrade at the moment, so that's it. */
	assert(!channel_has(channel, OPT_STATIC_REMOTEKEY));
	assert(feature_offered(type, OPT_STATIC_REMOTEKEY));

	/* Do upgrade, tell master. */
	tal_free(channel->type);
	channel->type = channel_type_from(channel, type);
	status_unusual("Upgraded channel to [%s]",
		       fmt_featurebits(tmpctx, type));
	wire_sync_write(MASTER_FD,
			take(towire_channeld_upgraded(NULL, channel->type)));
}
#else /* !EXPERIMENTAL_FEATURES */
static bool handle_master_request_later(struct peer *peer, const u8 *msg)
{
	return false;
}

static void maybe_send_stfu(struct peer *peer)
{
}
#endif

/* Tell gossipd to create channel_update (then it goes into
 * gossip_store, then streams out to peers, or sends it directly if
 * it's a private channel) */
static void send_channel_update(struct peer *peer, int disable_flag)
{
	u8 *msg;

	assert(disable_flag == 0 || disable_flag == ROUTING_FLAGS_DISABLED);

	/* Only send an update if we told gossipd */
	if (!peer->channel_local_active)
		return;

	assert(peer->short_channel_ids[LOCAL].u64);

	msg = towire_channeld_local_channel_update(NULL,
						  &peer->short_channel_ids[LOCAL],
						  disable_flag
						  == ROUTING_FLAGS_DISABLED,
						  peer->cltv_delta,
						  peer->channel->config[REMOTE].htlc_minimum,
						  peer->fee_base,
						  peer->fee_per_satoshi,
						  advertized_htlc_max(peer->channel));
	wire_sync_write(MASTER_FD, take(msg));
}

/* Tell gossipd and the other side what parameters we expect should
 * they route through us */
static void send_channel_initial_update(struct peer *peer)
{
	send_channel_update(peer, 0);
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
	const u8 *annfeatures = get_agreed_channelfeatures(tmpctx,
							   peer->our_features,
							   peer->their_features);

	/* Tell lightningd to tell gossipd about local channel. */
	msg = towire_channeld_local_private_channel(NULL,
						    peer->channel->funding_sats,
						    annfeatures);
 	wire_sync_write(MASTER_FD, take(msg));

	/* Under CI, because blocks come so fast, we often find that the
	 * peer sends its first channel_update before the above message has
	 * reached it. */
	notleak(new_reltimer(&peer->timers, peer,
			     time_from_sec(5),
			     send_channel_initial_update, peer));
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
	peer_write(peer->pps, take(msg));
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
		peer_failed_warn(peer->pps, &peer->channel_id,
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

	wire_sync_write(MASTER_FD,
			take(towire_channeld_local_channel_announcement(NULL,
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
				     time_from_sec(GOSSIP_ANNOUNCE_DELAY(peer->dev_fast_gossip)),
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

	peer->old_remote_per_commit = peer->remote_per_commit;
	if (!fromwire_funding_locked(msg, &chanid,
				     &peer->remote_per_commit))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad funding_locked %s", tal_hex(msg, msg));

	if (!channel_id_eq(&chanid, &peer->channel_id))
		peer_failed_err(peer->pps, &chanid,
				"Wrong channel id in %s (expected %s)",
				tal_hex(tmpctx, msg),
				type_to_string(msg, struct channel_id,
					       &peer->channel_id));

	peer->tx_sigs_allowed = false;
	peer->funding_locked[REMOTE] = true;
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
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad announcement_signatures %s",
				 tal_hex(msg, msg));

	/* Make sure we agree on the channel ids */
	if (!channel_id_eq(&chanid, &peer->channel_id)) {
		peer_failed_err(peer->pps, &chanid,
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
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad peer_add_htlc %s", tal_hex(msg, msg));

#if EXPERIMENTAL_FEATURES
	blinding = tlvs->blinding;
#endif
	add_err = channel_add_htlc(peer->channel, REMOTE, id, amount,
				   cltv_expiry, &payment_hash,
				   onion_routing_packet, blinding, &htlc, NULL,
				   /* We don't immediately fail incoming htlcs,
				    * instead we wait and fail them after
				    * they've been committed */
				   false);
	if (add_err != CHANNEL_ERR_ADD_OK)
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad peer_add_htlc: %s",
				 channel_add_err_name(add_err));
}

/* We don't get upset if they're outside the range, as long as they're
 * improving (or at least, not getting worse!). */
static bool feerate_same_or_better(const struct channel *channel,
				   u32 feerate, u32 feerate_min, u32 feerate_max)
{
	u32 current = channel_feerate(channel, LOCAL);

	/* Too low?  But is it going upwards?  */
	if (feerate < feerate_min)
		return feerate >= current;
	if (feerate > feerate_max)
		return feerate <= current;
	return true;
}

static void handle_peer_feechange(struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u32 feerate;

	if (!fromwire_update_fee(msg, &channel_id, &feerate)) {
		peer_failed_warn(peer->pps, &peer->channel_id,
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
		peer_failed_warn(peer->pps, &peer->channel_id,
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
	if (!feerate_same_or_better(peer->channel, feerate,
				    peer->feerate_min, peer->feerate_max))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "update_fee %u outside range %u-%u"
				 " (currently %u)",
				 feerate,
				 peer->feerate_min, peer->feerate_max,
				 channel_feerate(peer->channel, LOCAL));

	/* BOLT #2:
	 *
	 *  - if the sender cannot afford the new fee rate on the receiving
	 *    node's current commitment transaction:
	 *    - SHOULD fail the channel,
	 *      - but MAY delay this check until the `update_fee` is committed.
	 */
	if (!channel_update_feerate(peer->channel, feerate))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "update_fee %u unaffordable",
				 feerate);

	status_debug("peer updated fee to %u", feerate);
}

static void handle_peer_blockheight_change(struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u32 blockheight, current;

	if (!fromwire_update_blockheight(msg, &channel_id, &blockheight))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad update_blockheight %s",
				 tal_hex(msg, msg));

	/* BOLT- #2:
	 * A receiving node:
	 *   ...
	 *   - if the sender is not the initiator:
	 *     - MUST fail the channel.
	 */
	if (peer->channel->opener != REMOTE)
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "update_blockheight from non-opener?");

	current = get_blockheight(peer->channel->blockheight_states,
				  peer->channel->opener, LOCAL);

	status_debug("update_blockheight %u. last update height %u,"
		     " our current height %u",
		     blockheight, current, peer->our_blockheight);

	/* BOLT- #2:
	 * A receiving node:
	 *   - if the `update_blockheight` is less than the last
	 *     received `blockheight`:
	 *     - SHOULD fail the channel.
	 *    ...
	 *   - if `blockheight` is more than 1008 blocks behind
	 *   the current blockheight:
	 *   - SHOULD fail the channel
	 */
	/* Overflow check */
	if (blockheight + 1008 < blockheight)
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "blockheight + 1008 overflow (%u)",
				 blockheight);

	/* If they're behind the last one they sent, we just warn and
	 * reconnect, as they might be catching up */
	/* FIXME: track for how long they send backwards blockheight? */
	if (blockheight < current)
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "update_blockheight %u older than previous %u",
				 blockheight, current);

	/* BOLT- #2:
	 * A receiving node:
	 *    ...
	 *   - if `blockheight` is more than 1008 blocks behind
	 *   the current blockheight:
	 *   - SHOULD fail the channel
	 */
	assert(blockheight < blockheight + 1008);
	if (blockheight + 1008 < peer->our_blockheight)
		peer_failed_err(peer->pps, &peer->channel_id,
				"update_blockheight %u outside"
				" permissible range", blockheight);

	channel_update_blockheight(peer->channel, blockheight);

	status_debug("peer updated blockheight to %u", blockheight);
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
				 const struct height_states *blockheight_states,
				 const struct htlc **changed_htlcs,
				 const struct bitcoin_signature *commit_sig,
				 const struct bitcoin_signature *htlc_sigs)
{
	struct changed_htlc *changed;
	u8 *msg;

	/* We tell master what (of our) HTLCs peer will now be
	 * committed to. */
	changed = changed_htlc_arr(tmpctx, changed_htlcs);
	msg = towire_channeld_sending_commitsig(ctx, remote_commit_index,
						pbase, fee_states,
						blockheight_states, changed,
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
	struct tlv_shutdown_tlvs *tlvs;

	if (!peer->send_shutdown)
		return;

	/* Send a disable channel_update so others don't try to route
	 * over us */
	send_channel_update(peer, ROUTING_FLAGS_DISABLED);

	if (peer->shutdown_wrong_funding) {
		tlvs = tlv_shutdown_tlvs_new(tmpctx);
		tlvs->wrong_funding
			= tal(tlvs, struct tlv_shutdown_tlvs_wrong_funding);
		tlvs->wrong_funding->txid = peer->shutdown_wrong_funding->txid;
		tlvs->wrong_funding->outnum = peer->shutdown_wrong_funding->n;
	} else
		tlvs = NULL;

	msg = towire_shutdown(NULL, &peer->channel_id, peer->final_scriptpubkey,
			      tlvs);
	peer_write(peer->pps, take(msg));
	peer->send_shutdown = false;
	peer->shutdown_sent[LOCAL] = true;
	billboard_update(peer);
}

static void send_shutdown_complete(struct peer *peer)
{
	/* Now we can tell master shutdown is complete. */
	wire_sync_write(MASTER_FD,
			take(towire_channeld_shutdown_complete(NULL)));
	per_peer_state_fdpass_send(MASTER_FD, peer->pps);
	close(MASTER_FD);
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
						    channel_has(peer->channel,
								OPT_STATIC_REMOTEKEY));

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
						      channel_has(peer->channel,
								  OPT_ANCHOR_OUTPUTS));

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
		 * * if `option_anchors` applies to this commitment
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

/* Do we want to update fees? */
static bool want_fee_update(const struct peer *peer, u32 *target)
{
	u32 current, val;

	if (peer->channel->opener != LOCAL)
		return false;

#if EXPERIMENTAL_FEATURES
	/* No fee update while quiescing! */
	if (peer->stfu)
		return false;
#endif
	current = channel_feerate(peer->channel, REMOTE);

	/* max is *approximate*: only take it into account if we're
	 * trying to increase feerate. */
	if (peer->desired_feerate > current) {
		/* FIXME: We should avoid adding HTLCs until we can meet this
		 * feerate! */
		u32 max = approx_max_feerate(peer->channel);

		val = peer->desired_feerate;
		/* Respect max, but don't let us *decrease* us */
		if (val > max)
			val = max;
		if (val < current)
			val = current;
	} else
		val = peer->desired_feerate;

	if (target)
		*target = val;

	return val != current;
}

/* Do we want to update blockheight? */
static bool want_blockheight_update(const struct peer *peer, u32 *height)
{
	u32 last;

	if (peer->channel->opener != LOCAL)
		return false;

	if (peer->channel->lease_expiry == 0)
		return false;

#if EXPERIMENTAL_FEATURES
	/* No fee update while quiescing! */
	if (peer->stfu)
		return false;
#endif
	/* What's the current blockheight */
	last = get_blockheight(peer->channel->blockheight_states,
			       peer->channel->opener, LOCAL);

	if (peer->our_blockheight < last) {
		status_broken("current blockheight %u less than last %u",
			      peer->our_blockheight, last);
		return false;
	}

	if (peer->our_blockheight == last)
		return false;

	if (height)
		*height = peer->our_blockheight;

	return true;
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
	u32 our_blockheight;
	u32 feerate_target;

#if DEVELOPER
	if (peer->dev_disable_commit && !*peer->dev_disable_commit) {
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

	/* If we wanted to update fees, do it now. */
	if (want_fee_update(peer, &feerate_target)) {
		/* FIXME: We occasionally desynchronize with LND here, so
		 * don't stress things by having more than one feerate change
		 * in-flight! */
		if (feerate_changes_done(peer->channel->fee_states, false)) {
			u8 *msg;

			/* BOLT-919 #2:
			 *
			 * A sending node:
			 * - if the `dust_balance_on_counterparty_tx` at the
			 *   new `dust_buffer_feerate` is superior to
			 *   `max_dust_htlc_exposure_msat`:
			 *   - MAY NOT send `update_fee`
			 *   - MAY fail the channel
			 * - if the `dust_balance_on_holder_tx` at the
			 *   new `dust_buffer_feerate` is superior to
			 *   the `max_dust_htlc_exposure_msat`:
			 *   - MAY NOT send `update_fee`
			 *   - MAY fail the channel
			 */
			/* Is this feerate update going to push the committed
			 * htlcs over our allowed dust limits? */
			if (!htlc_dust_ok(peer->channel, feerate_target, REMOTE)
			    || !htlc_dust_ok(peer->channel, feerate_target, LOCAL))
				peer_failed_warn(peer->pps, &peer->channel_id,
						"Too much dust to update fee (Desired"
						" feerate update %d)", feerate_target);

			if (!channel_update_feerate(peer->channel, feerate_target))
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "Could not afford feerate %u"
					      " (vs max %u)",
					      feerate_target, approx_max_feerate(peer->channel));

			msg = towire_update_fee(NULL, &peer->channel_id,
						feerate_target);
			peer_write(peer->pps, take(msg));
		}
	}

	if (want_blockheight_update(peer, &our_blockheight)) {
		if (blockheight_changes_done(peer->channel->blockheight_states,
					     false)) {
			u8 *msg;

			channel_update_blockheight(peer->channel,
						   our_blockheight);

			msg = towire_update_blockheight(NULL,
							&peer->channel_id,
							our_blockheight);

			peer_write(peer->pps, take(msg));
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
		status_debug("Can't send commit: nothing to send,"
			     " feechange %s (%s)"
			     " blockheight %s (%s)",
			     want_fee_update(peer, NULL) ? "wanted": "not wanted",
			     type_to_string(tmpctx, struct fee_states, peer->channel->fee_states),
			     want_blockheight_update(peer, NULL) ? "wanted" : "not wanted",
			     type_to_string(tmpctx, struct height_states, peer->channel->blockheight_states));

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

#if DEVELOPER
	if (peer->dev_disable_commit) {
		(*peer->dev_disable_commit)--;
		if (*peer->dev_disable_commit == 0)
			status_unusual("dev-disable-commit-after: disabling");
	}
#endif

	status_debug("Telling master we're about to commit...");
	/* Tell master to save this next commit to database, then wait. */
	msg = sending_commitsig_msg(NULL, peer->next_index[REMOTE],
				    pbase,
				    peer->channel->fee_states,
				    peer->channel->blockheight_states,
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
	peer_write(peer->pps, take(msg));

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
			a.fail_immediate = htlc->fail_immediate;
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
					       peer->channel->blockheight_states,
					       commit_sig, htlc_sigs,
					       added,
					       fulfilled,
					       failed,
					       changed,
					       committx);
	master_wait_sync_reply(tmpctx, peer, take(msg_for_master),
			       WIRE_CHANNELD_GOT_COMMITSIG_REPLY);

	/* Now we can finally send revoke_and_ack to peer */
	peer_write(peer->pps, take(msg));
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
			peer_failed_warn(peer->pps, &peer->channel_id,
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
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad commit_sig %s", tal_hex(msg, msg));
	/* SIGHASH_ALL is implied. */
	commit_sig.sighash_type = SIGHASH_ALL;
	htlc_sigs = unraw_sigs(tmpctx, raw_sigs,
			       channel_has(peer->channel, OPT_ANCHOR_OUTPUTS));

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
	 *    - if `signature` is not valid for its local commitment transaction
	 *      OR non-compliant with LOW-S-standard rule...:
	 *      - MUST fail the channel.
	 */
	if (!check_tx_sig(txs[0], 0, NULL, funding_wscript,
			  &peer->channel->funding_pubkey[REMOTE], &commit_sig)) {
		dump_htlcs(peer->channel, "receiving commit_sig");
		peer_failed_warn(peer->pps, &peer->channel_id,
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
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Expected %zu htlc sigs, not %zu",
				 tal_count(txs) - 1, tal_count(htlc_sigs));

	/* BOLT #2:
	 *
	 *   - if any `htlc_signature` is not valid for the corresponding HTLC
	 *     transaction OR non-compliant with LOW-S-standard rule...:
	 *     - MUST fail the channel.
	 */
	for (i = 0; i < tal_count(htlc_sigs); i++) {
		u8 *wscript;

		wscript = bitcoin_tx_output_get_witscript(tmpctx, txs[0],
							  txs[i+1]->wtx->inputs[0].index);

		if (!check_tx_sig(txs[1+i], 0, NULL, wscript,
				  &remote_htlckey, &htlc_sigs[i]))
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "Bad commit_sig signature %s for htlc %s wscript %s key %s",
					 type_to_string(msg, struct bitcoin_signature, &htlc_sigs[i]),
					 type_to_string(msg, struct bitcoin_tx, txs[1+i]),
					 tal_hex(msg, wscript),
					 type_to_string(msg, struct pubkey,
							&remote_htlckey));
	}

	status_debug("Received commit_sig with %zu htlc sigs",
		     tal_count(htlc_sigs));

	send_revocation(peer,
			&commit_sig, htlc_sigs, changed_htlcs, txs[0]);

	/* We may now be quiescent on our side. */
	maybe_send_stfu(peer);

	/* This might have synced the feerates: if so, we may want to
	 * update */
	if (want_fee_update(peer, NULL))
		start_commit_timer(peer);
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
			  const struct fee_states *fee_states,
			  const struct height_states *blockheight_states)
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
					blockheight_states, changed,
					pbase, ptx);
	tal_free(ptx);
	return msg;
}

static void handle_peer_revoke_and_ack(struct peer *peer, const u8 *msg)
{
	struct secret old_commit_secret;
	struct privkey privkey;
	struct channel_id channel_id;
	const u8 *revocation_msg;
	struct pubkey per_commit_point, next_per_commit;
	const struct htlc **changed_htlcs = tal_arr(msg, const struct htlc *, 0);

	if (!fromwire_revoke_and_ack(msg, &channel_id, &old_commit_secret,
				     &next_per_commit)) {
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad revoke_and_ack %s", tal_hex(msg, msg));
	}

	if (peer->revocations_received != peer->next_index[REMOTE] - 2) {
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Unexpected revoke_and_ack");
	}

	/* Submit the old revocation secret to the signer so it can
	 * independently verify that the latest state is commited. It
	 * is also validated in this routine after the signer returns.
	 */
	revocation_msg = towire_hsmd_validate_revocation(tmpctx,
							 peer->next_index[REMOTE] - 2,
							 &old_commit_secret);
	revocation_msg = hsm_req(tmpctx, take(revocation_msg));
	if (!fromwire_hsmd_validate_revocation_reply(revocation_msg))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad hsmd_validate_revocation_reply: %s",
			      tal_hex(tmpctx, revocation_msg));

	/* BOLT #2:
	 *
	 * A receiving node:
	 *  - if `per_commitment_secret` is not a valid secret key or does not
	 *    generate the previous `per_commitment_point`:
	 *    - MUST fail the channel.
	 */
	memcpy(&privkey, &old_commit_secret, sizeof(privkey));
	if (!pubkey_from_privkey(&privkey, &per_commit_point)) {
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad privkey %s",
				 type_to_string(msg, struct privkey, &privkey));
	}
	if (!pubkey_eq(&per_commit_point, &peer->old_remote_per_commit)) {
		peer_failed_err(peer->pps, &peer->channel_id,
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
			     peer->channel->fee_states,
			     peer->channel->blockheight_states);
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

	/* We may now be quiescent on our side. */
	maybe_send_stfu(peer);

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
		peer_failed_warn(peer->pps, &peer->channel_id,
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
		peer_failed_warn(peer->pps, &peer->channel_id,
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
		peer_failed_warn(peer->pps, &peer->channel_id,
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
		peer_failed_warn(peer->pps, &peer->channel_id,
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
		peer_failed_warn(peer->pps, &peer->channel_id,
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
		peer_failed_warn(peer->pps, &peer->channel_id,
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
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad update_fail_malformed_htlc: failed to remove %"
				 PRIu64 " error %s", id, channel_remove_err_name(e));
	}
	abort();
}

static void handle_peer_shutdown(struct peer *peer, const u8 *shutdown)
{
	struct channel_id channel_id;
	u8 *scriptpubkey;
	struct tlv_shutdown_tlvs *tlvs = tlv_shutdown_tlvs_new(tmpctx);
	struct bitcoin_outpoint *wrong_funding;

	/* Disable the channel. */
	send_channel_update(peer, ROUTING_FLAGS_DISABLED);

	if (!fromwire_shutdown(tmpctx, shutdown, &channel_id, &scriptpubkey,
			       tlvs))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad shutdown %s", tal_hex(peer, shutdown));

	/* FIXME: We shouldn't let them initiate a shutdown while the
	 * channel is active (if we leased funds) */

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
		peer_failed_err(peer->pps, &peer->channel_id,
				"scriptpubkey %s is not as agreed upfront (%s)",
			    tal_hex(peer, scriptpubkey),
			    tal_hex(peer, peer->remote_upfront_shutdown_script));

	/* We only accept an wrong_funding if:
	 * 1. It was negotiated.
	 * 2. It's not dual-funding.
	 * 3. They opened it.
	 * 4. The channel was never used.
	 */
	if (tlvs->wrong_funding) {
		if (!feature_negotiated(peer->our_features,
					peer->their_features,
					OPT_SHUTDOWN_WRONG_FUNDING))
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "wrong_funding shutdown needs"
					 " feature %u",
					 OPT_SHUTDOWN_WRONG_FUNDING);
		if (feature_negotiated(peer->our_features,
				       peer->their_features,
				       OPT_DUAL_FUND))
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "wrong_funding shutdown invalid"
					 " with dual-funding");
		if (peer->channel->opener != REMOTE)
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "No shutdown wrong_funding"
					 " for channels we opened!");
		if (peer->next_index[REMOTE] != 1
		    || peer->next_index[LOCAL] != 1)
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "No shutdown wrong_funding"
					 " for used channels!");

		/* Turn into our outpoint type. */
		wrong_funding = tal(tmpctx, struct bitcoin_outpoint);
		wrong_funding->txid = tlvs->wrong_funding->txid;
		wrong_funding->n = tlvs->wrong_funding->outnum;
	} else {
		wrong_funding = NULL;
	}

	/* Tell master: we don't have to wait because on reconnect other end
	 * will re-send anyway. */
	wire_sync_write(MASTER_FD,
			take(towire_channeld_got_shutdown(NULL, scriptpubkey,
							  wrong_funding)));

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

static void handle_unexpected_tx_sigs(struct peer *peer, const u8 *msg)
{
	const struct witness_stack **ws;
	struct channel_id cid;
	struct bitcoin_txid txid;

	/* In a rare case, a v2 peer may re-send a tx_sigs message.
	 * This happens when they've/we've exchanged funding_locked,
	 * but they did not receive our funding_locked. */
	if (!fromwire_tx_signatures(tmpctx, msg, &cid, &txid,
				    cast_const3(struct witness_stack ***, &ws)))
		peer_failed_warn(peer->pps, &peer->channel_id,
			    "Bad tx_signatures %s",
			    tal_hex(msg, msg));

	status_info("Unexpected `tx_signatures` from peer. %s",
		    peer->tx_sigs_allowed ? "Allowing." : "Failing.");

	if (!peer->tx_sigs_allowed)
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Unexpected `tx_signatures`");

	peer->tx_sigs_allowed = false;
}

static void handle_unexpected_reestablish(struct peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 next_commitment_number;
	u64 next_revocation_number;
	struct secret your_last_per_commitment_secret;
	struct pubkey my_current_per_commitment_point;
#if EXPERIMENTAL_FEATURES
	struct tlv_channel_reestablish_tlvs *tlvs = tlv_channel_reestablish_tlvs_new(tmpctx);
#endif

	if (!fromwire_channel_reestablish(msg, &channel_id,
					  &next_commitment_number,
					  &next_revocation_number,
					  &your_last_per_commitment_secret,
					  &my_current_per_commitment_point
#if EXPERIMENTAL_FEATURES
					  , tlvs
#endif
		    ))
		peer_failed_warn(peer->pps, &peer->channel_id,
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
	peer_failed_err(peer->pps, &channel_id,
			"Peer sent unexpected message %u, (%s) "
			"for nonexistent channel %s",
			WIRE_CHANNEL_REESTABLISH, "WIRE_CHANNEL_REESTABLISH",
			type_to_string(tmpctx, struct channel_id,
				       &channel_id));
}

static void peer_in(struct peer *peer, const u8 *msg)
{
	enum peer_wire type = fromwire_peektype(msg);

	if (handle_peer_error(peer->pps, &peer->channel_id, msg))
		return;

	/* Must get funding_locked before almost anything. */
	if (!peer->funding_locked[REMOTE]) {
		if (type != WIRE_FUNDING_LOCKED
		    && type != WIRE_SHUTDOWN
		    /* We expect these for v2 !! */
		    && type != WIRE_TX_SIGNATURES
		    /* lnd sends these early; it's harmless. */
		    && type != WIRE_UPDATE_FEE
		    && type != WIRE_ANNOUNCEMENT_SIGNATURES) {
			peer_failed_warn(peer->pps, &peer->channel_id,
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
	case WIRE_UPDATE_BLOCKHEIGHT:
		handle_peer_blockheight_change(peer, msg);
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
	case WIRE_STFU:
		handle_stfu(peer, msg);
		return;
#endif
	case WIRE_INIT:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_CLOSING_SIGNED:
	case WIRE_TX_ADD_INPUT:
	case WIRE_TX_REMOVE_INPUT:
	case WIRE_TX_ADD_OUTPUT:
	case WIRE_TX_REMOVE_OUTPUT:
	case WIRE_TX_COMPLETE:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_TX_SIGNATURES:
		handle_unexpected_tx_sigs(peer, msg);
		return;
	case WIRE_INIT_RBF:
	case WIRE_ACK_RBF:
		break;

	case WIRE_CHANNEL_REESTABLISH:
		handle_unexpected_reestablish(peer, msg);
		return;

	/* These are all swallowed by connectd */
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
	case WIRE_WARNING:
	case WIRE_ERROR:
	case WIRE_OBS2_ONION_MESSAGE:
	case WIRE_ONION_MESSAGE:
		abort();
	}

	peer_failed_warn(peer->pps, &peer->channel_id,
			 "Peer sent unknown message %u (%s)",
			 type, peer_wire_name(type));
}

static void resend_revoke(struct peer *peer)
{
	struct pubkey point;
	/* Current commit is peer->next_index[LOCAL]-1, revoke prior */
	u8 *msg = make_revocation_msg(peer, peer->next_index[LOCAL]-2, &point);
	peer_write(peer->pps, take(msg));
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
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "HTLC %"PRIu64" state %s not failed/fulfilled",
				 h->id, htlc_state_name(h->state));
	peer_write(peer->pps, take(msg));
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

	status_debug("Retransmitting commitment, feerate LOCAL=%u REMOTE=%u,"
		     " blockheight LOCAL=%u REMOTE=%u",
		     channel_feerate(peer->channel, LOCAL),
		     channel_feerate(peer->channel, REMOTE),
		     channel_blockheight(peer->channel, LOCAL),
		     channel_blockheight(peer->channel, REMOTE));

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
			peer_failed_warn(peer->pps, &peer->channel_id,
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
			peer_failed_warn(peer->pps, &peer->channel_id,
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
			peer_write(peer->pps, take(msg));
		}
	}

	/* Make sure they have the correct fee and blockheight. */
	if (peer->channel->opener == LOCAL) {
		msg = towire_update_fee(NULL, &peer->channel_id,
					channel_feerate(peer->channel, REMOTE));
		peer_write(peer->pps, take(msg));

		if (peer->channel->lease_expiry > 0) {
			msg = towire_update_blockheight(NULL, &peer->channel_id,
							channel_blockheight(peer->channel, REMOTE));
			peer_write(peer->pps, take(msg));
		}
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
	peer_write(peer->pps, take(msg));

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
 *  - if `option_static_remotekey` or `option_anchors` applies to the
 *    commitment transaction:
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
		peer_failed_err(peer->pps,
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
	peer_failed_err(peer->pps, &peer->channel_id,
			"Awaiting unilateral close");
}

/* BOLT #2:
 *
 * A receiving node:
 *  - if `option_static_remotekey` or `option_anchors` applies to the
 *    commitment transaction:
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
		peer_failed_err(peer->pps,
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
			peer_failed_warn(peer->pps,
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
			peer_failed_warn(peer->pps,
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

#if EXPERIMENTAL_FEATURES
/* Unwrap a channel_type into a raw byte array for the wire: can be NULL */
static u8 *to_bytearr(const tal_t *ctx,
		      const struct channel_type *channel_type TAKES)
{
	u8 *ret;
	bool steal;

	steal = taken(channel_type);
	if (!channel_type)
		return NULL;

	if (steal) {
		ret = tal_steal(ctx, channel_type->features);
		tal_free(channel_type);
	} else
		ret = tal_dup_talarr(ctx, u8, channel_type->features);
	return ret;
}

/* This is the no-tlvs version, where we can't handle old tlvs */
static bool fromwire_channel_reestablish_notlvs(const void *p, struct channel_id *channel_id, u64 *next_commitment_number, u64 *next_revocation_number, struct secret *your_last_per_commitment_secret, struct pubkey *my_current_per_commitment_point)
{
	const u8 *cursor = p;
	size_t plen = tal_count(p);

	if (fromwire_u16(&cursor, &plen) != WIRE_CHANNEL_REESTABLISH)
		return false;
 	fromwire_channel_id(&cursor, &plen, channel_id);
 	*next_commitment_number = fromwire_u64(&cursor, &plen);
 	*next_revocation_number = fromwire_u64(&cursor, &plen);
 	fromwire_secret(&cursor, &plen, your_last_per_commitment_secret);
 	fromwire_pubkey(&cursor, &plen, my_current_per_commitment_point);
	return cursor != NULL;
}
#endif

static void peer_reconnect(struct peer *peer,
			   const struct secret *last_remote_per_commit_secret,
			   u8 *reestablish_only)
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
#if EXPERIMENTAL_FEATURES
	struct tlv_channel_reestablish_tlvs *send_tlvs, *recv_tlvs;
#endif

	dataloss_protect = feature_negotiated(peer->our_features,
					      peer->their_features,
					      OPT_DATA_LOSS_PROTECT);

	/* Both these options give us extra fields to check. */
	check_extra_fields
		= dataloss_protect || channel_has(peer->channel, OPT_STATIC_REMOTEKEY);

	/* Our current per-commitment point is the commitment point in the last
	 * received signed commitment */
	get_per_commitment_point(peer->next_index[LOCAL] - 1,
				 &my_current_per_commitment_point, NULL);

#if EXPERIMENTAL_FEATURES
	/* Subtle: we free tmpctx below as we loop, so tal off peer */
	send_tlvs = tlv_channel_reestablish_tlvs_new(peer);

	/* FIXME: v0.10.1 would send a different tlv set, due to older spec.
	 * That did *not* offer OPT_QUIESCE, so in that case don't send tlvs. */
	if (!feature_negotiated(peer->our_features,
				peer->their_features,
				OPT_QUIESCE))
		goto skip_tlvs;

	/* BOLT-upgrade_protocol #2:
	 * A node sending `channel_reestablish`, if it supports upgrading channels:
	 *   - MUST set `next_to_send` the commitment number of the next
	 *     `commitment_signed` it expects to send.
	 */
	send_tlvs->next_to_send = tal_dup(send_tlvs, u64, &peer->next_index[REMOTE]);

	/* BOLT-upgrade_protocol #2:
	 * - if it initiated the channel:
	 *   - MUST set `desired_type` to the channel_type it wants for the
	 *     channel.
	 */
	if (peer->channel->opener == LOCAL)
		send_tlvs->desired_channel_type =
			to_bytearr(send_tlvs,
				   take(channel_desired_type(NULL,
							     peer->channel)));
	else {
		/* BOLT-upgrade_protocol #2:
		 * - otherwise:
		 *  - MUST set `current_type` to the current channel_type of the
		 *    channel.
		 *  - MUST set `upgradable` to the channel types it could change
		 *    to.
		 *  - MAY not set `upgradable` if it would be empty.
		 */
		send_tlvs->current_channel_type
			= to_bytearr(send_tlvs, peer->channel->type);
		send_tlvs->upgradable_channel_type
			= to_bytearr(send_tlvs,
				     take(channel_upgradable_type(NULL,
								  peer->channel)));
	}

skip_tlvs:
#endif

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
	 *   - if `option_static_remotekey` or `option_anchors` applies to the commitment transaction:
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
	if (channel_has(peer->channel, OPT_STATIC_REMOTEKEY)) {
		msg = towire_channel_reestablish
			(NULL, &peer->channel_id,
			 peer->next_index[LOCAL],
			 peer->revocations_received,
			 last_remote_per_commit_secret,
			 /* Can send any (valid) point here */
			 &peer->remote_per_commit
#if EXPERIMENTAL_FEATURES
			 , send_tlvs
#endif
				);
	} else {
		msg = towire_channel_reestablish
			(NULL, &peer->channel_id,
			 peer->next_index[LOCAL],
			 peer->revocations_received,
			 last_remote_per_commit_secret,
			 &my_current_per_commitment_point
#if EXPERIMENTAL_FEATURES
			 , send_tlvs
#endif
				);
	}

	peer_write(peer->pps, take(msg));

	peer_billboard(false, "Sent reestablish, waiting for theirs");

	/* If they sent reestablish, we analyze it for courtesy, but also
	 * in case *they* are ahead of us! */
	if (reestablish_only) {
		msg = reestablish_only;
		goto got_reestablish;
	}

	/* Read until they say something interesting (don't forward
	 * gossip *to* them yet: we might try sending channel_update
	 * before we've reestablished channel). */
	do {
		clean_tmpctx();
		msg = peer_read(tmpctx, peer->pps);
	} while (handle_peer_error(peer->pps, &peer->channel_id, msg) ||
		 capture_premature_msg(&premature_msgs, msg));

got_reestablish:
#if EXPERIMENTAL_FEATURES
	recv_tlvs = tlv_channel_reestablish_tlvs_new(tmpctx);

	/* FIXME: v0.10.1 would send a different tlv set, due to older spec.
	 * That did *not* offer OPT_QUIESCE, so in that case ignore tlvs. */
	if (!feature_negotiated(peer->our_features,
				peer->their_features,
				OPT_QUIESCE)) {
		if (!fromwire_channel_reestablish_notlvs(msg,
					&channel_id,
					&next_commitment_number,
					&next_revocation_number,
					&last_local_per_commitment_secret,
					&remote_current_per_commitment_point))
			peer_failed_warn(peer->pps,
					 &peer->channel_id,
					 "bad reestablish msg: %s %s",
					 peer_wire_name(fromwire_peektype(msg)),
					 tal_hex(msg, msg));
	} else if (!fromwire_channel_reestablish(msg,
						 &channel_id,
						 &next_commitment_number,
						 &next_revocation_number,
						 &last_local_per_commitment_secret,
						 &remote_current_per_commitment_point,
						 recv_tlvs)) {
			peer_failed_warn(peer->pps,
					 &peer->channel_id,
					 "bad reestablish msg: %s %s",
					 peer_wire_name(fromwire_peektype(msg)),
					 tal_hex(msg, msg));
	}
#else /* !EXPERIMENTAL_FEATURES */
	if (!fromwire_channel_reestablish(msg,
					&channel_id,
					&next_commitment_number,
					&next_revocation_number,
					&last_local_per_commitment_secret,
					  &remote_current_per_commitment_point)) {
		peer_failed_warn(peer->pps,
				 &peer->channel_id,
				 "bad reestablish msg: %s %s",
				 peer_wire_name(fromwire_peektype(msg)),
				 tal_hex(msg, msg));
	}
#endif

	if (!channel_id_eq(&channel_id, &peer->channel_id)) {
		peer_failed_err(peer->pps,
				&channel_id,
				"bad reestablish msg for unknown channel %s: %s",
				type_to_string(tmpctx, struct channel_id,
					       &channel_id),
				tal_hex(msg, msg));
	}

	status_debug("Got reestablish commit=%"PRIu64" revoke=%"PRIu64,
		     next_commitment_number,
		     next_revocation_number);

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
		peer_write(peer->pps, take(msg));
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
	 *    - if it has previously sent a `commitment_signed` that needs to be
	 *      retransmitted:
	 *      - MUST retransmit `revoke_and_ack` and `commitment_signed` in the
	 *        same relative order as initially transmitted.
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
			peer_failed_err(peer->pps,
					&peer->channel_id,
					"bad reestablish revocation_number: %"
					PRIu64,
					next_revocation_number);
		}
		retransmit_revoke_and_ack = true;
	} else if (next_revocation_number < peer->next_index[LOCAL] - 1) {
		peer_failed_err(peer->pps,
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
			peer_failed_err(peer->pps,
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
					     channel_has(peer->channel,
							 OPT_STATIC_REMOTEKEY)
					     ? NULL :
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
			peer_failed_err(peer->pps,
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
		peer_failed_err(peer->pps,
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
					      channel_has(peer->channel,
							  OPT_STATIC_REMOTEKEY)
					      ? NULL
					      : &remote_current_per_commitment_point);

	/* BOLT #2:
 	 * - if it has previously sent a `commitment_signed` that needs to be
	 *   retransmitted:
	 *   - MUST retransmit `revoke_and_ack` and `commitment_signed` in the
	 *     same relative order as initially transmitted.
	 */
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

#if EXPERIMENTAL_FEATURES
	if (recv_tlvs->desired_channel_type)
		status_debug("They sent desired_channel_type [%s]",
			     fmt_featurebits(tmpctx,
					     recv_tlvs->desired_channel_type));
	if (recv_tlvs->current_channel_type)
		status_debug("They sent current_channel_type [%s]",
			     fmt_featurebits(tmpctx,
					     recv_tlvs->current_channel_type));

	if (recv_tlvs->upgradable_channel_type)
		status_debug("They offered upgrade to [%s]",
			     fmt_featurebits(tmpctx,
					     recv_tlvs->upgradable_channel_type));

	/* BOLT-upgrade_protocol #2:
	 *
	 * A node receiving `channel_reestablish`:
	 *  - if it has to retransmit `commitment_signed` or `revoke_and_ack`:
	 *    - MUST consider the channel feature change failed.
	 */
	if (retransmit_commitment_signed || retransmit_revoke_and_ack) {
		status_debug("No upgrade: we retransmitted");
	/* BOLT-upgrade_protocol #2:
	 *
	 *  - if `next_to_send` is missing, or not equal to the
	 *    `next_commitment_number` it sent:
	 *    - MUST consider the channel feature change failed.
	 */
	} else if (!recv_tlvs->next_to_send) {
		status_debug("No upgrade: no next_to_send received");
	} else if (*recv_tlvs->next_to_send != peer->next_index[LOCAL]) {
		status_debug("No upgrade: they're retransmitting");
	/* BOLT-upgrade_protocol #2:
	 *
	 *  - if updates are pending on either sides' commitment transaction:
	 *    - MUST consider the channel feature change failed.
	 */
		/* Note that we can have HTLCs we *want* to add or remove
		 * but haven't yet: thats OK! */
	} else if (pending_updates(peer->channel, LOCAL, true)
		   || pending_updates(peer->channel, REMOTE, true)) {
		status_debug("No upgrade: pending changes");
	} else {
		const struct tlv_channel_reestablish_tlvs *initr, *ninitr;
		const u8 *type;

		if (peer->channel->opener == LOCAL) {
			initr = send_tlvs;
			ninitr = recv_tlvs;
		} else {
			initr = recv_tlvs;
			ninitr = send_tlvs;
		}

		/* BOLT-upgrade_protocol #2:
		 *
		 * - if `desired_channel_type` matches `current_channel_type` or any
		 *   `upgradable_channel_type`:
		 *   - MUST consider the channel type to be `desired_channel_type`.
		 * - otherwise:
		 *   - MUST consider the channel type change failed.
		 *   - if there is a `current_channel_type` field:
		 *     - MUST consider the channel type to be `current_channel_type`.
		 */
		if (match_type(initr->desired_channel_type,
			       ninitr->current_channel_type)
		    || match_type(initr->desired_channel_type,
				  ninitr->upgradable_channel_type))
			type = initr->desired_channel_type;
		else if (ninitr->current_channel_type)
			type = ninitr->current_channel_type;
		else
			type = NULL;

		if (type)
			set_channel_type(peer->channel, type);
	}
	tal_free(send_tlvs);

#endif /* EXPERIMENTAL_FEATURES */

	/* Now stop, we've been polite long enough. */
	if (reestablish_only) {
		/* If we were successfully closing, we still go to closingd. */
		if (shutdown_complete(peer)) {
			send_shutdown_complete(peer);
			daemon_shutdown();
			exit(0);
		}
		peer_failed_err(peer->pps,
				&peer->channel_id,
				"Channel is already closed");
	}

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

	/* We allow peer to send us tx-sigs, until funding locked received */
	peer->tx_sigs_allowed = true;
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
		peer->depth_togo = 0;

		assert(scid);
		peer->short_channel_ids[LOCAL] = *scid;

		if (!peer->funding_locked[LOCAL]) {
			status_debug("funding_locked: sending commit index"
				     " %"PRIu64": %s",
				     peer->next_index[LOCAL],
				     type_to_string(tmpctx, struct pubkey,
						    &peer->next_local_per_commit));
			msg = towire_funding_locked(NULL,
						    &peer->channel_id,
						    &peer->next_local_per_commit);
			peer_write(peer->pps, take(msg));

			peer->funding_locked[LOCAL] = true;
		}

		peer->announce_depth_reached = (depth >= ANNOUNCE_MIN_DEPTH);

		/* Send temporary or final announcements */
		channel_announcement_negotiate(peer);
	}

	billboard_update(peer);
}

static const u8 *get_cupdate(const struct peer *peer)
{
	/* Technically we only need to tell it the first time (unless it's
	 * changed).  But it's not that common. */
	wire_sync_write(MASTER_FD,
			take(towire_channeld_used_channel_update(NULL)));
	return peer->channel_update;
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
			     onion_routing_packet, take(blinding), NULL,
			     &htlc_fee, true);
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
		peer_write(peer->pps, take(msg));
		start_commit_timer(peer);
		/* Tell the master. */
		msg = towire_channeld_offer_htlc_reply(NULL, peer->htlc_id,
						      0, "");
		wire_sync_write(MASTER_FD, take(msg));
		peer->htlc_id++;
		return;
	case CHANNEL_ERR_INVALID_EXPIRY:
		failwiremsg = towire_incorrect_cltv_expiry(inmsg, cltv_expiry, get_cupdate(peer));
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
		failwiremsg = towire_temporary_channel_failure(inmsg, get_cupdate(peer));
		failstr = tal_fmt(inmsg, "Capacity exceeded - HTLC fee: %s", fmt_amount_sat(inmsg, htlc_fee));
		goto failed;
	case CHANNEL_ERR_HTLC_BELOW_MINIMUM:
		failwiremsg = towire_amount_below_minimum(inmsg, amount, get_cupdate(peer));
		failstr = tal_fmt(inmsg, "HTLC too small (%s minimum)",
				  type_to_string(tmpctx,
						 struct amount_msat,
						 &peer->channel->config[REMOTE].htlc_minimum));
		goto failed;
	case CHANNEL_ERR_TOO_MANY_HTLCS:
		failwiremsg = towire_temporary_channel_failure(inmsg, get_cupdate(peer));
		failstr = "Too many HTLCs";
		goto failed;
	case CHANNEL_ERR_DUST_FAILURE:
		/* BOLT-919 #2:
		 * - upon an outgoing HTLC:
		 *   - if a HTLC's `amount_msat` is inferior the counterparty's...
		 *   - SHOULD NOT send this HTLC
		 *   - SHOULD fail this HTLC if it's forwarded
		 */
		failwiremsg = towire_temporary_channel_failure(inmsg, get_cupdate(peer));
		failstr = "HTLC too dusty, allowed dust limit reached";
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

static void handle_blockheight(struct peer *peer, const u8 *inmsg)
{
	u32 blockheight;

	if (!fromwire_channeld_blockheight(inmsg, &blockheight))
		master_badmsg(WIRE_CHANNELD_BLOCKHEIGHT, inmsg);

	/* Save it, so we know */
	peer->our_blockheight = blockheight;
	if (peer->channel->opener == LOCAL)
		start_commit_timer(peer);
	else {
		u32 peer_height = get_blockheight(peer->channel->blockheight_states,
						  peer->channel->opener,
						  REMOTE);
		/* BOLT- #2:
		 * The node _not responsible_ for initiating the channel:
		 *   ...
		 *   - if last received `blockheight` is > 1008 behind
		 *     currently known blockheight:
		 *     - SHOULD fail he channel
		 */
		assert(peer_height + 1008 > peer_height);
		if (peer_height + 1008 < blockheight)
			peer_failed_err(peer->pps, &peer->channel_id,
					"Peer is too far behind, terminating"
					" leased channel. Our current"
					" %u, theirs %u",
					blockheight, peer_height);
		/* We're behind them... what do. It's possible they're lying,
		 * but if we're in a lease this is actually in our favor so
		 * we log it but otherwise continue on unchanged */
		if (peer_height > blockheight
		    && peer_height > blockheight + 100)
			status_unusual("Peer reporting we've fallen %u"
				       " blocks behind. Our height %u,"
				       " their height %u",
				       peer_height - blockheight,
				       blockheight, peer_height);

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

	if (!fromwire_channeld_send_shutdown(peer, inmsg, &local_shutdown_script,
					     &peer->shutdown_wrong_funding))
		master_badmsg(WIRE_CHANNELD_SEND_SHUTDOWN, inmsg);

	tal_free(peer->final_scriptpubkey);
	peer->final_scriptpubkey = local_shutdown_script;

	/* We can't send this until commit (if any) is done, so start timer. */
	peer->send_shutdown = true;
	start_commit_timer(peer);
}

/* Lightningd tells us when channel_update has changed. */
static void handle_channel_update(struct peer *peer, const u8 *msg)
{
	peer->channel_update = tal_free(peer->channel_update);
	if (!fromwire_channeld_channel_update(peer, msg, &peer->channel_update))
		master_badmsg(WIRE_CHANNELD_CHANNEL_UPDATE, msg);
}

static void handle_send_error(struct peer *peer, const u8 *msg)
{
	char *reason;
	if (!fromwire_channeld_send_error(msg, msg, &reason))
		master_badmsg(WIRE_CHANNELD_SEND_ERROR, msg);
	status_debug("Send error reason: %s", reason);
	peer_write(peer->pps,
			  take(towire_errorfmt(NULL, &peer->channel_id,
					       "%s", reason)));

	wire_sync_write(MASTER_FD,
			take(towire_channeld_send_error_reply(NULL)));
}

#if DEVELOPER
static void handle_dev_reenable_commit(struct peer *peer)
{
	peer->dev_disable_commit = tal_free(peer->dev_disable_commit);
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

	found_leak = dump_memleak(memtable, memleak_status_broken);
	wire_sync_write(MASTER_FD,
			 take(towire_channeld_dev_memleak_reply(NULL,
							       found_leak)));
}

#if EXPERIMENTAL_FEATURES
static void handle_dev_quiesce(struct peer *peer, const u8 *msg)
{
	if (!fromwire_channeld_dev_quiesce(msg))
		master_badmsg(WIRE_CHANNELD_DEV_QUIESCE, msg);

	/* Don't do this twice. */
	if (peer->stfu)
		status_failed(STATUS_FAIL_MASTER_IO, "dev_quiesce already");

	peer->stfu = true;
	peer->stfu_initiator = LOCAL;
	maybe_send_stfu(peer);
}
#endif /* EXPERIMENTAL_FEATURES */
#endif /* DEVELOPER */

static void req_in(struct peer *peer, const u8 *msg)
{
	enum channeld_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CHANNELD_FUNDING_DEPTH:
		handle_funding_depth(peer, msg);
		return;
	case WIRE_CHANNELD_OFFER_HTLC:
		if (handle_master_request_later(peer, msg))
			return;
		handle_offer_htlc(peer, msg);
		return;
	case WIRE_CHANNELD_FEERATES:
		if (handle_master_request_later(peer, msg))
			return;
		handle_feerates(peer, msg);
		return;
	case WIRE_CHANNELD_BLOCKHEIGHT:
		if (handle_master_request_later(peer, msg))
			return;
		handle_blockheight(peer, msg);
		return;
	case WIRE_CHANNELD_FULFILL_HTLC:
		if (handle_master_request_later(peer, msg))
			return;
		handle_preimage(peer, msg);
		return;
	case WIRE_CHANNELD_FAIL_HTLC:
		if (handle_master_request_later(peer, msg))
			return;
		handle_fail(peer, msg);
		return;
	case WIRE_CHANNELD_SPECIFIC_FEERATES:
		if (handle_master_request_later(peer, msg))
			return;
		handle_specific_feerates(peer, msg);
		return;
	case WIRE_CHANNELD_SEND_SHUTDOWN:
		handle_shutdown_cmd(peer, msg);
		return;
	case WIRE_CHANNELD_SEND_ERROR:
		handle_send_error(peer, msg);
		return;
	case WIRE_CHANNELD_CHANNEL_UPDATE:
		handle_channel_update(peer, msg);
		return;
#if DEVELOPER
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT:
		handle_dev_reenable_commit(peer);
		return;
	case WIRE_CHANNELD_DEV_MEMLEAK:
		handle_dev_memleak(peer, msg);
		return;
	case WIRE_CHANNELD_DEV_QUIESCE:
#if EXPERIMENTAL_FEATURES
		handle_dev_quiesce(peer, msg);
		return;
#endif /* EXPERIMENTAL_FEATURES */
#else
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT:
	case WIRE_CHANNELD_DEV_MEMLEAK:
	case WIRE_CHANNELD_DEV_QUIESCE:
#endif /* DEVELOPER */
	case WIRE_CHANNELD_INIT:
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
	case WIRE_CHANNELD_DEV_QUIESCE_REPLY:
	case WIRE_CHANNELD_UPGRADED:
	case WIRE_CHANNELD_USED_CHANNEL_UPDATE:
	case WIRE_CHANNELD_LOCAL_CHANNEL_UPDATE:
	case WIRE_CHANNELD_LOCAL_CHANNEL_ANNOUNCEMENT:
	case WIRE_CHANNELD_LOCAL_PRIVATE_CHANNEL:
		break;
	}
	master_badmsg(-1, msg);
}

/* We do this synchronously. */
static void init_channel(struct peer *peer)
{
	struct basepoints points[NUM_SIDES];
	struct amount_sat funding_sats;
	struct amount_msat local_msat;
	struct pubkey funding_pubkey[NUM_SIDES];
	struct channel_config conf[NUM_SIDES];
	struct bitcoin_outpoint funding;
	enum side opener;
	struct existing_htlc **htlcs;
	bool reconnected;
	u8 *fwd_msg;
	const u8 *msg;
	struct fee_states *fee_states;
	struct height_states *blockheight_states;
	u32 minimum_depth, lease_expiry;
	struct secret last_remote_per_commit_secret;
	secp256k1_ecdsa_signature *remote_ann_node_sig;
	secp256k1_ecdsa_signature *remote_ann_bitcoin_sig;
	struct penalty_base *pbases;
	u8 *reestablish_only;
	struct channel_type *channel_type;
	u32 *dev_disable_commit; /* Always NULL */
	bool dev_fast_gossip;
#if !DEVELOPER
	bool dev_fail_process_onionpacket; /* Ignored */
#endif

	assert(!(fcntl(MASTER_FD, F_GETFL) & O_NONBLOCK));

	msg = wire_sync_read(tmpctx, MASTER_FD);
	if (!fromwire_channeld_init(peer, msg,
				    &chainparams,
				    &peer->our_features,
				    &peer->channel_id,
				    &funding,
				    &funding_sats,
				    &minimum_depth,
				    &peer->our_blockheight,
				    &blockheight_states,
				    &lease_expiry,
				    &conf[LOCAL], &conf[REMOTE],
				    &fee_states,
				    &peer->feerate_min,
				    &peer->feerate_max,
				    &peer->feerate_penalty,
				    &peer->their_commit_sig,
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
				    &channel_type,
				    &dev_fast_gossip,
				    &dev_fail_process_onionpacket,
				    &dev_disable_commit,
				    &pbases,
				    &reestablish_only,
				    &peer->channel_update)) {
		master_badmsg(WIRE_CHANNELD_INIT, msg);
	}

#if DEVELOPER
	peer->dev_disable_commit = dev_disable_commit;
	peer->dev_fast_gossip = dev_fast_gossip;
#endif

	status_debug("option_static_remotekey = %u, option_anchor_outputs = %u",
		     channel_type_has(channel_type, OPT_STATIC_REMOTEKEY),
		     channel_type_has(channel_type, OPT_ANCHOR_OUTPUTS));

	/* Keeping an array of pointers is better since it allows us to avoid
	 * extra allocations later. */
	peer->pbases = tal_arr(peer, struct penalty_base *, 0);
	for (size_t i=0; i<tal_count(pbases); i++)
		tal_arr_expand(&peer->pbases,
			       tal_dup(peer, struct penalty_base, &pbases[i]));
	tal_free(pbases);

	/* stdin == requests, 3 == peer */
	peer->pps = new_per_peer_state(peer);
	per_peer_state_set_fd(peer->pps, 3);

	status_debug("init %s: remote_per_commit = %s, old_remote_per_commit = %s"
		     " next_idx_local = %"PRIu64
		     " next_idx_remote = %"PRIu64
		     " revocations_received = %"PRIu64
		     " feerates %s range %u-%u"
		     " blockheights %s, our current %u",
		     side_to_str(opener),
		     type_to_string(tmpctx, struct pubkey,
				    &peer->remote_per_commit),
		     type_to_string(tmpctx, struct pubkey,
				    &peer->old_remote_per_commit),
		     peer->next_index[LOCAL], peer->next_index[REMOTE],
		     peer->revocations_received,
		     type_to_string(tmpctx, struct fee_states, fee_states),
		     peer->feerate_min, peer->feerate_max,
		     type_to_string(tmpctx, struct height_states, blockheight_states),
		     peer->our_blockheight);

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
					 &funding,
					 minimum_depth,
					 take(blockheight_states),
					 lease_expiry,
					 funding_sats,
					 local_msat,
					 take(fee_states),
					 &conf[LOCAL], &conf[REMOTE],
					 &points[LOCAL], &points[REMOTE],
					 &funding_pubkey[LOCAL],
					 &funding_pubkey[REMOTE],
					 take(channel_type),
					 feature_offered(peer->their_features,
							 OPT_LARGE_CHANNELS),
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
		peer_reconnect(peer, &last_remote_per_commit_secret,
			       reestablish_only);
	else
		assert(!reestablish_only);

	/* If we have a messages to send, send them immediately */
	if (fwd_msg)
		peer_write(peer->pps, take(fwd_msg));

	/* Reenable channel */
	channel_announcement_negotiate(peer);

	billboard_update(peer);
}

int main(int argc, char *argv[])
{
	setup_locale();

	int i, nfds;
	fd_set fds_in, fds_out;
	struct peer *peer;

	subdaemon_setup(argc, argv);

	status_setup_sync(MASTER_FD);

	peer = tal(NULL, struct peer);
	timers_init(&peer->timers, time_mono());
	peer->commit_timer = NULL;
	peer->have_sigs[LOCAL] = peer->have_sigs[REMOTE] = false;
	peer->announce_depth_reached = false;
	peer->channel_local_active = false;
	peer->from_master = msg_queue_new(peer, true);
	peer->shutdown_sent[LOCAL] = false;
	peer->shutdown_wrong_funding = NULL;
	peer->last_update_timestamp = 0;
	peer->last_empty_commitment = 0;
#if EXPERIMENTAL_FEATURES
	peer->stfu = false;
	peer->stfu_sent[LOCAL] = peer->stfu_sent[REMOTE] = false;
	peer->update_queue = msg_queue_new(peer, false);
#endif

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

	FD_ZERO(&fds_out);
	FD_SET(peer->pps->peer_fd, &fds_out);
	nfds = peer->pps->peer_fd+1;

	while (!shutdown_complete(peer)) {
		struct timemono first;
		fd_set rfds = fds_in;
		struct timeval timeout, *tptr;
		struct timer *expired;
		const u8 *msg;
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
			timer_expired(expired);
			continue;
		}

		/* Might not be waiting for anything. */
		tptr = NULL;

		if (timer_earliest(&peer->timers, &first)) {
			timeout = timespec_to_timeval(
				timemono_between(first, now).ts);
			tptr = &timeout;
		}

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
			msg = peer_read(tmpctx, peer->pps);
			peer_in(peer, msg);
		}
	}

	/* We only exit when shutdown is complete. */
	assert(shutdown_complete(peer));
	send_shutdown_complete(peer);
	daemon_shutdown();
	return 0;
}
