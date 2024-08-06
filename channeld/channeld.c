/* Main channel operation daemon: runs from channel_ready to shutdown_complete.
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
#include <bitcoin/script.h>
#include <ccan/asort/asort.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <channeld/channeld.h>
#include <channeld/channeld_wiregen.h>
#include <channeld/full_channel.h>
#include <channeld/inflight.h>
#include <channeld/splice.h>
#include <channeld/watchtower.h>
#include <common/billboard.h>
#include <common/ecdh_hsmd.h>
#include <common/gossip_store.h>
#include <common/hsm_capable.h>
#include <common/hsm_version.h>
#include <common/interactivetx.h>
#include <common/key_derive.h>
#include <common/memleak.h>
#include <common/msg_queue.h>
#include <common/onionreply.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/peer_io.h>
#include <common/per_peer_state.h>
#include <common/psbt_internal.h>
#include <common/psbt_open.h>
#include <common/read_peer_msg.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/timeout.h>
#include <common/wire_error.h>
#include <errno.h>
#include <fcntl.h>
#include <hsmd/hsmd_wiregen.h>
#include <stdio.h>
#include <wally_bip32.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

/* stdin == requests, 3 == peer, 4 = HSM */
#define MASTER_FD STDIN_FILENO
#define HSM_FD 4

#define VALID_STFU_MESSAGE(msg) \
	((msg) == WIRE_SPLICE || \
	(msg) == WIRE_SPLICE_ACK)

#define SAT_MIN(a, b) (amount_sat_less((a), (b)) ? (a) : (b))

struct peer {
	struct per_peer_state *pps;
	bool channel_ready[NUM_SIDES];
	u64 next_index[NUM_SIDES];

	/* ID of peer */
	struct node_id id;

	/* --developer? */
	bool developer;

	/* Features peer supports. */
	u8 *their_features;

	/* Features we support. */
	struct feature_set *our_features;

	/* What (additional) messages the HSM accepts */
	u32 *hsm_capabilities;

	/* Tolerable amounts for feerate (only relevant for fundee). */
	u32 feerate_min, feerate_max;

	/* Feerate to be used when creating penalty transactions. */
	u32 feerate_penalty;

	/* Local next per-commit point. */
	struct pubkey next_local_per_commit;

	/* Remote's current per-commit point. */
	struct pubkey remote_per_commit;

	/* Remotes's last per-commitment point: we keep this to check
	 * revoke_and_ack's `per_commitment_secret` is correct and for
	 * splices. */
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
	u32 commit_msec;

	/* The feerate we want. */
	u32 desired_feerate;

	/* Current blockheight */
	u32 our_blockheight;

	/* FIXME: Remove this. */
	struct short_channel_id short_channel_ids[NUM_SIDES];

	/* Local scid alias */
	struct short_channel_id local_alias;

	/* The scriptpubkey to use for shutting down. */
	u32 *final_index;
	struct ext_key *final_ext_key;
	u8 *final_scriptpubkey;

	/* If master told us to shut down */
	bool send_shutdown;
	/* Has shutdown been sent by each side? */
	bool shutdown_sent[NUM_SIDES];
	/* If master told us to send wrong_funding */
	struct bitcoin_outpoint *shutdown_wrong_funding;

	/* Do we want quiescence?
	 * Note: This flag is needed seperately from `stfu_sent` so we can
	 * detect the entering "stfu" mode. */
	bool want_stfu;
	/* Which side is considered the initiator? */
	enum side stfu_initiator;
	/* Has stfu been sent by each side? */
	bool stfu_sent[NUM_SIDES];
	/* After STFU mode is enabled, wait for a single message flag */
	bool stfu_wait_single_msg;
	/* Updates master asked, which we've deferred while quiescing */
	struct msg_queue *update_queue;
	/* Callback for when when stfu is negotiated successfully */
	void (*on_stfu_success)(struct peer*);

	struct splice_state *splice_state;
	struct splicing *splicing;

	/* If set, don't fire commit counter when this hits 0 */
	u32 *dev_disable_commit;

	/* Information used for reestablishment. */
	bool last_was_revoke;
	struct changed_htlc *last_sent_commit;
	u64 revocations_received;
	u8 channel_flags;

	/* Alt address for peer connections not publicly announced */
	u8 *my_alt_addr;

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

	/* We allow a 'tx-sigs' message between reconnect + channel_ready */
	bool tx_sigs_allowed;

	/* --experimental-upgrade-protocol */
	bool experimental_upgrade;
};

static void start_commit_timer(struct peer *peer);

static void billboard_update(const struct peer *peer)
{
	const char *update = billboard_message(tmpctx, peer->channel_ready,
					       NULL,
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

static bool is_stfu_active(const struct peer *peer)
{
	return peer->stfu_sent[LOCAL] && peer->stfu_sent[REMOTE];
}

static void end_stfu_mode(struct peer *peer)
{
	peer->want_stfu = false;
	peer->stfu_sent[LOCAL] = peer->stfu_sent[REMOTE] = false;
	peer->stfu_wait_single_msg = false;
	peer->on_stfu_success = NULL;

	status_debug("Left STFU mode.");
}

static void maybe_send_stfu(struct peer *peer)
{
	if (!peer->want_stfu)
		return;

	if (pending_updates(peer->channel, LOCAL, false)) {
		status_info("Pending updates prevent us from STFU mode at this"
			    " time.");
	}
	else if (!peer->stfu_sent[LOCAL]) {
		status_debug("Sending peer that we want to STFU.");
		u8 *msg = towire_stfu(NULL, &peer->channel_id,
				      peer->stfu_initiator == LOCAL);
		peer_write(peer->pps, take(msg));
		peer->stfu_sent[LOCAL] = true;
	}

	if (peer->stfu_sent[LOCAL] && peer->stfu_sent[REMOTE]) {
		/* Prevent STFU mode being inadvertantly activated twice during
		 * splice. This occurs because the commit -> revoke_and_ack
		 * cycle calls into `maybe_send_stfu`. The `want_stfu` flag is
		 * to prevent triggering the entering of stfu events twice. */
		peer->want_stfu = false;
		status_unusual("STFU complete: we are quiescent");
		wire_sync_write(MASTER_FD,
				towire_channeld_dev_quiesce_reply(tmpctx));

		peer->stfu_wait_single_msg = true;
		status_unusual("STFU complete: setting stfu_wait_single_msg = true");
		if (peer->on_stfu_success) {
			peer->on_stfu_success(peer);
			peer->on_stfu_success = NULL;
		}
	}
}

/* Durring reestablish, STFU mode is assumed if continuing a splice */
static void assume_stfu_mode(struct peer *peer)
{
	peer->stfu_sent[LOCAL] = peer->stfu_sent[REMOTE] = true;
}

static void handle_stfu(struct peer *peer, const u8 *stfu)
{
	struct channel_id channel_id;
	u8 remote_initiated;

	if (!feature_negotiated(peer->our_features,
				peer->their_features,
				OPT_QUIESCE))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "stfu not supported");

	if (!fromwire_stfu(stfu, &channel_id, &remote_initiated))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad stfu %s", tal_hex(peer, stfu));

	if (!channel_id_eq(&channel_id, &peer->channel_id)) {
		peer_failed_err(peer->pps, &channel_id,
				"Wrong stfu channel_id: expected %s, got %s",
				fmt_channel_id(tmpctx, &peer->channel_id),
				fmt_channel_id(tmpctx, &channel_id));
	}

	/* Sanity check */
	if (pending_updates(peer->channel, REMOTE, false))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "STFU but you still have updates pending?");

	if (!peer->want_stfu) {
		peer->want_stfu = true;
		if (!remote_initiated)
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "Unsolicited STFU but you said"
					 " you didn't initiate?");
		peer->stfu_initiator = REMOTE;

		status_debug("STFU initiator was remote.");
	} else {
		/* BOLT-quiescent #2:
		 *
		 * If both sides send `stfu` simultaneously, they will both
		 * set `initiator` to `1`, in which case the "initiator" is
		 * arbitrarily considered to be the channel funder (the sender
		 * of `open_channel`).
		 */
		if (remote_initiated) {
			status_debug("Dual STFU intiation tiebreaker. Setting initiator to %s",
				     peer->channel->opener == LOCAL ? "LOCAL" : "REMOTE");
			peer->stfu_initiator = peer->channel->opener;
		} else {
			status_debug("STFU initiator local.");
		}
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
	if (is_stfu_active(peer)) {
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

static void lock_signer_outpoint(const struct bitcoin_outpoint *outpoint)
{
	const u8 *msg;
	bool is_buried = false;

	/* FIXME(vincenzopalazzo): Sleeping in a deamon of cln should be never fine
	 * howerver the core deamon of cln will never trigger the sleep.
	 *
	 * I think that the correct solution for this is a timer base solution, but this
	 * required a little bit of refactoring */
	do {
		/* Make sure the hsmd agrees that this outpoint is
		 * sufficiently buried. */
		msg = towire_hsmd_check_outpoint(NULL, &outpoint->txid, outpoint->n);
		msg = hsm_req(tmpctx, take(msg));
		if (!fromwire_hsmd_check_outpoint_reply(msg, &is_buried))
			status_failed(STATUS_FAIL_HSM_IO,
				      "Bad hsmd_check_outpoint_reply: %s",
				      tal_hex(tmpctx, msg));

		/* the signer should have a shorter buried height requirement so
		 * it almost always will be ready ahead of us.*/
		if (!is_buried)
			sleep(10);
	} while (!is_buried);

	/* tell the signer that we are now locked */
	msg = towire_hsmd_lock_outpoint(NULL, &outpoint->txid, outpoint->n);
	msg = hsm_req(tmpctx, take(msg));
	if (!fromwire_hsmd_lock_outpoint_reply(msg))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad hsmd_lock_outpoint_reply: %s",
			      tal_hex(tmpctx, msg));
}

/* Call this method when channel_ready status are changed. */
static void check_mutual_channel_ready(const struct peer *peer)
{
	if (peer->channel_ready[LOCAL] && peer->channel_ready[REMOTE])
		lock_signer_outpoint(&peer->channel->funding);
}

/* Call this method when splice_locked status are changed. If both sides have
 * splice_locked'ed than this function consumes the `splice_locked_ready` values
 * and considers the channel funding to be switched to the splice tx. */
static void check_mutual_splice_locked(struct peer *peer)
{
	u8 *msg;
	const char *error;
	struct inflight *inflight;

	/* If both sides haven't `splice_locked` we're not ready */
	if (!peer->splice_state->locked_ready[LOCAL]
	    || !peer->splice_state->locked_ready[REMOTE])
		return;

	if (short_channel_id_eq(peer->short_channel_ids[LOCAL],
				peer->splice_state->short_channel_id))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Duplicate splice_locked events detected");

	peer->splice_state->await_commitment_succcess = true;

	/* This splice_locked event is used, so reset the flags to false */
	peer->splice_state->locked_ready[LOCAL] = false;
	peer->splice_state->locked_ready[REMOTE] = false;

	peer->splice_state->last_short_channel_id = peer->short_channel_ids[LOCAL];
	peer->short_channel_ids[LOCAL] = peer->splice_state->short_channel_id;
	peer->short_channel_ids[REMOTE] = peer->splice_state->short_channel_id;

	peer->channel->view[LOCAL].lowest_splice_amnt[LOCAL] = 0;
	peer->channel->view[LOCAL].lowest_splice_amnt[REMOTE] = 0;
	peer->channel->view[REMOTE].lowest_splice_amnt[LOCAL] = 0;
	peer->channel->view[REMOTE].lowest_splice_amnt[REMOTE] = 0;

	status_debug("mutual splice_locked, scid LOCAL & REMOTE updated to: %s",
		     fmt_short_channel_id(tmpctx,
					  peer->splice_state->short_channel_id));

	inflight = NULL;
	for (size_t i = 0; i < tal_count(peer->splice_state->inflights); i++)
		if (bitcoin_txid_eq(&peer->splice_state->inflights[i]->outpoint.txid,
			&peer->splice_state->locked_txid))
			inflight = peer->splice_state->inflights[i];

	if (!inflight)
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Unable to find inflight txid amoung %zu"
				 " inflights. new funding txid: %s",
				 tal_count(peer->splice_state->inflights),
				 fmt_bitcoin_txid(tmpctx,
						  &peer->splice_state->locked_txid));

	status_debug("mutual splice_locked, updating change from: %s",
		     fmt_channel(tmpctx, peer->channel));

	error = channel_update_funding(peer->channel, &inflight->outpoint,
				       inflight->amnt,
				       inflight->splice_amnt);
	if (error)
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Splice lock unable to update funding. %s",
				 error);

	status_debug("mutual splice_locked, channel updated to: %s",
		     fmt_channel(tmpctx, peer->channel));

	/* ensure the signer is locking at the same time */
	lock_signer_outpoint(&inflight->outpoint);

	msg = towire_channeld_got_splice_locked(NULL, inflight->amnt,
						inflight->splice_amnt,
						&inflight->outpoint.txid);
	wire_sync_write(MASTER_FD, take(msg));

	billboard_update(peer);

	peer->splice_state->inflights = tal_free(peer->splice_state->inflights);
	peer->splice_state->count = 0;
}

/* Our peer told us they saw our splice confirm on chain with `splice_locked`.
 * If we see it to we jump into tansitioning to post-splice, otherwise we mark
 * a flag and wait until we see it on chain too. */
static void handle_peer_splice_locked(struct peer *peer, const u8 *msg)
{
	struct channel_id chanid;

	if (!fromwire_splice_locked(msg, &chanid))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad splice_locked %s", tal_hex(msg, msg));

	if (!channel_id_eq(&chanid, &peer->channel_id))
		peer_failed_err(peer->pps, &chanid,
				"Wrong splice lock channel id in %s "
				"(expected %s)",
				tal_hex(tmpctx, msg),
				fmt_channel_id(msg, &peer->channel_id));

	/* If we've `mutual_splice_locked` but our peer hasn't, we can ignore
	 * this message harmlessly */
	if (!tal_count(peer->splice_state->inflights)) {
		status_info("Peer sent redundant splice_locked, ignoring");
		return;
	}

	peer->splice_state->locked_ready[REMOTE] = true;
	check_mutual_splice_locked(peer);
}

static void handle_peer_channel_ready(struct peer *peer, const u8 *msg)
{
	struct channel_id chanid;
	struct tlv_channel_ready_tlvs *tlvs;

	/* BOLT #2:
	 *
	 * A node:
	 *...
	 *  - upon reconnection:
	 *    - MUST ignore any redundant `channel_ready` it receives.
	 */
	if (peer->channel_ready[REMOTE])
		return;

	/* Too late, we're shutting down! */
	if (peer->shutdown_sent[LOCAL])
		return;

	peer->old_remote_per_commit = peer->remote_per_commit;
	if (!fromwire_channel_ready(msg, msg, &chanid,
				     &peer->remote_per_commit, &tlvs))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad channel_ready %s", tal_hex(msg, msg));

	if (!channel_id_eq(&chanid, &peer->channel_id))
		peer_failed_err(peer->pps, &chanid,
				"Wrong channel id in %s (expected %s)",
				tal_hex(tmpctx, msg),
				fmt_channel_id(msg, &peer->channel_id));

	peer->tx_sigs_allowed = false;
	peer->channel_ready[REMOTE] = true;
	check_mutual_channel_ready(peer);
	if (tlvs->short_channel_id != NULL) {
		status_debug(
		    "Peer told us that they'll use alias=%s for this channel",
		    fmt_short_channel_id(tmpctx, *tlvs->short_channel_id));
		peer->short_channel_ids[REMOTE] = *tlvs->short_channel_id;
	}
	wire_sync_write(MASTER_FD,
			take(towire_channeld_got_channel_ready(
			    NULL, &peer->remote_per_commit, tlvs->short_channel_id)));

	billboard_update(peer);
}

static void handle_peer_announcement_signatures(struct peer *peer, const u8 *msg)
{
	struct channel_id chanid;
	struct short_channel_id remote_scid;
	secp256k1_ecdsa_signature remote_node_sig, remote_bitcoin_sig;

	if (!fromwire_announcement_signatures(msg,
					      &chanid,
					      &remote_scid,
					      &remote_node_sig,
					      &remote_bitcoin_sig))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad announcement_signatures %s",
				 tal_hex(msg, msg));

	wire_sync_write(MASTER_FD,
			take(towire_channeld_got_announcement(NULL,
							      remote_scid,
							      &remote_node_sig,
							      &remote_bitcoin_sig)));
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
	struct tlv_update_add_htlc_tlvs *tlvs;

	if (!fromwire_update_add_htlc(msg, msg, &channel_id, &id, &amount,
				      &payment_hash, &cltv_expiry,
				      onion_routing_packet, &tlvs)) {
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad peer_add_htlc %s", tal_hex(msg, msg));
	}
	add_err = channel_add_htlc(peer->channel, REMOTE, id, amount,
				   cltv_expiry, &payment_hash,
				   onion_routing_packet, tlvs->blinding_point, &htlc, NULL,
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
	 *    - MUST send a `warning` and close the connection, or send an
	 *      `error` and fail the channel.
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
	 *     - MUST send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
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
	 *    - SHOULD send a `warning` and close the connection, or send an
	 *      `error` and fail the channel.
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
				 const struct htlc **changed_htlcs)
{
	struct changed_htlc *changed;
	u8 *msg;

	/* We tell master what (of our) HTLCs peer will now be
	 * committed to. */
	changed = changed_htlc_arr(tmpctx, changed_htlcs);
	msg = towire_channeld_sending_commitsig(ctx, remote_commit_index,
						pbase, fee_states,
						blockheight_states, changed);
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

	/* DTODO: Ensure 'shutdown' rules around splice are followed once those
	 * rules get settled on spec */

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

	/* Give master a chance to pass the fd along */
	sleep(1);

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
			status_failed(STATUS_FAIL_MASTER_IO,
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

/* Collect the htlcs for call to hsmd. */
static struct simple_htlc **collect_htlcs(const tal_t *ctx, const struct htlc **htlc_map)
{
	struct simple_htlc **htlcs;

	htlcs = tal_arr(ctx, struct simple_htlc *, 0);
	size_t num_entries = tal_count(htlc_map);
	for (size_t ndx = 0; ndx < num_entries; ++ndx) {
		struct htlc const *hh = htlc_map[ndx];
		if (hh) {
			struct simple_htlc *simple =
				new_simple_htlc(htlcs,
						htlc_state_owner(hh->state),
						hh->amount,
						&hh->rhash,
						hh->expiry.locktime);
			tal_arr_expand(&htlcs, simple);
		}
	}
	return htlcs;
}

/* Returns HTLC sigs, sets commit_sig. Also used for making commitsigs for each
 * splice awaiting on-chain confirmation. */
static struct bitcoin_signature *calc_commitsigs(const tal_t *ctx,
						  const struct peer *peer,
						  struct bitcoin_tx **txs,
						  const u8 *funding_wscript,
						  const struct htlc **htlc_map,
						  u64 commit_index,
						  const struct pubkey *remote_per_commit,
						  struct bitcoin_signature *commit_sig)
{
	struct simple_htlc **htlcs;
	size_t i;
	struct pubkey local_htlckey;
	const u8 *msg;
	struct bitcoin_signature *htlc_sigs;

	htlcs = collect_htlcs(tmpctx, htlc_map);
	msg = towire_hsmd_sign_remote_commitment_tx(NULL, txs[0],
						   &peer->channel->funding_pubkey[REMOTE],
						   remote_per_commit,
						    channel_has(peer->channel,
								OPT_STATIC_REMOTEKEY),
						    commit_index,
						    (const struct simple_htlc **) htlcs,
						    channel_feerate(peer->channel, REMOTE));

	msg = hsm_req(tmpctx, take(msg));
	if (!fromwire_hsmd_sign_tx_reply(msg, commit_sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading sign_remote_commitment_tx reply: %s",
			      tal_hex(tmpctx, msg));

	status_debug("Creating commit_sig signature %"PRIu64" %s for tx %s wscript %s key %s",
		     commit_index,
		     fmt_bitcoin_signature(tmpctx, commit_sig),
		     fmt_bitcoin_tx(tmpctx, txs[0]),
		     tal_hex(tmpctx, funding_wscript),
		     fmt_pubkey(tmpctx, &peer->channel->funding_pubkey[LOCAL]));
	dump_htlcs(peer->channel, "Sending commit_sig");

	if (!derive_simple_key(&peer->channel->basepoints[LOCAL].htlc,
			       remote_per_commit,
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
						      remote_per_commit,
						      channel_has_anchors(peer->channel));

		msg = hsm_req(tmpctx, take(msg));
		if (!fromwire_hsmd_sign_tx_reply(msg, &htlc_sigs[i]))
			status_failed(STATUS_FAIL_HSM_IO,
				      "Bad sign_remote_htlc_tx reply: %s",
				      tal_hex(tmpctx, msg));

		status_debug("Creating HTLC signature %s for tx %s wscript %s key %s",
			     fmt_bitcoin_signature(tmpctx, &htlc_sigs[i]),
			     fmt_bitcoin_tx(tmpctx, txs[1+i]),
			     tal_hex(tmpctx, wscript),
			     fmt_pubkey(tmpctx, &local_htlckey));
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
		 *   used as described in [BOLT #5]
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

	/* No fee update while quiescing! */
	if (peer->want_stfu || is_stfu_active(peer))
		return false;

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

	/* No fee update while quiescing! */
	if (peer->want_stfu || is_stfu_active(peer))
		return false;

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

/* Returns commitment_signed msg, sets @local_anchor */
static u8 *send_commit_part(const tal_t *ctx,
			    struct peer *peer,
			    const struct bitcoin_outpoint *funding,
			    struct amount_sat funding_sats,
			    const struct htlc **changed_htlcs,
			    bool notify_master,
			    s64 splice_amnt,
			    s64 remote_splice_amnt,
			    u64 remote_index,
			    const struct pubkey *remote_per_commit,
			    struct local_anchor_info **anchor)
{
	u8 *msg;
	struct bitcoin_signature commit_sig, *htlc_sigs;
	struct bitcoin_tx **txs;
	const u8 *funding_wscript;
	const struct htlc **htlc_map;
	struct wally_tx_output *direct_outputs[NUM_SIDES];
	struct penalty_base *pbase;
	int local_anchor_outnum;
	struct tlv_commitment_signed_tlvs *cs_tlv
		= tlv_commitment_signed_tlvs_new(tmpctx);

	/* In theory, peer will ignore TLV 1 as unknown, but while
	 * spec is in flux this is dangerous, as it may change: so don't
	 * send unless negotiated */
	if (feature_negotiated(peer->our_features,
			       peer->their_features,
			       OPT_EXPERIMENTAL_SPLICE)) {
		status_debug("send_commit_part(splice: %d, remote_splice: %d)",
			     (int)splice_amnt, (int)remote_splice_amnt);

		cs_tlv->splice_info = tal(cs_tlv, struct channel_id);
		derive_channel_id(cs_tlv->splice_info, funding);
	}

	txs = channel_txs(tmpctx, funding, funding_sats, &htlc_map,
			  direct_outputs, &funding_wscript,
			  peer->channel, remote_per_commit,
			  remote_index, REMOTE,
			  splice_amnt, remote_splice_amnt, &local_anchor_outnum);
	htlc_sigs =
	    calc_commitsigs(tmpctx, peer, txs, funding_wscript, htlc_map,
			    remote_index, remote_per_commit, &commit_sig);

	if (direct_outputs[LOCAL] != NULL) {
		pbase = penalty_base_new(tmpctx, remote_index,
					 txs[0], direct_outputs[LOCAL]);

		/* Add the penalty_base to our in-memory list as well, so we
		 * can find it again later. */
		tal_arr_expand(&peer->pbases, tal_steal(peer, pbase));
	}  else
		pbase = NULL;

	if (local_anchor_outnum == -1) {
		*anchor = NULL;
	} else {
		*anchor = tal(ctx, struct local_anchor_info);
		bitcoin_txid(txs[0], &(*anchor)->anchor_point.txid);
		(*anchor)->anchor_point.n = local_anchor_outnum;
		(*anchor)->commitment_weight = bitcoin_tx_weight(txs[0]);
		(*anchor)->commitment_fee = bitcoin_tx_compute_fee(txs[0]);
	}

	if (peer->dev_disable_commit) {
		(*peer->dev_disable_commit)--;
		if (*peer->dev_disable_commit == 0)
			status_unusual("dev-disable-commit-after: disabling");
	}

	if (notify_master) {
		status_debug("Telling master we're about to commit...");
		/* Tell master to save this next commit to database, then wait.
		 */
		msg = sending_commitsig_msg(NULL, remote_index, pbase,
					    peer->channel->fee_states,
					    peer->channel->blockheight_states,
					    changed_htlcs);
		/* Message is empty; receiving it is the point. */
		master_wait_sync_reply(tmpctx, peer, take(msg),
				       WIRE_CHANNELD_SENDING_COMMITSIG_REPLY);

		status_debug("Sending commit_sig with %zu htlc sigs",
			     tal_count(htlc_sigs));
	}

	msg = towire_commitment_signed(ctx, &peer->channel_id,
				       &commit_sig.s,
				       raw_sigs(tmpctx, htlc_sigs),
				       cs_tlv);
	return msg;
}

/* unlike amount.h, we expect negative values for a - b. */
static s64 sats_diff(struct amount_sat a, struct amount_sat b)
{
        return (s64)a.satoshis - (s64)b.satoshis; /* Raw: splicing numbers can wrap! */
}

static void send_commit(struct peer *peer)
{
	const struct htlc **changed_htlcs;
	u32 our_blockheight;
	u32 feerate_target;
	u8 **msgs = tal_arr(tmpctx, u8*, 1);
	u8 *msg;
	struct local_anchor_info *local_anchor, *anchors_info;

	if (peer->dev_disable_commit && !*peer->dev_disable_commit) {
		peer->commit_timer = NULL;
		return;
	}

	/* FIXME: Document this requirement in BOLT 2! */
	/* We can't send two commits in a row. */
	if (peer->revocations_received != peer->next_index[REMOTE] - 1) {
		assert(peer->revocations_received
		       == peer->next_index[REMOTE] - 2);
		status_debug("Can't send commit: waiting for revoke_and_ack");
		/* Mark this as done: handle_peer_revoke_and_ack will
		 * restart. */
		peer->commit_timer = NULL;
		return;
	}

	/* BOLT #2:
	 *
	 *   - if no HTLCs remain in either commitment transaction (including dust HTLCs)
	 *     and neither side has a pending `revoke_and_ack` to send:
	 *	- MUST NOT send any `update` message after that point.
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
			     fmt_fee_states(tmpctx, peer->channel->fee_states),
			     want_blockheight_update(peer, NULL) ? "wanted" : "not wanted",
			     fmt_height_states(tmpctx, peer->channel->blockheight_states));

		/* Covers the case where we've just been told to shutdown. */
		maybe_send_shutdown(peer);

		peer->commit_timer = NULL;
		return;
	}

	anchors_info = tal_arr(tmpctx, struct local_anchor_info, 0);
	msgs[0] = send_commit_part(msgs, peer, &peer->channel->funding,
				   peer->channel->funding_sats, changed_htlcs,
				   true, 0, 0, peer->next_index[REMOTE],
				   &peer->remote_per_commit, &local_anchor);
	if (local_anchor)
		tal_arr_expand(&anchors_info, *local_anchor);

	/* Loop over current inflights
	 * BOLT-0d8b701614b09c6ee4172b04da2203e73deec7e2 #2:
	 *
	 * A sending node:
	 *...
	 *   - MUST first send a `commitment_signed` for the active channel then immediately
	 *     send a `commitment_signed` for each splice awaiting confirmation, in increasing
	 *     feerate order.
	 */
	for (u32 i = 0; i < tal_count(peer->splice_state->inflights); i++) {
		s64 funding_diff = sats_diff(peer->splice_state->inflights[i]->amnt,
					     peer->channel->funding_sats);
		s64 remote_splice_amnt = funding_diff
					- peer->splice_state->inflights[i]->splice_amnt;

		tal_arr_expand(&msgs,
			       send_commit_part(msgs, peer,
						&peer->splice_state->inflights[i]->outpoint,
						peer->splice_state->inflights[i]->amnt,
						changed_htlcs, false,
						peer->splice_state->inflights[i]->splice_amnt,
						remote_splice_amnt,
						peer->next_index[REMOTE],
						&peer->remote_per_commit,
						&local_anchor));
		if (local_anchor)
			tal_arr_expand(&anchors_info, *local_anchor);
	}

	/* Now, tell master about the anchor on each of their commitments */
	msg = towire_channeld_local_anchor_info(NULL, peer->next_index[REMOTE],
						anchors_info);
	wire_sync_write(MASTER_FD, take(msg));

	peer->next_index[REMOTE]++;

	for(u32 i = 0; i < tal_count(msgs); i++)
		peer_write(peer->pps, take(msgs[i]));

	maybe_send_shutdown(peer);

	/* Timer now considered expired, you can add a new one. */
	peer->commit_timer = NULL;
	start_commit_timer(peer);
}

static void send_commit_if_not_stfu(struct peer *peer)
{
	if (!is_stfu_active(peer) && !peer->want_stfu) {
		send_commit(peer);
	}
	else {
		/* Timer now considered expired, you can add a new one. */
		peer->commit_timer = NULL;
		start_commit_timer(peer);
	}
}

static void start_commit_timer(struct peer *peer)
{
	/* Already armed? */
	if (peer->commit_timer)
		return;

	peer->commit_timer = new_reltimer(&peer->timers, peer,
					  time_from_msec(peer->commit_msec),
					  send_commit_if_not_stfu, peer);
}

/* Fetch the requested point. The secret is no longer returned, use
 * revoke_commitment instead.  It is legal to call this on any
 * commitment (including distant future).
 */
static void get_per_commitment_point(u64 index, struct pubkey *point)
{
	struct secret *unused;
	const u8 *msg;

	msg = hsm_req(tmpctx,
		      take(towire_hsmd_get_per_commitment_point(NULL, index)));

	if (!fromwire_hsmd_get_per_commitment_point_reply(tmpctx, msg,
							 point,
							 &unused))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad per_commitment_point reply %s",
			      tal_hex(tmpctx, msg));
}

/* Revoke the specified commitment, the old secret is returned and
 * next commitment point are returned.  This call is idempotent, it is
 * fine to re-revoke a previously revoked commitment.  It is an error
 * to revoke a commitment beyond the next revocable commitment.
 */
static void revoke_commitment(u64 index, struct secret *old_secret, struct pubkey *point)
{
	const u8 *msg;

	msg = hsm_req(tmpctx,
		      take(towire_hsmd_revoke_commitment_tx(tmpctx, index)));

	if (!fromwire_hsmd_revoke_commitment_tx_reply(msg, old_secret, point))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading revoke_commitment_tx reply: %s",
			      tal_hex(tmpctx, msg));
}

/* revoke_index == current index - 1 (usually; not for retransmission) */
static u8 *make_revocation_msg(const struct peer *peer, u64 revoke_index,
			       struct pubkey *point)
{
	struct secret old_commit_secret;

	/* Now that the master has persisted the new commitment advance the HSMD
	 * and fetch the revocation secret for the old one.
	 *
	 * After HSM_VERSION 5 we explicitly revoke the commitment in case
	 * the original revoke didn't complete.  The hsmd_revoke_commitment_tx
	 * call is idempotent ...
	 */
	revoke_commitment(revoke_index, &old_commit_secret, point);

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
			a.blinding = htlc->blinding;
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
			    const struct bitcoin_tx *committx,
			    const struct secret *old_secret,
			    const struct pubkey *next_point,
			    const struct commitsig **splice_commitsigs)
{
	struct changed_htlc *changed;
	struct fulfilled_htlc *fulfilled;
	const struct failed_htlc **failed;
	struct added_htlc *added;
	const u8 *msg;
	const u8 *msg_for_master;

	/* Marshall it now before channel_sending_revoke_and_ack changes htlcs */
	/* FIXME: Make infrastructure handle state post-revoke_and_ack! */
	marshall_htlc_info(tmpctx,
			   changed_htlcs,
			   &changed,
			   &fulfilled,
			   &failed,
			   &added);

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
					       committx,
					       splice_commitsigs);
	master_wait_sync_reply(tmpctx, peer, take(msg_for_master),
			       WIRE_CHANNELD_GOT_COMMITSIG_REPLY);

	peer->splice_state->await_commitment_succcess = false;

	/* Now that the master has persisted the new commitment advance the HSMD
	 * and fetch the revocation secret for the old one. */
	msg = make_revocation_msg(peer, peer->next_index[LOCAL]-2,
				  &peer->next_local_per_commit);

	/* Now we can finally send revoke_and_ack to peer */
	peer_write(peer->pps, take(msg));
}

static struct inflight *last_inflight(const struct peer *peer)
{
	size_t count = tal_count(peer->splice_state->inflights);

	if (count)
		return peer->splice_state->inflights[count - 1];

	return NULL;
}

static size_t last_inflight_index(const struct peer *peer)
{
	assert(tal_count(peer->splice_state->inflights) > 0);

	return tal_count(peer->splice_state->inflights) - 1;
}

static u32 find_channel_funding_input(const struct wally_psbt *psbt,
				      const struct bitcoin_outpoint *funding)
{
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct bitcoin_outpoint psbt_outpoint;
		wally_psbt_input_get_outpoint(&psbt->inputs[i], &psbt_outpoint);

		if (!bitcoin_outpoint_eq(&psbt_outpoint, funding))
			continue;

		if (funding->n == psbt->inputs[i].index)
			return i;
	}

	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "Unable to find splice funding tx");

	return UINT_MAX;
}

/* This checks if local has signed the funding input only */
static bool have_i_signed_inflight(const struct peer *peer,
				   const struct inflight *inflight)
{
	bool has_sig;
	u32 index;

	if (!inflight || !inflight->psbt)
		return false;

	index = find_channel_funding_input(inflight->psbt,
					   &peer->channel->funding);

	if (!psbt_input_have_signature(inflight->psbt, index,
				       &peer->channel->funding_pubkey[LOCAL],
				       &has_sig))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Unable parse inflight psbt");

	return has_sig;
}

/* this checks if local has signed everything buy the funding input */
static bool missing_user_signatures(const struct peer *peer,
				    const struct inflight *inflight)
{
	int sigs_needed;
	u32 splice_funding_index;
	const struct witness **outws;
	enum tx_role our_role = inflight->i_am_initiator
				? TX_INITIATOR : TX_ACCEPTER;

	if (!inflight || !inflight->psbt)
		return false;

	splice_funding_index = find_channel_funding_input(inflight->psbt,
							  &peer->channel->funding);
	sigs_needed = 0;
	for (u32 i = 0; i < inflight->psbt->num_inputs; i++) {
		struct wally_psbt_input *in = &inflight->psbt->inputs[i];
		u64 in_serial;

		if (!psbt_get_serial_id(&in->unknowns, &in_serial)) {
			status_broken("PSBT input %"PRIu32" missing serial_id"
				      " %s", i,
				      fmt_wally_psbt(tmpctx, inflight->psbt));
			return true;
		}
		if (in_serial % 2 == our_role && i != splice_funding_index)
			sigs_needed++;
	}

	outws = psbt_to_witnesses(tmpctx, inflight->psbt,
				  our_role, splice_funding_index);
	return tal_count(outws) != sigs_needed;
}

static void check_tx_abort(struct peer *peer, const u8 *msg)
{
	struct inflight *inflight = last_inflight(peer);
	struct bitcoin_outpoint *outpoint;
	struct channel_id channel_id;
	u8 *reason;

	if (fromwire_peektype(msg) != WIRE_TX_ABORT)
		return;

	if (have_i_signed_inflight(peer, inflight)) {
		peer_failed_err(peer->pps, &peer->channel_id, "tx_abort"
			        " is not allowed after I have sent my"
			        " signature. msg: %s",
			        tal_hex(tmpctx, msg));
	}

	if (!fromwire_tx_abort(tmpctx, msg, &channel_id, &reason))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "bad tx_abort %s", tal_hex(msg, msg));

	status_info("Send ack of tx_abort");

	peer_write(peer->pps,
		   take(towire_tx_abort(NULL, &peer->channel_id, NULL)));

	outpoint = NULL;
	if (inflight)
		outpoint = &inflight->outpoint;

	status_info("Send tx_abort to master");

	wire_sync_write(MASTER_FD,
			take(towire_channeld_splice_abort(NULL, false,
							  outpoint,
							  (char*)reason)));

	/* Give master a chance to pass the fd along */
	status_info("Delaying closing of master fd by 1 second");
	sleep(1);

	close(MASTER_FD);
	exit(0);
}

static void splice_abort(struct peer *peer, const char *fmt, ...)
{
	struct inflight *inflight = last_inflight(peer);
	struct bitcoin_outpoint *outpoint;
	u8 *msg;
	char *reason;
	va_list ap;

	va_start(ap, fmt);
	reason = tal_vfmt(NULL, fmt, ap);
	va_end(ap);

	if (have_i_signed_inflight(peer, inflight))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Tried to abort a splice where I have already"
			      " sent my signatures");

	status_info("We are initiating tx_abort for reason: %s", reason);

	peer_write(peer->pps,
		   take(towire_tx_abort(NULL, &peer->channel_id, (u8*)reason)));

	do {
		msg = peer_read(tmpctx, peer->pps);
		if (handle_peer_error_or_warning(peer->pps, msg)) {
			status_info("Received warning/error while expecting "
				    "tx_abort, msg: %s", tal_hex(tmpctx, msg));
			exit(0);
		}
	} while (fromwire_peektype(msg) != WIRE_TX_ABORT);

	status_info("We got TX_ABORT ack, now telling master about it");

	outpoint = NULL;
	if (inflight)
		outpoint = &inflight->outpoint;

	msg = towire_channeld_splice_abort(tmpctx, true, outpoint, reason);

	wire_sync_write(MASTER_FD, msg);

	/* Give master a chance to pass the fd along */
	status_info("Delaying closing of master fd by 1 second");
	sleep(1);


	close(MASTER_FD);
	exit(0);
}

struct commitsig_info {
	struct commitsig *commitsig;
	struct secret *old_secret;
};

/* Calling `handle_peer_commit_sig` with a `commit_index` of 0 and
 * `changed_htlcs` of NULL will process the message, then read & process coming
 * consecutive commitment messages equal to the number of inflight splices.
 *
 * Returns the last commitsig received. When splicing this is the
 * newest splice commit sig.
 *
 * `commit_index` 0 refers to the funding commit. `commit_index` 1 and above
 * refer to inflight splices.
 */
static struct commitsig_info *handle_peer_commit_sig(struct peer *peer,
						     const u8 *msg,
						     u32 commit_index,
						     const struct htlc **changed_htlcs,
						     s64 splice_amnt,
						     s64 remote_splice_amnt,
						     u64 local_index,
						     const struct pubkey *local_per_commit,
						     bool allow_empty_commit)
{
	struct commitsig_info *result;
	struct channel_id channel_id;
	struct bitcoin_signature commit_sig;
	secp256k1_ecdsa_signature *raw_sigs;
	struct bitcoin_signature *htlc_sigs;
	struct pubkey remote_htlckey;
	struct bitcoin_tx **txs;
	const struct htlc **htlc_map;
	const u8 *funding_wscript;
	size_t i;
	struct simple_htlc **htlcs;
	const u8 * msg2;
	u8 *splice_msg;
	int type;
	struct bitcoin_outpoint outpoint;
	struct amount_sat funding_sats;
	struct channel_id active_id;
	const struct commitsig **commitsigs;
	int remote_anchor_outnum;

	status_debug("handle_peer_commit_sig(splice: %d, remote_splice: %d)",
		     (int)splice_amnt, (int)remote_splice_amnt);

	struct tlv_commitment_signed_tlvs *cs_tlv
		= tlv_commitment_signed_tlvs_new(tmpctx);
	if (!fromwire_commitment_signed(tmpctx, msg,
					&channel_id, &commit_sig.s, &raw_sigs,
					&cs_tlv))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad commit_sig %s", tal_hex(msg, msg));

	/* BOLT-0d8b701614b09c6ee4172b04da2203e73deec7e2 #2:
	 * Once a node has received and sent `splice_locked`:
	 *   - Until sending OR receiving of `revoke_and_ack`
	 * ...
	 *     - MUST ignore `commitment_signed` messages where `splice_channel_id`
	 *       does not match the `channel_id` of the confirmed splice. */
	derive_channel_id(&active_id, &peer->channel->funding);
	if (peer->splice_state->await_commitment_succcess
	    && !tal_count(peer->splice_state->inflights) && cs_tlv && cs_tlv->splice_info) {
		if (!channel_id_eq(&active_id, cs_tlv->splice_info)) {
			status_info("Ignoring stale commit_sig for channel_id"
				    " %s, as %s is locked in now.",
				    fmt_channel_id(tmpctx, cs_tlv->splice_info),
				    fmt_channel_id(tmpctx, &active_id));
			return NULL;
		}
	}

	/* In a race we can get here with a commitsig with too many splices
	 * attached. In that case we ignore the main commit msg for the old
	 * funding tx, and for the splice candidates that didnt win. But we must
	 * listen to the one that is for the winning splice candidate */

	if (!changed_htlcs) {
		changed_htlcs = tal_arr(msg, const struct htlc *, 0);
		if (!channel_rcvd_commit(peer->channel, &changed_htlcs)
			&& !allow_empty_commit) {
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

	/* SIGHASH_ALL is implied. */
	commit_sig.sighash_type = SIGHASH_ALL;
	htlc_sigs = unraw_sigs(tmpctx, raw_sigs,
			       channel_has_anchors(peer->channel));

	if (commit_index) {
		outpoint = peer->splice_state->inflights[commit_index - 1]->outpoint;
		funding_sats = peer->splice_state->inflights[commit_index - 1]->amnt;
	}
	else {
		outpoint = peer->channel->funding;
		funding_sats = peer->channel->funding_sats;
	}

	txs = channel_txs(tmpctx, &outpoint, funding_sats, &htlc_map,
			  NULL, &funding_wscript, peer->channel,
			  local_per_commit,
			  local_index, LOCAL, splice_amnt,
			  remote_splice_amnt, &remote_anchor_outnum);

	/* Set the commit_sig on the commitment tx psbt */
	if (!psbt_input_set_signature(txs[0]->psbt, 0,
				      &peer->channel->funding_pubkey[REMOTE],
				      &commit_sig))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Unable to set signature internally");

	if (!derive_simple_key(&peer->channel->basepoints[REMOTE].htlc,
			       local_per_commit, &remote_htlckey))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving remote_htlckey");
	status_debug("Derived key %s from basepoint %s, point %s",
		     fmt_pubkey(tmpctx, &remote_htlckey),
		     fmt_pubkey(tmpctx, &peer->channel->basepoints[REMOTE].htlc),
		     fmt_pubkey(tmpctx, local_per_commit));
	/* BOLT #2:
	 *
	 * A receiving node:
	 *  - once all pending updates are applied:
	 *    - if `signature` is not valid for its local commitment transaction
	 *      OR non-compliant with LOW-S-standard rule...:
	 *      - MUST send a `warning` and close the connection, or send an
	 *        `error` and fail the channel.
	 */
	if (!check_tx_sig(txs[0], 0, NULL, funding_wscript,
			  &peer->channel->funding_pubkey[REMOTE], &commit_sig)) {
		dump_htlcs(peer->channel, "receiving commit_sig");
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad commit_sig signature %"PRIu64" %s for tx"
				 " %s wscript %s key %s feerate %u. Cur funding"
				 " %s, splice_info: %s, race_await_commit: %s,"
				 " inflight splice count: %zu",
				 local_index,
				 fmt_bitcoin_signature(msg, &commit_sig),
				 fmt_bitcoin_tx(msg, txs[0]),
				 tal_hex(msg, funding_wscript),
				 fmt_pubkey(msg,
					    &peer->channel->funding_pubkey[REMOTE]),
				 channel_feerate(peer->channel, LOCAL),
				 fmt_channel_id(tmpctx,	&active_id),
				 cs_tlv && cs_tlv->splice_info
				 	? fmt_channel_id(tmpctx,
							 cs_tlv->splice_info)
				 	: "N/A",
				 peer->splice_state->await_commitment_succcess ? "yes"
				 					: "no",
				 tal_count(peer->splice_state->inflights));
	}

	/* BOLT #2:
	 *
	 * A receiving node:
	 *...
	 *    - if `num_htlcs` is not equal to the number of HTLC outputs in the
	 * local commitment transaction:
	 *     - MUST send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */
	if (tal_count(htlc_sigs) != tal_count(txs) - 1)
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Expected %zu htlc sigs, not %zu",
				 tal_count(txs) - 1, tal_count(htlc_sigs));

	/* BOLT #2:
	 *
	 *   - if any `htlc_signature` is not valid for the corresponding HTLC
	 *     transaction OR non-compliant with LOW-S-standard rule...:
	 *     - MUST send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */
	for (i = 0; i < tal_count(htlc_sigs); i++) {
		u8 *wscript;

		wscript = bitcoin_tx_output_get_witscript(tmpctx, txs[0],
							  txs[i+1]->wtx->inputs[0].index);

		if (!check_tx_sig(txs[1+i], 0, NULL, wscript,
				  &remote_htlckey, &htlc_sigs[i]))
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "Bad commit_sig signature %s for htlc %s wscript %s key %s",
					 fmt_bitcoin_signature(msg, &htlc_sigs[i]),
					 fmt_bitcoin_tx(msg, txs[1+i]),
					 tal_hex(msg, wscript),
					 fmt_pubkey(msg, &remote_htlckey));
	}

	status_debug("Received commit_sig with %zu htlc sigs",
		     tal_count(htlc_sigs));

	/* First pass some common error scenarios for nicer log outputs */
	if (peer->splice_state->count) {
		if (!cs_tlv)
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "Bad commitment_signed mesage"
					 " without a splice commit sig"
					 " section during a splice.");
		if (tal_count(peer->splice_state->inflights) != peer->splice_state->count)
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "Internal splice inflight counting "
					 "error");
	}

	/* As of HSM_VERSION 5 returned old_secret is always NULL (revoke returns it instead) */
	htlcs = collect_htlcs(NULL, htlc_map);
	msg2 = towire_hsmd_validate_commitment_tx(NULL,
						  txs[0],
						  (const struct simple_htlc **) htlcs,
						  local_index,
						  channel_feerate(peer->channel, LOCAL),
						  &commit_sig,
						  htlc_sigs);
	tal_free(htlcs);
	msg2 = hsm_req(tmpctx, take(msg2));
	struct secret *old_secret;
	struct pubkey next_point;
	if (!fromwire_hsmd_validate_commitment_tx_reply(tmpctx, msg2, &old_secret, &next_point))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading validate_commitment_tx reply: %s",
			      tal_hex(tmpctx, msg2));

	struct commitsig *commitsig;
	commitsig = tal(tmpctx, struct commitsig);
	commitsig->tx = clone_bitcoin_tx(tmpctx, txs[0]);
	commitsig->commit_signature = commit_sig;
	commitsig->htlc_signatures = htlc_sigs;

	result = tal(tmpctx, struct commitsig_info);
	result->commitsig = commitsig;
	result->old_secret = old_secret;
	/* Only the parent call continues from here.
	 * Return for all child calls. */
	if(commit_index)
		return result;

	commitsigs = tal_arr(NULL, const struct commitsig*, 0);
	/* We expect multiple consequtive commit_sig messages if we have
	 * inflight splices. Since consequtive is requred, we recurse for
	 * each expected message, blocking until all are received. */
	for (i = 0; i < tal_count(peer->splice_state->inflights); i++) {
		s64 funding_diff = sats_diff(peer->splice_state->inflights[i]->amnt,
					     peer->channel->funding_sats);
		s64 sub_splice_amnt = peer->splice_state->inflights[i]->splice_amnt;

		splice_msg = peer_read(tmpctx, peer->pps);
		check_tx_abort(peer, splice_msg);
		/* Check type for cleaner failure message */
		type = fromwire_peektype(msg);
		if (type != WIRE_COMMITMENT_SIGNED)
			peer_failed_err(peer->pps, &peer->channel_id,
					"Expected splice related "
					"WIRE_COMMITMENT_SIGNED but got %s",
					peer_wire_name(type));

		/* We purposely just store the last commit msg in result */
		result = handle_peer_commit_sig(peer, splice_msg, i + 1,
						changed_htlcs, sub_splice_amnt,
						funding_diff - sub_splice_amnt,
						local_index, local_per_commit,
						allow_empty_commit);
		old_secret = result->old_secret;
		tal_arr_expand(&commitsigs, result->commitsig);
		tal_steal(commitsigs, result);
	}

	/* After HSM_VERSION 5 old_secret is always NULL */
	assert(!old_secret);

	send_revocation(peer, &commit_sig, htlc_sigs, changed_htlcs, txs[0],
			old_secret, &next_point, commitsigs);

	tal_steal(tmpctx, result);
	tal_free(commitsigs);

	/* STFU can't be activated during pending updates.
	 * With updates finish let's handle a potentially queued stfu request.
	 */
	maybe_send_stfu(peer);

	/* This might have synced the feerates: if so, we may want to
	 * update */
	if (want_fee_update(peer, NULL))
		start_commit_timer(peer);

	/* We return the last commit commit msg */
	return result;
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
		/* DTODO we need penalty tx's per splice candidate */
		ptx = penalty_tx_create(
		    NULL, peer->channel, peer->feerate_penalty,
		    peer->final_index, peer->final_ext_key,
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
	 *     - MUST send an `error` and fail the channel.
	 */
	memcpy(&privkey, &old_commit_secret, sizeof(privkey));
	if (!pubkey_from_privkey(&privkey, &per_commit_point)) {
		peer_failed_err(peer->pps, &peer->channel_id,
				"Bad privkey %s",
				fmt_privkey(msg, &privkey));
	}
	if (!pubkey_eq(&per_commit_point, &peer->old_remote_per_commit)) {
		peer_failed_err(peer->pps, &peer->channel_id,
				"Wrong privkey %s for %"PRIu64" %s",
				fmt_privkey(msg, &privkey),
				peer->next_index[LOCAL]-2,
				fmt_pubkey(msg, &peer->old_remote_per_commit));
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
		     fmt_pubkey(tmpctx, &peer->remote_per_commit),
		     fmt_pubkey(tmpctx, &peer->old_remote_per_commit));

	peer->splice_state->await_commitment_succcess = false;

	/* STFU can't be activated during pending updates.
	 * With updates finish let's handle a potentially queued stfu request.
	 */
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
	 *      - MUST send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */
	if (!(failure_code & BADONION)) {
		/* But LND (at least, Bitrefill to Blockstream Store) sends this? */
		status_unusual("Bad update_fail_malformed_htlc failure code %u",
			       failure_code);
		/* We require this internally. */
		failure_code |= BADONION;
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
	struct tlv_shutdown_tlvs *tlvs;
	struct bitcoin_outpoint *wrong_funding;

	/* DTODO: Ensure `shutdown` follows new splice related rules once
	 * completed in the spec */

	if (!fromwire_shutdown(tmpctx, shutdown, &channel_id, &scriptpubkey,
			       &tlvs))
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
	 *    - MAY send a `warning`.
	 *    - MUST fail the connection.
	 */
	/* openingd only sets this if feature was negotiated at opening. */
	if (tal_count(peer->remote_upfront_shutdown_script)
	    && !memeq(scriptpubkey, tal_count(scriptpubkey),
		      peer->remote_upfront_shutdown_script,
		      tal_count(peer->remote_upfront_shutdown_script)))
		peer_failed_warn(peer->pps, &peer->channel_id,
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
	const struct witness **witnesses;
	struct channel_id cid;
	struct bitcoin_txid txid;

	struct tlv_txsigs_tlvs *txsig_tlvs = tlv_txsigs_tlvs_new(tmpctx);

	/* In a rare case, a v2 peer may re-send a tx_sigs message.
	 * This happens when they've/we've exchanged channel_ready,
	 * but they did not receive our channel_ready. */
	if (!fromwire_tx_signatures(tmpctx, msg, &cid, &txid,
				    cast_const3(struct witness ***, &witnesses),
				    &txsig_tlvs))
		peer_failed_warn(peer->pps, &peer->channel_id,
			    "Bad tx_signatures %s",
			    tal_hex(msg, msg));

	status_info("Unexpected `tx_signatures` from peer-> %s",
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
	struct tlv_channel_reestablish_tlvs *tlvs;

	if (!fromwire_channel_reestablish(tmpctx, msg, &channel_id,
					  &next_commitment_number,
					  &next_revocation_number,
					  &your_last_per_commitment_secret,
					  &my_current_per_commitment_point,
					  &tlvs)) {
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad channel_reestablish %s", tal_hex(peer, msg));
	}

	/* Is it the same as the peer channel ID?  */
	if (channel_id_eq(&channel_id, &peer->channel_id)) {
		/* Log this event as unusual.  */
		status_unusual("Got repeated WIRE_CHANNEL_REESTABLISH "
			       "for channel %s, ignoring: %s",
			       fmt_channel_id(tmpctx, &peer->channel_id),
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
			fmt_channel_id(tmpctx, &channel_id));
}

static bool is_initiators_serial(const struct wally_map *unknowns)
{
	/* BOLT #2:
	 * The sending node: ...
	 *   - if is the *initiator*:
	 *     - MUST send even `serial_id`s
	 *   - if is the *non-initiator*:
	 *     - MUST send odd `serial_id`s
	 */
	u64 serial_id;
	if (!psbt_get_serial_id(unknowns, &serial_id))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "PSBTs must have serial_ids set");

	return serial_id % 2 == TX_INITIATOR;
}

static void add_amount_to_side(struct peer *peer,
			       struct amount_msat amounts[NUM_TX_ROLES],
			       const struct amount_sat amount,
			       const struct wally_map *unknowns)
{
	enum tx_role role;

	if (amount_sat_zero(amount))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Unable to add 0 sat fields to calculation");

	if(is_initiators_serial(unknowns))
		role = TX_INITIATOR;
	else
		role = TX_ACCEPTER;

	if (!amount_msat_add_sat(&amounts[role], amounts[role], amount))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Unable to add field amount %s to rolling"
				 " total %s",
				 fmt_amount_sat(tmpctx, amount),
				 fmt_amount_msat(tmpctx, amounts[role]));
}

static bool do_i_sign_first(struct peer *peer, struct wally_psbt *psbt,
			    enum tx_role our_role, bool force_sign_first)
{
	struct amount_msat in[NUM_TX_ROLES];

	/* BOLT-0d8b701614b09c6ee4172b04da2203e73deec7e2 #2:
  	 *   - MAY send `tx_signatures` first. */
	if (force_sign_first)
		return true;

	in[TX_INITIATOR] = AMOUNT_MSAT(0);
	in[TX_ACCEPTER] = AMOUNT_MSAT(0);

	for (size_t i = 0; i < psbt->num_inputs; i++)
		add_amount_to_side(peer, in, psbt_input_get_amount(psbt, i),
				   &psbt->inputs[i].unknowns);

	/* BOLT-0d8b701614b09c6ee4172b04da2203e73deec7e2 #2:
	 * - If recipient's sum(tx_add_input.amount) < peer's
	 *   sum(tx_add_input.amount); or if recipient's
	 *   sum(tx_add_input.amount) == peer's sum(tx_add_input.amount) and
	 * recipient is the `initiator` of the splice:
  	 *   - SHOULD send `tx_signatures` first for the splice transaction. */
	if (amount_msat_less(in[TX_ACCEPTER], in[TX_INITIATOR]))
		return our_role == TX_ACCEPTER;

	if (amount_msat_less(in[TX_INITIATOR], in[TX_ACCEPTER]))
		return our_role == TX_INITIATOR;

	return our_role == TX_INITIATOR;
}

static struct wally_psbt *next_splice_step(const tal_t *ctx,
					   struct interactivetx_context *ictx)
{
	/* DTODO: add plugin wrapper for accepter side of splice to add to the
	 * negotiated splice. */
	if (ictx->our_role == TX_ACCEPTER)
		return NULL;

	return ictx->desired_psbt;
}

static const u8 *peer_expect_msg_three(const tal_t *ctx,
				       struct peer *peer,
				       enum peer_wire expect_type,
				       enum peer_wire second_allowed_type,
				       enum peer_wire third_allowed_type)
{
	u8 *msg;
	enum peer_wire type;

	msg = peer_read(ctx, peer->pps);
	type = fromwire_peektype(msg);
	if (type != expect_type && type != second_allowed_type
	    && type != third_allowed_type)
		peer_failed_warn(peer->pps, &peer->channel_id,
				"Got incorrect message from peer: %s"
				" (should be %s) [%s]",
				peer_wire_name(type),
				peer_wire_name(expect_type),
				sanitize_error(tmpctx, msg, &peer->channel_id));

	return msg;
}

/* The question of "who signs splice commitments first" is the same order as the
 * splice `tx_signature`s are. This function handles sending & receiving the
 * required commitments as part of the splicing process.
 * If the first message received is `tx_abort` or `tx_signatures, NULL is
 * returned. */
static struct commitsig *interactive_send_commitments(struct peer *peer,
						      struct wally_psbt *psbt,
						      enum tx_role our_role,
						      size_t inflight_index,
						      bool send_commitments,
						      bool recv_commitments,
						      const u8 **msg_received)
{
	struct commitsig_info *result;
	const u8 *msg;
	struct pubkey my_current_per_commitment_point;
	struct inflight *inflight = peer->splice_state->inflights[inflight_index];
	s64 funding_diff = sats_diff(inflight->amnt,
				     peer->channel->funding_sats);
	s64 remote_splice_amnt = funding_diff - inflight->splice_amnt;
	struct local_anchor_info *local_anchor;
	u64 next_index_local = peer->next_index[LOCAL];
	u64 next_index_remote = peer->next_index[REMOTE];

	if(msg_received)
		*msg_received = NULL;

	if (do_i_sign_first(peer, psbt, our_role, inflight->force_sign_first)
		&& send_commitments) {

		status_debug("Splice %s: we commit first",
			     our_role == TX_INITIATOR ? "initiator" : "accepter");

		peer_write(peer->pps, send_commit_part(tmpctx,
						       peer,
						       &inflight->outpoint,
						       inflight->amnt,
						       NULL, false,
						       inflight->splice_amnt,
						       remote_splice_amnt,
						       next_index_remote - 1,
						       &peer->old_remote_per_commit,
						       &local_anchor));
	}

	result = NULL;

	if (recv_commitments) {
		msg = peer_expect_msg_three(tmpctx, peer,
					    WIRE_COMMITMENT_SIGNED,
					    WIRE_TX_SIGNATURES,
					    WIRE_TX_ABORT);

		check_tx_abort(peer, msg);

		if (msg_received)
			*msg_received = msg;

		/* Funding counts as 0th commit so we do inflight_index + 1 */
		if (fromwire_peektype(msg) == WIRE_COMMITMENT_SIGNED) {
			get_per_commitment_point(next_index_local - 1,
						 &my_current_per_commitment_point);

			result = handle_peer_commit_sig(peer, msg,
							inflight_index + 1,
							NULL,
							inflight->splice_amnt,
							remote_splice_amnt,
							next_index_local - 1,
							&my_current_per_commitment_point,
							true);
		}
	}

	if (!do_i_sign_first(peer, psbt, our_role, inflight->force_sign_first)
		&& send_commitments) {

		status_debug("Splice %s: we commit second",
			     our_role == TX_INITIATOR ? "initiator" : "accepter");

		peer_write(peer->pps, send_commit_part(tmpctx,
						       peer,
						       &inflight->outpoint,
						       inflight->amnt,
						       NULL, false,
						       inflight->splice_amnt,
						       remote_splice_amnt,
						       next_index_remote - 1,
						       &peer->old_remote_per_commit,
						       &local_anchor));
	}

	/* Sending and receiving splice commit should not increment commit
	 * related indices */
	assert(next_index_local == peer->next_index[LOCAL]);
	assert(next_index_remote == peer->next_index[REMOTE]);

	return result ? result->commitsig : NULL;
}

static struct wally_psbt_output *find_channel_output(struct peer *peer,
						   struct wally_psbt *psbt,
						   u32 *chan_output_index)
{
	const u8 *wit_script;
	u8 *scriptpubkey;

	wit_script = bitcoin_redeem_2of2(tmpctx,
					 &peer->channel->funding_pubkey[LOCAL],
					 &peer->channel->funding_pubkey[REMOTE]);

	scriptpubkey = scriptpubkey_p2wsh(tmpctx, wit_script);

	for (size_t i = 0; i < psbt->num_outputs; i++) {
		if (memeq(psbt->outputs[i].script,
			 psbt->outputs[i].script_len,
			 scriptpubkey,
			 tal_bytelen(scriptpubkey))) {
			if (chan_output_index)
				*chan_output_index = i;
			return &psbt->outputs[i];
		}
	}

	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "Unable to find channel output");
	return NULL;
}

static size_t calc_weight(enum tx_role role, const struct wally_psbt *psbt)
{
	size_t weight = 0;

	/* BOLT #2:
	 * The *initiator* is responsible for paying the fees for the following fields,
	 * to be referred to as the `common fields`.
	 *
	 *   - version
	 *   - segwit marker + flag
	 *   - input count
	 *   - output count
	 *   - locktime
	 */
	if (role == TX_INITIATOR)
		weight += bitcoin_tx_core_weight(psbt->num_inputs,
						 psbt->num_outputs);

	/* BOLT #2:
	 * The rest of the transaction bytes' fees are the responsibility of
	 * the peer who contributed that input or output via `tx_add_input` or
	 * `tx_add_output`, at the agreed upon `feerate`.
	 */
	for (size_t i = 0; i < psbt->num_inputs; i++)
		if (is_initiators_serial(&psbt->inputs[i].unknowns)) {
			if (role == TX_INITIATOR)
				weight += psbt_input_get_weight(psbt, i);
		}
		else
			if (role != TX_INITIATOR)
				weight += psbt_input_get_weight(psbt, i);

	for (size_t i = 0; i < psbt->num_outputs; i++)
		if (is_initiators_serial(&psbt->outputs[i].unknowns)) {
			if (role == TX_INITIATOR)
				weight += psbt_output_get_weight(psbt, i);
		}
		else
			if (role != TX_INITIATOR)
				weight += psbt_output_get_weight(psbt, i);

	return weight;
}

/* Get the fundee amount in the channel after the splice */
static struct amount_msat
relative_splice_balance_fundee(struct peer *peer,
			       enum tx_role our_role,
			       const struct wally_psbt *psbt,
			       int chan_output_index,
			       int chan_input_index)
{
	/* Relative fundee channel balance */
	u64 push_value;

	/* We calculcate the `push_value` to send to the
	 * hsmd, that is the remote amount in the channel
	 * after the splice. */
	switch (our_role) {
	case TX_INITIATOR:
		/* push_value is the fundee relative value so if we open the channel
		 * fundee is the remote node. */
		push_value = peer->splicing->accepter_relative;
		break;
	case TX_ACCEPTER:
		/* push_value is the fundee relative value so if the remote node open the channel
		 * fundee in this case is the opener. */
		push_value = peer->splicing->opener_relative;
		break;
	default:
		/* This should never happen. Help us to early catch the tx_role change */
		abort();
	}

	return amount_msat(push_value);
}

/* Returns the total channel funding output amount if all checks pass.
 * Otherwise, exits via peer_failed_warn. DTODO: Change to `tx_abort`. */
static struct amount_sat check_balances(struct peer *peer,
					enum tx_role our_role,
					const struct wally_psbt *psbt,
					int chan_output_index,
					int chan_input_index)
{
	struct amount_sat min_initiator_fee, min_accepter_fee,
			  max_initiator_fee, max_accepter_fee,
			  funding_amount_res, min_multiplied;
	struct amount_msat funding_amount,
			   initiator_fee, accepter_fee;
	struct amount_msat in[NUM_TX_ROLES], out[NUM_TX_ROLES],
			   pending_htlcs[NUM_TX_ROLES];
	struct htlc_map_iter it;
	const struct htlc *htlc;
	bool opener = our_role == TX_INITIATOR;
	u8 *msg;

	/* The channel funds less any pending htlcs */
	in[TX_INITIATOR] = peer->channel->view->owed[opener ? LOCAL : REMOTE];
	in[TX_ACCEPTER] = peer->channel->view->owed[opener ? REMOTE : LOCAL];

	/* pending_htlcs holds the value of all pending htlcs for each side */
	pending_htlcs[TX_INITIATOR] = AMOUNT_MSAT(0);
	pending_htlcs[TX_ACCEPTER] = AMOUNT_MSAT(0);
	for (htlc = htlc_map_first(peer->channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(peer->channel->htlcs, &it)) {
		struct amount_msat *itr;

		if (htlc_owner(htlc) == opener ? LOCAL : REMOTE)
			itr = &pending_htlcs[TX_INITIATOR];
		else
			itr = &pending_htlcs[TX_ACCEPTER];

		if (!amount_msat_add(itr, *itr, htlc->amount))
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "Unable to add HTLC balance");
	}

	for (size_t i = 0; i < psbt->num_inputs; i++)
		if (i != chan_input_index)
			add_amount_to_side(peer, in,
					   psbt_input_get_amount(psbt, i),
					   &psbt->inputs[i].unknowns);

	/* The outgoing channel funds start as current funds, will be modified
	 * by the splice amount later on */
	out[TX_INITIATOR] = peer->channel->view->owed[opener ? LOCAL : REMOTE];
	out[TX_ACCEPTER] = peer->channel->view->owed[opener ? REMOTE : LOCAL];

	for (size_t i = 0; i < psbt->num_outputs; i++)
		if (i != chan_output_index)
			add_amount_to_side(peer, out,
					   psbt_output_get_amount(psbt, i),
					   &psbt->outputs[i].unknowns);

	/* Calculate original channel output amount */
	if (!amount_msat_add(&funding_amount,
			     peer->channel->view->owed[LOCAL],
			     peer->channel->view->owed[REMOTE]))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Unable to calculate starting channel amount");
	if (!amount_msat_add(&funding_amount,
			     funding_amount,
			     pending_htlcs[TX_INITIATOR]))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Unable to calculate starting channel amount");
	if (!amount_msat_add(&funding_amount,
			     funding_amount,
			     pending_htlcs[TX_ACCEPTER]))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Unable to calculate starting channel amount");

	/* Tasks:
	 *   Add up total funding_amount
	 *   Check in[TX_INITIATOR] - out[TX_INITIATOR] > opener_relative
	 *    - refactor as in[TX_INITIATOR] > opener_relative + out[TX_INITIATOR]
	 *      - remainder is the fee contribution
	 *   Check in[TX_ACCEPTER] - out[TX_ACCEPTER] > accepter_relative
	 *    - refactor as in[TX_INITIATOR] > opener_relative + out[TX_INITIATOR]
	 *      - remainder is the fee contribution
	 *
	 *   Check if fee rate is too low anywhere
	 *   Check if fee rate is too high locally
	 *
	 *   While we're, here, adjust the output counts by splice amount.
	 */
	if (!amount_msat_add_sat_s64(&funding_amount, funding_amount,
				peer->splicing->opener_relative))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Unable to add opener funding");
	if (!amount_msat_add_sat_s64(&out[TX_INITIATOR], out[TX_INITIATOR],
				peer->splicing->opener_relative))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Unable to add opener funding to out amnt.");

	if (!amount_msat_add_sat_s64(&funding_amount, funding_amount,
				peer->splicing->accepter_relative))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Unable to add accepter funding");
	if (!amount_msat_add_sat_s64(&out[TX_ACCEPTER], out[TX_ACCEPTER],
				peer->splicing->accepter_relative))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Unable to add accepter funding to out amnt.");

	if (amount_msat_less(in[TX_INITIATOR], out[TX_INITIATOR])) {
		msg = towire_channeld_splice_funding_error(NULL,
							   in[TX_INITIATOR],
							   out[TX_INITIATOR],
							   true);
		wire_sync_write(MASTER_FD, take(msg));
		splice_abort(peer,
				 "Initiator funding is less than commited"
				 " amount. Initiator contributing %s but they"
				 " committed to %s. Pending offered HTLC"
				 " balance of %s is not available for this"
				 " operation.",
				 fmt_amount_msat(tmpctx, in[TX_INITIATOR]),
				 fmt_amount_msat(tmpctx, out[TX_INITIATOR]),
				 fmt_amount_msat(tmpctx,
				 		 pending_htlcs[TX_INITIATOR]));
	}

	if (!amount_msat_sub(&initiator_fee, in[TX_INITIATOR], out[TX_INITIATOR]))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "amount_sat_less / amount_sat_sub mismtach");

	if (amount_msat_less(in[TX_ACCEPTER], out[TX_ACCEPTER])) {
		msg = towire_channeld_splice_funding_error(NULL,
							   in[TX_INITIATOR],
							   out[TX_INITIATOR],
							   true);
		wire_sync_write(MASTER_FD, take(msg));
		splice_abort(peer,
				 "Accepter funding is less than commited"
				 " amount. Accepter contributing %s but they"
				 " committed to %s. Pending offered HTLC"
				 " balance of %s is not available for this"
				 " operation.",
				 fmt_amount_msat(tmpctx, in[TX_INITIATOR]),
				 fmt_amount_msat(tmpctx, out[TX_INITIATOR]),
				 fmt_amount_msat(tmpctx,
				 		 pending_htlcs[TX_INITIATOR]));
	}

	if (!amount_msat_sub(&accepter_fee, in[TX_ACCEPTER], out[TX_ACCEPTER]))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "amount_sat_less / amount_sat_sub mismtach");

	min_initiator_fee = amount_tx_fee(peer->splicing->feerate_per_kw,
					  calc_weight(TX_INITIATOR, psbt));
	min_accepter_fee = amount_tx_fee(peer->splicing->feerate_per_kw,
					 calc_weight(TX_ACCEPTER, psbt));

	/* As a safeguard max feerate is checked (only) locally, if it's
	 * particularly high we fail and tell the user but allow them to
	 * override with `splice_force_feerate` */
	max_accepter_fee = amount_tx_fee(peer->feerate_max,
					 calc_weight(TX_ACCEPTER, psbt));
	max_initiator_fee = amount_tx_fee(peer->feerate_max,
					  calc_weight(TX_INITIATOR, psbt));

	/* Sometimes feerate_max is some absurdly high value, in that case we
	 * give a fee warning based of a multiple of the min value. */
	amount_sat_mul(&min_multiplied, min_accepter_fee, 5);
	max_accepter_fee = SAT_MIN(min_multiplied, max_accepter_fee);

	amount_sat_mul(&min_multiplied, min_initiator_fee, 5);
	max_initiator_fee = SAT_MIN(min_multiplied, max_initiator_fee);

	/* Check initiator fee */
	if (amount_msat_less_sat(initiator_fee, min_initiator_fee)) {
		msg = towire_channeld_splice_feerate_error(NULL, initiator_fee,
							   false);
		wire_sync_write(MASTER_FD, take(msg));
		splice_abort(peer,
				 "%s fee (%s) was too low, must be at least %s",
				 opener ? "Our" : "Your",
				 fmt_amount_msat(tmpctx, initiator_fee),
				 fmt_amount_sat(tmpctx, min_initiator_fee));
	}
	if (!peer->splicing->force_feerate && opener
		&& amount_msat_greater_sat(initiator_fee, max_initiator_fee)) {
		msg = towire_channeld_splice_feerate_error(NULL, initiator_fee,
							   true);
		wire_sync_write(MASTER_FD, take(msg));
		splice_abort(peer,
				 "Our own fee (%s) was too high, max without"
				 " forcing is %s.",
				 fmt_amount_msat(tmpctx, initiator_fee),
				 fmt_amount_sat(tmpctx, max_initiator_fee));
	}
	/* Check accepter fee */
	if (amount_msat_less_sat(accepter_fee, min_accepter_fee)) {
		msg = towire_channeld_splice_feerate_error(NULL, accepter_fee,
							   false);
		wire_sync_write(MASTER_FD, take(msg));
		splice_abort(peer,
				 "%s fee (%s) was too low, must be at least %s",
				 opener ? "Your" : "Our",
				 fmt_amount_msat(tmpctx, accepter_fee),
				 fmt_amount_sat(tmpctx, min_accepter_fee));
	}
	if (!peer->splicing->force_feerate && !opener
		&& amount_msat_greater_sat(accepter_fee, max_accepter_fee)) {
		msg = towire_channeld_splice_feerate_error(NULL, accepter_fee,
							   true);
		wire_sync_write(MASTER_FD, take(msg));
		splice_abort(peer,
				 "Our own fee (%s) was too high, max without"
				 " forcing is %s.",
				 fmt_amount_msat(tmpctx, accepter_fee),
				 fmt_amount_sat(tmpctx, max_accepter_fee));
	}

	/* BOLT-??? #2:
	 * - if either side has added an output other than the new channel
	 *   funding output:
  	 *   - MUST fail the negotiation if the balance for that side is less
  	 *     than 1% of the total channel capacity. */
	/* DTODO: Spec out reserve requirements for splices!! Lets gooo */
	/* DTODO: If we were at or over the reserve at start of splice,
	 * then we must ensure the reserve is preserved through splice.
	 * It should only to 1% of the old balance
	 * 1: The channel is growing
	 *  --- your balnce was underneath reserve req
	 *  Valid: YES
	 * 2: The node's balance is shrinking
	 *  --- and it shrinks below the reserve
	 *  Valid: NO
	 *
	 * The reserve requirement should only matter if someone is withdrawing
	 * from.
	 *
	 * Node A       Node B
	 * 1000 sat <-> 1000 sat
	 * reserve: 20sat
	 *
	 * Node B desires withdraw 990 sats
	 * Can I?
	 * New reserve req = 1010 * 0.01 = 10 (round down from 10.1)
	 * */

	if (!amount_msat_to_sat(&funding_amount_res, funding_amount)) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "splice error: msat of total funding %s should"
			      " always add up to a full sat. original local bal"
			      " %s, original remote bal %s,",
			      fmt_amount_msat(tmpctx, funding_amount),
			      fmt_amount_msat(tmpctx,
					      peer->channel->view->owed[LOCAL]),
			      fmt_amount_msat(tmpctx,
					      peer->channel->view->owed[REMOTE]));
	}

	return funding_amount_res;
}

static void update_view_from_inflights(struct peer *peer)
{
	struct inflight **inflights = peer->splice_state->inflights;

	for (size_t i = 0; i < tal_count(inflights); i++) {
		s64 splice_amnt = inflights[i]->amnt.satoshis; /* Raw: splicing */
		s64 funding_diff = sats_diff(inflights[i]->amnt, peer->channel->funding_sats);
		s64 remote_splice_amnt = funding_diff - inflights[i]->splice_amnt;

		if (splice_amnt < peer->channel->view[LOCAL].lowest_splice_amnt[LOCAL])
			peer->channel->view[LOCAL].lowest_splice_amnt[LOCAL] = splice_amnt;

		if (splice_amnt < peer->channel->view[REMOTE].lowest_splice_amnt[REMOTE])
			peer->channel->view[REMOTE].lowest_splice_amnt[LOCAL] = splice_amnt;

		if (remote_splice_amnt < peer->channel->view[LOCAL].lowest_splice_amnt[REMOTE])
			peer->channel->view[LOCAL].lowest_splice_amnt[REMOTE] = remote_splice_amnt;

		if (remote_splice_amnt < peer->channel->view[REMOTE].lowest_splice_amnt[LOCAL])
			peer->channel->view[REMOTE].lowest_splice_amnt[REMOTE] = remote_splice_amnt;
	}
}

/* Called to finish an ongoing splice OR on restart from chanenl_reestablish. */
static void resume_splice_negotiation(struct peer *peer,
				      bool send_commitments,
				      bool recv_commitments,
				      bool send_signature,
				      bool recv_signature)
{
	struct inflight *inflight = last_inflight(peer);
	enum tx_role our_role = inflight->i_am_initiator
						   ? TX_INITIATOR
						   : TX_ACCEPTER;
	const u8 *wit_script;
	struct channel_id cid;
	enum peer_wire type;
	struct wally_psbt *current_psbt = inflight->psbt;
	struct commitsig *their_commit;
	struct witness **inws;
	const struct witness **outws;
	u8 der[73];
	size_t der_len;
	struct bitcoin_signature splice_sig;
	struct bitcoin_tx *bitcoin_tx;
	u32 splice_funding_index;
	const u8 *msg, *sigmsg;
	u32 chan_output_index;
	struct bitcoin_signature their_sig;
	struct pubkey *their_pubkey;
	struct bitcoin_tx *final_tx COMPILER_WANTS_INIT("12.3.0 -O3");
	struct bitcoin_txid final_txid;
	u8 **wit_stack;
	struct tlv_txsigs_tlvs *txsig_tlvs, *their_txsigs_tlvs;
	const u8 *msg_received;

	status_info("Splice negotation, will %ssend commit, %srecv commit,"
		    " %ssend signature, %srecv signature as %s",
		    send_commitments ? "" : "not ",
		    recv_commitments ? "" : "not ",
		    send_signature ? "" : "not ",
		    recv_signature ? "" : "not ",
		    our_role == TX_INITIATOR ? "initiator" : "accepter");

	wit_script = bitcoin_redeem_2of2(tmpctx,
					 &peer->channel->funding_pubkey[LOCAL],
					 &peer->channel->funding_pubkey[REMOTE]);

	find_channel_output(peer, current_psbt, &chan_output_index);

	splice_funding_index = find_channel_funding_input(current_psbt,
							  &peer->channel->funding);

	msg_received = NULL;
	their_commit = interactive_send_commitments(peer, current_psbt,
						    our_role,
						    last_inflight_index(peer),
						    send_commitments,
						    recv_commitments,
						    &msg_received);

	check_tx_abort(peer, msg_received);

	if (their_commit) {
		if (inflight->last_tx != their_commit->tx)
			inflight->last_tx = tal_free(inflight->last_tx);
		inflight->last_tx = tal_steal(inflight, their_commit->tx);
		inflight->last_sig = their_commit->commit_signature;

		msg = towire_channeld_update_inflight(NULL, current_psbt,
						      their_commit->tx,
						      &their_commit->commit_signature);
		wire_sync_write(MASTER_FD, take(msg));
	}

	if (!inflight->last_tx)
		peer_failed_err(peer->pps, &peer->channel_id,
				"Splice needs commitment signature to continue"
				" but your last msg was %s",
				msg_received ? tal_hex(tmpctx, msg_received) : "NULL");

	/* DTODO Validate splice tx takes none of our funds in either:
	 * 1) channel balance
	 * 2) other side sneakily adding other outputs we own
	 */

	/* BOLT-a8b9f495cac28124c69cc5ee429f9ef2bacb9921 #2:
	 * Both nodes:
	 *   - MUST sign the transaction using SIGHASH_ALL */
	splice_sig.sighash_type = SIGHASH_ALL;

	bitcoin_tx = bitcoin_tx_with_psbt(tmpctx, current_psbt);

	status_info("Splice signing tx: %s",
		    tal_hex(tmpctx, linearize_tx(tmpctx, bitcoin_tx)));

	msg = towire_hsmd_sign_splice_tx(tmpctx, bitcoin_tx,
					 &peer->channel->funding_pubkey[REMOTE],
					 splice_funding_index);

	msg = hsm_req(tmpctx, take(msg));
	if (!fromwire_hsmd_sign_tx_reply(msg, &splice_sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading sign_splice_tx reply: %s",
			      tal_hex(tmpctx, msg));

	/* Set the splice_sig on the splice funding tx psbt */
	if (!psbt_input_set_signature(current_psbt, splice_funding_index,
				      &peer->channel->funding_pubkey[LOCAL],
				      &splice_sig))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Unable to set signature internally "
			      "funding_index: %d "
			      "my pubkey: %s "
			      "my signature: %s "
			      "psbt: %s",
			      splice_funding_index,
			      fmt_pubkey(tmpctx,
					 &peer->channel->funding_pubkey[LOCAL]),
			      fmt_bitcoin_signature(tmpctx, &splice_sig),
			      fmt_wally_psbt(tmpctx, current_psbt));

	txsig_tlvs = tlv_txsigs_tlvs_new(tmpctx);
	der_len = signature_to_der(der, &splice_sig);
	txsig_tlvs->funding_outpoint_sig = tal_dup_arr(tmpctx, u8, der,
						       der_len, 0);

	/* DTODO: is this finalize call required? */
	psbt_finalize(current_psbt);

	outws = psbt_to_witnesses(tmpctx, current_psbt,
				  our_role, splice_funding_index);
	sigmsg = towire_tx_signatures(tmpctx, &peer->channel_id,
				      &inflight->outpoint.txid, outws,
				      txsig_tlvs);

	psbt_txid(tmpctx, current_psbt, &final_txid, NULL);

	if (do_i_sign_first(peer, current_psbt, our_role,
			    inflight->force_sign_first)
		&& send_signature) {
		msg = towire_channeld_update_inflight(NULL, current_psbt,
						      NULL, NULL);
		wire_sync_write(MASTER_FD, take(msg));

		msg = towire_channeld_splice_sending_sigs(tmpctx, &final_txid);
		wire_sync_write(MASTER_FD, take(msg));

		peer_write(peer->pps, sigmsg);
	}

	their_pubkey = &peer->channel->funding_pubkey[REMOTE];

	if (recv_signature) {
		if (peer->splicing && peer->splicing->tx_sig_msg) {
			msg_received = tal_steal(tmpctx,
						 peer->splicing->tx_sig_msg);
			peer->splicing->tx_sig_msg = NULL;
			status_debug("Splice is using cached tx_sig_msg");
		}

		if (fromwire_peektype(msg_received) == WIRE_TX_SIGNATURES)
			msg = msg_received;
		else
			msg = peer_read(tmpctx, peer->pps);

		type = fromwire_peektype(msg);

		check_tx_abort(peer, msg);

		if (handle_peer_error_or_warning(peer->pps, msg))
			return;

		if (type != WIRE_TX_SIGNATURES)
			peer_failed_warn(peer->pps, &peer->channel_id,
					"Splicing got incorrect message from"
					" peer: %s (should be"
					" WIRE_TX_SIGNATURES)",
					peer_wire_name(type));

		their_txsigs_tlvs = tlv_txsigs_tlvs_new(tmpctx);
		if (!fromwire_tx_signatures(tmpctx, msg, &cid,
					    &inflight->outpoint.txid,
					    cast_const3(struct witness ***,
					    		&inws),
					    &their_txsigs_tlvs))
			peer_failed_warn(peer->pps, &peer->channel_id,
				    "Splicing bad tx_signatures %s",
				    tal_hex(msg, msg));

		/* BOLT-0d8b701614b09c6ee4172b04da2203e73deec7e2 #2:
		 * - Upon receipt of `tx_signatures` for the splice transaction:
	  	 *  - MUST consider splice negotiation complete.
	  	 *  - MUST consider the connection no longer quiescent.
	  	 */
		end_stfu_mode(peer);

		/* BOLT-a8b9f495cac28124c69cc5ee429f9ef2bacb9921 #2:
		 * Both nodes:
		 *   - MUST sign the transaction using SIGHASH_ALL */
		their_sig.sighash_type = SIGHASH_ALL;

		if (!signature_from_der(their_txsigs_tlvs->funding_outpoint_sig,
				       tal_count(their_txsigs_tlvs->funding_outpoint_sig),
				       &their_sig)) {

			peer_failed_warn(peer->pps, &peer->channel_id,
					 "Splicing bad tx_signatures %s",
					 tal_hex(msg, msg));
		}

		/* Set the commit_sig on the commitment tx psbt */
		if (!psbt_input_set_signature(current_psbt,
					      splice_funding_index,
					      their_pubkey,
					      &their_sig)) {

			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Unable to set signature internally "
				      "funding_index: %d "
				      "pubkey: %s "
				      "signature: %s "
				      "psbt: %s",
				      splice_funding_index,
				      fmt_pubkey(tmpctx, their_pubkey),
				      fmt_bitcoin_signature(tmpctx, &their_sig),
				      fmt_wally_psbt(tmpctx, current_psbt));
		}

		psbt_input_set_witscript(current_psbt,
					 splice_funding_index,
					 wit_script);

		if (tal_count(inws) > current_psbt->num_inputs)
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "%zu too many witness elements"
					 " received",
					 tal_count(inws) - current_psbt->num_inputs);

		/* We put the PSBT + sigs all together */
		for (size_t j = 0, i = 0; i < current_psbt->num_inputs; i++) {
			struct wally_psbt_input *in =
				&current_psbt->inputs[i];
			u64 in_serial;

			if (!psbt_get_serial_id(&in->unknowns, &in_serial)) {
				status_broken("PSBT input %zu missing serial_id"
					      " %s", i,
					      fmt_wally_psbt(tmpctx,
							     current_psbt));
				return;
			}
			if (in_serial % 2 == our_role)
				continue;

			if (i == splice_funding_index)
				continue;

			if (j == tal_count(inws))
				peer_failed_warn(peer->pps,
						 &peer->channel_id,
						 "Mismatch witness stack count."
						 " Most likely you are missing"
						 " signatures. Your"
						 " TX_SIGNATURES message: %s.",
						 tal_hex(msg, msg));

			psbt_finalize_input(current_psbt, in, inws[j++]);
		}

		final_tx = bitcoin_tx_with_psbt(tmpctx, current_psbt);

		wit_stack = bitcoin_witness_2of2(final_tx, &splice_sig,
						 &their_sig,
						 &peer->channel->funding_pubkey[LOCAL],
						 their_pubkey);

		bitcoin_tx_input_set_witness(final_tx, splice_funding_index,
					     wit_stack);

		/* We let core validate our peer's signatures are correct. */

		msg = towire_channeld_update_inflight(NULL, current_psbt, NULL,
						      NULL);
		wire_sync_write(MASTER_FD, take(msg));
	}

	if (!do_i_sign_first(peer, current_psbt, our_role,
			     inflight->force_sign_first)
		&& send_signature) {
		msg = towire_channeld_splice_sending_sigs(tmpctx, &final_txid);
		wire_sync_write(MASTER_FD, take(msg));

		peer_write(peer->pps, sigmsg);
		status_debug("Splice: we signed second");
	}

	peer->splicing = tal_free(peer->splicing);

	if (recv_signature) {
		msg = towire_channeld_splice_confirmed_signed(tmpctx, final_tx,
							      chan_output_index);
		wire_sync_write(MASTER_FD, take(msg));
	}
}

static struct inflight *inflights_new(struct peer *peer)
{
	struct inflight *inf;

	if (!peer->splice_state->inflights)
		peer->splice_state->inflights = tal_arr(peer->splice_state,
							struct inflight *, 0);

	inf = tal(peer->splice_state->inflights, struct inflight);
	tal_arr_expand(&peer->splice_state->inflights, inf);
	return inf;
}

static void update_hsmd_with_splice(struct peer *peer, struct inflight *inflight,
				    const enum tx_role our_role,
				    const struct amount_msat push_val)
{
	u8 *msg;

	/* local_upfront_shutdown_script, local_upfront_shutdown_wallet_index,
	 * remote_upfront_shutdown_script aren't allowed to change, so we
	 * don't need to gather them */
	msg = towire_hsmd_setup_channel(
		NULL,
		peer->channel->opener == LOCAL,
		inflight->amnt,
		push_val,
		&inflight->outpoint.txid,
		inflight->outpoint.n,
		peer->channel->config[LOCAL].to_self_delay,
		/*local_upfront_shutdown_script*/ NULL,
		/*local_upfront_shutdown_wallet_index*/ NULL,
		&peer->channel->basepoints[REMOTE],
		&peer->channel->funding_pubkey[REMOTE],
		peer->channel->config[REMOTE].to_self_delay,
		/*remote_upfront_shutdown_script*/ NULL,
		peer->channel->type);

	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_setup_channel_reply(msg))
		status_failed(STATUS_FAIL_HSM_IO, "Bad setup_channel_reply %s",
			      tal_hex(tmpctx, msg));
}

/* ACCEPTER side of the splice. Here we handle all the accepter's steps for the
 * splice. Since the channel must be in STFU mode we block the daemon here until
 * the splice is finished or aborted. */
static void splice_accepter(struct peer *peer, const u8 *inmsg)
{
	const u8 *msg;
	struct interactivetx_context *ictx;
	u32 splice_funding_index;
	struct bitcoin_blkid genesis_blockhash;
	struct channel_id channel_id;
	struct amount_sat both_amount;
	u32 funding_feerate_perkw;
	u32 locktime;
	struct pubkey splice_remote_pubkey;
	char *error;
	struct inflight *new_inflight;
	struct wally_psbt_output *new_chan_output;
	struct bitcoin_outpoint outpoint;
	struct amount_msat current_push_val;
	const enum tx_role our_role = TX_ACCEPTER;
	u8 *abort_msg;

	/* Can't start a splice with another splice still active */
	assert(!peer->splicing);
	peer->splicing = splicing_new(peer);

	ictx = new_interactivetx_context(tmpctx, our_role,
					 peer->pps, peer->channel_id);

	if (!fromwire_splice(inmsg,
			     &channel_id,
			     &genesis_blockhash,
			     &peer->splicing->opener_relative,
			     &funding_feerate_perkw,
			     &locktime,
			     &splice_remote_pubkey))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad wire_splice %s", tal_hex(tmpctx, inmsg));

	peer->splice_state->await_commitment_succcess = false;

	if (!is_stfu_active(peer))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Must be in STFU mode before intiating splice");

	if (!bitcoin_blkid_eq(&genesis_blockhash,
			      &chainparams->genesis_blockhash))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad splice blockhash");

	if (!channel_id_eq(&channel_id, &peer->channel_id))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Splice internal error: mismatched channelid");

	if (!pubkey_eq(&splice_remote_pubkey,
		       &peer->channel->funding_pubkey[REMOTE]))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Splice doesnt support changing pubkeys");

	if (funding_feerate_perkw < peer->feerate_min)
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Splice feerate_perkw is too low");

	/* TODO: Add plugin hook for user to adjust accepter amount */
	peer->splicing->accepter_relative = 0;

	msg = towire_splice_ack(NULL,
				&peer->channel_id,
				&chainparams->genesis_blockhash,
				peer->splicing->accepter_relative,
				&peer->channel->funding_pubkey[LOCAL]);

	peer->splicing->mode = true;

	peer_write(peer->pps, take(msg));

	/* Now we wait for the other side to go first.
	 *
	 * BOLT-0d8b701614b09c6ee4172b04da2203e73deec7e2 #2:
	 *   The receiver of `splice_ack`:
	 *    - MUST begin splice negotiation.
	 */
	ictx->next_update_fn = next_splice_step;
	ictx->desired_psbt = NULL;
	ictx->pause_when_complete = false;

	error = process_interactivetx_updates(tmpctx, ictx,
					      &peer->splicing->received_tx_complete,
					      &abort_msg);
	if (error)
		peer_failed_err(peer->pps, &peer->channel_id,
				"Interactive splicing error: %s", error);

	check_tx_abort(peer, abort_msg);

	assert(ictx->pause_when_complete == false);
	peer->splicing->sent_tx_complete = true;

	/* DTODO validate locktime */
	ictx->current_psbt->fallback_locktime = locktime;

	splice_funding_index = find_channel_funding_input(ictx->current_psbt,
							  &peer->channel->funding);

	new_chan_output = find_channel_output(peer, ictx->current_psbt,
					      &outpoint.n);

	both_amount = check_balances(peer, our_role, ictx->current_psbt,
				     outpoint.n, splice_funding_index);
	new_chan_output->amount = both_amount.satoshis; /* Raw: type conv */

	psbt_elements_normalize_fees(ictx->current_psbt);

	psbt_txid(tmpctx, ictx->current_psbt, &outpoint.txid, NULL);

	psbt_finalize(ictx->current_psbt);

	status_debug("Splice accepter adding inflight: %s",
		     fmt_wally_psbt(tmpctx, ictx->current_psbt));

	msg = towire_channeld_add_inflight(NULL,
					   &outpoint.txid,
					   outpoint.n,
					   funding_feerate_perkw,
					   both_amount,
					   peer->splicing->accepter_relative,
					   ictx->current_psbt,
					   false,
					   peer->splicing->force_sign_first);

	master_wait_sync_reply(tmpctx, peer, take(msg),
			       WIRE_CHANNELD_GOT_INFLIGHT);

	new_inflight = inflights_new(peer);

	psbt_txid(new_inflight, ictx->current_psbt,
		  &new_inflight->outpoint.txid, NULL);
	new_inflight->outpoint = outpoint;
	new_inflight->amnt = both_amount;
	new_inflight->psbt = tal_steal(new_inflight, ictx->current_psbt);
	new_inflight->splice_amnt = peer->splicing->accepter_relative;
	new_inflight->last_tx = NULL;
	new_inflight->i_am_initiator = false;
	new_inflight->force_sign_first = peer->splicing->force_sign_first;

	current_push_val = relative_splice_balance_fundee(peer, our_role,ictx->current_psbt,
					  outpoint.n, splice_funding_index);
	update_hsmd_with_splice(peer, new_inflight, our_role, current_push_val);

	update_view_from_inflights(peer);

	peer->splice_state->count++;

	resume_splice_negotiation(peer, true, true, true, true);
}

static struct bitcoin_tx *bitcoin_tx_from_txid(struct peer *peer,
					       struct bitcoin_txid txid)
{
	u8 *msg;
	struct bitcoin_tx *tx = NULL;

	msg = towire_channeld_splice_lookup_tx(NULL, &txid);

	msg = master_wait_sync_reply(tmpctx, peer, take(msg),
				     WIRE_CHANNELD_SPLICE_LOOKUP_TX_RESULT);

	if (!fromwire_channeld_splice_lookup_tx_result(tmpctx, msg, &tx))
		master_badmsg(WIRE_CHANNELD_SPLICE_LOOKUP_TX_RESULT, msg);

	return tx;
}

/* splice_initiator runs when splice_ack is received by the other side. It
 * handles the initial splice creation while callbacks will handle later
 * stages. */
static void splice_initiator(struct peer *peer, const u8 *inmsg)
{
	struct bitcoin_blkid genesis_blockhash;
	struct channel_id channel_id;
	struct pubkey splice_remote_pubkey;
	size_t input_index;
	const u8 *wit_script;
	u8 *outmsg;
	struct interactivetx_context *ictx;
	struct bitcoin_tx *prev_tx;
	u32 sequence = 0;
	u8 *scriptPubkey;
	char *error;
	u8 *abort_msg;

	ictx = new_interactivetx_context(tmpctx, TX_INITIATOR,
					 peer->pps, peer->channel_id);

	if (!fromwire_splice_ack(inmsg,
				 &channel_id,
				 &genesis_blockhash,
				 &peer->splicing->accepter_relative,
				 &splice_remote_pubkey))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad wire_splice_ack %s",
				 tal_hex(tmpctx, inmsg));

	if (!bitcoin_blkid_eq(&genesis_blockhash,
			      &chainparams->genesis_blockhash))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad splice[ACK] blockhash");

	if (!channel_id_eq(&channel_id, &peer->channel_id))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Splice[ACK] internal error: mismatched channelid");

	if (!pubkey_eq(&splice_remote_pubkey,
		       &peer->channel->funding_pubkey[REMOTE]))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Splice[ACK] doesnt support changing pubkeys");

	peer->splicing->received_tx_complete = false;
	peer->splicing->sent_tx_complete = false;
	peer->splice_state->locked_ready[LOCAL] = false;
	peer->splice_state->locked_ready[REMOTE] = false;

	ictx->next_update_fn = next_splice_step;
	ictx->pause_when_complete = true;
	ictx->desired_psbt = peer->splicing->current_psbt;

	/* We go first as the receiver of the ack.
	 *
	 * BOLT-0d8b701614b09c6ee4172b04da2203e73deec7e2 #2:
	 *   The receiver of `splice_ack`:
	 *    - MUST begin splice negotiation.
	 */
	BUILD_ASSERT(NUM_SIDES == 2);
	wit_script = bitcoin_redeem_2of2(tmpctx,
					 &peer->channel->funding_pubkey[LOCAL],
					 &peer->channel->funding_pubkey[REMOTE]);

	input_index = ictx->desired_psbt->num_inputs;

	/* First we spend the existing channel outpoint
	 *
	 * BOLT-0d8b701614b09c6ee4172b04da2203e73deec7e2 #2:
	 *   The initiator:
	 *     - MUST `tx_add_input` an input which spends the current funding
	 *       transaction output.
	 */
	psbt_append_input(ictx->desired_psbt, &peer->channel->funding, sequence,
			  NULL, wit_script, NULL);

	/* Segwit requires us to store the value of the outpoint being spent,
	 * so let's do that */
	scriptPubkey = scriptpubkey_p2wsh(ictx->desired_psbt, wit_script);
	psbt_input_set_wit_utxo(ictx->desired_psbt, input_index,
				scriptPubkey, peer->channel->funding_sats);

	/* We must loading the funding tx as our previous utxo */
	prev_tx = bitcoin_tx_from_txid(peer, peer->channel->funding.txid);
	psbt_input_set_utxo(ictx->desired_psbt, input_index, prev_tx->wtx);

	/* PSBT v2 requires this */
	psbt_input_set_outpoint(ictx->desired_psbt, input_index,
				peer->channel->funding);

	/* Next we add the new channel outpoint, with a 0 amount for now. It
	 * will be filled in later.
	 *
	 * BOLT-0d8b701614b09c6ee4172b04da2203e73deec7e2 #2:
	 *   The initiator:
	 *   ...
	 *     - MUST `tx_add_output` a zero-value output which pays to the two
	 *       funding keys using the higher of the two `generation` fields.
	 */
	psbt_append_output(ictx->desired_psbt,
			   scriptpubkey_p2wsh(ictx->desired_psbt, wit_script),
			   amount_sat(0));

	psbt_add_serials(ictx->desired_psbt, ictx->our_role);

	error = process_interactivetx_updates(tmpctx,
					      ictx,
					      &peer->splicing->received_tx_complete,
					      &abort_msg);

	if (error)
		peer_failed_warn(peer->pps, &peer->channel_id,
				"Interactive splicing_ack error: %s", error);

	check_tx_abort(peer, abort_msg);

	peer->splicing->tx_add_input_count = ictx->tx_add_input_count;
	peer->splicing->tx_add_output_count = ictx->tx_add_output_count;

	if (peer->splicing->current_psbt != ictx->current_psbt)
		tal_free(peer->splicing->current_psbt);
	peer->splicing->current_psbt = tal_steal(peer->splicing,
						 ictx->current_psbt);

	peer->splicing->mode = true;

	/* Return the current PSBT to the channel_control to give to user. */
	outmsg = towire_channeld_splice_confirmed_init(NULL,
						       ictx->current_psbt);
	wire_sync_write(MASTER_FD, take(outmsg));
}

/* This occurs when the user has marked they are done making changes to the
 * PSBT. Now we continually send `tx_complete` and intake our peer's changes
 * inside `process_interactivetx_updates`. Once they are onboard indicated
 * with their sending of `tx_complete` we clean up the final PSBT and return
 * to the user for their final signing steps. */
static void splice_initiator_user_finalized(struct peer *peer)
{
	u8 *outmsg;
	struct interactivetx_context *ictx;
	char *error;
	u32 chan_output_index, splice_funding_index;
	struct wally_psbt_output *new_chan_output;
	struct inflight *new_inflight;
	struct bitcoin_txid current_psbt_txid;
	struct amount_sat both_amount;
	struct commitsig *their_commit;
	struct amount_msat current_push_val;
	const enum tx_role our_role = TX_INITIATOR;
	u8 *abort_msg;

	ictx = new_interactivetx_context(tmpctx, our_role,
					 peer->pps, peer->channel_id);

	ictx->next_update_fn = next_splice_step;
	ictx->pause_when_complete = false;
	ictx->desired_psbt = ictx->current_psbt = peer->splicing->current_psbt;
	ictx->tx_add_input_count = peer->splicing->tx_add_input_count;
	ictx->tx_add_output_count = peer->splicing->tx_add_output_count;

	error = process_interactivetx_updates(tmpctx, ictx,
					      &peer->splicing->received_tx_complete,
					      &abort_msg);
	if (error)
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Splice interactivetx error: %s", error);

	check_tx_abort(peer, abort_msg);

	/* With pause_when_complete fase, this assert should never fail */
	assert(peer->splicing->received_tx_complete);
	peer->splicing->sent_tx_complete = true;

	psbt_sort_by_serial_id(ictx->current_psbt);

	new_chan_output = find_channel_output(peer, ictx->current_psbt,
					      &chan_output_index);

	splice_funding_index = find_channel_funding_input(ictx->current_psbt,
							  &peer->channel->funding);

	both_amount = check_balances(peer, our_role, ictx->current_psbt,
				     chan_output_index, splice_funding_index);
	new_chan_output->amount = both_amount.satoshis; /* Raw: type conv */

	psbt_elements_normalize_fees(ictx->current_psbt);

	status_debug("Splice adding inflight: %s",
		     fmt_wally_psbt(tmpctx, ictx->current_psbt));

	psbt_txid(tmpctx, ictx->current_psbt, &current_psbt_txid, NULL);

	outmsg = towire_channeld_add_inflight(tmpctx,
					      &current_psbt_txid,
					      chan_output_index,
					      peer->splicing->feerate_per_kw,
					      amount_sat(new_chan_output->amount),
					      peer->splicing->opener_relative,
					      ictx->current_psbt,
					      true,
					      peer->splicing->force_sign_first);

	master_wait_sync_reply(tmpctx, peer, take(outmsg),
			       WIRE_CHANNELD_GOT_INFLIGHT);

	new_inflight = inflights_new(peer);

	psbt_txid(tmpctx, ictx->current_psbt, &new_inflight->outpoint.txid, NULL);
	new_inflight->outpoint.n = chan_output_index;
	new_inflight->psbt = tal_steal(new_inflight, ictx->current_psbt);
	new_inflight->amnt = amount_sat(new_chan_output->amount);
	new_inflight->splice_amnt = peer->splicing->opener_relative;
	new_inflight->last_tx = NULL;
	new_inflight->i_am_initiator = true;
	new_inflight->force_sign_first = peer->splicing->force_sign_first;

	current_push_val = relative_splice_balance_fundee(peer, our_role, ictx->current_psbt,
					  chan_output_index, splice_funding_index);
	update_hsmd_with_splice(peer, new_inflight, our_role, current_push_val);

	update_view_from_inflights(peer);

	peer->splice_state->count++;

	their_commit = interactive_send_commitments(peer, ictx->current_psbt,
						    our_role,
						    last_inflight_index(peer),
						    true, true, NULL);

	new_inflight->last_tx = tal_steal(new_inflight, their_commit->tx);
	new_inflight->last_sig = their_commit->commit_signature;

	outmsg = towire_channeld_update_inflight(NULL, ictx->current_psbt,
						 their_commit->tx,
						 &their_commit->commit_signature);
	wire_sync_write(MASTER_FD, take(outmsg));

	if (peer->splicing->current_psbt != ictx->current_psbt)
		tal_free(peer->splicing->current_psbt);
	peer->splicing->current_psbt = tal_steal(peer->splicing, ictx->current_psbt);
	outmsg = towire_channeld_splice_confirmed_update(NULL,
							 ictx->current_psbt,
							 true);
	wire_sync_write(MASTER_FD, take(outmsg));
}

/* During a splice the user may call splice_update mulitple times adding
 * new details to the active PSBT. Each user call enters here: */
static void splice_initiator_user_update(struct peer *peer, const u8 *inmsg)
{
	u8 *outmsg, *msg, *abort_msg;
	struct interactivetx_context *ictx;
	char *error;

	if (!peer->splicing) {
		msg = towire_channeld_splice_state_error(NULL, "Can't accept a"
							 " splice PSBT update"
							 " because this channel"
							 " hasn't begun a"
							 " splice.");
		wire_sync_write(MASTER_FD, take(msg));
		return;
	}

	ictx = new_interactivetx_context(tmpctx, TX_INITIATOR,
					 peer->pps, peer->channel_id);

	if (!fromwire_channeld_splice_update(ictx, inmsg, &ictx->desired_psbt))
		master_badmsg(WIRE_CHANNELD_SPLICE_UPDATE, inmsg);

	if (!peer->splicing->mode) {
		msg = towire_channeld_splice_state_error(NULL, "Can't update a"
							 " splice when not in"
							 " splice mode.");
		wire_sync_write(MASTER_FD, take(msg));
		return;

	}

	ictx->next_update_fn = next_splice_step;
	ictx->pause_when_complete = true;

	/* Should already have a current_psbt from a previously initiated one */
	assert(peer->splicing->current_psbt);
	ictx->current_psbt = peer->splicing->current_psbt;
	ictx->tx_add_input_count = peer->splicing->tx_add_input_count;
	ictx->tx_add_output_count = peer->splicing->tx_add_output_count;

	/* User may not have setup serial numbers on their modifeid PSBT, so we
	 * ensure that for them here */
	psbt_add_serials(ictx->desired_psbt, ictx->our_role);

	/* If there no are no changes, we consider the splice 'user finalized' */
	if (!interactivetx_has_changes(ictx, ictx->desired_psbt)) {
		splice_initiator_user_finalized(peer);
		return;
	}

	error = process_interactivetx_updates(tmpctx, ictx,
					      &peer->splicing->received_tx_complete,
					      &abort_msg);
	if (error)
		peer_failed_warn(peer->pps, &peer->channel_id,
				"Splice update error: %s", error);

	check_tx_abort(peer, abort_msg);

	peer->splicing->tx_add_input_count = ictx->tx_add_input_count;
	peer->splicing->tx_add_output_count = ictx->tx_add_output_count;

	if (peer->splicing->current_psbt != ictx->current_psbt)
		tal_free(peer->splicing->current_psbt);
	peer->splicing->current_psbt = tal_steal(peer->splicing,
						 ictx->current_psbt);

	/* Peer may have modified our PSBT so we return it to the user here */
	outmsg = towire_channeld_splice_confirmed_update(NULL,
							 ictx->current_psbt,
							 false);
	wire_sync_write(MASTER_FD, take(outmsg));
}

/* This occurs when the user has signed the final version of the PSBT. At this
 * point we do a commitment transaction round with our peer via
 * `interactive_send_commitments`.
 *
 * Then we finalize the PSBT some more and sign away our funding output,
 * place that signature in the PSBT, and pass our signature to the peer and get
 * theirs back. */
static void splice_initiator_user_signed(struct peer *peer, const u8 *inmsg)
{
	struct wally_psbt *signed_psbt;
	struct bitcoin_txid current_psbt_txid, signed_psbt_txid;
	struct inflight *inflight;
	const u8 *msg, *outmsg;

	if (!peer->splicing) {
		msg = towire_channeld_splice_state_error(NULL, "Can't accept a"
							 " signed splice PSBT"
							 " because this channel"
							 " hasn't begun a"
							 " splice.");
		wire_sync_write(MASTER_FD, take(msg));
		return;
	}

	if (!fromwire_channeld_splice_signed(tmpctx, inmsg, &signed_psbt,
					     &peer->splicing->force_sign_first))
		master_badmsg(WIRE_CHANNELD_SPLICE_SIGNED, inmsg);

	if (!peer->splicing->mode) {
		msg = towire_channeld_splice_state_error(NULL, "Can't sign a"
							 " splice when not in"
							 " splice mode.");
		wire_sync_write(MASTER_FD, take(msg));
		return;
	}
	if (!peer->splicing->received_tx_complete) {
		msg = towire_channeld_splice_state_error(NULL, "Can't sign a"
							 " splice when we"
							 " haven't received"
							 " tx_complete yet.");
		wire_sync_write(MASTER_FD, take(msg));
		return;
	}
	if (!peer->splicing->sent_tx_complete) {
		msg = towire_channeld_splice_state_error(NULL, "Can't sign a"
							 " splice when we"
							 " haven't sent"
							 " tx_complete yet.");
		wire_sync_write(MASTER_FD, take(msg));
		return;
	}

	psbt_txid(tmpctx, peer->splicing->current_psbt, &current_psbt_txid, NULL);
	psbt_txid(tmpctx, signed_psbt, &signed_psbt_txid, NULL);

	if (!bitcoin_txid_eq(&signed_psbt_txid, &current_psbt_txid))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Signed PSBT txid %s does not match"
			      " current_psbt_txid %s",
			      fmt_bitcoin_txid(tmpctx, &signed_psbt_txid),
			      fmt_bitcoin_txid(tmpctx, &current_psbt_txid));

	peer->splicing->current_psbt = tal_free(peer->splicing->current_psbt);

	inflight = last_inflight(peer);
	inflight->psbt = tal_steal(inflight, signed_psbt);

	/* Save the user provided signatures to DB incase we have to
	 * restart and reestablish later. */
	outmsg = towire_channeld_update_inflight(NULL, inflight->psbt,
						 inflight->last_tx,
						 &inflight->last_sig);

	wire_sync_write(MASTER_FD, take(outmsg));

	resume_splice_negotiation(peer, false, false, true, true);
}

/* This occurs once our 'stfu' transition was successful. */
static void handle_splice_stfu_success(struct peer *peer)
{
	u8 *msg = towire_splice(tmpctx,
				&peer->channel_id,
				&chainparams->genesis_blockhash,
				peer->splicing->opener_relative,
				peer->splicing->feerate_per_kw,
				peer->splicing->current_psbt->fallback_locktime,
				&peer->channel->funding_pubkey[LOCAL]);
	peer->splice_state->await_commitment_succcess = false;
	peer_write(peer->pps, take(msg));
}

/* User has begun a splice with `splice_init` command. Here we request entry
 * into STFU mode, when we get it, send `splice` to our peer->
 * Later the peer will send `splice_ack` and the code that starts the actual
 * splice happens at that point in `splice_initiator()`. */
static void handle_splice_init(struct peer *peer, const u8 *inmsg)
{
	u8 *msg;

	/* Can't start a splice with another splice still active */
	if (peer->splicing) {
		msg = towire_channeld_splice_state_error(NULL, "Can't start two"
							 " splices on the same"
							 " channel at once.");
		wire_sync_write(MASTER_FD, take(msg));
		return;
	}

	peer->splicing = splicing_new(peer);

	if (!fromwire_channeld_splice_init(peer->splicing, inmsg,
					   &peer->splicing->current_psbt,
					   &peer->splicing->opener_relative,
					   &peer->splicing->feerate_per_kw,
					   &peer->splicing->force_feerate))
		master_badmsg(WIRE_CHANNELD_SPLICE_INIT, inmsg);

	if (peer->want_stfu) {
		msg = towire_channeld_splice_state_error(NULL, "Can't begin a"
							 " splice while waiting"
							 " for STFU.");
		wire_sync_write(MASTER_FD, take(msg));
		return;
	}
	if (is_stfu_active(peer)) {
		msg = towire_channeld_splice_state_error(NULL, "Can't begin a"
							 " splice while"
							 " currently in STFU");
		wire_sync_write(MASTER_FD, take(msg));
		return;
	}
	if (peer->splicing->mode) {
		msg = towire_channeld_splice_state_error(NULL, "Can't begin a"
							 " splice while already"
							 " doing a splice.");
		wire_sync_write(MASTER_FD, take(msg));
		return;
	}
	if (peer->splicing->feerate_per_kw < peer->feerate_min) {
		msg = towire_channeld_splice_state_error(NULL, tal_fmt(tmpctx,
							 "Feerate %u is too"
							 " low. Lower than"
							 " channel feerate_min"
							 " %u",
							 peer->splicing->feerate_per_kw,
							 peer->feerate_min));
		wire_sync_write(MASTER_FD, take(msg));
		return;
	}

	status_debug("Getting handle_splice_init psbt version %d", peer->splicing->current_psbt->version);

	peer->on_stfu_success = handle_splice_stfu_success;

	/* First things first we must STFU the channel */
	peer->stfu_initiator = LOCAL;
	peer->want_stfu = true;
	maybe_send_stfu(peer);
}

static void peer_in(struct peer *peer, const u8 *msg)
{
	enum peer_wire type = fromwire_peektype(msg);

	if (handle_peer_error_or_warning(peer->pps, msg))
		return;

	check_tx_abort(peer, msg);

	/* If we're in STFU mode and aren't waiting for a STFU mode
	 * specific message, the only valid message was tx_abort */
	if (is_stfu_active(peer) && !peer->stfu_wait_single_msg) {
		if (peer->splicing && type == WIRE_TX_SIGNATURES) {
			if (peer->splicing->tx_sig_msg)
				peer_failed_warn(peer->pps, &peer->channel_id,
						 "Received TX_SIGNATURES while"
						 " we already have one cached");
			peer->splicing->tx_sig_msg = tal_steal(peer->splicing,
							       msg);
			return;
		} else {
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "Received message %s when only TX_ABORT was"
					 " valid", peer_wire_name(type));
		}
	}

	/* Must get channel_ready before almost anything. */
	if (!peer->channel_ready[REMOTE]) {
		if (type != WIRE_CHANNEL_READY
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

	/* For cleaner errors, we check message is valid during STFU mode */
	if (peer->stfu_wait_single_msg)
		if (!VALID_STFU_MESSAGE(type))
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "Got invalid message during STFU "
					 "mode: %s",
					 peer_wire_name(type));

	peer->stfu_wait_single_msg = false;

	switch (type) {
	case WIRE_CHANNEL_READY:
		handle_peer_channel_ready(peer, msg);
		return;
	case WIRE_ANNOUNCEMENT_SIGNATURES:
		handle_peer_announcement_signatures(peer, msg);
		return;
	case WIRE_UPDATE_ADD_HTLC:
		handle_peer_add_htlc(peer, msg);
		return;
	case WIRE_COMMITMENT_SIGNED:
		handle_peer_commit_sig(peer, msg, 0, NULL, 0, 0,
				       peer->next_index[LOCAL],
				       &peer->next_local_per_commit, false);
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
	case WIRE_STFU:
		handle_stfu(peer, msg);
		return;
	case WIRE_SPLICE:
		splice_accepter(peer, msg);
		return;
	case WIRE_SPLICE_ACK:
		splice_initiator(peer, msg);
		return;
	case WIRE_SPLICE_LOCKED:
		handle_peer_splice_locked(peer, msg);
		return;
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
	case WIRE_TX_ABORT:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_TX_SIGNATURES:
		handle_unexpected_tx_sigs(peer, msg);
		return;
	case WIRE_TX_INIT_RBF:
	case WIRE_TX_ACK_RBF:
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
	case WIRE_ONION_MESSAGE:
	case WIRE_PEER_STORAGE:
	case WIRE_YOUR_PEER_STORAGE:
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
	u8 *msg;
	u8 **msgs = tal_arr(tmpctx, u8*, 1);
	struct local_anchor_info *local_anchor;

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
	if (last)
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
			struct tlv_update_add_htlc_tlvs *tlvs;
			if (h->blinding) {
				tlvs = tlv_update_add_htlc_tlvs_new(tmpctx);
				tlvs->blinding_point = tal_dup(tlvs, struct pubkey,
							       h->blinding);
			} else
				tlvs = NULL;
			msg = towire_update_add_htlc(NULL, &peer->channel_id,
						     h->id, h->amount,
						     &h->rhash,
						     abs_locktime_to_blocks(
							     &h->expiry),
						     h->routing, tlvs);
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

	msgs[0] = send_commit_part(msgs, peer, &peer->channel->funding,
				   peer->channel->funding_sats, NULL,
				   false, 0, 0, peer->next_index[REMOTE] - 1,
				   &peer->remote_per_commit,
				   &local_anchor);

	/* Loop over current inflights
	 * BOLT-0d8b701614b09c6ee4172b04da2203e73deec7e2 #2:
	 *
	 * A sending node:
	 *...
	 *   - MUST first send a `commitment_signed` for the active channel then immediately
	 *     send a `commitment_signed` for each splice awaiting confirmation, in increasing
	 *     feerate order.
	 */
	for (i = 0; i < tal_count(peer->splice_state->inflights); i++) {
		s64 funding_diff = sats_diff(peer->splice_state->inflights[i]->amnt,
					     peer->channel->funding_sats);
		s64 remote_splice_amnt = funding_diff
					- peer->splice_state->inflights[i]->splice_amnt;

		tal_arr_expand(&msgs,
			       send_commit_part(msgs, peer,
						&peer->splice_state->inflights[i]->outpoint,
						peer->splice_state->inflights[i]->amnt,
						NULL, false,
						peer->splice_state->inflights[i]->splice_amnt,
						remote_splice_amnt,
						peer->next_index[REMOTE] - 1,
						&peer->remote_per_commit,
						&local_anchor));
	}

	for(i = 0; i < tal_count(msgs); i++)
		peer_write(peer->pps, take(msgs[i]));

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
 *    - MUST ignore `my_current_per_commitment_point`, but MAY require it to be
 *      a valid point.
 *    - if `next_revocation_number` is greater than expected above, AND
 *    `your_last_per_commitment_secret` is correct for that
 *    `next_revocation_number` minus 1:
 *      - MUST NOT broadcast its commitment transaction.
 *      - SHOULD send an `error` to request the peer to fail the channel.
 */
static void check_future_dataloss_fields(struct peer *peer,
			u64 next_revocation_number,
			const struct secret *last_local_per_commit_secret)
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
	 * - SHOULD send an `error` to request the peer to fail the channel.
	 */
	wire_sync_write(MASTER_FD,
			take(towire_channeld_fail_fallen_behind(NULL)));

	sleep(1);
	/* We have to send them an error to trigger dropping to chain. */
	peer_failed_err(peer->pps, &peer->channel_id,
			"Awaiting unilateral close");
}

/* BOLT #2:
 *
 * A receiving node:
 * ...
 *  - if `your_last_per_commitment_secret` does not match the expected values:
 *     - SHOULD send an `error` and fail the channel.
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
		revoke_commitment(next_revocation_number - 1, &old_commit_secret, &unused);
	}

	if (!secret_eq_consttime(&old_commit_secret,
				 last_local_per_commit_secret))
		peer_failed_err(peer->pps,
				&peer->channel_id,
				"bad reestablish: your_last_per_commitment_secret %"PRIu64
				": %s should be %s",
				next_revocation_number,
				fmt_secret(tmpctx, last_local_per_commit_secret),
				fmt_secret(tmpctx, &old_commit_secret));

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
					 fmt_pubkey(tmpctx,
						    remote_current_per_commitment_point),
					 fmt_pubkey(tmpctx,
						    &peer->old_remote_per_commit),
					 fmt_pubkey(tmpctx,
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
					 fmt_pubkey(tmpctx,
						    remote_current_per_commitment_point),
					 fmt_pubkey(tmpctx,
						    &peer->remote_per_commit),
					 fmt_pubkey(tmpctx,
						    &peer->old_remote_per_commit));
		}
	}

	status_debug("option_data_loss_protect: fields are correct");
}

/* Older LND sometimes sends channel_ready before reestablish! */
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

static void peer_reconnect(struct peer *peer,
			   const struct secret *last_remote_per_commit_secret,
			   bool reestablish_only)
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
	struct inflight *inflight;
	struct bitcoin_txid *local_next_funding, *remote_next_funding;

	struct tlv_channel_reestablish_tlvs *send_tlvs, *recv_tlvs;

	dataloss_protect = feature_negotiated(peer->our_features,
					      peer->their_features,
					      OPT_DATA_LOSS_PROTECT);

	/* Both these options give us extra fields to check. */
	check_extra_fields
		= dataloss_protect || channel_has(peer->channel, OPT_STATIC_REMOTEKEY);

	/* Our current per-commitment point is the commitment point in the last
	 * received signed commitment */
	get_per_commitment_point(peer->next_index[LOCAL] - 1,
				 &my_current_per_commitment_point);

	send_tlvs = NULL;

	if (peer->experimental_upgrade) {
		/* Subtle: we free tmpctx below as we loop, so tal off peer */
		send_tlvs = tlv_channel_reestablish_tlvs_new(peer);

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
		if (peer->channel->opener == LOCAL) {
			send_tlvs->desired_channel_type =
				to_bytearr(send_tlvs,
					   take(channel_desired_type(NULL,
								     peer->channel)));
		} else {
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
	}

	inflight = last_inflight(peer);

	if (inflight && (!inflight->last_tx || !inflight->remote_tx_sigs)) {
		if (missing_user_signatures(peer, inflight)) {
			status_info("Unable to resume splice as user sigs are"
				    " missing.");
			inflight = NULL;
		} else {
			status_info("Reconnecting to peer with pending inflight"
				    " commit: %s, remote sigs: %s.",
				    inflight->last_tx ? "received" : "missing",
				    inflight->remote_tx_sigs ? "received" : "missing");

			if (!send_tlvs) {
				/* Subtle: we free tmpctx below as we loop, so
				 * tal off peer */
				send_tlvs = tlv_channel_reestablish_tlvs_new(peer);
			}
			send_tlvs->next_funding = &inflight->outpoint.txid;
		}
	}

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
	 *   - MUST set `my_current_per_commitment_point` to a valid point.
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
			 &peer->remote_per_commit, send_tlvs);
	} else {
		/* Older BOLT spec said for non-static-remotekey:
		 *
		 * - MUST set `my_current_per_commitment_point` to its
		 *   commitment point for the last signed commitment it
		 *   received from its channel peer (i.e. the commitment_point
		 *   corresponding to the commitment transaction the sender
		 *   would use to unilaterally close).
		 */
		msg = towire_channel_reestablish
			(NULL, &peer->channel_id,
			 peer->next_index[LOCAL],
			 peer->revocations_received,
			 last_remote_per_commit_secret,
			 &my_current_per_commitment_point,
			 send_tlvs);
	}

	peer_write(peer->pps, take(msg));

	peer_billboard(false, "Sent reestablish, waiting for theirs");

	/* Read until they say something interesting (don't forward
	 * gossip *to* them yet: we might try sending channel_update
	 * before we've reestablished channel). */
	do {
		clean_tmpctx();
		msg = peer_read(tmpctx, peer->pps);

		/* connectd promised us the msg was reestablish? */
		if (reestablish_only) {
			if (fromwire_peektype(msg) != WIRE_CHANNEL_REESTABLISH)
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "Expected reestablish, got: %s",
					      tal_hex(tmpctx, msg));
		}
	} while (handle_peer_error_or_warning(peer->pps, msg) ||
		 capture_premature_msg(&premature_msgs, msg));

	/* Initialize here in case we don't read it below! */
	recv_tlvs = tlv_channel_reestablish_tlvs_new(tmpctx);

	if (!fromwire_channel_reestablish(tmpctx, msg,
					  &channel_id,
					  &next_commitment_number,
					  &next_revocation_number,
					  &last_local_per_commitment_secret,
					  &remote_current_per_commitment_point,
					  &recv_tlvs)) {
		peer_failed_warn(peer->pps,
				 &peer->channel_id,
				 "bad reestablish msg: %s %s",
				 peer_wire_name(fromwire_peektype(msg)),
				 tal_hex(msg, msg));
	}

	if (!channel_id_eq(&channel_id, &peer->channel_id)) {
		peer_failed_err(peer->pps,
				&channel_id,
				"bad reestablish msg for unknown channel %s: %s",
				fmt_channel_id(tmpctx, &channel_id),
				tal_hex(msg, msg));
	}

	status_debug("Got reestablish commit=%"PRIu64" revoke=%"PRIu64
		     " inflights: %zu, active splices: %"PRIu32,
		     next_commitment_number,
		     next_revocation_number,
		     tal_count(peer->splice_state->inflights),
		     peer->splice_state->count);

	local_next_funding = (send_tlvs ? send_tlvs->next_funding : NULL);
	remote_next_funding = (recv_tlvs ? recv_tlvs->next_funding : NULL);

	status_debug("Splice resume check with local_next_funding: %s,"
		    " remote_next_funding: %s, inflights: %zu",
		    local_next_funding ? "sent" : "omitted",
		    remote_next_funding ? "received" : "empty",
		    tal_count(peer->splice_state->inflights));

	/* DTODO: Update splice BOLT spec PR and reference here. */
	if (inflight && (remote_next_funding || local_next_funding)) {
		if (!remote_next_funding) {
			status_info("Resuming splice negotation.");
			assume_stfu_mode(peer);
			resume_splice_negotiation(peer,
						  false,
						  true,
						  false,
						  true);
		} else if (bitcoin_txid_eq(remote_next_funding,
					   &inflight->outpoint.txid)) {
			/* Don't send sigs unless we have theirs */
			assert(local_next_funding || inflight->remote_tx_sigs);

			status_info("Resuming splice negotation");
			if (local_next_funding)
				assume_stfu_mode(peer);
			resume_splice_negotiation(peer,
						  true,
						  local_next_funding,
						  true,
						  local_next_funding);
		} else if (bitcoin_txid_eq(remote_next_funding,
					   &peer->channel->funding.txid)) {
			peer_failed_err(peer->pps,
					&peer->channel_id,
					"Invalid reestablish with next_funding"
					" txid %s that matches our current"
					" active funding txid %s. Should be %s"
					" or NULL",
					fmt_bitcoin_txid(tmpctx,
							 remote_next_funding),
					fmt_bitcoin_txid(tmpctx,
							 &peer->channel->funding.txid),
					fmt_bitcoin_txid(tmpctx,
							 &inflight->outpoint.txid));
		} else { /* remote_next_funding set but unrecognized */
			peer_failed_err(peer->pps,
					&peer->channel_id,
					"Invalid reestablish with unrecognized"
					" next_funding txid %s, should be %s",
					fmt_bitcoin_txid(tmpctx,
							 remote_next_funding),
					fmt_bitcoin_txid(tmpctx,
							 &inflight->outpoint.txid));
		}
	} else if (remote_next_funding) { /* No current inflight */
		if (bitcoin_txid_eq(remote_next_funding,
				    &peer->channel->funding.txid)) {
			status_info("We have no pending splice but peer"
				    " expects one; resending splice_lock");
			peer_write(peer->pps,
				   take(towire_splice_locked(NULL, &peer->channel_id)));
		}
		else {
			splice_abort(peer, "next_funding_txid not recognized."
					     " Sending tx_abort.");
		}
	}

	/* BOLT #2:
	 *
	 *   - if `next_commitment_number` is 1 in both the
	 *    `channel_reestablish` it sent and received:
	 *     - MUST retransmit `channel_ready`.
	 *   - otherwise:
	 *     - MUST NOT retransmit `channel_ready`, but MAY send
	 *       `channel_ready` with a different `short_channel_id`
	 *       `alias` field.
	 */
	if (peer->channel_ready[LOCAL]
	    && peer->next_index[LOCAL] == 1
	    && next_commitment_number == 1) {
		struct tlv_channel_ready_tlvs *tlvs = tlv_channel_ready_tlvs_new(tmpctx);

		tlvs->short_channel_id = &peer->local_alias;
		status_debug("Retransmitting channel_ready for channel %s",
		             fmt_channel_id(tmpctx, &peer->channel_id));
		/* Contains per commit point #1, for first post-opening commit */
		msg = towire_channel_ready(NULL,
					    &peer->channel_id,
					    &peer->next_local_per_commit, tlvs);
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
	 *      - SHOULD send an `error` and fail the channel.
	 *    - if it has not sent `revoke_and_ack`, AND
	 *      `next_revocation_number` is not equal to 0:
	 *      - SHOULD send an `error` and fail the channel.
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
		/* Send a warning here!  Because this is what it looks like if peer is
		 * in the past, and they might still recover.
		 *
		 * We don't disconnect: they might send an error, meaning
		 * we will force-close the channel for them.
		 */
		peer_failed_warn_nodisconnect(peer->pps,
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
					     &last_local_per_commitment_secret);
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
	 *       - SHOULD send an `error` and fail the channel.
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

	/* Now stop, we've been polite long enough. */
	if (reestablish_only) {
		/* We've reestablished! */
		wire_sync_write(MASTER_FD,
				take(towire_channeld_reestablished(NULL)));

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

	tal_free(send_tlvs);

	/* We've reestablished! */
	wire_sync_write(MASTER_FD, take(towire_channeld_reestablished(NULL)));

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
	struct tlv_channel_ready_tlvs *tlvs;
	struct pubkey point;
	bool splicing;
	struct bitcoin_txid txid;

	if (!fromwire_channeld_funding_depth(tmpctx,
					     msg,
					     &scid,
					     &depth,
					     &splicing,
					     &txid))
		master_badmsg(WIRE_CHANNELD_FUNDING_DEPTH, msg);

	/* Too late, we're shutting down! */
	if (peer->shutdown_sent[LOCAL])
		return;

	if (depth < peer->channel->minimum_depth) {
		peer->depth_togo = peer->channel->minimum_depth - depth;
	} else {
		peer->depth_togo = 0;

		/* For splicing we only update the short channel id on mutual
		 * splice lock */
		if (splicing) {
			peer->splice_state->short_channel_id = *scid;
			status_debug("Current channel id is %s, "
				     "splice_short_channel_id now set to %s",
				      fmt_short_channel_id(tmpctx,
							   peer->short_channel_ids[LOCAL]),
				      fmt_short_channel_id(tmpctx,
							   peer->splice_state->short_channel_id));
		} else {
			status_debug("handle_funding_depth: Setting short_channel_ids[LOCAL] to %s",
				fmt_short_channel_id(tmpctx,
						     (scid ? *scid : peer->local_alias)));
			/* If we know an actual short_channel_id prefer to use
			 * that, otherwise fill in the alias. From channeld's
			 * point of view switching from zeroconf to an actual
			 * funding scid is just a reorg. */
			if (scid)
				peer->short_channel_ids[LOCAL] = *scid;
			else
				peer->short_channel_ids[LOCAL] = peer->local_alias;
		}

		if (!peer->channel_ready[LOCAL]) {
			status_debug("channel_ready: sending commit index"
				     " %"PRIu64": %s",
				     peer->next_index[LOCAL],
				     fmt_pubkey(tmpctx,
						&peer->next_local_per_commit));
			tlvs = tlv_channel_ready_tlvs_new(tmpctx);
			tlvs->short_channel_id = &peer->local_alias;

			/* Need to retrieve the first point again, even if we
			 * moved on, as channel_ready explicitly includes the
			 * first one. */
			get_per_commitment_point(1, &point);

			msg = towire_channel_ready(NULL, &peer->channel_id,
						    &point, tlvs);
			peer_write(peer->pps, take(msg));

			peer->channel_ready[LOCAL] = true;
			check_mutual_channel_ready(peer);
		} else if(splicing && !peer->splice_state->locked_ready[LOCAL]) {
			assert(scid);

			msg = towire_splice_locked(NULL, &peer->channel_id);

			peer->splice_state->locked_txid = txid;

			peer_write(peer->pps, take(msg));

			peer->splice_state->locked_ready[LOCAL] = true;
			check_mutual_splice_locked(peer);
		}
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
	struct tlv_update_add_htlc_tlvs *tlvs;

	if (!peer->channel_ready[LOCAL] || !peer->channel_ready[REMOTE])
		status_failed(STATUS_FAIL_MASTER_IO,
			      "funding not locked for offer_htlc");

	if (!fromwire_channeld_offer_htlc(tmpctx, inmsg, &amount,
					 &cltv_expiry, &payment_hash,
					 onion_routing_packet, &blinding))
		master_badmsg(WIRE_CHANNELD_OFFER_HTLC, inmsg);

	if (blinding) {
		tlvs = tlv_update_add_htlc_tlvs_new(tmpctx);
		tlvs->blinding_point = tal_dup(tlvs, struct pubkey, blinding);
	} else
		tlvs = NULL;

	e = channel_add_htlc(peer->channel, LOCAL, peer->htlc_id,
			     amount, cltv_expiry, &payment_hash,
			     onion_routing_packet, take(blinding), NULL,
			     &htlc_fee, true);
	status_debug("Adding HTLC %"PRIu64" amount=%s cltv=%u gave %s",
		     peer->htlc_id,
		     fmt_amount_msat(tmpctx, amount),
		     cltv_expiry,
		     channel_add_err_name(e));

	switch (e) {
	case CHANNEL_ERR_ADD_OK:
		/* Tell the peer. */
		msg = towire_update_add_htlc(NULL, &peer->channel_id,
					     peer->htlc_id, amount,
					     &payment_hash, cltv_expiry,
					     onion_routing_packet, tlvs);
		peer_write(peer->pps, take(msg));
		start_commit_timer(peer);
		/* Tell the master. */
		msg = towire_channeld_offer_htlc_reply(NULL, peer->htlc_id,
						      0, "");
		wire_sync_write(MASTER_FD, take(msg));
		peer->htlc_id++;
		return;
	case CHANNEL_ERR_INVALID_EXPIRY:
		failwiremsg = towire_incorrect_cltv_expiry(inmsg, cltv_expiry, NULL);
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
		failwiremsg = towire_temporary_channel_failure(inmsg, NULL);
		failstr = tal_fmt(inmsg, "Capacity exceeded - HTLC fee: %s", fmt_amount_sat(inmsg, htlc_fee));
		goto failed;
	case CHANNEL_ERR_HTLC_BELOW_MINIMUM:
		failwiremsg = towire_amount_below_minimum(inmsg, amount, NULL);
		failstr = tal_fmt(inmsg, "HTLC too small (%s minimum)",
				  fmt_amount_msat(tmpctx,
						  peer->channel->config[REMOTE].htlc_minimum));
		goto failed;
	case CHANNEL_ERR_TOO_MANY_HTLCS:
		failwiremsg = towire_temporary_channel_failure(inmsg, NULL);
		failstr = "Too many HTLCs";
		goto failed;
	case CHANNEL_ERR_DUST_FAILURE:
		/* BOLT-919 #2:
		 * - upon an outgoing HTLC:
		 *   - if a HTLC's `amount_msat` is inferior the counterparty's...
		 *   - SHOULD NOT send this HTLC
		 *   - SHOULD fail this HTLC if it's forwarded
		 */
		failwiremsg = towire_temporary_channel_failure(inmsg, NULL);
		failstr = "HTLC too dusty, allowed dust limit reached";
		goto failed;
	}
	/* Shouldn't return anything else! */
	abort();

failed:
	/* lightningd appends update to this for us */
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
	u32 *final_index;
	struct ext_key *final_ext_key;
	u8 *local_shutdown_script;

	if (!fromwire_channeld_send_shutdown(peer, inmsg,
					     &final_index,
					     &final_ext_key,
					     &local_shutdown_script,
					     &peer->shutdown_wrong_funding))
		master_badmsg(WIRE_CHANNELD_SEND_SHUTDOWN, inmsg);

	tal_free(peer->final_index);
	peer->final_index = final_index;

	tal_free(peer->final_ext_key);
	peer->final_ext_key = final_ext_key;

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
	peer_write(peer->pps,
			  take(towire_errorfmt(NULL, &peer->channel_id,
					       "%s", reason)));

	wire_sync_write(MASTER_FD,
			take(towire_channeld_send_error_reply(NULL)));
	exit(0);
}

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

	memtable = memleak_start(tmpctx);
	memleak_ptr(memtable, msg);

	/* Now delete peer and things it has pointers to. */
	memleak_scan_obj(memtable, peer);

	found_leak = dump_memleak(memtable, memleak_status_broken, NULL);
	wire_sync_write(MASTER_FD,
			 take(towire_channeld_dev_memleak_reply(NULL,
							       found_leak)));
}

static void handle_dev_quiesce(struct peer *peer, const u8 *msg)
{
	if (!fromwire_channeld_dev_quiesce(msg))
		master_badmsg(WIRE_CHANNELD_DEV_QUIESCE, msg);

	/* Don't do this twice. */
	if (peer->want_stfu)
		status_failed(STATUS_FAIL_MASTER_IO, "dev_quiesce already");

	peer->want_stfu = true;
	peer->stfu_initiator = LOCAL;
	maybe_send_stfu(peer);
}

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
	case WIRE_CHANNELD_SEND_SHUTDOWN:
		handle_shutdown_cmd(peer, msg);
		return;
	case WIRE_CHANNELD_SEND_ERROR:
		handle_send_error(peer, msg);
		return;
	case WIRE_CHANNELD_SPLICE_INIT:
		handle_splice_init(peer, msg);
		return;
	case WIRE_CHANNELD_SPLICE_UPDATE:
		splice_initiator_user_update(peer, msg);
		return;
	case WIRE_CHANNELD_SPLICE_SIGNED:
		splice_initiator_user_signed(peer, msg);
		return;
	case WIRE_CHANNELD_SPLICE_CONFIRMED_INIT:
	case WIRE_CHANNELD_SPLICE_CONFIRMED_SIGNED:
	case WIRE_CHANNELD_SPLICE_SENDING_SIGS:
	case WIRE_CHANNELD_SPLICE_CONFIRMED_UPDATE:
	case WIRE_CHANNELD_SPLICE_LOOKUP_TX:
	case WIRE_CHANNELD_SPLICE_LOOKUP_TX_RESULT:
	case WIRE_CHANNELD_SPLICE_FEERATE_ERROR:
	case WIRE_CHANNELD_SPLICE_FUNDING_ERROR:
	case WIRE_CHANNELD_SPLICE_ABORT:
		check_tx_abort(peer, msg);
		break;
 	case WIRE_CHANNELD_DEV_REENABLE_COMMIT:
		if (peer->developer) {
			handle_dev_reenable_commit(peer);
			return;
		}
		break;
	case WIRE_CHANNELD_DEV_MEMLEAK:
		if (peer->developer) {
			handle_dev_memleak(peer, msg);
			return;
		}
		break;
	case WIRE_CHANNELD_DEV_QUIESCE:
		if (peer->developer) {
			handle_dev_quiesce(peer, msg);
			return;
		}
		break;
	case WIRE_CHANNELD_INIT:
	case WIRE_CHANNELD_OFFER_HTLC_REPLY:
	case WIRE_CHANNELD_SENDING_COMMITSIG:
	case WIRE_CHANNELD_GOT_COMMITSIG:
	case WIRE_CHANNELD_GOT_REVOKE:
	case WIRE_CHANNELD_SENDING_COMMITSIG_REPLY:
	case WIRE_CHANNELD_GOT_COMMITSIG_REPLY:
	case WIRE_CHANNELD_GOT_REVOKE_REPLY:
	case WIRE_CHANNELD_GOT_CHANNEL_READY:
	case WIRE_CHANNELD_GOT_SPLICE_LOCKED:
	case WIRE_CHANNELD_GOT_ANNOUNCEMENT:
	case WIRE_CHANNELD_GOT_SHUTDOWN:
	case WIRE_CHANNELD_SHUTDOWN_COMPLETE:
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT_REPLY:
	case WIRE_CHANNELD_FAIL_FALLEN_BEHIND:
	case WIRE_CHANNELD_DEV_MEMLEAK_REPLY:
	case WIRE_CHANNELD_SEND_ERROR_REPLY:
	case WIRE_CHANNELD_DEV_QUIESCE_REPLY:
	case WIRE_CHANNELD_UPGRADED:
	case WIRE_CHANNELD_ADD_INFLIGHT:
	case WIRE_CHANNELD_UPDATE_INFLIGHT:
	case WIRE_CHANNELD_GOT_INFLIGHT:
	case WIRE_CHANNELD_SPLICE_STATE_ERROR:
	case WIRE_CHANNELD_LOCAL_ANCHOR_INFO:
	case WIRE_CHANNELD_REESTABLISHED:
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
	u32 final_index;
	struct ext_key final_ext_key;
	u8 *fwd_msg;
	const u8 *msg;
	struct fee_states *fee_states;
	struct height_states *blockheight_states;
	u32 minimum_depth, lease_expiry;
	struct secret last_remote_per_commit_secret;
	struct penalty_base *pbases;
	bool reestablish_only;
	struct channel_type *channel_type;

	assert(!(fcntl(MASTER_FD, F_GETFL) & O_NONBLOCK));

	msg = wire_sync_read(tmpctx, MASTER_FD);
	if (!fromwire_channeld_init(peer, msg,
				    &chainparams,
				    &peer->our_features,
				    &peer->hsm_capabilities,
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
				    &local_msat,
				    &points[LOCAL],
				    &funding_pubkey[LOCAL],
				    &peer->commit_msec,
				    &peer->last_was_revoke,
				    &peer->last_sent_commit,
				    &peer->next_index[LOCAL],
				    &peer->next_index[REMOTE],
				    &peer->revocations_received,
				    &peer->htlc_id,
				    &htlcs,
				    &peer->channel_ready[LOCAL],
				    &peer->channel_ready[REMOTE],
				    &peer->short_channel_ids[LOCAL],
				    &reconnected,
				    &peer->send_shutdown,
				    &peer->shutdown_sent[REMOTE],
				    &final_index,
				    &final_ext_key,
				    &peer->final_scriptpubkey,
				    &peer->channel_flags,
				    &fwd_msg,
				    &last_remote_per_commit_secret,
				    &peer->their_features,
				    &peer->remote_upfront_shutdown_script,
				    &channel_type,
				    &peer->dev_disable_commit,
				    &pbases,
				    &reestablish_only,
				    &peer->experimental_upgrade,
				    &peer->splice_state->inflights,
				    &peer->local_alias,
				    &peer->my_alt_addr,
				    &peer->id)) {
		master_badmsg(WIRE_CHANNELD_INIT, msg);
	}

	peer->final_index = tal_dup(peer, u32, &final_index);
	peer->final_ext_key = tal_dup(peer, struct ext_key, &final_ext_key);
	peer->splice_state->count = tal_count(peer->splice_state->inflights);

	status_debug("option_static_remotekey = %u,"
		     " option_anchor_outputs = %u"
		     " option_anchors_zero_fee_htlc_tx = %u",
		     channel_type_has(channel_type, OPT_STATIC_REMOTEKEY),
		     channel_type_has(channel_type, OPT_ANCHOR_OUTPUTS_DEPRECATED),
		     channel_type_has(channel_type, OPT_ANCHORS_ZERO_FEE_HTLC_TX));

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
		     fmt_pubkey(tmpctx, &peer->remote_per_commit),
		     fmt_pubkey(tmpctx, &peer->old_remote_per_commit),
		     peer->next_index[LOCAL], peer->next_index[REMOTE],
		     peer->revocations_received,
		     fmt_fee_states(tmpctx, fee_states),
		     peer->feerate_min, peer->feerate_max,
		     fmt_height_states(tmpctx, blockheight_states),
		     peer->our_blockheight);

	/* First commit is used for opening: if we've sent 0, we're on
	 * index 1. */
	assert(peer->next_index[LOCAL] > 0);
	assert(peer->next_index[REMOTE] > 0);

	get_per_commitment_point(peer->next_index[LOCAL],
				 &peer->next_local_per_commit);

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

	update_view_from_inflights(peer);

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

	billboard_update(peer);
}

int main(int argc, char *argv[])
{
	setup_locale();

	int nfds;
	fd_set fds_in, fds_out;
	struct peer *peer;
	bool developer;

	developer = subdaemon_setup(argc, argv);

	status_setup_sync(MASTER_FD);

	peer = tal(NULL, struct peer);
	peer->developer = developer;
	timers_init(&peer->timers, time_mono());
	peer->commit_timer = NULL;
	peer->from_master = msg_queue_new(peer, true);
	peer->shutdown_sent[LOCAL] = false;
	peer->shutdown_wrong_funding = NULL;
	peer->last_update_timestamp = 0;
	peer->last_empty_commitment = 0;
	peer->want_stfu = false;
	peer->stfu_sent[LOCAL] = peer->stfu_sent[REMOTE] = false;
	peer->stfu_wait_single_msg = false;
	peer->on_stfu_success = NULL;
	peer->update_queue = msg_queue_new(peer, false);
	peer->splice_state = splice_state_new(peer);
	peer->splicing = NULL;

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
	sleep(1);
	return 0;
}
