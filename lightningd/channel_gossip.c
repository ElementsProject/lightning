#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <common/clock_time.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/wire_error.h>
#include <connectd/connectd_wiregen.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_gossip.h>
#include <lightningd/gossip_generation.h>
#include <lightningd/hsm_control.h>
#include <lightningd/lightningd.h>
#include <lightningd/subd.h>

enum channel_gossip_state {
	/* It's dead, so don't talk about it. */
	CGOSSIP_CHANNEL_DEAD,
	/* It's dying, but not announced */
	CGOSSIP_CHANNEL_UNANNOUNCED_DYING,
	/* It's dying, but we can still broadcast the "disabled" update. */
	CGOSSIP_CHANNEL_ANNOUNCED_DYING,
	/* It's dead: send the "disabled" update only as error reply. */
	CGOSSIP_CHANNEL_ANNOUNCED_DEAD,

	/* Unannounced channels: without alias or scid */
	CGOSSIP_PRIVATE_WAITING_FOR_USABLE,
	/* With alias/scid */
	CGOSSIP_PRIVATE,

	/* Public channels: */
	/* Not usable. */
	CGOSSIP_WAITING_FOR_USABLE,
	/* No scid (zeroconf can be in CHANNELD_NORMAL without scid) */
	CGOSSIP_WAITING_FOR_SCID,
	/* Sent ours, we want the peer's announcement_signatures (or
	 * we have it, but different scids) */
	CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS,
	/* Not yet in at announceable depth (6). */
	CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH,
	/* We have received sigs, and announced. */
	CGOSSIP_ANNOUNCED,
};

static const char *channel_gossip_state_str(enum channel_gossip_state s)
{
	switch (s) {
	case CGOSSIP_PRIVATE_WAITING_FOR_USABLE:
		return "CGOSSIP_PRIVATE_WAITING_FOR_USABLE";
	case CGOSSIP_PRIVATE:
		return "CGOSSIP_PRIVATE";
	case CGOSSIP_WAITING_FOR_USABLE:
		return "CGOSSIP_WAITING_FOR_USABLE";
	case CGOSSIP_WAITING_FOR_SCID:
		return "CGOSSIP_WAITING_FOR_SCID";
	case CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS:
		return "CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS";
	case CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH:
		return "CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH";
	case CGOSSIP_ANNOUNCED:
		return "CGOSSIP_ANNOUNCED";
	case CGOSSIP_CHANNEL_DEAD:
		return "CGOSSIP_CHANNEL_DEAD";
	case CGOSSIP_CHANNEL_UNANNOUNCED_DYING:
		return "CGOSSIP_CHANNEL_UNANNOUNCED_DYING";
	case CGOSSIP_CHANNEL_ANNOUNCED_DYING:
		return "CGOSSIP_CHANNEL_ANNOUNCED_DYING";
	case CGOSSIP_CHANNEL_ANNOUNCED_DEAD:
		return "CGOSSIP_CHANNEL_ANNOUNCED_DEAD";
	}
	return "***INVALID***";
}

struct state_transition {
	enum channel_gossip_state from, to;
	const char *description;
};

static struct state_transition allowed_transitions[] = {
	/* Private channels */
	{ CGOSSIP_PRIVATE_WAITING_FOR_USABLE, CGOSSIP_CHANNEL_DEAD,
	  "Unannounced channel closed before it had scid or alias" },
	{ CGOSSIP_PRIVATE_WAITING_FOR_USABLE, CGOSSIP_PRIVATE,
	  "Unannounced channel live" },
	{ CGOSSIP_PRIVATE, CGOSSIP_CHANNEL_DEAD,
	  "Unannounced channel closed" },

	/* Public channels, startup */
	{ CGOSSIP_WAITING_FOR_USABLE, CGOSSIP_CHANNEL_DEAD,
	  "Channel closed before it had scid or alias" },
	{ CGOSSIP_WAITING_FOR_USABLE, CGOSSIP_WAITING_FOR_SCID,
	  "Channel usable (zeroconf) but no scid yet" },
	{ CGOSSIP_WAITING_FOR_SCID, CGOSSIP_CHANNEL_DEAD,
	  "Zeroconf channel closed before funding tx mined" },
	{ CGOSSIP_WAITING_FOR_SCID, CGOSSIP_CHANNEL_UNANNOUNCED_DYING,
	  "Zeroconf channel closing mutually before funding tx" },
	{ CGOSSIP_WAITING_FOR_USABLE, CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS,
	  "Channel mined, but we haven't got matching announcment sigs from peer" },
	{ CGOSSIP_WAITING_FOR_USABLE, CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH,
	  "Channel mined, they had already sent announcement sigs when we noticed" },
	{ CGOSSIP_WAITING_FOR_SCID, CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH,
	  "Channel mined (zeroconf), they had already sent announcement sigs when we noticed" },
	{ CGOSSIP_WAITING_FOR_SCID, CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS,
	  "Channel mined (zeroconf), but we haven't got matching announcment sigs from peer" },
	{ CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS, CGOSSIP_CHANNEL_UNANNOUNCED_DYING,
	  "Channel closing while waiting for announcement sigs from peer" },
	{ CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS, CGOSSIP_CHANNEL_DEAD,
	  "Channel closed while waiting for announcement sigs from peer" },
	{ CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS, CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH,
	  "Channel now waiting for 6 confirms to publish announcement" },
	{ CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH, CGOSSIP_CHANNEL_DEAD,
	  "Channel closed before 6 confirms" },
	{ CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH, CGOSSIP_CHANNEL_UNANNOUNCED_DYING,
	  "Channel closing before 6 confirms" },
	{ CGOSSIP_CHANNEL_UNANNOUNCED_DYING, CGOSSIP_CHANNEL_DEAD,
	  "Unannounced channel closed onchain." },
	{ CGOSSIP_CHANNEL_UNANNOUNCED_DYING, CGOSSIP_CHANNEL_ANNOUNCED_DYING,
	  "Unannounced closing channel reached announce depth." },
	{ CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH, CGOSSIP_ANNOUNCED,
	  "Channel fully announced" },
	{ CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS, CGOSSIP_ANNOUNCED,
	  "Got peer announcement signatures after already at 6 confirmations" },
	{ CGOSSIP_WAITING_FOR_USABLE, CGOSSIP_CHANNEL_UNANNOUNCED_DYING,
	  "Closed while waiting for first confirmation" },
	{ CGOSSIP_WAITING_FOR_USABLE, CGOSSIP_ANNOUNCED,
	  "We got peer sigs first, then 6 confirms, then finally received CHANNEL_READY" },

	/* Splice */
	{ CGOSSIP_ANNOUNCED, CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS,
	  "Splicing"},
	{ CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH, CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS,
	  "Splicing before 6 confirmations"},

	/* Public channels, closing */
	{ CGOSSIP_ANNOUNCED, CGOSSIP_CHANNEL_ANNOUNCED_DYING,
	  "Announced channel closing, but close tx not seen onchain yet." },
	{ CGOSSIP_ANNOUNCED, CGOSSIP_CHANNEL_ANNOUNCED_DEAD,
	  "Announced channel closed by seeing onchain tx." },
	{ CGOSSIP_CHANNEL_ANNOUNCED_DYING, CGOSSIP_CHANNEL_ANNOUNCED_DEAD,
	  "Announced channel closed onchain." },
	{ CGOSSIP_CHANNEL_DEAD, CGOSSIP_CHANNEL_ANNOUNCED_DEAD,
	  "Channel closed before 6 confirms, but now has 6 confirms so could be announced." },
	{ CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH, CGOSSIP_CHANNEL_ANNOUNCED_DYING,
	  "Channel hit announced depth, but closed" },
};

static void check_state_transition(const struct channel *channel,
				   enum channel_gossip_state oldstate,
				   enum channel_gossip_state newstate)
{
	/* Check transition */
	for (size_t i = 0; i < ARRAY_SIZE(allowed_transitions); i++) {
		if (allowed_transitions[i].from == oldstate
		    && allowed_transitions[i].to == newstate) {
			log_debug(channel->log, "gossip state: %s->%s (%s)",
				  channel_gossip_state_str(oldstate),
				  channel_gossip_state_str(newstate),
				  allowed_transitions[i].description);
			return;
		}
	}

	log_broken(channel->log, "Illegal gossip state transition: %s->%s",
		   channel_gossip_state_str(oldstate),
		   channel_gossip_state_str(newstate));
}

struct remote_announce_sigs {
	struct short_channel_id scid;
	secp256k1_ecdsa_signature node_sig;
	secp256k1_ecdsa_signature bitcoin_sig;
};

struct channel_gossip {
	enum channel_gossip_state state;

	/* Cached update info */
	const u8 *cupdate;

	/* Remote channel_announcement sigs we've received (but not
	 * necessarily committed!) */
	struct remote_announce_sigs *remote_sigs;

	/* Timer to refresh public channels every 13 days */
	struct oneshot *refresh_timer;

	/* Details of latest channel_update sent by peer */
	const struct peer_update *peer_update;

	/* To avoid a storm, we only respond to announcement_signatures with
	 * our own signatures once */
	bool sent_sigs;
};

static bool starting_up = true, gossipd_init_done = false;

static bool is_private(const struct channel *channel)
{
	return !(channel->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL);
}

static bool is_usable(const struct channel *channel)
{
	if (channel_state_pre_open(channel->state))
		return false;
	/* Can't send if we can't talk about it. */
	return channel->scid != NULL || channel->alias[REMOTE] != NULL;
}

static bool has_scid(const struct channel *channel)
{
	if (!is_usable(channel))
		return false;
	return channel->scid != NULL;
}

static bool has_matching_peer_sigs(const struct channel *channel)
{
	const struct channel_gossip *cg = channel->channel_gossip;

	if (!has_scid(channel))
		return false;

	if (!cg->remote_sigs)
		return false;

	return short_channel_id_eq(cg->remote_sigs->scid, *channel->scid);
}

static bool has_announce_depth(const struct channel *channel)
{
	u32 block_height = get_block_height(channel->peer->ld->topology);

	if (!has_matching_peer_sigs(channel))
		return false;

	return is_scid_depth_announceable(*channel->scid, block_height);
}

/* Truly dead once we've seen spend onchain */
static bool is_dead(const struct channel *channel)
{
	return channel_state_funding_spent_onchain(channel->state);
}

static bool is_unannounced_dying(const struct channel *channel)
{
	return !is_private(channel)
		&& channel_state_closing(channel->state)
		&& !has_announce_depth(channel)
		&& !channel_state_funding_spent_onchain(channel->state);
}

static bool is_announced_dying(const struct channel *channel)
{
	return !is_private(channel)
		&& has_announce_depth(channel)
		&& channel_state_closing(channel->state)
		&& !channel_state_funding_spent_onchain(channel->state);
}

static bool is_announced_dead(const struct channel *channel)
{
	return !is_private(channel)
		&& has_announce_depth(channel)
		&& channel_state_funding_spent_onchain(channel->state);
}

static void check_channel_gossip(const struct channel *channel)
{
	struct channel_gossip *cg = channel->channel_gossip;
	bool enabled;

	/* Note: we can't assert is_scid_depth_announceable, for two reasons:
	 * 1. on restar_t and rescan, block numbers can go backwards.'
	 * 2. We don't get notified via channel_gossip_notify_new_block until
	 *    there are no new blocks to add, not on every block.
	 */
	switch (cg->state) {
	case CGOSSIP_PRIVATE_WAITING_FOR_USABLE:
		assert(is_private(channel));
		assert(!is_dead(channel));
		assert(!is_usable(channel));
		assert(!cg->remote_sigs);
		assert(!cg->refresh_timer);
		return;
	case CGOSSIP_PRIVATE:
		assert(is_private(channel));
		assert(!is_dead(channel));
		assert(is_usable(channel));
		assert(!cg->remote_sigs);
		assert(!cg->refresh_timer);
		return;
	case CGOSSIP_WAITING_FOR_USABLE:
		assert(!is_private(channel));
		assert(!is_dead(channel));
		assert(!is_usable(channel));
		assert(!cg->refresh_timer);
		return;
	case CGOSSIP_WAITING_FOR_SCID:
		assert(!is_private(channel));
		assert(!is_dead(channel));
		assert(!has_scid(channel));
		assert(!cg->refresh_timer);
		return;
	case CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS:
		assert(has_scid(channel));
		assert(!is_private(channel));
		assert(!is_dead(channel));
		assert(!has_matching_peer_sigs(channel));
		assert(!cg->refresh_timer);
		return;
	case CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH:
		assert(!is_private(channel));
		assert(!is_dead(channel));
		/* We can't actually know !has_announce_depth: current
		 * block height may not have been updated to match! */
		assert(!cg->refresh_timer);
		return;
	case CGOSSIP_ANNOUNCED:
		assert(!is_private(channel));
		assert(!is_dead(channel));
		/* We can't actually know !has_announce_depth: current
		 * block height may not have been updated to match! */
		/* refresh_timer is not always set at init */
		return;
	case CGOSSIP_CHANNEL_UNANNOUNCED_DYING:
		assert(!is_dead(channel));
		assert(!has_announce_depth(channel));
		assert(!cg->refresh_timer);
		return;
	case CGOSSIP_CHANNEL_ANNOUNCED_DYING:
		assert(!is_dead(channel));
		assert(has_announce_depth(channel));
		/* We may not have a cupdate in some odd cases, e.g. reorg */
		if (cg->cupdate) {
			assert(channel_update_details(cg->cupdate, NULL,
						      &enabled));
			assert(!enabled);
		}
		assert(!cg->refresh_timer);
		return;
	case CGOSSIP_CHANNEL_ANNOUNCED_DEAD:
		assert(is_dead(channel));
		assert(is_announced_dead(channel));
		/* We may not have a cupdate in some odd cases, e.g. reorg */
		if (cg->cupdate) {
			assert(channel_update_details(cg->cupdate, NULL,
						      &enabled));
			assert(!enabled);
		}
		assert(!cg->refresh_timer);
		return;
	case CGOSSIP_CHANNEL_DEAD:
		assert(is_dead(channel));
		assert(!is_announced_dying(channel));
		assert(!cg->cupdate);
		assert(!cg->refresh_timer);
		return;
	}
	fatal("Bad channel_gossip_state %u", cg->state);
}

static void msg_to_peer(const struct peer *peer, const u8 *msg TAKES)
{
	struct lightningd *ld = peer->ld;

	/* Shutting down, or peer not connected? */
	if (ld->connectd && peer->connected == PEER_CONNECTED) {
		subd_send_msg(ld->connectd,
			      take(towire_connectd_peer_send_msg(NULL,
								 &peer->id,
								 peer->connectd_counter,
								 msg)));
	}

	if (taken(msg))
		tal_free(msg);
}

static void addgossip_reply(struct subd *gossipd,
			    const u8 *reply,
			    const int *fds UNUSED,
			    char *desc)
{
	char *err;

	if (!fromwire_gossipd_addgossip_reply(reply, reply, &err))
		fatal("Reading gossipd_addgossip_reply for %s: %s",
		      desc, tal_hex(tmpctx, reply));

	if (strlen(err))
		log_broken(gossipd->log, "gossipd rejected our %s: %s", desc, err);
}

static void broadcast_new_gossip(struct lightningd *ld,
				 const u8 *msg TAKES,
				 struct amount_sat *known_channel,
				 const char *desc)
{
	struct peer *peer;
	struct peer_node_id_map_iter it;

	if (taken(msg))
		tal_steal(tmpctx, msg);

	/* Don't crash if shutting down */
	if (!ld->gossip)
		return;

	/* Tell gossipd about it */
	subd_req(ld->gossip, ld->gossip,
		 take(towire_gossipd_addgossip(NULL, msg, known_channel)),
		 -1, 0, addgossip_reply, cast_const(char *, desc));

	/* Don't tell them if we're supposed to be suppressing gossip for tests */
	if (ld->dev_suppress_gossip)
		return;

	/* Tell all our peers about it, too! */
	for (peer = peer_node_id_map_first(ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(ld->peers, &it)) {
		msg_to_peer(peer, msg);
	}
}

/* Recursion */
static void cupdate_timer_refresh(struct channel *channel);

static enum channel_gossip_state derive_channel_state(const struct channel *channel)
{
	if (is_unannounced_dying(channel))
		return CGOSSIP_CHANNEL_UNANNOUNCED_DYING;

	if (is_announced_dying(channel))
		return CGOSSIP_CHANNEL_ANNOUNCED_DYING;

	if (is_announced_dead(channel))
		return CGOSSIP_CHANNEL_ANNOUNCED_DEAD;

	if (is_dead(channel))
		return CGOSSIP_CHANNEL_DEAD;

	if (is_private(channel)) {
		if (!is_usable(channel))
			return CGOSSIP_PRIVATE_WAITING_FOR_USABLE;
		return CGOSSIP_PRIVATE;
	}

	if (!is_usable(channel))
		return CGOSSIP_WAITING_FOR_USABLE;

	if (!has_scid(channel))
		return CGOSSIP_WAITING_FOR_SCID;

	if (!has_matching_peer_sigs(channel))
		return CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS;

	if (!has_announce_depth(channel))
		return CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH;

	return CGOSSIP_ANNOUNCED;
}

static u8 *sign_update(const tal_t *ctx,
		       struct lightningd *ld,
		       const u8 *unsigned_cupdate)
{
	const u8 *msg;
	u8 *signed_update;

	/* Sign it please! */
	msg = hsm_sync_req(tmpctx, ld,
			   take(towire_hsmd_cupdate_sig_req(NULL, unsigned_cupdate)));

	if (!fromwire_hsmd_cupdate_sig_reply(ctx, msg, &signed_update))
		fatal("Reading cupdate_sig_reply: %s", tal_hex(tmpctx, msg));
	return signed_update;
}

/* Try to send a channel_update direct to peer, unless redundant */
static void send_private_cupdate(struct channel *channel, bool even_if_redundant)
{
	struct channel_gossip *cg = channel->channel_gossip;
	const u8 *cupdate;
	struct short_channel_id scid;

	/* BOLT #7:
	 *
	 * - MAY create a `channel_update` to communicate the channel
	 *   parameters to the channel peer, even though the channel has not
	 *   yet been announced (i.e. the `announce_channel` bit was not set
	 *   or the `channel_update` is sent before the peers exchanged
	 *   [announcement signatures](#the-announcement_signatures-message)).
	 *    - MUST set the `short_channel_id` to either an `alias` it has
	 *    received from the peer, or the real channel `short_channel_id`.
	 *    - MUST set `dont_forward` to 1 in `message_flags`
	 */
	/* We prefer their alias, if possible: they might not have seen the block which
	 * mined the funding tx yet, so the scid would be meaningless to them. */
	if (channel->alias[REMOTE])
		scid = *channel->alias[REMOTE];
	else
		scid = *channel->scid;

	/* We always set "enabled" on unannounced channels, since if peer
	 * receives it, that's what it means */
	cupdate = unsigned_channel_update(tmpctx, channel, scid,
					  NULL, false, true);

	/* Suppress redundant ones (except on reconnect, in case it's
	 * lost) */
	if (cg->cupdate) {
		if (!even_if_redundant
		    && channel_update_same(cg->cupdate, cupdate)) {
			return;
		}
		tal_free(cg->cupdate);
	}

	cg->cupdate = sign_update(cg, channel->peer->ld, cupdate);
	msg_to_peer(channel->peer, cg->cupdate);
}

/* Sets channel->channel_gossip->cupdate.  Returns true if it changed. */
static bool update_channel_update(const struct channel *channel,
				  bool enable)
{
	struct channel_gossip *cg = channel->channel_gossip;
	const u8 *cupdate;
	u32 old_timestamp;
	bool have_old;

	/* If we have no previous channel_update, this fails */
	have_old = channel_update_details(cg->cupdate, &old_timestamp, NULL);
	cupdate = unsigned_channel_update(tmpctx, channel, *channel->scid,
					  have_old ? &old_timestamp : NULL,
					  true,
					  enable);

	/* Suppress redundant ones */
	if (cg->cupdate && channel_update_same(cg->cupdate, cupdate))
		return false;

	tal_free(cg->cupdate);
	cg->cupdate = sign_update(cg, channel->peer->ld, cupdate);
	return true;
}

/* Using default logic, should this channel be enabled? */
static bool channel_should_enable(const struct channel *channel,
				  bool ok_if_disconnected)
{
	bool enable, have_old;

	/* If we have no previous channel_update, this fails */
	have_old = channel_update_details(channel->channel_gossip->cupdate,
					  NULL, &enable);

	if (!channel_state_can_add_htlc(channel->state)) {
		/* If it's (no longer) usable, it's a simply courtesy
		 * to disable */
		return false;
	} else if (channel->owner) {
		/* If it's live, it's enabled */
		return true;
	} else if (starting_up) {
		/* If we are starting up, don't change it! */
		if (!have_old)
			/* Assume the best if we don't have an updated */
			enable = true;
		return enable;
	} else {
		return ok_if_disconnected;
	}
}

/* Based on existing update, schedule next refresh */
static void arm_refresh_timer(struct channel *channel)
{
	struct lightningd *ld = channel->peer->ld;
	struct channel_gossip *cg = channel->channel_gossip;
	struct timeabs now = clock_time(), due;
	u32 timestamp;

	if (!channel_update_details(cg->cupdate, &timestamp, NULL)) {
		log_broken(channel->log, "Missing channel_update for refresh?");
		return;
	}
	due.ts.tv_sec = timestamp;
	due.ts.tv_nsec = 0;

	due = timeabs_add(due,
			  time_from_sec(GOSSIP_PRUNE_INTERVAL(ld->dev_fast_gossip_prune)
					- GOSSIP_BEFORE_DEADLINE(ld->dev_fast_gossip_prune)));

	/* In case it's passed, timer should be zero */
	if (time_after(now, due))
		due = now;

	cg->refresh_timer = new_reltimer(ld->timers, cg,
					 time_between(due, now),
					 cupdate_timer_refresh,
					 channel);
}

static void cupdate_timer_refresh(struct channel *channel)
{
	struct lightningd *ld = channel->peer->ld;
	struct channel_gossip *cg = channel->channel_gossip;

	/* Don't try to free this again if set_public_cupdate called later */
	cg->refresh_timer = NULL;

	log_debug(channel->log, "Sending keepalive channel_update for %s",
		  fmt_short_channel_id(tmpctx, *channel->scid));

	/* Free old cupdate to force a new one to be generated */
	cg->cupdate = tal_free(cg->cupdate);
	update_channel_update(channel, channel_should_enable(channel, true));

	broadcast_new_gossip(ld, cg->cupdate, NULL, "channel update");
	arm_refresh_timer(channel);
}

static void stash_remote_announce_sigs(struct channel *channel,
				       struct short_channel_id scid,
				       const secp256k1_ecdsa_signature *node_sig,
				       const secp256k1_ecdsa_signature *bitcoin_sig)
{
	struct channel_gossip *cg = channel->channel_gossip;
	const char *err;

	/* BOLT #7:
	 * - If the `node_signature` OR the `bitcoin_signature` is NOT correct:
	 *   - MAY send a `warning` and close the connection, or send an
         *     `error` and fail the channel.
	 */
	err = check_announce_sigs(channel, scid, node_sig, bitcoin_sig);
	if (err) {
		channel_fail_transient(channel, true,
				       "Bad gossip announcement_signatures for scid %s: %s",
				       fmt_short_channel_id(tmpctx, scid),
				       err);
		return;
	}

	tal_free(cg->remote_sigs);
	cg->remote_sigs = tal(cg, struct remote_announce_sigs);
	cg->remote_sigs->scid = scid;
	cg->remote_sigs->node_sig = *node_sig;
	cg->remote_sigs->bitcoin_sig = *bitcoin_sig;
	log_debug(channel->log,
		  "channel_gossip: received announcement sigs for %s (we have %s)",
		  fmt_short_channel_id(tmpctx, scid),
		  channel->scid ? fmt_short_channel_id(tmpctx, *channel->scid) : "none");

	/* Save to db if we like these signatures */
	if (!channel->scid)
		return;

	if (!short_channel_id_eq(cg->remote_sigs->scid, *channel->scid)) {
		log_debug(channel->log, "We have remote sigs, but wrong scid!");
		return;
	}

	wallet_announcement_save(channel->peer->ld->wallet,
				 channel->dbid,
				 &cg->remote_sigs->node_sig,
				 &cg->remote_sigs->bitcoin_sig);
}

/* BOLT #7:
 * A node:
 * - If the `open_channel` message has the `announce_channel` bit set AND a
 *   `shutdown` message has not been sent:
 *    - After `channel_ready` has been sent and received AND the funding
 *       transaction has enough confirmations to ensure that it won't be
 *       reorganized:
 *       - MUST send `announcement_signatures` for the funding transaction.
 * - Otherwise:
 *   - MUST NOT send the `announcement_signatures` message.
 */

static void send_channel_announce_sigs(struct channel *channel)
{
	/* First 2 + 256 byte are the signatures and msg type, skip them */
	const size_t offset = 258;
	struct lightningd *ld = channel->peer->ld;
	struct sha256_double hash;
	secp256k1_ecdsa_signature local_node_sig, local_bitcoin_sig;
	struct channel_gossip *cg = channel->channel_gossip;
	const u8 *ca, *msg;

	/* Wait until we've exchanged reestablish messages */
	if (!channel->reestablished) {
		log_debug(channel->log, "channel_gossip: not sending channel_announcement_sigs until reestablished");
		return;
	}

	if (cg->sent_sigs)
		return;

	ca = create_channel_announcement(tmpctx, channel, *channel->scid,
					 NULL, NULL, NULL, NULL);

	msg = hsm_sync_req(tmpctx, ld,
			   take(towire_hsmd_sign_any_cannouncement_req(NULL,
								       ca,
								       &channel->peer->id,
								       channel->dbid)));
	if (!fromwire_hsmd_sign_any_cannouncement_reply(msg, &local_node_sig, &local_bitcoin_sig))
		fatal("Reading hsmd_sign_any_cannouncement_reply: %s", tal_hex(tmpctx, msg));

	/* Double-check that HSM gave valid signatures. */
	sha256_double(&hash, ca + offset, tal_count(ca) - offset);
	if (!check_signed_hash(&hash, &local_node_sig, &ld->our_pubkey)) {
		channel_internal_error(channel,
				       "HSM returned an invalid node signature");
		return;
	}

	if (!check_signed_hash(&hash, &local_bitcoin_sig, &channel->local_funding_pubkey)) {
		channel_internal_error(channel,
				       "HSM returned an invalid bitcoin signature");
		return;
	}

	msg = towire_announcement_signatures(NULL,
					     &channel->cid, *channel->scid,
					     &local_node_sig, &local_bitcoin_sig);
	msg_to_peer(channel->peer, take(msg));
	cg->sent_sigs = true;
}

/* Sends channel_announcement */
static void send_channel_announcement(struct channel *channel)
{
	secp256k1_ecdsa_signature local_node_sig, local_bitcoin_sig;
	struct lightningd *ld = channel->peer->ld;
	const u8 *ca, *msg;
	struct channel_gossip *cg = channel->channel_gossip;

 	ca = create_channel_announcement(tmpctx, channel, *channel->scid,
					 NULL, NULL,
					 &cg->remote_sigs->node_sig,
					 &cg->remote_sigs->bitcoin_sig);

	msg = hsm_sync_req(tmpctx, ld,
			   take(towire_hsmd_sign_any_cannouncement_req(NULL, ca,
								       &channel->peer->id,
								       channel->dbid)));
	if (!fromwire_hsmd_sign_any_cannouncement_reply(msg,
							&local_node_sig,
							&local_bitcoin_sig))
		fatal("Reading hsmd_sign_any_cannouncement_reply: %s", tal_hex(tmpctx, msg));

	ca = create_channel_announcement(tmpctx, channel, *channel->scid,
					 &local_node_sig,
					 &local_bitcoin_sig,
					 &cg->remote_sigs->node_sig,
					 &cg->remote_sigs->bitcoin_sig);

	/* Send everyone our new channel announcement */
	broadcast_new_gossip(ld, ca, &channel->funding_sats, "channel announcement");
}

static void set_gossip_state(struct channel *channel,
			     enum channel_gossip_state state)
{
	struct channel_gossip *cg = channel->channel_gossip;

	check_state_transition(channel, cg->state, state);

	/* Steps as we leave old state */
	switch (cg->state) {
	case CGOSSIP_PRIVATE_WAITING_FOR_USABLE:
	case CGOSSIP_WAITING_FOR_USABLE:
	case CGOSSIP_PRIVATE:
	case CGOSSIP_WAITING_FOR_SCID:
	case CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS:
	case CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH:
	case CGOSSIP_CHANNEL_ANNOUNCED_DYING:
	case CGOSSIP_CHANNEL_UNANNOUNCED_DYING:
		break;
	case CGOSSIP_ANNOUNCED:
		/* Stop refreshing (if we were) */
		cg->refresh_timer = tal_free(cg->refresh_timer);
		break;

	/* We should never leave these */
	case CGOSSIP_CHANNEL_ANNOUNCED_DEAD:
	case CGOSSIP_CHANNEL_DEAD:
		break;
	}

	cg->state = state;

	/* Now the state we're entering */
	switch (cg->state) {
	/* These are initial states, never set */
	case CGOSSIP_PRIVATE_WAITING_FOR_USABLE:
	case CGOSSIP_WAITING_FOR_USABLE:
		abort();

	/* We don't do anything when we first enter these states */
	case CGOSSIP_PRIVATE:
	case CGOSSIP_WAITING_FOR_SCID:
		return;

	/* Always ready to send sigs (once) if we're waiting
	 * for theirs: particularly for splicing. */
	case CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS:
		cg->sent_sigs = false;
		return;

	case CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH:
		wallet_announcement_save(channel->peer->ld->wallet,
					 channel->dbid,
					 &cg->remote_sigs->node_sig,
					 &cg->remote_sigs->bitcoin_sig);
		return;

	case CGOSSIP_ANNOUNCED:
		/* In case this snuck up on us (fast confirmations),
		 * make sure we sent sigs */
		send_channel_announce_sigs(channel);

		/* BOLT #7:
		 * A recipient node:
		 *...
		 *   - If it has sent AND received a valid `announcement_signatures`
		 *     message:
		 *     - If the funding transaction has at least 6 confirmations:
		 *       - SHOULD queue the `channel_announcement` message for
		 *         its peers.
		 */
		send_channel_announcement(channel);

		/* Any private cupdate will be different from this, so will force a refresh. */
		update_channel_update(channel, channel_should_enable(channel, true));
		broadcast_new_gossip(channel->peer->ld, cg->cupdate, NULL, "channel update");

		/* We need to refresh channel update every 13 days */
		arm_refresh_timer(channel);

		/* And maybe our first node_announcement */
		channel_gossip_node_announce(channel->peer->ld);
		return;

	case CGOSSIP_CHANNEL_ANNOUNCED_DYING:
		/* Make sure update tells them it's disabled */
		if (update_channel_update(channel, false)) {
			/* We might have skipped over CGOSSIP_ANNOUNCED, so tell
			 * gossipd about us now, so it doesn't complain. */
			send_channel_announcement(channel);
			/* And tell the world */
			broadcast_new_gossip(channel->peer->ld, cg->cupdate, NULL,
					     "channel update");
		}
		return;

	case CGOSSIP_CHANNEL_ANNOUNCED_DEAD:
		/* It's disabled, but gossipd has forgotten it, so no
		 * broadcast */
		update_channel_update(channel, false);
		return;

	case CGOSSIP_CHANNEL_UNANNOUNCED_DYING:
	case CGOSSIP_CHANNEL_DEAD:
		return;
	}
	fatal("Bad channel_gossip_state %u", cg->state);
}

static void update_gossip_state(struct channel *channel)
{
	enum channel_gossip_state newstate;
	struct channel_gossip *cg = channel->channel_gossip;

	newstate = derive_channel_state(channel);
	if (newstate != cg->state)
		set_gossip_state(channel, newstate);

	switch (cg->state) {
	case CGOSSIP_CHANNEL_DEAD:
	case CGOSSIP_CHANNEL_UNANNOUNCED_DYING:
	case CGOSSIP_CHANNEL_ANNOUNCED_DYING:
	case CGOSSIP_CHANNEL_ANNOUNCED_DEAD:
	case CGOSSIP_WAITING_FOR_USABLE:
	case CGOSSIP_PRIVATE_WAITING_FOR_USABLE:
		return;
	case CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS:
	case CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH:
		send_channel_announce_sigs(channel);
		/* fall thru */
	case CGOSSIP_WAITING_FOR_SCID:
	case CGOSSIP_PRIVATE:
		/* Always try to send private cupdate: ignored if redundant */
		send_private_cupdate(channel, false);
		return;
	case CGOSSIP_ANNOUNCED:
		/* If a channel parameter has changed, send new update */
		if (update_channel_update(channel, channel_should_enable(channel, true)))
			broadcast_new_gossip(channel->peer->ld, cg->cupdate, NULL,
					     "channel update");
		return;
	}

	fatal("Bad channel_gossip_state %u", cg->state);
}

/* Initialize channel->channel_gossip state */
void channel_gossip_init(struct channel *channel,
			 const struct peer_update *remote_update)
{
	struct lightningd *ld = channel->peer->ld;
	struct channel_gossip *cg;
	bool public = (channel->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL);

	cg = channel->channel_gossip = tal(channel, struct channel_gossip);
	cg->cupdate = NULL;
	cg->refresh_timer = NULL;
	cg->peer_update = tal_dup_or_null(channel, struct peer_update, remote_update);
	cg->remote_sigs = NULL;
	cg->sent_sigs = false;

	/* If we have an scid, we might have announcement signatures
	 * saved in the db already. */
	if (channel->scid && public) {
		cg->remote_sigs = tal(cg, struct remote_announce_sigs);
		cg->remote_sigs->scid = *channel->scid;
		if (!wallet_remote_ann_sigs_load(ld->wallet,
						 channel,
						 &cg->remote_sigs->node_sig,
						 &cg->remote_sigs->bitcoin_sig)) {
			cg->remote_sigs = tal_free(cg->remote_sigs);
		}
	}

	cg->state = derive_channel_state(channel);
	log_debug(channel->log, "Initial channel state %s",
		  channel_gossip_state_str(cg->state));

	check_channel_gossip(channel);
}

/* Something about channel changed: update if required */
void channel_gossip_update(struct channel *channel)
{
	struct channel_gossip *cg = channel->channel_gossip;

	/* Ignore unsaved channels */
	if (!cg)
		return;

	update_gossip_state(channel);
}

void channel_gossip_got_announcement_sigs(struct channel *channel,
					  struct short_channel_id scid,
					  const secp256k1_ecdsa_signature *node_sig,
					  const secp256k1_ecdsa_signature *bitcoin_sig)
{
	/* Ignore unsaved channels */
	if (!channel->channel_gossip) {
		log_broken(channel->log, "They sent an announcement_signatures message for a unsaved channel?  Ignoring.");
		return;
	}

	/* Ignore the weird cases */
	switch (channel->channel_gossip->state) {
	case CGOSSIP_CHANNEL_DEAD:
	case CGOSSIP_CHANNEL_UNANNOUNCED_DYING:
	case CGOSSIP_CHANNEL_ANNOUNCED_DYING:
	case CGOSSIP_CHANNEL_ANNOUNCED_DEAD:
		return;
	case CGOSSIP_PRIVATE_WAITING_FOR_USABLE:
	case CGOSSIP_PRIVATE:
		log_unusual(channel->log, "They sent an announcement_signatures message for a private channel?  Ignoring.");
		u8 *warning = towire_warningfmt(NULL,
						&channel->cid,
						"You sent announcement_signatures for private channel");
		msg_to_peer(channel->peer, take(warning));
		return;
	case CGOSSIP_WAITING_FOR_USABLE:
	case CGOSSIP_WAITING_FOR_SCID:
		stash_remote_announce_sigs(channel, scid, node_sig, bitcoin_sig);
		return;
	case CGOSSIP_ANNOUNCED:
		/* We don't care what they said, but it does prompt our response */
		goto send_our_sigs;
	case CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS:
	case CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH:
		stash_remote_announce_sigs(channel, scid, node_sig, bitcoin_sig);
		update_gossip_state(channel);
		goto send_our_sigs;
	}
	fatal("Bad channel_gossip_state %u", channel->channel_gossip->state);

send_our_sigs:
	/* This only works once, so we won't spam them. */
	send_channel_announce_sigs(channel);
}

/* Short channel id changed (splice, or reorg). */
void channel_gossip_scid_changed(struct channel *channel)
{
	struct lightningd *ld = channel->peer->ld;
	struct channel_gossip *cg = channel->channel_gossip;

	/* Ignore unsaved channels */
	if (!cg)
		return;

	/* Clear any cached update, we'll need a new one! */
	cg->cupdate = tal_free(cg->cupdate);

	/* Any announcement signatures we received for old scid are no longer
	 * valid.  We keep cg->remote_sigs though: it's common that they
	 * have already sent them for the new scid. */
	wallet_remote_ann_sigs_clear(ld->wallet, channel);

	/* Sanity check */
	switch (cg->state) {
	case CGOSSIP_PRIVATE_WAITING_FOR_USABLE:
	case CGOSSIP_WAITING_FOR_USABLE:
	case CGOSSIP_WAITING_FOR_SCID:
	case CGOSSIP_CHANNEL_ANNOUNCED_DYING:
	case CGOSSIP_CHANNEL_ANNOUNCED_DEAD:
	case CGOSSIP_CHANNEL_DEAD:
		/* Shouldn't happen. */
		log_broken(channel->log, "Got scid change in state %s!",
			   channel_gossip_state_str(cg->state));
		return;
	case CGOSSIP_PRIVATE:
	case CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS:
	case CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH:
	case CGOSSIP_CHANNEL_UNANNOUNCED_DYING:
	case CGOSSIP_ANNOUNCED:
		break;
	}

	update_gossip_state(channel);
}

/* Block height changed */
static void new_blockheight(struct lightningd *ld,
			    struct channel *channel)
{
	/* This can change state if we're CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH */
	update_gossip_state(channel);
}

void channel_gossip_notify_new_block(struct lightningd *ld)
{
	struct peer *peer;
	struct channel *channel;
	struct peer_node_id_map_iter it;

	for (peer = peer_node_id_map_first(ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(ld->peers, &it)) {
		list_for_each(&peer->channels, channel, list) {
			/* Ignore unsaved channels */
			if (!channel->channel_gossip)
				continue;

			new_blockheight(ld, channel);
		}
	}
}

/* Gossipd told us about a channel update on one of our channels (on loading) */
void channel_gossip_update_from_gossipd(struct channel *channel,
					const u8 *channel_update TAKES)
{
	struct channel_gossip *cg = channel->channel_gossip;

	if (!channel->channel_gossip) {
		log_broken(channel->log,
			   "gossipd gave channel_update for unsaved channel? update=%s",
			   tal_hex(tmpctx, channel_update));
		return;
	}

	/* We might still want signatures from peer (we lost state?) */
	switch (channel->channel_gossip->state) {
	case CGOSSIP_PRIVATE:
	case CGOSSIP_PRIVATE_WAITING_FOR_USABLE:
	case CGOSSIP_WAITING_FOR_USABLE:
	case CGOSSIP_CHANNEL_DEAD:
	case CGOSSIP_CHANNEL_UNANNOUNCED_DYING:
	case CGOSSIP_CHANNEL_ANNOUNCED_DEAD:
		/* Shouldn't happen. */
		log_broken(channel->log,
			   "gossipd gave channel_update in %s? update=%s",
			   channel_gossip_state_str(channel->channel_gossip->state),
			   tal_hex(tmpctx, channel_update));
	/* fall thru */
	case CGOSSIP_CHANNEL_ANNOUNCED_DYING:
		if (taken(channel_update))
			tal_free(channel_update);
		return;

	/* This happens: we step back a block when restarting. */
	case CGOSSIP_WAITING_FOR_SCID:
	case CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS:
	case CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH:
	case CGOSSIP_ANNOUNCED:
		break;
	}

	/* In case we generated one before gossipd told us? */
	if (cg->cupdate) {
		tal_free(cg->cupdate);
		cg->refresh_timer = tal_free(cg->refresh_timer);
	}

	/* We don't set refresh timer if we're not ANNOUNCED, we're just saving updates
	 * for later! */
	cg->cupdate = tal_dup_talarr(cg, u8, channel_update);
	if (cg->state == CGOSSIP_ANNOUNCED) {
		broadcast_new_gossip(channel->peer->ld,
				     cg->cupdate, NULL, "channel update");
		arm_refresh_timer(channel);
	}
	check_channel_gossip(channel);
}

static void set_not_starting_up(struct lightningd *ld)
{
	starting_up = false;
	log_debug(ld->log, "channel_gossip: no longer in startup mode");
	/* Now we can create/update a node_announcement */
	channel_gossip_node_announce(ld);
}

/* We also wait ten seconds *after* connection, for lease registration */
void channel_gossip_startup_done(struct lightningd *ld)
{
	notleak(new_reltimer(ld->timers, ld,
			     time_from_sec(10),
			     set_not_starting_up, ld));
}

/* Gossipd init is done: if you expected a channel_update, be
 * disappointed.  */
void channel_gossip_init_done(struct lightningd *ld)
{
	struct peer *peer;
	struct channel *channel;
	struct peer_node_id_map_iter it;

	gossipd_init_done = true;
	for (peer = peer_node_id_map_first(ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(ld->peers, &it)) {
		list_for_each(&peer->channels, channel, list) {
			/* Ignore unsaved channels */
			if (!channel->channel_gossip)
				continue;

			check_channel_gossip(channel);
			if (channel->channel_gossip->cupdate)
				continue;
			if (channel->channel_gossip->state != CGOSSIP_ANNOUNCED)
				continue;
			/* gossipd lost announcement: re-create */
			log_unusual(channel->log,
				    "gossipd lost track of announced channel: re-announcing!");
			check_channel_gossip(channel);
			send_channel_announcement(channel);
			update_channel_update(channel, channel_should_enable(channel, true));
			broadcast_new_gossip(ld, channel->channel_gossip->cupdate, NULL, "channel update");

			/* We need to refresh channel update every 13 days */
			arm_refresh_timer(channel);
		}
	}

	/* And maybe our first node_announcement */
	channel_gossip_node_announce(ld);
}

static void channel_reestablished_stable(struct channel *channel)
{
	channel->stable_conn_timer = NULL;
	channel->last_stable_connection = clock_time().ts.tv_sec;
	wallet_channel_save(channel->peer->ld->wallet, channel);
}

/* Peer has connected and successfully reestablished channel. */
void channel_gossip_channel_reestablished(struct channel *channel)
{
	channel->reestablished = true;
	tal_free(channel->stable_conn_timer);
	channel->stable_conn_timer = new_reltimer(channel->peer->ld->timers,
						  channel, time_from_sec(60),
						  channel_reestablished_stable,
						  channel);

	log_debug(channel->log, "channel_gossip: reestablished");

	/* Ignore unsaved channels */
	if (!channel->channel_gossip)
		return;

	/* We can re-xmit sigs once per reconnect */
	channel->channel_gossip->sent_sigs = false;

	/* BOLT #7:
	 * - Upon reconnection (once the above timing requirements have
	 *   been met):
	 *    - If it has NOT previously received
	 *      `announcement_signatures` for the funding transaction:
	 *        - MUST send its own `announcement_signatures` message.
	 */
	/* We also always send a private channel_update, even if redundant
	 * (they might have lost it) */
	switch (channel->channel_gossip->state) {
	case CGOSSIP_CHANNEL_DEAD:
	case CGOSSIP_CHANNEL_UNANNOUNCED_DYING:
	case CGOSSIP_CHANNEL_ANNOUNCED_DYING:
	case CGOSSIP_CHANNEL_ANNOUNCED_DEAD:
	case CGOSSIP_ANNOUNCED:
	case CGOSSIP_WAITING_FOR_USABLE:
	case CGOSSIP_PRIVATE_WAITING_FOR_USABLE:
		check_channel_gossip(channel);
		return;
	case CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS:
		send_channel_announce_sigs(channel);
		/* fall thru */
	case CGOSSIP_PRIVATE:
	case CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH:
	case CGOSSIP_WAITING_FOR_SCID:
		send_private_cupdate(channel, true);
		check_channel_gossip(channel);
		return;
	}
	fatal("Bad channel_gossip_state %u", channel->channel_gossip->state);
}

void channel_gossip_channel_disconnect(struct channel *channel)
{
	channel->stable_conn_timer = tal_free(channel->stable_conn_timer);
	channel->reestablished = false;
}

/* We *could* send channel_updates for private channels, or
 * unannounced.  We do not */
const u8 *channel_gossip_update_for_error(const tal_t *ctx,
					  struct channel *channel)
{
	/* We cannot ask this about unsaved channels. */
	struct channel_gossip *cg = channel->channel_gossip;

	switch (cg->state) {
	case CGOSSIP_CHANNEL_DEAD:
	case CGOSSIP_CHANNEL_UNANNOUNCED_DYING:
	case CGOSSIP_PRIVATE_WAITING_FOR_USABLE:
	case CGOSSIP_PRIVATE:
	case CGOSSIP_WAITING_FOR_USABLE:
	case CGOSSIP_WAITING_FOR_SCID:
	case CGOSSIP_WAITING_FOR_MATCHING_PEER_SIGS:
	case CGOSSIP_WAITING_FOR_ANNOUNCE_DEPTH:
		return NULL;
	case CGOSSIP_CHANNEL_ANNOUNCED_DYING:
	case CGOSSIP_CHANNEL_ANNOUNCED_DEAD:
		return cg->cupdate;
	case CGOSSIP_ANNOUNCED:
		/* At this point we actually disable disconnected peers. */
		if (update_channel_update(channel, channel_should_enable(channel, false))) {
			broadcast_new_gossip(channel->peer->ld,
					     cg->cupdate, NULL,
					     "channel update");
		}
		check_channel_gossip(channel);
		return cg->cupdate;
	}
	fatal("Bad channel_gossip_state %u", cg->state);
}

/* BOLT #7:
 *    - MUST set the `short_channel_id` to either an `alias` it has
 *      received from the peer, or the real channel `short_channel_id`.
 */
/* But we used to get this wrong!  So this is the only place where we
 * look up by *remote* id.  It's not unique, but it is unique for a
 * specific peer. */
static struct channel *lookup_by_peer_remote_alias(struct lightningd *ld,
						   const struct node_id *source,
						   struct short_channel_id scid)
{
	const struct peer *p;
	struct channel *chan;

	if (!source)
		return NULL;

	p = peer_by_id(ld, source);
	if (!p)
		return NULL;

	list_for_each(&p->channels, chan, list) {
		if (chan->alias[REMOTE]
		    && short_channel_id_eq(scid, *chan->alias[REMOTE])) {
			return chan;
		}
	}
	return NULL;
}

/* A peer sent gossipd an update_channel message for one of our channels.
 * Gossipd checked the signature.
 */
void channel_gossip_set_remote_update(struct lightningd *ld,
				      const struct peer_update *update TAKES,
				      const struct node_id *source)
{
	struct channel *channel;
	struct channel_gossip *cg;

	channel = any_channel_by_scid(ld, update->scid, true);
	if (!channel) {
		channel = lookup_by_peer_remote_alias(ld, source, update->scid);
		if (channel)
			log_debug(channel->log,
				  "Bad gossip order: peer sent update using their own alias!");
	}
	if (!channel) {
		log_unusual(ld->log, "Bad gossip order: could not find channel %s for peer's "
			    "channel update",
			    fmt_short_channel_id(tmpctx, update->scid));
		return;
	}

	cg = channel->channel_gossip;

	if (!cg) {
		log_broken(ld->log, "Peer sent update_channel for unsaved channel");
		return;
	}

	/* For public channels, it could come from anywhere.  Private
	 * channels must come from gossipd itself (the old store
	 * migration!) or the correct peer. */
	if (is_private(channel)
	    && source
	    && !node_id_eq(source, &channel->peer->id)) {
		log_unusual(ld->log, "Bad gossip order: %s sent us a channel update for a "
			    "channel owned by %s (%s)",
			    fmt_node_id(tmpctx, source),
			    fmt_node_id(tmpctx, &channel->peer->id),
			    fmt_short_channel_id(tmpctx, update->scid));
		return;
	}

	log_debug(ld->log, "updating channel %s with inbound settings",
		  fmt_short_channel_id(tmpctx, update->scid));
	tal_free(cg->peer_update);
	cg->peer_update = tal_dup(cg, struct peer_update, update);
	wallet_channel_save(ld->wallet, channel);
}

const struct peer_update *channel_gossip_get_remote_update(const struct channel *channel)
{
	struct channel_gossip *cg = channel->channel_gossip;

	if (!cg)
		return NULL;
	return cg->peer_update;
}

static bool has_announced_channels(struct lightningd *ld)
{
	struct peer *peer;
	struct peer_node_id_map_iter it;

	for (peer = peer_node_id_map_first(ld->peers, &it);
	     peer;
	     peer = peer_node_id_map_next(ld->peers, &it)) {
		struct channel *channel;
		list_for_each(&peer->channels, channel, list) {
			/* Ignore unsaved channels */
			if (!channel->channel_gossip)
				continue;
			if (channel->channel_gossip->state == CGOSSIP_ANNOUNCED)
				return true;
		}
	}
	return false;
}

void channel_gossip_node_announce(struct lightningd *ld)
{
	u8 *nannounce;
	const u8 *msg;
	secp256k1_ecdsa_signature sig;

	/* Everyone will ignore our node_announcement unless we have
	 * announced a channel. */
	if (!has_announced_channels(ld))
		return;

	/* Don't produce a node announcement until *after* gossipd has
	 * told us it's finished. */
	if (!gossipd_init_done)
		return;

	nannounce = unsigned_node_announcement(tmpctx, ld, ld->node_announcement);

	/* Don't bother with duplicates */
	if (ld->node_announcement
	    && node_announcement_same(ld->node_announcement, nannounce))
		return;

	/* Ask hsmd to sign it (synchronous) */
	msg = hsm_sync_req(tmpctx, ld,
			   take(towire_hsmd_node_announcement_sig_req(NULL,
								      nannounce)));
	if (!fromwire_hsmd_node_announcement_sig_reply(msg, &sig))
		fatal("Reading hsmd_node_announcement_sig_reply: %s",
		      tal_hex(tmpctx, msg));

	add_node_announcement_sig(nannounce, &sig);

	/* Update our cached copy. */
	tal_free(ld->node_announcement);
	ld->node_announcement = tal_steal(ld, nannounce);

	/* Tell gossipd and peers. */
	broadcast_new_gossip(ld, nannounce, NULL, "node announcement");
}
