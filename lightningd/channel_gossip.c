#include "config.h"
#include <ccan/mem/mem.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <connectd/connectd_wiregen.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_gossip.h>
#include <lightningd/gossip_generation.h>
#include <lightningd/hsm_control.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

enum channel_gossip_state {
	/* Not a public channel */
	CGOSSIP_PRIVATE,
	/* We can't yet send (non-forwardable) channel_update. */
	CGOSSIP_NOT_USABLE,
	/* Not yet in at announcable depth. */
	CGOSSIP_NOT_DEEP_ENOUGH,
	/* We want the peer's announcement_signatures. */
	CGOSSIP_NEED_PEER_SIGS,
	/* We have received sigs, and announced. */
	CGOSSIP_ANNOUNCED,
};

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
};

static bool starting_up = true, gossipd_init_done = false;

/* We send non-forwardable channel updates if we can. */
static bool can_send_channel_update(const struct channel *channel)
{
	/* Can't send if we can't talk about it. */
	if (!channel->scid && !channel->alias[REMOTE])
		return false;
	if (channel_state_pre_open(channel->state))
		return false;
	return true;
}

/* We send start the channel announcement signatures if we can.
 * Caller must check it's not CGOSSIP_PRIVATE, but this is used
 * to set up state so we cannot assert here!
 */
static bool channel_announceable(const struct channel *channel,
				 u32 block_height)
{
	if (!channel->scid)
		return false;
	return is_scid_depth_announceable(channel->scid, block_height);
}

static void check_channel_gossip(const struct channel *channel)
{
	struct channel_gossip *cg = channel->channel_gossip;

	/* Note: we can't assert is_scid_depth_announceable, for two reasons:
	 * 1. on restart and rescan, block numbers can go backwards.'
	 * 2. We don't get notified via channel_gossip_notify_new_block until
	 *    there are no new blocks to add, not on every block.
	 */
	switch (cg->state) {
	case CGOSSIP_PRIVATE:
		assert(!(channel->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL));
		assert(!cg->remote_sigs);
		assert(!cg->refresh_timer);
		return;

	case CGOSSIP_NOT_USABLE:
		assert(channel->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL);
		assert(!can_send_channel_update(channel));
		assert(!cg->refresh_timer);
		return;
	case CGOSSIP_NOT_DEEP_ENOUGH:
		assert(channel->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL);
		assert(can_send_channel_update(channel));
		assert(!cg->refresh_timer);
		return;
	case CGOSSIP_NEED_PEER_SIGS:
		assert(can_send_channel_update(channel));
		assert(channel->scid);
		/* If we have sigs, they don't match */
		if (cg->remote_sigs)
			assert(!channel->scid || !short_channel_id_eq(&cg->remote_sigs->scid, channel->scid));
		assert(!cg->refresh_timer);
		return;
	case CGOSSIP_ANNOUNCED:
		assert(can_send_channel_update(channel));
		assert(channel->scid);
		assert(cg->remote_sigs);
		return;
	}
	fatal("Bad channel_gossip_state %u", cg->state);
}

/* Recursion */
static void cupdate_timer_refresh(struct channel *channel);

static void set_public_cupdate(struct channel *channel,
			       const u8 *cupdate TAKES)
{
	struct lightningd *ld = channel->peer->ld;
	struct channel_gossip *cg = channel->channel_gossip;
	u32 timestamp;
	bool enabled;
	struct timeabs now, due;

	if (!channel_update_details(cupdate, &timestamp, &enabled)) {
		log_broken(channel->log, "Invalid channel_update %s: ignoring",
			   tal_hex(tmpctx, cupdate));
		if (taken(cupdate))
			tal_free(cupdate);
		return;
	}

	tal_free(cg->cupdate);
	cg->cupdate = tal_dup_talarr(cg, u8, cupdate);

	cg->refresh_timer = tal_free(cg->refresh_timer);

	/* If enabled, we refresh, based on old timestamp */
	if (!enabled)
		return;

	due.ts.tv_sec = timestamp;
	due.ts.tv_nsec = 0;
	due = timeabs_add(due,
			  time_from_sec(GOSSIP_PRUNE_INTERVAL(ld->dev_fast_gossip_prune)
					- GOSSIP_BEFORE_DEADLINE(ld->dev_fast_gossip_prune)));

	/* In case it's passed, timer should be zero */
	now = time_now();
	if (time_after(now, due))
		due = now;

	cg->refresh_timer = new_reltimer(ld->timers, cg,
					 time_between(due, now),
					 cupdate_timer_refresh,
					 channel);
}

static void msg_to_peer(const struct channel *channel, const u8 *msg TAKES)
{
	struct peer *peer = channel->peer;
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

static enum channel_gossip_state init_public_state(struct channel *channel,
						   const struct remote_announce_sigs *remote_sigs)
{
	struct lightningd *ld = channel->peer->ld;

	if (!can_send_channel_update(channel))
		return CGOSSIP_NOT_USABLE;

	/* Note: depth when we startup is not actually reliable, since
	 * we step one block back.  We'll fix this up when gossipd
	 * tells us it's announced, or, when we add the block. */
	if (!channel_announceable(channel, get_block_height(ld->topology)))
		return CGOSSIP_NOT_DEEP_ENOUGH;

	if (!remote_sigs) {
		return CGOSSIP_NEED_PEER_SIGS;
	}

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
	const struct short_channel_id *scid;

	/* BOLT #7:
	 *
	 * - MAY create a `channel_update` to communicate the channel
	 *   parameters to the channel peer, even though the channel has not
	 *   yet been announced (i.e. the `announce_channel` bit was not set).
	 *    - MUST set the `short_channel_id` to either an `alias` it has
	 *    received from the peer, or the real channel `short_channel_id`.
	 *    - MUST set `dont_forward` to 1 in `message_flags`
	 */
	/* We prefer their alias, if possible: they might not have seen the block which
	 * mined the funding tx yet, so the scid would be meaningless to them. */
	if (channel->alias[REMOTE])
		scid = channel->alias[REMOTE];
	else
		scid = channel->scid;

	/* Only useful channels: not if closing */
	if (!channel_state_can_add_htlc(channel->state))
		return;

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
	msg_to_peer(channel, cg->cupdate);
}

static void broadcast_public_cupdate_addgossip_reply(struct subd *gossip UNUSED,
						     const u8 *reply,
						     const int *fds UNUSED,
						     struct channel *channel)
{
	char *err;

	if (!fromwire_gossipd_addgossip_reply(reply, reply, &err))
		fatal("Reading broadcast_public_cupdate_addgossip_reply: %s",
		      tal_hex(tmpctx, reply));

	if (strlen(err))
		log_broken(channel->log, "gossipd rejected our channel update: %s", err);
}

/* Send gossipd a channel_update, if not redundant. */
static void broadcast_public_cupdate(struct channel *channel,
				     bool ok_if_disconnected)
{
	struct lightningd *ld = channel->peer->ld;
	struct channel_gossip *cg = channel->channel_gossip;
	const u8 *cupdate;
	u32 old_timestamp;
	bool enable, have_old;

	/* If we have no previous channel_update, this fails */
	have_old = channel_update_details(cg->cupdate,
					  &old_timestamp, &enable);

	if (!channel_state_can_add_htlc(channel->state)) {
		/* If it's (no longer) usable, it's a simply courtesy
		 * to disable */
		enable = false;
	} else if (channel->owner) {
		/* If it's live, it's enabled */
		enable = true;
	} else if (starting_up) {
		/* If we are starting up, don't change it! */
		if (!have_old)
			/* Assume the best if we don't have an updated */
			enable = true;
	} else {
		enable = ok_if_disconnected;
	}

	cupdate = unsigned_channel_update(tmpctx, channel, channel->scid,
					  have_old ? &old_timestamp : NULL,
					  true,
					  enable);

	/* Suppress redundant ones */
	if (cg->cupdate && channel_update_same(cg->cupdate, cupdate))
		return;

	set_public_cupdate(channel,
			   take(sign_update(NULL, channel->peer->ld, cupdate)));

	subd_req(ld->gossip, ld->gossip,
		 take(towire_gossipd_addgossip(NULL, cg->cupdate, NULL)),
		 -1, 0, broadcast_public_cupdate_addgossip_reply, channel);
}

static void cupdate_timer_refresh(struct channel *channel)
{
	struct channel_gossip *cg = channel->channel_gossip;

	/* Don't try to free this again if set_public_cupdate called later */
	cg->refresh_timer = NULL;

	log_debug(channel->log, "Sending keepalive channel_update for %s",
		  short_channel_id_to_str(tmpctx, channel->scid));

	/* Free old cupdate to force a new one to be generated */
	cg->cupdate = tal_free(cg->cupdate);
	broadcast_public_cupdate(channel, true);
}

static void stash_remote_announce_sigs(struct channel *channel,
				       struct short_channel_id scid,
				       const secp256k1_ecdsa_signature *node_sig,
				       const secp256k1_ecdsa_signature *bitcoin_sig)
{
	struct channel_gossip *cg = channel->channel_gossip;
	const char *err;

	/* BOLT #7:
	 * - if the `node_signature` OR the `bitcoin_signature` is NOT correct:
	 *   - MAY send a `warning` and close the connection, or send an
         *     `error` and fail the channel.
	 */
	err = check_announce_sigs(channel, scid, node_sig, bitcoin_sig);
	if (err) {
		channel_fail_transient(channel, true,
				       "Bad gossip announcement_signatures for scid %s: %s",
				       short_channel_id_to_str(tmpctx, &scid),
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
		  short_channel_id_to_str(tmpctx, &scid),
		  channel->scid ? short_channel_id_to_str(tmpctx, channel->scid) : "none");
}

static bool apply_remote_sigs(struct channel *channel)
{
	struct channel_gossip *cg = channel->channel_gossip;

	if (!cg->remote_sigs)
		return false;

	if (!short_channel_id_eq(&cg->remote_sigs->scid, channel->scid)) {
		log_debug(channel->log, "We have remote sigs, but wrong scid!");
		return false;
	}

	wallet_announcement_save(channel->peer->ld->wallet,
				 channel->dbid,
				 &cg->remote_sigs->node_sig,
				 &cg->remote_sigs->bitcoin_sig);
	return true;
}

static void send_channel_announce_sigs(struct channel *channel)
{
	/* First 2 + 256 byte are the signatures and msg type, skip them */
	const size_t offset = 258;
	struct lightningd *ld = channel->peer->ld;
	struct sha256_double hash;
	secp256k1_ecdsa_signature local_node_sig, local_bitcoin_sig;
	struct pubkey mykey;
	const u8 *ca, *msg;

	/* If it's already closing, don't bother. */
	if (!channel_state_can_add_htlc(channel->state))
		return;

	/* Wait until we've exchanged reestablish messages */
	if (!channel->reestablished) {
		log_debug(channel->log, "channel_gossip: not sending channel_announcement_sigs until reestablished");
		return;
	}

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
	if (!pubkey_from_node_id(&mykey, &ld->id))
		fatal("Could not convert own public key");

	if (!check_signed_hash(&hash, &local_node_sig, &mykey)) {
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
					     &channel->cid, channel->scid,
					     &local_node_sig, &local_bitcoin_sig);
	msg_to_peer(channel, take(msg));
}

static void send_channel_announce_addgossip_reply(struct subd *gossip UNUSED,
						  const u8 *reply,
						  const int *fds UNUSED,
						  struct channel *channel)
{
	char *err;

	if (!fromwire_gossipd_addgossip_reply(reply, reply, &err))
		fatal("Reading send_channel_announce_addgossip_reply: %s",
		      tal_hex(tmpctx, reply));

	if (strlen(err))
		log_broken(channel->log, "gossipd rejected our channel announcement: %s", err);
}

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

	/* Don't crash if shutting down */
	if (!ld->gossip)
		return;

	ca = create_channel_announcement(tmpctx, channel, *channel->scid,
					 &local_node_sig,
					 &local_bitcoin_sig,
					 &cg->remote_sigs->node_sig,
					 &cg->remote_sigs->bitcoin_sig);

	subd_req(ld->gossip, ld->gossip,
		 take(towire_gossipd_addgossip(NULL, ca, &channel->funding_sats)),
		 -1, 0, send_channel_announce_addgossip_reply, channel);
	/* We can also send our first public channel_update now */
	broadcast_public_cupdate(channel, true);
	/* And maybe our first node_announcement */
	channel_gossip_node_announce(ld);
}

static void set_gossip_state(struct channel *channel,
			     enum channel_gossip_state state)
{
	struct channel_gossip *cg = channel->channel_gossip;

	cg->state = state;

	switch (cg->state) {
	case CGOSSIP_PRIVATE:
		abort();
	case CGOSSIP_NOT_USABLE:
		return;
	case CGOSSIP_NOT_DEEP_ENOUGH:
		/* But it exists, so try sending private channel_update */
		send_private_cupdate(channel, false);
		return;
	case CGOSSIP_NEED_PEER_SIGS:
		send_channel_announce_sigs(channel);
		/* We may already have remote signatures */
		if (!apply_remote_sigs(channel))
			return;
		cg->state = CGOSSIP_ANNOUNCED;
		/* fall thru */
	case CGOSSIP_ANNOUNCED:
		/* Any previous update was private, so clear. */
		cg->cupdate = tal_free(cg->cupdate);
		send_channel_announcement(channel);
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

	if (public)
		cg->state = init_public_state(channel, cg->remote_sigs);
	else
		cg->state = CGOSSIP_PRIVATE;

	check_channel_gossip(channel);
}

/* Something about channel changed: update if required */
void channel_gossip_update(struct channel *channel)
{
	struct lightningd *ld = channel->peer->ld;
	struct channel_gossip *cg = channel->channel_gossip;

	/* Ignore unsaved channels */
	if (!cg)
		return;

	switch (cg->state) {
	case CGOSSIP_NOT_USABLE:
		/* Change might make it usable */
		if (!can_send_channel_update(channel)) {
			check_channel_gossip(channel);
			return;
		}
		set_gossip_state(channel, CGOSSIP_NOT_DEEP_ENOUGH);
		/* fall thru */
	case CGOSSIP_NOT_DEEP_ENOUGH:
		/* Now we can send at non-forwardable update */
		send_private_cupdate(channel, false);
		/* Might have gotten straight from not-usable to announceable
		 * if we have a flurry of blocks, or minconf >= 6. */
		if (!channel_announceable(channel, get_block_height(ld->topology))) {
			check_channel_gossip(channel);
			return;
		}
		set_gossip_state(channel, CGOSSIP_NEED_PEER_SIGS);
		/* Could have actually already had sigs! */
		if (cg->state == CGOSSIP_ANNOUNCED)
			goto announced;
		/* fall thru */
	case CGOSSIP_PRIVATE:
	case CGOSSIP_NEED_PEER_SIGS:
		send_private_cupdate(channel, false);
		check_channel_gossip(channel);
		return;
	case CGOSSIP_ANNOUNCED:
	announced:
		/* We don't penalize disconnected clients normally: we only
		 * do that if we actually try to send an htlc through */
		broadcast_public_cupdate(channel, true);
		check_channel_gossip(channel);
		return;
	}
	fatal("Bad channel_gossip_state %u", channel->channel_gossip->state);
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

	switch (channel->channel_gossip->state) {
	case CGOSSIP_PRIVATE:
		log_unusual(channel->log, "They sent an announcement_signatures message for a private channel?  Ignoring.");
		u8 *warning = towire_warningfmt(NULL,
						&channel->cid,
						"You sent announcement_signatures for private channel");
		msg_to_peer(channel, take(warning));
		return;
	case CGOSSIP_NOT_USABLE:
	case CGOSSIP_NOT_DEEP_ENOUGH:
		/* They're early? */
		stash_remote_announce_sigs(channel,
					   scid, node_sig, bitcoin_sig);
		check_channel_gossip(channel);
		return;
	case CGOSSIP_NEED_PEER_SIGS:
		stash_remote_announce_sigs(channel,
					   scid, node_sig, bitcoin_sig);
		if (apply_remote_sigs(channel))
			set_gossip_state(channel, CGOSSIP_ANNOUNCED);
		check_channel_gossip(channel);
		return;
	case CGOSSIP_ANNOUNCED:
		/* BOLT #7:
		 * - upon reconnection (once the above timing requirements
                 *   have been met):
		 *     - MUST respond to the first `announcement_signatures`
		 *       message with its own `announcement_signatures` message.
		 */
		send_channel_announce_sigs(channel);
		check_channel_gossip(channel);
		return;
	}
	fatal("Bad channel_gossip_state %u", channel->channel_gossip->state);
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
	 * valid. */
	wallet_remote_ann_sigs_clear(ld->wallet, channel);

	switch (cg->state) {
	case CGOSSIP_PRIVATE:
		/* Still private, just send new channel_update */
		send_private_cupdate(channel, false);
		check_channel_gossip(channel);
		return;
	case CGOSSIP_NOT_USABLE:
		/* Shouldn't happen. */
		return;
	case CGOSSIP_NOT_DEEP_ENOUGH:
	case CGOSSIP_NEED_PEER_SIGS:
	case CGOSSIP_ANNOUNCED:
		log_debug(channel->log, "channel_gossip: scid now %s",
			  short_channel_id_to_str(tmpctx, channel->scid));
		/* Start again. */
		/* Maybe remote announcement signatures now apply?  If not,
		 * free them */
		if (cg->remote_sigs
		    && !short_channel_id_eq(&cg->remote_sigs->scid,
					    channel->scid)) {
			cg->remote_sigs = tal_free(cg->remote_sigs);
		}

		/* Stop refresh timer, we're not announcing the old one. */
		cg->refresh_timer = tal_free(cg->refresh_timer);

		set_gossip_state(channel,
 				 init_public_state(channel, cg->remote_sigs));
		send_channel_announce_sigs(channel);
		check_channel_gossip(channel);
		return;
	}
	fatal("Bad channel_gossip_state %u", cg->state);
}

/* Block height changed */
static void new_blockheight(struct lightningd *ld,
			    struct channel *channel,
			    u32 block_height)
{
	switch (channel->channel_gossip->state) {
	case CGOSSIP_PRIVATE:
	case CGOSSIP_NEED_PEER_SIGS:
	case CGOSSIP_ANNOUNCED:
	case CGOSSIP_NOT_USABLE:
		return;
	case CGOSSIP_NOT_DEEP_ENOUGH:
		if (!channel_announceable(channel, block_height)) {
			check_channel_gossip(channel);
			return;
		}
		set_gossip_state(channel, CGOSSIP_NEED_PEER_SIGS);
		check_channel_gossip(channel);
		return;
	}
	fatal("Bad channel_gossip_state %u", channel->channel_gossip->state);
}

void channel_gossip_notify_new_block(struct lightningd *ld,
				     u32 block_height)
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

			new_blockheight(ld, channel, block_height);
			check_channel_gossip(channel);
		}
	}
}

/* Gossipd told us about a channel update on one of our channels (on loading) */
void channel_gossip_update_from_gossipd(struct channel *channel,
					const u8 *channel_update TAKES)
{
	if (!channel->channel_gossip) {
		log_broken(channel->log,
			   "gossipd gave channel_update for unsaved channel? update=%s",
			   tal_hex(tmpctx, channel_update));
		return;
	}

	/* If we didn't think it was announced already, it is now! */
	switch (channel->channel_gossip->state) {
	case CGOSSIP_PRIVATE:
		log_broken(channel->log,
			   "gossipd gave channel_update for private channel? update=%s",
			   tal_hex(tmpctx, channel_update));
		return;
	case CGOSSIP_NOT_USABLE:
	case CGOSSIP_NOT_DEEP_ENOUGH:
	case CGOSSIP_NEED_PEER_SIGS:
		set_gossip_state(channel, CGOSSIP_ANNOUNCED);
		break;
	case CGOSSIP_ANNOUNCED:
		break;
	}

	set_public_cupdate(channel, channel_update);
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
		}
	}
}

static void channel_reestablished_stable(struct channel *channel)
{
	channel->stable_conn_timer = NULL;
	channel->last_stable_connection = time_now().ts.tv_sec;
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

	switch (channel->channel_gossip->state) {
	case CGOSSIP_NOT_USABLE:
		return;
	case CGOSSIP_PRIVATE:
	case CGOSSIP_NOT_DEEP_ENOUGH:
		send_private_cupdate(channel, true);
		check_channel_gossip(channel);
		return;
	case CGOSSIP_NEED_PEER_SIGS:
		/* BOLT #7:
		 * - upon reconnection (once the above timing
		 *  requirements have been met):
		 * ...
		 *   - if it has NOT received an
		 *     `announcement_signatures` message:
		 *     - SHOULD retransmit the
		 *       `announcement_signatures` message.
		 */
		send_private_cupdate(channel, true);
		send_channel_announce_sigs(channel);
		check_channel_gossip(channel);
		return;
	case CGOSSIP_ANNOUNCED:
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
	case CGOSSIP_PRIVATE:
	case CGOSSIP_NOT_USABLE:
	case CGOSSIP_NOT_DEEP_ENOUGH:
	case CGOSSIP_NEED_PEER_SIGS:
		return NULL;
	case CGOSSIP_ANNOUNCED:
		broadcast_public_cupdate(channel, false);
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
		    && short_channel_id_eq(&scid, chan->alias[REMOTE])) {
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

	channel = any_channel_by_scid(ld, &update->scid, true);
	if (!channel) {
		channel = lookup_by_peer_remote_alias(ld, source, update->scid);
		if (channel)
			log_debug(channel->log,
				  "Bad gossip order: peer sent update using their own alias!");
	}
	if (!channel) {
		log_unusual(ld->log, "Bad gossip order: could not find channel %s for peer's "
			    "channel update",
			    short_channel_id_to_str(tmpctx, &update->scid));
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
	if (cg->state == CGOSSIP_PRIVATE
	    && source
	    && !node_id_eq(source, &channel->peer->id)) {
		log_unusual(ld->log, "Bad gossip order: %s sent us a channel update for a "
			    "channel owned by %s (%s)",
			    type_to_string(tmpctx, struct node_id, source),
			    type_to_string(tmpctx, struct node_id,
					   &channel->peer->id),
			    type_to_string(tmpctx, struct short_channel_id, &update->scid));
		return;
	}

	log_debug(ld->log, "updating channel %s with inbound settings",
		  type_to_string(tmpctx, struct short_channel_id, &update->scid));
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

static void node_announce_addgossip_reply(struct subd *gossipd,
					  const u8 *reply,
					  const int *fds UNUSED,
					  void *unused)
{
	char *err;

	if (!fromwire_gossipd_addgossip_reply(reply, reply, &err))
		fatal("Reading node_announce_addgossip_reply: %s",
		      tal_hex(tmpctx, reply));

	if (strlen(err))
		log_broken(gossipd->ld->log,
			   "gossipd rejected our node announcement: %s", err);
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

	/* Tell gossipd. */
	subd_req(ld->gossip, ld->gossip,
		 take(towire_gossipd_addgossip(NULL, nannounce, NULL)),
		 -1, 0, node_announce_addgossip_reply, NULL);
}
