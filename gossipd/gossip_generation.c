/* Routines to make our own gossip messages.  Not as in "we're the gossip
 * generation, man!" */
#include "config.h"
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <common/features.h>
#include <common/memleak.h>
#include <common/status.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/wireaddr.h>
#include <errno.h>
#include <gossipd/gossip_generation.h>
#include <gossipd/gossip_store.h>
#include <gossipd/gossip_store_wiregen.h>
#include <gossipd/gossipd.h>
#include <gossipd/gossipd_peerd_wiregen.h>
#include <hsmd/hsmd_wiregen.h>
#include <wire/wire_sync.h>

/* Create a node_announcement with the given signature. It may be NULL in the
 * case we need to create a provisional announcement for the HSM to sign.
 * This is called twice: once with the dummy signature to get it signed and a
 * second time to build the full packet with the signature. The timestamp is
 * handed in rather than using time_now() internally, since that could change
 * between the dummy creation and the call with a signature. */
static u8 *create_node_announcement(const tal_t *ctx, struct daemon *daemon,
				    const secp256k1_ecdsa_signature *sig,
				    u32 timestamp,
				    const struct lease_rates *rates)
{
	u8 *addresses = tal_arr(tmpctx, u8, 0);
	u8 *announcement;
	struct tlv_node_ann_tlvs *na_tlv;
	size_t i;

	if (!sig)
		sig = talz(tmpctx, secp256k1_ecdsa_signature);

	for (i = 0; i < tal_count(daemon->announcable); i++)
		towire_wireaddr(&addresses, &daemon->announcable[i]);

	na_tlv = tlv_node_ann_tlvs_new(tmpctx);
	na_tlv->option_will_fund = cast_const(struct lease_rates *, rates);

	announcement =
	    towire_node_announcement(ctx, sig,
				     daemon->our_features->bits
				     [NODE_ANNOUNCE_FEATURE],
				     timestamp,
				     &daemon->id, daemon->rgb, daemon->alias,
				     addresses,
				     na_tlv);
	return announcement;
}

/* Helper to get non-signature, non-timestamp parts of (valid!) channel_update */
void get_cupdate_parts(const u8 *channel_update,
		       const u8 *parts[2],
		       size_t sizes[2])
{
	/* BOLT #7:
	 *
	 * 1. type: 258 (`channel_update`)
	 * 2. data:
	 *    * [`signature`:`signature`]
	 *    * [`chain_hash`:`chain_hash`]
	 *    * [`short_channel_id`:`short_channel_id`]
	 *    * [`u32`:`timestamp`]
	 *...
	 */
	/* Note: 2 bytes for `type` field */
	/* We already checked it's valid before accepting */
	assert(tal_count(channel_update) > 2 + 64 + 32 + 8 + 4);
	parts[0] = channel_update + 2 + 64;
	sizes[0] = 32 + 8;
	parts[1] = channel_update + 2 + 64 + 32 + 8 + 4;
	sizes[1] = tal_count(channel_update) - (64 + 2 + 32 + 8 + 4);
}

/* Is this channel_update different from prev (not sigs and timestamps)? */
bool cupdate_different(struct gossip_store *gs,
		       const struct half_chan *hc,
		       const u8 *cupdate)
{
	const u8 *oparts[2], *nparts[2];
	size_t osizes[2], nsizes[2];
	const u8 *orig;

	/* Get last one we have. */
	orig = gossip_store_get(tmpctx, gs, hc->bcast.index);
	get_cupdate_parts(orig, oparts, osizes);
	get_cupdate_parts(cupdate, nparts, nsizes);

	return !memeq(oparts[0], osizes[0], nparts[0], nsizes[0])
		|| !memeq(oparts[1], osizes[1], nparts[1], nsizes[1]);
}

/* Get non-signature, non-timestamp parts of (valid!) node_announcement,
 * with TLV broken out separately  */
static void get_nannounce_parts(const u8 *node_announcement,
				const u8 *parts[3],
				size_t sizes[3])
{
	size_t len, ad_len;
	const u8 *flen, *ad_start;

	/* BOLT #7:
	 *
	 * 1. type: 257 (`node_announcement`)
	 * 2. data:
	 *    * [`signature`:`signature`]
	 *    * [`u16`:`flen`]
	 *    * [`flen*byte`:`features`]
	 *    * [`u32`:`timestamp`]
	 *...
	 */
	/* Note: 2 bytes for `type` field */
	/* We already checked it's valid before accepting */
	assert(tal_count(node_announcement) > 2 + 64);
	parts[0] = node_announcement + 2 + 64;

	/* Read flen to get size */
	flen = parts[0];
	len = tal_count(node_announcement) - (2 + 64);
	sizes[0] = 2 + fromwire_u16(&flen, &len);
	assert(flen != NULL && len >= 4);

	/* BOLT-0fe3485a5320efaa2be8cfa0e570ad4d0259cec3 #7:
	 *
	 *    * [`u32`:`timestamp`]
	 *    * [`point`:`node_id`]
	 *    * [`3*byte`:`rgb_color`]
	 *    * [`32*byte`:`alias`]
	 *    * [`u16`:`addrlen`]
	 *    * [`addrlen*byte`:`addresses`]
	 *    * [`node_ann_tlvs`:`tlvs`]
	*/
	parts[1] = node_announcement + 2 + 64 + sizes[0] + 4;

	/* Find the end of the addresses */
	ad_start = parts[1] + 33 + 3 + 32;
	len = tal_count(node_announcement)
		- (2 + 64 + sizes[0] + 4 + 33 + 3 + 32);
	ad_len = fromwire_u16(&ad_start, &len);
	assert(ad_start != NULL && len >= ad_len);

	sizes[1] = 33 + 3 + 32 + 2 + ad_len;

	/* Is there a TLV ? */
	sizes[2] = len - ad_len;
	if (sizes[2] != 0)
		parts[2] = parts[1] + sizes[1];
	else
		parts[2] = NULL;
}

/* Is this node_announcement different from prev (not sigs and timestamps)? */
bool nannounce_different(struct gossip_store *gs,
			 const struct node *node,
			 const u8 *nannounce,
			 bool *only_missing_tlv)
{
	const u8 *oparts[3], *nparts[3];
	size_t osizes[3], nsizes[3];
	const u8 *orig;

	/* Get last one we have. */
	orig = gossip_store_get(tmpctx, gs, node->bcast.index);
	get_nannounce_parts(orig, oparts, osizes);
	get_nannounce_parts(nannounce, nparts, nsizes);

	if (only_missing_tlv)
		*only_missing_tlv = memeq(oparts[0], osizes[0], nparts[0], nsizes[0])
			&& memeq(oparts[1], osizes[1], nparts[1], nsizes[1])
			&& !memeq(oparts[2], osizes[2], nparts[2], nsizes[2]);

	return !memeq(oparts[0], osizes[0], nparts[0], nsizes[0])
		|| !memeq(oparts[1], osizes[1], nparts[1], nsizes[1])
		|| !memeq(oparts[2], osizes[2], nparts[2], nsizes[2]);
}

static void sign_and_send_nannounce(struct daemon *daemon,
				    u8 *nannounce,
				    u32 timestamp)
{
	secp256k1_ecdsa_signature sig;
	u8 *msg, *err;

	/* Ask hsmd to sign it (synchronous) */
	if (!wire_sync_write(HSM_FD, take(towire_hsmd_node_announcement_sig_req(NULL, nannounce))))
		status_failed(STATUS_FAIL_MASTER_IO, "Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_node_announcement_sig_reply(msg, &sig))
		status_failed(STATUS_FAIL_MASTER_IO, "HSM returned an invalid node_announcement sig");

	/* We got the signature for our provisional node_announcement back
	 * from the HSM, create the real announcement and forward it to
	 * gossipd so it can take care of forwarding it. */
	nannounce = create_node_announcement(NULL, daemon, &sig,
					     timestamp, daemon->rates);

	/* This injects it into the routing code in routing.c; it should not
	 * reject it! */
	err = handle_node_announcement(daemon->rstate, take(nannounce),
				       NULL, NULL);
	if (err)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "rejected own node announcement: %s",
			      tal_hex(tmpctx, err));
}


/* Mutual recursion via timer */
static void update_own_node_announcement_after_startup(struct daemon *daemon);

/* This routine created a `node_announcement` for our node, and hands it to
 * the routing.c code like any other `node_announcement`.  Such announcements
 * are only accepted if there is an announced channel associated with that node
 * (to prevent spam), so we only call this once we've announced a channel. */
static void update_own_node_announcement(struct daemon *daemon, bool startup)
{
	u32 timestamp = gossip_time_now(daemon->rstate).ts.tv_sec;
	u8 *nannounce;
	struct node *self = get_node(daemon->rstate, &daemon->id);

	/* Discard existing timer. */
	daemon->node_announce_timer = tal_free(daemon->node_announce_timer);

	/* If we ever use set-based propagation, ensuring the toggle the lower
	 * bit in consecutive timestamps makes it more robust. */
	if (self && self->bcast.index
	    && (timestamp & 1) == (self->bcast.timestamp & 1))
		timestamp++;

	/* Make unsigned announcement. */
	nannounce = create_node_announcement(tmpctx, daemon, NULL,
					     timestamp,
					     daemon->rates);

	/* If it's the same as the previous, nothing to do. */
	if (self && self->bcast.index) {
		u32 next;
		bool only_missing_tlv;

		if (!nannounce_different(daemon->rstate->gs, self, nannounce,
					 &only_missing_tlv))
			return;

		/* Missing liquidity_ad, maybe we'll get plugin callback */
		if (startup && only_missing_tlv) {
			u32 delay = GOSSIP_NANN_STARTUP_DELAY(daemon->rstate->dev_fast_gossip);
			status_debug("node_announcement: delaying"
				     " %u secs at start", delay);

			daemon->node_announce_timer
				= new_reltimer(&daemon->timers,
					       daemon,
					       time_from_sec(delay),
					       update_own_node_announcement_after_startup,
					       daemon);
			return;
		}
		/* BOLT #7:
		 *
		 * The origin node:
		 *   - MUST set `timestamp` to be greater than that of any
		 *    previous `node_announcement` it has previously created.
		 */
		/* We do better: never send them within more than 5 minutes. */
		next = self->bcast.timestamp
			+ GOSSIP_MIN_INTERVAL(daemon->rstate->dev_fast_gossip);

		if (timestamp < next) {
			status_debug("node_announcement: delaying %u secs",
				     next - timestamp);

			daemon->node_announce_timer
				= new_reltimer(&daemon->timers,
					       daemon,
					       time_from_sec(next - timestamp),
					       update_own_node_announcement_after_startup,
					       daemon);
			return;
		}
	}

	sign_and_send_nannounce(daemon, nannounce, timestamp);
}

static void update_own_node_announcement_after_startup(struct daemon *daemon)
{
	update_own_node_announcement(daemon, false);
}

/* Should we announce our own node?  Called at strategic places. */
void maybe_send_own_node_announce(struct daemon *daemon, bool startup)
{
	/* We keep an internal flag in the routing code to say we've announced
	 * a local channel.  The alternative would be to have it make a
	 * callback, but when we start up we don't want to make multiple
	 * announcments, so we use this approach for now. */
	if (!daemon->rstate->local_channel_announced)
		return;

	update_own_node_announcement(daemon, startup);
}

/* Our timer callbacks take a single argument, so we marshall everything
 * we need into this structure: */
struct local_cupdate {
	struct daemon *daemon;
	struct local_chan *local_chan;

	bool disable;
	bool even_if_identical;
	bool even_if_too_soon;

	u16 cltv_expiry_delta;
	struct amount_msat htlc_minimum, htlc_maximum;
	u32 fee_base_msat, fee_proportional_millionths;
};

/* This generates a `channel_update` message for one of our channels.  We do
 * this here, rather than in `channeld` because we (may) need to do it
 * ourselves anyway if channeld dies, or when we refresh it once a week,
 * and so we can avoid creating redundant ones. */
static void update_local_channel(struct local_cupdate *lc /* frees! */)
{
	struct daemon *daemon = lc->daemon;
	secp256k1_ecdsa_signature dummy_sig;
	u8 *update, *msg;
	u32 timestamp = gossip_time_now(daemon->rstate).ts.tv_sec, next;
	u8 message_flags, channel_flags;
	struct chan *chan = lc->local_chan->chan;
	struct half_chan *hc;
	const int direction = lc->local_chan->direction;

	/* Discard existing timer. */
	lc->local_chan->channel_update_timer
		= tal_free(lc->local_chan->channel_update_timer);

	/* So valgrind doesn't complain */
	memset(&dummy_sig, 0, sizeof(dummy_sig));

	/* Create an unsigned channel_update: we backdate enables, so
	 * we can always send a disable in an emergency. */
	if (!lc->disable)
		timestamp -= GOSSIP_MIN_INTERVAL(daemon->rstate->dev_fast_gossip);

	/* BOLT #7:
	 *
	 * The `channel_flags` bitfield is used to indicate the direction of
	 * the channel: it identifies the node that this update originated
	 * from and signals various options concerning the channel. The
	 * following table specifies the meaning of its individual bits:
	 *
	 * | Bit Position  | Name        | Meaning                          |
	 * | ------------- | ----------- | -------------------------------- |
	 * | 0             | `direction` | Direction this update refers to. |
	 * | 1             | `disable`   | Disable the channel.             |
	 */
	channel_flags = direction;
	if (lc->disable)
		channel_flags |= ROUTING_FLAGS_DISABLED;

	/* BOLT #7:
	 *
	 * The `message_flags` bitfield is used to indicate the presence of
	 * optional fields in the `channel_update` message:
	 *
	 *| Bit Position  | Name                      | Field                 |
	 *...
	 *| 0             | `option_channel_htlc_max` | `htlc_maximum_msat`   |
	 */
	message_flags = 0 | ROUTING_OPT_HTLC_MAX_MSAT;

	/* Convenience variable. */
	hc = &chan->half[direction];

	/* If we ever use set-based propagation, ensuring the toggle
	 * the lower bit in consecutive timestamps makes it more
	 * robust. */
	if (is_halfchan_defined(hc)
	    && (timestamp & 1) == (hc->bcast.timestamp & 1))
		timestamp++;

	/* We create an update with a dummy signature, and hand to hsmd to get
	 * it signed. */
	update = towire_channel_update_option_channel_htlc_max(tmpctx, &dummy_sig,
				       &chainparams->genesis_blockhash,
				       &chan->scid,
				       timestamp,
				       message_flags, channel_flags,
				       lc->cltv_expiry_delta,
				       lc->htlc_minimum,
				       lc->fee_base_msat,
				       lc->fee_proportional_millionths,
				       lc->htlc_maximum);

	if (is_halfchan_defined(hc)) {
		/* Suppress duplicates. */
		if (!lc->even_if_identical
		    && !cupdate_different(daemon->rstate->gs, hc, update)) {
			tal_free(lc);
			return;
		}

		/* Is it too soon to send another update? */
		next = hc->bcast.timestamp
			+ GOSSIP_MIN_INTERVAL(daemon->rstate->dev_fast_gossip);

		if (timestamp < next && !lc->even_if_too_soon) {
			status_debug("channel_update %s/%u: delaying %u secs",
				     type_to_string(tmpctx,
						    struct short_channel_id,
						    &chan->scid),
				     direction,
				     next - timestamp);
			lc->local_chan->channel_update_timer
				= new_reltimer(&daemon->timers, lc,
					       time_from_sec(next - timestamp),
					       update_local_channel,
					       lc);
			/* If local chan vanishes, so does update, and timer. */
			notleak(tal_steal(lc->local_chan, lc));
			return;
		}
	}

	/* Note that we treat the hsmd as synchronous.  This is simple (no
	 * callback hell)!, but may need to change to async if we ever want
	 * remote HSMs */
	if (!wire_sync_write(HSM_FD,
			     towire_hsmd_cupdate_sig_req(tmpctx, update))) {
		status_failed(STATUS_FAIL_HSM_IO, "Writing cupdate_sig_req: %s",
			      strerror(errno));
	}

	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg || !fromwire_hsmd_cupdate_sig_reply(tmpctx, msg, &update)) {
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading cupdate_sig_req: %s",
			      strerror(errno));
	}

	/* BOLT #7:
	 *
	 * The origin node:
	 *...
	 *  - MAY create a `channel_update` to communicate the channel parameters to the
	 *    channel peer, even though the channel has not yet been announced (i.e. the
	 *    `announce_channel` bit was not set).
	 */
	if (!is_chan_public(chan)) {
		/* handle_channel_update will not put private updates in the
		 * broadcast list, but we send it direct to the peer (if we
		 * have one connected) now */
		struct peer *peer = find_peer(daemon,
					      &chan->nodes[!direction]->id);
		if (peer)
			queue_peer_msg(peer, update);
	}

	/* We feed it into routing.c like any other channel_update; it may
	 * discard it (eg. non-public channel), but it should not complain
	 * about it being invalid! __func__ is a magic C constant which
	 * expands to this function name. */
	msg = handle_channel_update(daemon->rstate, update,
				    find_peer(daemon,
					      &chan->nodes[!direction]->id),
				    NULL, true);
	if (msg)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "%s: rejected local channel update %s: %s",
			      __func__,
			      /* Normally we must not touch something taken()
			       * but we're in deep trouble anyway, and
			       * handle_channel_update only tal_steals onto
			       * tmpctx, so it's actually OK. */
			      tal_hex(tmpctx, update),
			      tal_hex(tmpctx, msg));

	tal_free(lc);
}

/* This is a refresh of a local channel: sends an update if one is needed. */
void refresh_local_channel(struct daemon *daemon,
			   struct local_chan *local_chan,
			   bool even_if_identical)
{
	const struct half_chan *hc;
	struct local_cupdate *lc;
	u8 *prev;
	secp256k1_ecdsa_signature signature;
	struct bitcoin_blkid chain_hash;
	struct short_channel_id short_channel_id;
	u32 timestamp;
	u8 message_flags, channel_flags;

	hc = &local_chan->chan->half[local_chan->direction];

	/* Don't generate a channel_update for an uninitialized channel. */
	if (!is_halfchan_defined(hc))
		return;

	/* If there's an update pending already, force it to apply now. */
	if (local_chan->channel_update_timer) {
		lc = reltimer_arg(local_chan->channel_update_timer);
		lc->even_if_too_soon = true;
		update_local_channel(lc);
		/* Free timer */
		local_chan->channel_update_timer
			= tal_free(local_chan->channel_update_timer);
	}

	lc = tal(NULL, struct local_cupdate);
	lc->daemon = daemon;
	lc->local_chan = local_chan;
	lc->even_if_identical = even_if_identical;
	lc->even_if_too_soon = false;

	prev = cast_const(u8 *,
			  gossip_store_get(tmpctx, daemon->rstate->gs,
					   local_chan->chan->half[local_chan->direction]
					   .bcast.index));

	/* If it's a private update, unwrap */
	fromwire_gossip_store_private_update(tmpctx, prev, &prev);

	if (!fromwire_channel_update_option_channel_htlc_max(prev,
				     &signature, &chain_hash,
				     &short_channel_id, &timestamp,
				     &message_flags, &channel_flags,
				     &lc->cltv_expiry_delta,
				     &lc->htlc_minimum,
				     &lc->fee_base_msat,
				     &lc->fee_proportional_millionths,
				     &lc->htlc_maximum)) {
		status_broken("Could not decode local channel_update %s!",
			      tal_hex(tmpctx, prev));
		tal_free(lc);
		return;
	}

	lc->disable = (channel_flags & ROUTING_FLAGS_DISABLED)
		|| local_chan->local_disabled;
	update_local_channel(lc);
}

/* channeld asks us to update the local channel. */
bool handle_local_channel_update(struct daemon *daemon,
				 const struct node_id *src,
				 const u8 *msg)
{
	struct short_channel_id scid;
	struct local_cupdate *lc = tal(tmpctx, struct local_cupdate);

	lc->daemon = daemon;
	lc->even_if_identical = false;
	lc->even_if_too_soon = false;

	/* FIXME: We should get scid from lightningd when setting up the
	 * connection, so no per-peer daemon can mess with channels other than
	 * its own! */
	if (!fromwire_gossipd_local_channel_update(msg,
						   &scid,
						   &lc->disable,
						   &lc->cltv_expiry_delta,
						   &lc->htlc_minimum,
						   &lc->fee_base_msat,
						   &lc->fee_proportional_millionths,
						   &lc->htlc_maximum)) {
		status_peer_broken(src, "bad local_channel_update %s",
				   tal_hex(tmpctx, msg));
		return false;
	}

	lc->local_chan = local_chan_map_get(&daemon->rstate->local_chan_map,
					    &scid);
	/* Can theoretically happen if channel just closed. */
	if (!lc->local_chan) {
		status_peer_debug(src, "local_channel_update for unknown %s",
				  type_to_string(tmpctx, struct short_channel_id,
						 &scid));
		return true;
	}

	/* Remove soft local_disabled flag, if they're marking it enabled. */
	if (!lc->disable)
		local_enable_chan(daemon->rstate, lc->local_chan->chan);

	/* Apply the update they told us */
	update_local_channel(tal_steal(NULL, lc));
	return true;
}
