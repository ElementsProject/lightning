/* Routines to make our own gossip messages.  Not as in "we're the gossip
 * generation, man!" */
#include "config.h"
#include <ccan/asort/asort.h>
#include <ccan/cast/cast.h>
#include <ccan/ccan/opt/opt.h>
#include <ccan/mem/mem.h>
#include <common/daemon_conn.h>
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
#include <gossipd/gossipd_wiregen.h>
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
	struct wireaddr *was;
	u8 *addresses = tal_arr(tmpctx, u8, 0);
	u8 *announcement;
	struct tlv_node_ann_tlvs *na_tlv;
	size_t i, count_announceable;

	/* add all announceable addresses */
	count_announceable = tal_count(daemon->announceable);
	was = tal_arr(tmpctx, struct wireaddr, 0);
	for (i = 0; i < count_announceable; i++)
		tal_arr_expand(&was, daemon->announceable[i]);

	/* Add discovered IPs v4/v6 verified by peer `remote_addr` feature. */
	/* Only do that if we don't have any addresses announced or
	 * `config.ip_discovery` is explicitly enabled. */
	if ((daemon->ip_discovery == OPT_AUTOBOOL_AUTO && count_announceable == 0) ||
	     daemon->ip_discovery == OPT_AUTOBOOL_TRUE) {
		if (daemon->discovered_ip_v4 != NULL &&
		    !wireaddr_arr_contains(was, daemon->discovered_ip_v4))
			tal_arr_expand(&was, *daemon->discovered_ip_v4);
		if (daemon->discovered_ip_v6 != NULL &&
		    !wireaddr_arr_contains(was, daemon->discovered_ip_v6))
			tal_arr_expand(&was, *daemon->discovered_ip_v6);
	}

	/* Sort by address type again, as we added dynamic discovered_ip v4/v6. */
	/* BOLT #7:
	 *
	 * The origin node:
	 *...
	 *   - MUST place address descriptors in ascending order.
	 */
	asort(was, tal_count(was), wireaddr_cmp_type, NULL);

	if (!sig)
		sig = talz(tmpctx, secp256k1_ecdsa_signature);

	for (i = 0; i < tal_count(was); i++)
		towire_wireaddr(&addresses, &was[i]);

	na_tlv = tlv_node_ann_tlvs_new(tmpctx);
	na_tlv->option_will_fund = cast_const(struct lease_rates *, rates);

	announcement =
	    towire_node_announcement(ctx, sig,
				     daemon->our_features->bits[NODE_ANNOUNCE_FEATURE],
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
static void setup_force_nannounce_regen_timer(struct daemon *daemon);

/* This routine created a `node_announcement` for our node, and hands it to
 * the routing.c code like any other `node_announcement`.  Such announcements
 * are only accepted if there is an announced channel associated with that node
 * (to prevent spam), so we only call this once we've announced a channel. */
static void update_own_node_announcement(struct daemon *daemon,
					 bool startup,
					 bool always_refresh)
{
	u32 timestamp = gossip_time_now(daemon->rstate).ts.tv_sec;
	u8 *nannounce;
	struct node *self = get_node(daemon->rstate, &daemon->id);

	/* If we don't have any channels now, don't send node_announcement */
	if (!self || !node_has_broadcastable_channels(self))
		goto reset_timer;

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
					 &only_missing_tlv)) {
			if (always_refresh)
				goto send;
			/* Update if old announcement is at least 7 days old. */
			if (timestamp > self->bcast.timestamp &&
			    timestamp - self->bcast.timestamp >
			    GOSSIP_PRUNE_INTERVAL(daemon->rstate->dev_fast_gossip_prune) / 2)
				goto send;
			/* First time? Start regen timer. */
			if (!daemon->node_announce_regen_timer)
				goto reset_timer;
			return;
		}

		/* Missing liquidity_ad, maybe we'll get plugin callback */
		if (startup && only_missing_tlv) {
			u32 delay = GOSSIP_NANN_STARTUP_DELAY(daemon->rstate->dev_fast_gossip);
			status_debug("node_announcement: delaying"
				     " %u secs at start", delay);

			/* Discard existing timer. */
			daemon->node_announce_timer
				= tal_free(daemon->node_announce_timer);
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

			/* Discard existing timer. */
			daemon->node_announce_timer
				= tal_free(daemon->node_announce_timer);
			daemon->node_announce_timer
				= new_reltimer(&daemon->timers,
					       daemon,
					       time_from_sec(next - timestamp),
					       update_own_node_announcement_after_startup,
					       daemon);
			return;
		}
	}

send:
	sign_and_send_nannounce(daemon, nannounce, timestamp);

reset_timer:
	/* Generate another one in 24 hours. */
	setup_force_nannounce_regen_timer(daemon);

	return;
}

static void update_own_node_announcement_after_startup(struct daemon *daemon)
{
	update_own_node_announcement(daemon, false, false);
}

/* This creates and transmits a *new* node announcement */
static void force_self_nannounce_regen(struct daemon *daemon)
{
	update_own_node_announcement(daemon, false, true);
}

/* Because node_announcement propagation is spotty, we regenerate this every
 * 24 hours. */
static void setup_force_nannounce_regen_timer(struct daemon *daemon)
{
	struct timerel regen_time;

	/* For developers we can force a regen every 24 seconds to test */
	if (daemon->rstate->dev_fast_gossip_prune)
		regen_time = time_from_sec(24);
	else
		regen_time = time_from_sec(24 * 3600);

	tal_free(daemon->node_announce_regen_timer);
	daemon->node_announce_regen_timer
		= new_reltimer(&daemon->timers,
			       daemon,
			       regen_time,
			       force_self_nannounce_regen,
			       daemon);
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

	update_own_node_announcement(daemon, startup, false);
}

/* Fast accessors for channel_update fields */
static u8 *channel_flags_access(const u8 *channel_update)
{
	/* BOLT #7:
	 * 1. type: 258 (`channel_update`)
	 * 2. data:
	 *     * [`signature`:`signature`]
	 *     * [`chain_hash`:`chain_hash`]
	 *     * [`short_channel_id`:`short_channel_id`]
	 *     * [`u32`:`timestamp`]
	 *     * [`byte`:`message_flags`]
	 *     * [`byte`:`channel_flags`]
	 */
	/* Note: 2 bytes for `type` field */
	return cast_const(u8 *, &channel_update[2 + 64 + 32 + 8 + 4 + 1]);
}

static u8 *timestamp_access(const u8 *channel_update)
{
	/* BOLT #7:
	 * 1. type: 258 (`channel_update`)
	 * 2. data:
	 *     * [`signature`:`signature`]
	 *     * [`chain_hash`:`chain_hash`]
	 *     * [`short_channel_id`:`short_channel_id`]
	 *     * [`u32`:`timestamp`]
	 *     * [`byte`:`message_flags`]
	 *     * [`byte`:`channel_flags`]
	 */
	/* Note: 2 bytes for `type` field */
	return cast_const(u8 *, &channel_update[2 + 64 + 32 + 8]);
}

static bool is_disabled(const u8 *channel_update)
{
	return *channel_flags_access(channel_update) & ROUTING_FLAGS_DISABLED;
}

static bool is_enabled(const u8 *channel_update)
{
	return !is_disabled(channel_update);
}


static u32 timestamp_for_update(struct daemon *daemon,
				const u32 *prev_timestamp,
				bool disable)
{
	u32 timestamp = gossip_time_now(daemon->rstate).ts.tv_sec;

	/* Create an unsigned channel_update: we backdate enables, so
	 * we can always send a disable in an emergency. */
	if (!disable)
		timestamp -= GOSSIP_MIN_INTERVAL(daemon->rstate->dev_fast_gossip);

	if (prev_timestamp) {
		/* Timestamps can't go backwards! */
		if (timestamp < *prev_timestamp)
			timestamp = *prev_timestamp + 1;

		/* If we ever use set-based propagation, ensuring the toggle
		 * the lower bit in consecutive timestamps makes it more
		 * robust. */
		if ((timestamp & 1) == (*prev_timestamp & 1))
			timestamp++;
	}

	return timestamp;
}

static u8 *sign_and_timestamp_update(const tal_t *ctx,
				     struct daemon *daemon,
				     const struct chan *chan,
				     int direction,
				     u8 *unsigned_update TAKES)
{
	u8 *msg, *update;
	be32 timestamp;
	const u32 *prev_timestamp;
	const struct half_chan *hc = &chan->half[direction];

	if (is_halfchan_defined(hc))
		prev_timestamp = &hc->bcast.timestamp;
	else
		prev_timestamp = NULL;

	/* Get an appropriate timestamp */
	timestamp = cpu_to_be32(timestamp_for_update(daemon,
						     prev_timestamp,
						     is_disabled(unsigned_update)));
	memcpy(timestamp_access(unsigned_update), &timestamp, sizeof(timestamp));

	/* Note that we treat the hsmd as synchronous.  This is simple (no
	 * callback hell)!, but may need to change to async if we ever want
	 * remote HSMs */
	if (!wire_sync_write(HSM_FD,
			     towire_hsmd_cupdate_sig_req(tmpctx, unsigned_update))) {
		status_failed(STATUS_FAIL_HSM_IO, "Writing cupdate_sig_req: %s",
			      strerror(errno));
	}

	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!msg || !fromwire_hsmd_cupdate_sig_reply(ctx, msg, &update)) {
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading cupdate_sig_req: %s",
			      strerror(errno));
	}

	if (taken(unsigned_update))
		tal_free(unsigned_update);

	/* Tell lightningd about this immediately (even if we're not actually
	 * applying it now).  We choose not to send info about private
	 * channels, even in errors. */
	if (is_chan_public(chan)) {
		msg = towire_gossipd_got_local_channel_update(NULL, &chan->scid,
							      update);
		daemon_conn_send(daemon->master, take(msg));
	}

	return update;
}

static u8 *create_unsigned_update(const tal_t *ctx,
				  const struct short_channel_id *scid,
				  int direction,
				  bool disable,
				  u16 cltv_expiry_delta,
				  struct amount_msat htlc_minimum,
				  struct amount_msat htlc_maximum,
				  u32 fee_base_msat,
				  u32 fee_proportional_millionths,
				  bool public)
{
	secp256k1_ecdsa_signature dummy_sig;
	u8 message_flags, channel_flags;

	/* So valgrind doesn't complain */
	memset(&dummy_sig, 0, sizeof(dummy_sig));

	/* BOLT-f3a9f7f4e9e7a5a2997f3129e13d94090091846a #7:
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
	if (disable)
		channel_flags |= ROUTING_FLAGS_DISABLED;

	/* BOLT #7:
	 *
	 * The `message_flags` bitfield is used to provide additional
	 * details about the message:
	 *
	 * | Bit Position  | Name           |
	 * | ------------- | ---------------|
	 * | 0             | `must_be_one`  |
	 * | 1             | `dont_forward` |
	 */
	message_flags = ROUTING_OPT_HTLC_MAX_MSAT;
	if (!public)
		message_flags |= ROUTING_OPT_DONT_FORWARD;

	/* We create an update with a dummy signature and timestamp. */
	return towire_channel_update(ctx,
				       &dummy_sig, /* sig set later */
				       &chainparams->genesis_blockhash,
				       scid,
				       0, /* timestamp set later */
				       message_flags, channel_flags,
				       cltv_expiry_delta,
				       htlc_minimum,
				       fee_base_msat,
				       fee_proportional_millionths,
				       htlc_maximum);
}

static void apply_update(struct daemon *daemon,
			 const struct chan *chan,
			 int direction,
			 u8 *update TAKES)
{
	u8 *msg;
	struct peer *peer = find_peer(daemon, &chan->nodes[!direction]->id);

	if (!is_chan_public(chan)) {
		/* Save and restore taken state, for handle_channel_update */
		bool update_taken = taken(update);

		/* handle_channel_update will not put private updates in the
		 * broadcast list, but we send it direct to the peer (if we
		 * have one connected) now */
		if (peer)
			queue_peer_msg(peer, update);

		if (update_taken)
			take(update);
	}

	msg = handle_channel_update(daemon->rstate, update, &chan->nodes[!direction]->id, NULL, true);
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
}

static void sign_timestamp_and_apply_update(struct daemon *daemon,
					    const struct chan *chan,
					    int direction,
					    u8 *update TAKES)
{
	update = sign_and_timestamp_update(NULL, daemon, chan, direction,
					   update);
	apply_update(daemon, chan, direction, take(update));
}

/* We don't want to thrash the gossip network, so we often defer sending an
 * update.  We track them here. */
struct deferred_update {
	/* Off daemon->deferred_updates (our leak detection needs this as
	 * first element in struct, because it's dumb!) */
	struct list_node list;
	/* The daemon */
	struct daemon *daemon;
	/* Channel it's for (and owner) */
	const struct chan *chan;
	int direction;
	/* Timer which will fire when it's time to apply. */
	struct oneshot *channel_update_timer;
	/* The actual `update_channel` to apply */
	u8 *update;
};

static struct deferred_update *find_deferred_update(struct daemon *daemon,
						    const struct chan *chan)
{
	struct deferred_update *du;

	list_for_each(&daemon->deferred_updates, du, list) {
		if (du->chan == chan)
			return du;
	}
	return NULL;
}

static void destroy_deferred_update(struct deferred_update *du)
{
	list_del(&du->list);
}

static void apply_deferred_update(struct deferred_update *du)
{
	apply_update(du->daemon, du->chan, du->direction, take(du->update));
	tal_free(du);
}

static void defer_update(struct daemon *daemon,
			 u32 delay,
			 const struct chan *chan,
			 int direction,
			 u8 *unsigned_update TAKES)
{
	struct deferred_update *du;

	/* Override any existing one */
	tal_free(find_deferred_update(daemon, chan));

	/* If chan is gone, so are we. */
	du = tal(chan, struct deferred_update);
	du->daemon = daemon;
	du->chan = chan;
	du->direction = direction;
	du->update = sign_and_timestamp_update(du, daemon, chan, direction,
					       unsigned_update);
	if (delay != 0xFFFFFFFF)
		du->channel_update_timer = new_reltimer(&daemon->timers, du,
							time_from_sec(delay),
							apply_deferred_update,
							du);
	else
		du->channel_update_timer = NULL;
	list_add_tail(&daemon->deferred_updates, &du->list);
	tal_add_destructor(du, destroy_deferred_update);
}

/* If there is a pending update for this local channel, apply immediately. */
static bool local_channel_update_latest(struct daemon *daemon, struct chan *chan)
{
	struct deferred_update *du;

	du = find_deferred_update(daemon, chan);
	if (!du)
		return false;

	/* Frees itself */
	apply_deferred_update(du);
	return true;
}

/* Get previous update. */
static u8 *prev_update(const tal_t *ctx,
		       struct daemon *daemon, const struct chan *chan, int direction)
{
	u8 *prev;

	if (!is_halfchan_defined(&chan->half[direction]))
		return NULL;

	prev = cast_const(u8 *,
			  gossip_store_get(tmpctx, daemon->rstate->gs,
					   chan->half[direction].bcast.index));

	/* If it's a private update, unwrap */
	if (!fromwire_gossip_store_private_update(ctx, prev, &prev))
		tal_steal(ctx, prev);
	return prev;
}

/* This is a refresh of a local channel (after 13 days). */
void refresh_local_channel(struct daemon *daemon,
			   struct chan *chan, int direction)
{
	u16 cltv_expiry_delta;
	struct amount_msat htlc_minimum, htlc_maximum;
	u32 fee_base_msat, fee_proportional_millionths, timestamp;
	u8 *prev, *update;
	u8 message_flags, channel_flags;
	secp256k1_ecdsa_signature signature;
	struct bitcoin_blkid chain_hash;
	struct short_channel_id short_channel_id;

	/* If there's a pending update, apply it and we're done. */
	if (local_channel_update_latest(daemon, chan))
		return;

	prev = prev_update(tmpctx, daemon, chan, direction);
	if (!prev)
		return;

	if (!fromwire_channel_update(prev,
				     &signature, &chain_hash,
				     &short_channel_id, &timestamp,
				     &message_flags, &channel_flags,
				     &cltv_expiry_delta,
				     &htlc_minimum,
				     &fee_base_msat,
				     &fee_proportional_millionths,
				     &htlc_maximum)) {
		status_broken("Could not decode local channel_update %s!",
			      tal_hex(tmpctx, prev));
		return;
	}

	/* BOLT-f3a9f7f4e9e7a5a2997f3129e13d94090091846a #7:
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
	if (direction != (channel_flags & ROUTING_FLAGS_DIRECTION)) {
		status_broken("Wrong channel direction %s!",
			      tal_hex(tmpctx, prev));
		return;
	}

	/* Don't refresh disabled channels. */
	if (channel_flags & ROUTING_FLAGS_DISABLED)
		return;

	update = create_unsigned_update(NULL, &short_channel_id, direction,
					false, cltv_expiry_delta,
					htlc_minimum, htlc_maximum,
					fee_base_msat,
					fee_proportional_millionths,
					!(message_flags & ROUTING_OPT_DONT_FORWARD));
	sign_timestamp_and_apply_update(daemon, chan, direction, take(update));
}

/* channeld (via lightningd) asks us to update the local channel. */
void handle_local_channel_update(struct daemon *daemon, const u8 *msg)
{
	struct node_id id;
	struct short_channel_id scid;
	bool disable;
	u16 cltv_expiry_delta;
	struct amount_msat htlc_minimum, htlc_maximum;
	u32 fee_base_msat, fee_proportional_millionths;
	struct chan *chan;
	int direction;
	u8 *unsigned_update;
	const struct half_chan *hc;
	bool public;

	if (!fromwire_gossipd_local_channel_update(msg,
						   &id,
						   &scid,
						   &disable,
						   &cltv_expiry_delta,
						   &htlc_minimum,
						   &fee_base_msat,
						   &fee_proportional_millionths,
						   &htlc_maximum,
						   &public)) {
		master_badmsg(WIRE_GOSSIPD_LOCAL_CHANNEL_UPDATE, msg);
	}

	chan = get_channel(daemon->rstate, &scid);
	/* Can theoretically happen if channel just closed. */
	if (!chan) {
		status_peer_debug(&id, "local_channel_update for unknown %s",
				  type_to_string(tmpctx, struct short_channel_id,
						 &scid));
		return;
	}

	if (!local_direction(daemon->rstate, chan, &direction)) {
		status_peer_broken(&id, "bad local_channel_update chan %s",
				   type_to_string(tmpctx,
						  struct short_channel_id,
						  &scid));
		return;
	}

	unsigned_update = create_unsigned_update(tmpctx, &scid, direction,
						 disable, cltv_expiry_delta,
						 htlc_minimum, htlc_maximum,
						 fee_base_msat,
						 fee_proportional_millionths,
						 public);

	hc = &chan->half[direction];

	/* Ignore duplicates. */
	if (is_halfchan_defined(hc)
	    && !cupdate_different(daemon->rstate->gs, hc, unsigned_update))
		return;

	/* Too early?  Defer (don't worry if it's unannounced). */
	if (is_halfchan_defined(hc) && is_chan_public(chan)) {
		u32 now = time_now().ts.tv_sec;
		u32 next_time = hc->bcast.timestamp
			+ GOSSIP_MIN_INTERVAL(daemon->rstate->dev_fast_gossip);
		if (now < next_time) {
			defer_update(daemon, next_time - now,
				     chan, direction, take(unsigned_update));
			return;
		}
	}

	sign_timestamp_and_apply_update(daemon, chan, direction,
					take(unsigned_update));
}

/* Take update, set/unset disabled flag (and update timestamp).
 */
static void set_disable_flag(u8 *channel_update, bool disable)
{
	u8 *channel_flags = channel_flags_access(channel_update);

	if (disable)
		*channel_flags |= ROUTING_FLAGS_DISABLED;
	else
		*channel_flags &= ~ROUTING_FLAGS_DISABLED;
}

/* We don't immediately disable, to avoid flapping. */
void local_disable_chan(struct daemon *daemon, const struct chan *chan, int direction)
{
	struct deferred_update *du;
	u8 *update = prev_update(tmpctx, daemon, chan, direction);
	if (!update)
		return;

	du = find_deferred_update(daemon, chan);

	/* Will a deferred update disable it already?  OK, nothing to do. */
	if (du && is_disabled(du->update))
		return;

	/* OK, we definitely don't want deferred update to re-enable! */
	tal_free(du);

	/* Is it already disabled? */
	if (is_disabled(update))
		return;

	/* This is deferred indefinitely (flushed if needed though) */
	set_disable_flag(update, true);
	defer_update(daemon, 0xFFFFFFFF, chan, direction, take(update));
}

/* lightningd tells us it used the local channel update. */
void handle_used_local_channel_update(struct daemon *daemon, const u8 *msg)
{
	struct short_channel_id scid;
	struct chan *chan;

	if (!fromwire_gossipd_used_local_channel_update(msg, &scid))
		master_badmsg(WIRE_GOSSIPD_USED_LOCAL_CHANNEL_UPDATE, msg);

	chan = get_channel(daemon->rstate, &scid);
	/* Might have closed in meantime, but v unlikely! */
	if (!chan) {
		status_broken("used_local_channel_update on unknown %s",
			      type_to_string(tmpctx, struct short_channel_id,
					     &scid));
		return;
	}

	/* This whole idea is racy: they might have used a *previous* update.
	 * But that's OK: the notification is an optimization to avoid
	 * broadcasting updates we never use (route flapping).  In this case,
	 * we might broadcast a more recent update than the one we sent to a
	 * peer. */
	local_channel_update_latest(daemon, chan);
}

void local_enable_chan(struct daemon *daemon, const struct chan *chan, int direction)
{
	struct deferred_update *du;
	u8 *update = prev_update(tmpctx, daemon, chan, direction);


	if (!update)
		return;

	du = find_deferred_update(daemon, chan);

	/* Will a deferred update enable it?  If so, apply immediately. */
	if (du && is_enabled(du->update)) {
		apply_deferred_update(du);
		return;
	}

	/* OK, we definitely don't want deferred update to disable! */
	tal_free(du);

	/* Is it already enabled? */
	if (is_enabled(update))
		return;

	/* Apply this enabling update immediately. */
	set_disable_flag(update, false);
	sign_timestamp_and_apply_update(daemon, chan, direction, take(update));
}
