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

