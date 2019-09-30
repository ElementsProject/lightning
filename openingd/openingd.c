/*~ Welcome to the opening daemon: gateway to channels!
 *
 * This daemon handles a single peer.  It's happy to trade gossip with the
 * peer until either lightningd asks it to fund a channel, or the peer itself
 * asks to fund a channel.  Then it goes through with the channel opening
 * negotiations.  It's important to note that until this negotiation is complete,
 * there's nothing permanent about the channel: lightningd will only have to
 * commit to the database once openingd succeeds.
 */
#include <bitcoin/block.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/cast/cast.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/mem/mem.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/tal/str/str.h>
#include <common/crypto_sync.h>
#include <common/derive_basepoints.h>
#include <common/features.h>
#include <common/fee_states.h>
#include <common/funding_tx.h>
#include <common/gen_peer_status_wire.h>
#include <common/gossip_rcvd_filter.h>
#include <common/gossip_store.h>
#include <common/initial_channel.h>
#include <common/key_derive.h>
#include <common/memleak.h>
#include <common/overflows.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/pseudorand.h>
#include <common/read_peer_msg.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/version.h>
#include <common/wire_error.h>
#include <errno.h>
#include <gossipd/gen_gossip_peerd_wire.h>
#include <hsmd/gen_hsm_wire.h>
#include <inttypes.h>
#include <openingd/channel_establishment.h>
#include <openingd/gen_opening_wire.h>
#include <poll.h>
#include <secp256k1.h>
#include <stdio.h>
#include <wally_bip32.h>
#include <wire/gen_common_wire.h>
#include <wire/gen_peer_wire.h>
#include <wire/peer_wire.h>
#include <wire/wire.h>
#include <wire/wire_sync.h>

/* stdin == lightningd, 3 == peer, 4 == gossipd, 5 = gossip_store, 6 = hsmd */
#define REQ_FD STDIN_FILENO
#define HSM_FD 6

#if DEVELOPER
/* If --dev-force-tmp-channel-id is set, it ends up here */
static struct channel_id *dev_force_tmp_channel_id;
#endif /* DEVELOPER */

/* Global state structure.  This is only for the one specific peer and channel */
struct state {
	struct per_peer_state *pps;

	/* Features they offered */
	u8 *their_features;

	/* Constraints on a channel they open. */
	u32 minimum_depth;
	u32 min_feerate, max_feerate;
	struct amount_msat min_effective_htlc_capacity;

	/* Limits on what remote config we accept. */
	u32 max_to_self_delay;

	/* These are the points lightningd told us to use when accepting or
	 * opening a channel. */
	struct basepoints our_points;
	struct pubkey our_funding_pubkey;

	/* Information we need between funding_start and funding_complete */
	struct basepoints their_points;
	struct pubkey their_funding_pubkey;

	/* hsmd gives us our first per-commitment point, and peer tells us
	 * theirs */
	struct pubkey first_per_commitment_point[NUM_SIDES];

	/* Initially temporary, then final channel id. */
	struct channel_id channel_id;

	/* Funding and feerate: set by opening peer. */
	struct amount_sat opener_funding;
	struct amount_msat push_msat;
	u32 feerate_per_kw;
	struct bitcoin_txid funding_txid;
	u16 funding_txout;

	/* If non-NULL, this is the scriptpubkey we/they *must* close with */
	u8 *upfront_shutdown_script[NUM_SIDES];

	/* This is a cluster of fields in open_channel and accept_channel which
	 * indicate the restrictions each side places on the channel. */
	struct channel_config localconf, remoteconf;

	/* The channel structure, as defined in common/initial_channel.h.  While
	 * the structure has room for HTLCs, those routines are channeld-specific
	 * as initial channels never have HTLCs. */
	struct channel *channel;

	bool option_static_remotekey;

	struct feature_set *our_features;

	/* Things for v2 */
	bool use_v2;
	struct amount_sat accepter_funding;
	u32 feerate_per_kw_funding;
};

static u8 *dev_upfront_shutdown_script(const tal_t *ctx)
{
#if DEVELOPER
	/* This is a hack, for feature testing */
	const char *e = getenv("DEV_OPENINGD_UPFRONT_SHUTDOWN_SCRIPT");
	if (e)
		return tal_hexdata(ctx, e, strlen(e));
#endif
	return NULL;
}


static struct amount_sat total_funding(const struct state *state)
{
	struct amount_sat total;
	if (!amount_sat_add(&total, state->opener_funding,
			    state->accepter_funding))
		abort();

	return total;

}

/*~ If we can't agree on parameters, we fail to open the channel.  If we're
 * the opener, we need to tell lightningd, otherwise it never really notices. */
static void negotiation_aborted(struct state *state, bool am_opener,
				const char *why)
{
	status_debug("aborted opening negotiation: %s", why);
	/*~ The "billboard" (exposed as "status" in the JSON listpeers RPC
	 * call) is a transient per-channel area which indicates important
	 * information about what is happening.  It has a "permanent" area for
	 * each state, which can be used to indicate what went wrong in that
	 * state (such as here), and a single transient area for current
	 * status. */
	peer_billboard(true, why);

	/* If necessary, tell master that funding failed. */
	if (am_opener) {
		u8 *msg = towire_opening_funder_failed(NULL, why);
		wire_sync_write(REQ_FD, take(msg));
	}

	/* Default is no shutdown_scriptpubkey: free any leftover ones. */
	state->upfront_shutdown_script[LOCAL]
		= tal_free(state->upfront_shutdown_script[LOCAL]);
	state->upfront_shutdown_script[REMOTE]
		= tal_free(state->upfront_shutdown_script[REMOTE]);

	/*~ Reset state.  We keep gossipping with them, even though this open
	* failed. */
	memset(&state->channel_id, 0, sizeof(state->channel_id));
	state->channel = tal_free(state->channel);
}

/*~ For negotiation failures: we tell them the parameter we didn't like. */
static void negotiation_failed(struct state *state, bool am_opener,
			       const char *fmt, ...)
{
	va_list ap;
	const char *errmsg;
	u8 *msg;

	va_start(ap, fmt);
	errmsg = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	msg = towire_errorfmt(NULL, &state->channel_id,
			      "You gave bad parameters: %s", errmsg);
	sync_crypto_write(state->pps, take(msg));

	negotiation_aborted(state, am_opener, errmsg);
}

/*~ This is the key function that checks that their configuration is reasonable:
 * it applied for both the case where they're trying to open a channel, and when
 * they've accepted our open. */
static bool check_config_bounds(struct state *state,
				const struct channel_config *remoteconf,
				bool am_opener)
{
	struct amount_sat capacity, reserve, all_funding;

	all_funding = total_funding(state);

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `to_self_delay` is unreasonably large.
	 */
	if (remoteconf->to_self_delay > state->max_to_self_delay) {
		negotiation_failed(state, am_opener,
				   "to_self_delay %u larger than %u",
				   remoteconf->to_self_delay,
				   state->max_to_self_delay);
		return false;
	}

	/* BOLT #2:
	 *
	 * The receiving node MAY fail the channel if:
	 *...
	 *   - `funding_satoshis` is too small.
	 *   - it considers `htlc_minimum_msat` too large.
	 *   - it considers `max_htlc_value_in_flight_msat` too small.
	 *   - it considers `channel_reserve_satoshis` too large.
	 *   - it considers `max_accepted_htlcs` too small.
	 */
	/* We accumulate this into an effective bandwidth minimum. */

	/* Add both reserves to deduct from capacity. */
	if (!amount_sat_add(&reserve,
			    remoteconf->channel_reserve,
			    state->localconf.channel_reserve)) {
		negotiation_failed(state, am_opener,
				   "channel_reserve_satoshis %s"
				   " too large",
				   type_to_string(tmpctx, struct amount_sat,
						  &remoteconf->channel_reserve));
		return false;
	}

	/* If reserves are larger than total sat, we fail. */
	if (!amount_sat_sub(&capacity, all_funding, reserve)) {
		negotiation_failed(state, am_opener,
				   "channel_reserve_satoshis %s"
				   " and %s too large for funding %s",
				   type_to_string(tmpctx, struct amount_sat,
						  &remoteconf->channel_reserve),
				   type_to_string(tmpctx, struct amount_sat,
						  &state->localconf.channel_reserve),
				   type_to_string(tmpctx, struct amount_sat,
						  &all_funding));
		return false;
	}

	/* If they set the max HTLC value to less than that number, it caps
	 * the channel capacity. */
	if (amount_sat_greater(capacity,
			       amount_msat_to_sat_round_down(remoteconf->max_htlc_value_in_flight)))
		capacity = amount_msat_to_sat_round_down(remoteconf->max_htlc_value_in_flight);

	/* If the minimum htlc is greater than the capacity, the channel is
	 * useless. */
	if (amount_msat_greater_sat(remoteconf->htlc_minimum, capacity)) {
		negotiation_failed(state, am_opener,
				   "htlc_minimum_msat %s"
				   " too large for funding %s"
				   " capacity_msat %s",
				   type_to_string(tmpctx, struct amount_msat,
						  &remoteconf->htlc_minimum),
				   type_to_string(tmpctx, struct amount_sat,
						  &all_funding),
				   type_to_string(tmpctx, struct amount_sat,
						  &capacity));
		return false;
	}

	/* If the resulting channel doesn't meet our minimum "effective capacity"
	 * set by lightningd, don't bother opening it. */
	if (amount_msat_greater_sat(state->min_effective_htlc_capacity,
				    capacity)) {
		negotiation_failed(state, am_opener,
				   "channel capacity with funding %s,"
				   " reserves %s/%s,"
				   " max_htlc_value_in_flight_msat is %s,"
				   " channel capacity is %s, which is below %s",
				   type_to_string(tmpctx, struct amount_sat,
						  &all_funding),
				   type_to_string(tmpctx, struct amount_sat,
						  &remoteconf->channel_reserve),
				   type_to_string(tmpctx, struct amount_sat,
						  &state->localconf.channel_reserve),
				   type_to_string(tmpctx, struct amount_msat,
						  &remoteconf->max_htlc_value_in_flight),
				   type_to_string(tmpctx, struct amount_sat,
						  &capacity),
				   type_to_string(tmpctx, struct amount_msat,
						  &state->min_effective_htlc_capacity));
		return false;
	}

	/* We don't worry about how many HTLCs they accept, as long as > 0! */
	if (remoteconf->max_accepted_htlcs == 0) {
		negotiation_failed(state, am_opener,
				   "max_accepted_htlcs %u invalid",
				   remoteconf->max_accepted_htlcs);
		return false;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `max_accepted_htlcs` is greater than 483.
	 */
	if (remoteconf->max_accepted_htlcs > 483) {
		negotiation_failed(state, am_opener,
				   "max_accepted_htlcs %u too large",
				   remoteconf->max_accepted_htlcs);
		return false;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `dust_limit_satoshis` is greater than `channel_reserve_satoshis`.
	 */
	if (amount_sat_greater(remoteconf->dust_limit,
			       remoteconf->channel_reserve)) {
		negotiation_failed(state, am_opener,
				   "dust_limit_satoshis %s"
				   " too large for channel_reserve_satoshis %s",
				   type_to_string(tmpctx, struct amount_sat,
						  &remoteconf->dust_limit),
				   type_to_string(tmpctx, struct amount_sat,
						  &remoteconf->channel_reserve));
		return false;
	}

	return true;
}

/* We always set channel_reserve_satoshis to 1%, rounded down. */
static void set_reserve(struct state *state)
{
	state->localconf.channel_reserve.satoshis  /* Raw: rounding. */
		= total_funding(state).satoshis / 100;   /* Raw: rounding. */

	/* BOLT #2:
	 *
	 * The sending node:
	 *...
	 * - MUST set `channel_reserve_satoshis` greater than or equal to
         *   `dust_limit_satoshis`.
	 */
	if (amount_sat_greater(state->localconf.dust_limit,
			       state->localconf.channel_reserve))
		state->localconf.channel_reserve
			= state->localconf.dust_limit;

	/* Early return if we're not setting the remote's also (v2) */
	if (!state->use_v2)
		return;

	state->remoteconf.channel_reserve.satoshis  /* Raw: rounding. */
		= total_funding(state).satoshis / 100;   /* Raw: rounding. */

	if (amount_sat_greater(state->remoteconf.dust_limit,
			       state->remoteconf.channel_reserve))
		state->remoteconf.channel_reserve
			= state->remoteconf.dust_limit;
}

/* BOLT #2:
 *
 * The sending node:
 *...
 *  - MUST ensure `temporary_channel_id` is unique from any other channel ID
 *    with the same peer.
 */
static void temporary_channel_id(struct channel_id *channel_id)
{
	size_t i;

	/* Randomness FTW. */
	for (i = 0; i < sizeof(*channel_id); i++)
		channel_id->id[i] = pseudorand(256);
}

/*~ Handle random messages we might get during opening negotiation, (eg. gossip)
 * returning the first non-handled one, or NULL if we aborted negotiation. */
static u8 *opening_negotiate_msg(const tal_t *ctx, struct state *state,
				 bool am_opener)
{
	/* This is an event loop of its own.  That's generally considered poor
	 * form, but we use it in a very limited way. */
	for (;;) {
		u8 *msg;
		bool from_gossipd;
		char *err;
		bool all_channels;
		struct channel_id actual;

		/* The event loop is responsible for freeing tmpctx, so our
		 * temporary allocations don't grow unbounded. */
		clean_tmpctx();

		/* This helper routine polls both the peer and gossipd. */
		msg = peer_or_gossip_sync_read(ctx, state->pps, &from_gossipd);

		/* Use standard helper for gossip msgs (forwards, if it's an
		 * error, exits). */
		if (from_gossipd) {
			handle_gossip_msg(state->pps, take(msg));
			continue;
		}

		/* Some messages go straight to gossipd. */
		if (is_msg_for_gossipd(msg)) {
			gossip_rcvd_filter_add(state->pps->grf, msg);
			wire_sync_write(state->pps->gossip_fd, take(msg));
			continue;
		}

		/* BOLT #1:
		 *
		 * A receiving node:
		 *   - upon receiving a message of _odd_, unknown type:
		 *     - MUST ignore the received message.
		 */
		if (is_unknown_msg_discardable(msg))
			continue;

		/* Might be a timestamp filter request: handle. */
		if (handle_timestamp_filter(state->pps, msg))
			continue;

		/* A helper which decodes an error. */
		if (is_peer_error(tmpctx, msg, &state->channel_id,
				  &err, &all_channels)) {
			/* BOLT #1:
			 *
			 *  - if no existing channel is referred to by the
			 *    message:
			 *    - MUST ignore the message.
			 */
			/* In this case, is_peer_error returns true, but sets
			 * err to NULL */
			if (!err) {
				tal_free(msg);
				continue;
			}
			/* Close connection on all_channels error. */
			if (all_channels) {
				if (am_opener) {
					msg = towire_opening_funder_failed(NULL,
									   err);
					wire_sync_write(REQ_FD, take(msg));
				}
				peer_failed_received_errmsg(state->pps, err,
							    NULL, false);
			}
			negotiation_aborted(state, am_opener,
					    tal_fmt(tmpctx, "They sent error %s",
						    err));
			/* Return NULL so caller knows to stop negotiating. */
			return NULL;
		}

		/*~ We do not support multiple "live" channels, though the
		 * protocol has a "channel_id" field in all non-gossip messages
		 * so it's possible.  Our one-process-one-channel mechanism
		 * keeps things simple: if we wanted to change this, we would
		 * probably be best with another daemon to de-multiplex them;
		 * this could be connectd itself, in fact. */
		if (is_wrong_channel(msg, &state->channel_id, &actual)) {
			status_debug("Rejecting %s for unknown channel_id %s",
				     wire_type_name(fromwire_peektype(msg)),
				     type_to_string(tmpctx, struct channel_id,
						    &actual));
			sync_crypto_write(state->pps,
					  take(towire_errorfmt(NULL, &actual,
							       "Multiple channels"
							       " unsupported")));
			tal_free(msg);
			continue;
		}

		/* If we get here, it's an interesting message. */
		return msg;
	}
}

static bool check_reserves(struct state *state)
{
	/* BOLT #2:
	 *
	 * The receiver:
	 *...
	 *  - if `channel_reserve_satoshis` is less than `dust_limit_satoshis`
	 *    within the `open_channel` message:
	 *    - MUST reject the channel.
	 *
	 *  - if `channel_reserve_satoshis` from the `open_channel` message is
	 *    less than `dust_limit_satoshis`:
	 *    - MUST reject the channel.
	 */
	if (amount_sat_greater(state->localconf.dust_limit,
			       state->remoteconf.channel_reserve)) {
		negotiation_failed(state, true,
				   "channel reserve %s"
				   " would be below our dust %s",
				   type_to_string(tmpctx, struct amount_sat,
						  &state->remoteconf.channel_reserve),
				   type_to_string(tmpctx, struct amount_sat,
						  &state->localconf.dust_limit));
		return false;
	}
	if (amount_sat_greater(state->remoteconf.dust_limit,
			       state->localconf.channel_reserve)) {
		negotiation_failed(state, true,
				   "dust limit %s"
				   " would be above our reserve %s",
				   type_to_string(tmpctx, struct amount_sat,
						  &state->remoteconf.dust_limit),
				   type_to_string(tmpctx, struct amount_sat,
						  &state->localconf.channel_reserve));
		return false;
	}
	return true;
}

static bool setup_channel_funder(struct state *state)
{
	if (!state->use_v2) {
		/*~ For symmetry, we calculate our own reserve even though lightningd
		 * could do it for the we-are-funding case. */
		state->accepter_funding = AMOUNT_SAT(0);
		set_reserve(state);
	}

	/*~ Grab a random ID until the funding tx is created (we can't do that
	 * until we know their funding_pubkey) */
	temporary_channel_id(&state->channel_id);

#if DEVELOPER
	/* --dev-force-tmp-channel-id specified */
	if (dev_force_tmp_channel_id)
		state->channel_id = *dev_force_tmp_channel_id;
#endif
	/* BOLT #2:
	 *
	 * The sending node:
	 *...
	 *  - if both nodes advertised `option_support_large_channel`:
	 *    - MAY set `funding_satoshis` greater than or equal to 2^24 satoshi.
	 *  - otherwise:
	 *    - MUST set `funding_satoshis` to less than 2^24 satoshi.
	 */
	if (!feature_negotiated(state->our_features,
				state->their_features, OPT_LARGE_CHANNELS)
	    && amount_sat_greater(state->opener_funding, chainparams->max_funding)) {
		status_failed(STATUS_FAIL_MASTER_IO,
			      "funding_satoshis must be < %s, not %s",
			      type_to_string(tmpctx, struct amount_sat,
					     &chainparams->max_funding),
			      type_to_string(tmpctx, struct amount_sat,
					     &state->opener_funding));
		return false;
	}

	return true;
}

/* We start the 'fund a channel' negotation with the supplied peer, but
 * stop when we get to the part where we need the funding txid */
static u8 *funder_channel_start(struct state *state, u8 channel_flags)
{
	u8 *msg;
	u8 *funding_output_script;
	struct channel_id id_in;

	if (!setup_channel_funder(state))
		return NULL;

	/* BOLT #2:
	 *
	 * - if both nodes advertised the `option_upfront_shutdown_script`
	 *   feature:
	 *   - MUST include either a valid `shutdown_scriptpubkey` as required
	 *     by `shutdown` `scriptpubkey`, or a zero-length
	 *     `shutdown_scriptpubkey`.
	 * - otherwise:
	 *   - MAY include a`shutdown_scriptpubkey`.
	 */
	if (!state->upfront_shutdown_script[LOCAL])
		state->upfront_shutdown_script[LOCAL] = dev_upfront_shutdown_script(state);

	if (state->use_v2) {
#if EXPERIMENTAL_FEATURES
		struct tlv_opening_tlvs *tlv = tlv_opening_tlvs_new(tmpctx);
		if (state->upfront_shutdown_script[LOCAL]) {
			tlv->option_upfront_shutdown_script =
				tal(tlv, struct tlv_opening_tlvs_option_upfront_shutdown_script);
			tlv->option_upfront_shutdown_script->shutdown_scriptpubkey =
				state->upfront_shutdown_script[LOCAL];
		}

		/* For now, we use the same feerate for funding + commitment tx */
		/* FIXME: allow these to be done separately? */
		state->feerate_per_kw_funding = state->feerate_per_kw;
		msg = towire_open_channel2(NULL,
					   &chainparams->genesis_blockhash,
					   &state->channel_id,
					   state->opener_funding,
					   state->push_msat,
					   state->localconf.dust_limit,
					   state->localconf.max_htlc_value_in_flight,
					   state->localconf.htlc_minimum,
					   state->feerate_per_kw,
					   state->feerate_per_kw_funding,
					   state->localconf.to_self_delay,
					   state->localconf.max_accepted_htlcs,
					   &state->our_funding_pubkey,
					   &state->our_points.revocation,
					   &state->our_points.payment,
					   &state->our_points.delayed_payment,
					   &state->our_points.htlc,
					   &state->first_per_commitment_point[LOCAL],
					   channel_flags,
					   tlv);
#else
		peer_failed(state->pps,
			    &state->channel_id,
			    "Bad state: signaled v2 channel_open but missing "
			    "experimental features.");
#endif /* EXPERIMENTAL_FEATURES */
	} else {
		/* BOLT #2:
		 *
		 * - if both nodes advertised the `option_upfront_shutdown_script`
		 *   feature:
		 *   - MUST include either a valid `shutdown_scriptpubkey` as required
		 *     by `shutdown` `scriptpubkey`, or a zero-length
		 *     `shutdown_scriptpubkey`.
		 * - otherwise:
		 *   - MAY include a`shutdown_scriptpubkey`.
		 */
		/* We don't use shutdown_scriptpubkey (at least for now), so leave it
		 * NULL. */
		msg = towire_open_channel_option_upfront_shutdown_script(NULL,
				  	  &chainparams->genesis_blockhash,
					  &state->channel_id,
					  state->opener_funding,
					  state->push_msat,
					  state->localconf.dust_limit,
					  state->localconf.max_htlc_value_in_flight,
					  state->localconf.channel_reserve,
					  state->localconf.htlc_minimum,
					  state->feerate_per_kw,
					  state->localconf.to_self_delay,
					  state->localconf.max_accepted_htlcs,
					  &state->our_funding_pubkey,
					  &state->our_points.revocation,
					  &state->our_points.payment,
					  &state->our_points.delayed_payment,
					  &state->our_points.htlc,
					  &state->first_per_commitment_point[LOCAL],
					  channel_flags,
				  	  state->upfront_shutdown_script[LOCAL]);
	}

	sync_crypto_write(state->pps, take(msg));

	/* This is usually a very transient state... */
	peer_billboard(false,
		       "Funding channel start: offered, now waiting for accept_channel%s",
		       state->use_v2 ? "2" : "");

	/* ... since their reply should be immediate. */
	msg = opening_negotiate_msg(tmpctx, state, true);
	if (!msg)
		return NULL;

	/* Default is no shutdown_scriptpubkey: free any leftover one. */
	state->upfront_shutdown_script[REMOTE]
		= tal_free(state->upfront_shutdown_script[REMOTE]);

	if (state->use_v2) {
#if EXPERIMENTAL_FEATURES
		struct tlv_accept_tlvs *tlv = tlv_accept_tlvs_new(tmpctx);
		if (!fromwire_accept_channel2(msg, &id_in,
					      &state->accepter_funding,
					      &state->remoteconf.dust_limit,
					      &state->remoteconf.max_htlc_value_in_flight,
					      &state->remoteconf.htlc_minimum,
					      &state->minimum_depth,
					      &state->remoteconf.to_self_delay,
					      &state->remoteconf.max_accepted_htlcs,
					      &state->their_funding_pubkey,
					      &state->their_points.revocation,
					      &state->their_points.payment,
					      &state->their_points.delayed_payment,
					      &state->their_points.htlc,
					      &state->first_per_commitment_point[REMOTE],
					      tlv))
			peer_failed(state->pps,
				    &state->channel_id,
				    "Parsing accept_channel2 %s", tal_hex(msg, msg));

		/* This is gross */
		if (tlv->option_upfront_shutdown_script &&
			    tlv->option_upfront_shutdown_script->shutdown_scriptpubkey)
			state->upfront_shutdown_script[REMOTE] = tal_steal(state,
				tlv->option_upfront_shutdown_script->shutdown_scriptpubkey);

#else
		peer_failed(state->pps,
			    &state->channel_id,
			    "Bad state: signaled v2 channel_accept but missing "
			    "experimental features. %s",
			    tal_hex(msg, msg));
#endif

	} else {
		/* BOLT #2:
		 *
		 * The receiving node MUST fail the channel if:
		 *...
		 *  - `funding_pubkey`, `revocation_basepoint`, `htlc_basepoint`,
		 *    `payment_basepoint`, or `delayed_payment_basepoint` are not
		 *    valid DER-encoded compressed secp256k1 pubkeys.
		 */
		if (feature_negotiated(state->our_features, state->their_features,
				       OPT_UPFRONT_SHUTDOWN_SCRIPT)) {
			if (!fromwire_accept_channel_option_upfront_shutdown_script(state,
					     msg, &id_in,
					     &state->remoteconf.dust_limit,
					     &state->remoteconf.max_htlc_value_in_flight,
					     &state->remoteconf.channel_reserve,
					     &state->remoteconf.htlc_minimum,
					     &state->minimum_depth,
					     &state->remoteconf.to_self_delay,
					     &state->remoteconf.max_accepted_htlcs,
					     &state->their_funding_pubkey,
					     &state->their_points.revocation,
					     &state->their_points.payment,
					     &state->their_points.delayed_payment,
					     &state->their_points.htlc,
					     &state->first_per_commitment_point[REMOTE],
					     &state->upfront_shutdown_script[REMOTE]))
				peer_failed(state->pps,
					    &state->channel_id,
					    "Parsing accept_channel with option_upfront_shutdown_script %s", tal_hex(msg, msg));
		} else if (!fromwire_accept_channel(msg, &id_in,
					     &state->remoteconf.dust_limit,
					     &state->remoteconf.max_htlc_value_in_flight,
					     &state->remoteconf.channel_reserve,
					     &state->remoteconf.htlc_minimum,
					     &state->minimum_depth,
					     &state->remoteconf.to_self_delay,
					     &state->remoteconf.max_accepted_htlcs,
					     &state->their_funding_pubkey,
					     &state->their_points.revocation,
					     &state->their_points.payment,
					     &state->their_points.delayed_payment,
					     &state->their_points.htlc,
					     &state->first_per_commitment_point[REMOTE]))
			peer_failed(state->pps,
				    &state->channel_id,
				    "Parsing accept_channel %s", tal_hex(msg, msg));
	}

	/* BOLT #2:
	 *
	 * The `temporary_channel_id` MUST be the same as the
	 * `temporary_channel_id` in the `open_channel` message. */
	if (!channel_id_eq(&id_in, &state->channel_id))
		/* In this case we exit, since we don't know what's going on. */
		peer_failed(state->pps,
			    &state->channel_id,
			    "accept_channel ids don't match: sent %s got %s",
			    type_to_string(msg, struct channel_id, &id_in),
			    type_to_string(msg, struct channel_id,
					   &state->channel_id));

	if (state->use_v2)
		set_reserve(state);
	else if (!check_reserves(state))
		return NULL;

	if (!check_config_bounds(state, &state->remoteconf, true))
		return NULL;

	funding_output_script =
		scriptpubkey_p2wsh(tmpctx,
				   bitcoin_redeem_2of2(tmpctx,
						       &state->our_funding_pubkey,
						       &state->their_funding_pubkey));

	/* Update the billboard with our infos */
	peer_billboard(false,
		       "Funding channel start: awaiting funding_txid with output to %s",
		       tal_hex(tmpctx, funding_output_script));

	return towire_opening_funder_start_reply(state,
						 funding_output_script,
						 feature_negotiated(
							 state->our_features,
							 state->their_features,
							 OPT_UPFRONT_SHUTDOWN_SCRIPT));
}

#if EXPERIMENTAL_FEATURES
static void check_channel_id(struct state *state,
		             struct channel_id *id_in,
			     struct channel_id *original_channel_id)
{
	/* BOLT #2:
	 *
	 * The `temporary_channel_id` MUST be the same as the
	 * `temporary_channel_id` in the `open_channel` message.
	 */
	if (!channel_id_eq(id_in, original_channel_id))
		peer_failed(state->pps, id_in,
			    "channel establishment: ids don't match: expected %s got %s",
			    type_to_string(tmpctx, struct channel_id, original_channel_id),
			    type_to_string(tmpctx, struct channel_id, id_in));
}

/* Derives the needed inputs / outputs from a bitcoin tx */
static void derive_input_output_info(const tal_t *ctx,
				     struct bitcoin_tx *tx,
				     struct utxo **utxos,
				     bool exclude_funding_output,
				     struct input_info ***inputs,
				     struct output_info ***outputs)
{
	size_t i;

	*inputs = tal_arr(ctx, struct input_info *, tal_count(utxos));
	for (i = 0; i < tal_count(utxos); i++) {
		struct input_info *in;
		in = tal(*inputs, struct input_info);

		in->input_satoshis = utxos[i]->amount;
		in->prevtx_txid = utxos[i]->txid;
		in->prevtx_vout = utxos[i]->outnum;
		in->prevtx_scriptpubkey = tal_dup_arr(in, u8, utxos[i]->scriptPubkey,
						      tal_bytelen(utxos[i]->scriptPubkey), 0);

		/* All our inputs are sig + key (P2WPKH or P2SH-P2WPKH) */
		in->max_witness_len = 1 + 1 + 73 + 1 + 33;

		/*
		 *	FIXME: add BOLT reference when merged.
		 *	`input_info`.`script` is the scriptPubkey data for the input.
		 *	NB: for native SegWit inputs (P2WPKH and P2WSH) inputs, the `script` field
		 *	will be empty.
		 */
		if (utxos[i]->is_p2sh) {
			in->script = tal_arr(in, u8, tx->wtx->inputs[i].script_len);
			memcpy(in->script, tx->wtx->inputs[i].script,
			       tx->wtx->inputs[i].script_len);
		} else
			in->script = NULL;

		(*inputs)[i] = in;
	}

	*outputs = tal_arr(ctx, struct output_info *, 0);
	for (i = 0; i < tx->wtx->num_outputs; i++) {
		struct output_info *out;
		struct wally_tx_output wo;

		wo = tx->wtx->outputs[i];

		/* This is a hack that excludes P2WSH outputs
		 * which for us, now are exclusively funding outputs */
		if (exclude_funding_output && wo.script_len == 34)
			continue;

		out = tal(*outputs, struct output_info);
		out->output_satoshis.satoshis = wo.satoshi; /* Raw: type conversion */
		out->script = tal_arr(out, u8, wo.script_len);
		memcpy(out->script, wo.script, wo.script_len);

		tal_arr_expand(outputs, out);
	}
}

static bool check_remote_inputs(struct input_info **remote_inputs,
				struct amount_sat *input_funding)
{
	size_t i = 0;

	// FIXME: we should check that they don't also
	// turn in the funding output
	// and maybe check that none of their outputs
	// are duplicates??
	*input_funding = AMOUNT_SAT(0);
	for (i = 0; i < tal_count(remote_inputs); i++) {

		if (!amount_sat_add(input_funding, *input_funding, remote_inputs[i]->input_satoshis))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Overflow in remote input amount %s + %s",
			               type_to_string(tmpctx, struct amount_sat,
					              &remote_inputs[i]->input_satoshis),
			               type_to_string(tmpctx, struct amount_sat,
					              input_funding));
		/** TODO: add BOLT reference when merged
		 * - MUST ensure each `input_info` refers to a non-malleable (segwit) UTXO. */
		/* P2SH wrapped inputs send the redeemscript, which we can check */
		if (remote_inputs[i]->script) {
			if (!is_p2wpkh(remote_inputs[i]->script, NULL)
					&& !is_p2wsh(remote_inputs[i]->script, NULL))
				return false;
		} else if (!is_p2wpkh(remote_inputs[i]->prevtx_scriptpubkey, NULL)
				&& !is_p2wsh(remote_inputs[i]->prevtx_scriptpubkey, NULL))
			return false;

	}
	return true;
}


/* Check that the tx info your peer sent you is kosher */
static bool check_remote_input_outputs(struct state *state,
				       enum role remote_role,
				       struct input_info **remote_inputs,
				       struct output_info **remote_outputs,
				       struct amount_sat stated_funding_sats)
{
	size_t i = 0;
	struct amount_sat funding, other_outputs, funding_tx_sats;
	bool has_change_address;

	/**
	 *  BOLT-737016aef544011f385a9e081f85eca34eb61ab6
	 *  - if is the `opener`:
	 *   - MUST NOT send zero inputs (`num_inputs` cannot be zero).
	 */
	if (remote_role == OPENER) {
		if (!tal_count(remote_inputs))
			peer_failed(state->pps,
				    &state->channel_id,
				    "Opener sent no funding inputs");
	} else {
		/**
		 * BOLT-737016aef544011f385a9e081f85eca34eb61ab6
		 * - if is the `accepter`:
		 *   - consider the `contribution count` the total of their `num_inputs` plus
		 *    `num_outputs'
		 *     - MUST NOT send a `funding_compose` message where the `contribution count`
		 *       exceeds the limit of 4.
		 */
		if (tal_count(remote_inputs) + tal_count(remote_outputs) > REMOTE_CONTRIB_LIMIT)
			peer_failed(state->pps,
				    &state->channel_id,
				    "Too many remote contributions. "
				    "Received %ld inputs, %ld outputs; "
				    "max allowed is %d",
				    tal_count(remote_inputs),
				    tal_count(remote_outputs),
				    REMOTE_CONTRIB_LIMIT);
	}

	if (!check_remote_inputs(remote_inputs, &funding))
		peer_failed(state->pps,
			    &state->channel_id,
			    "Peer sent malleable (non-Segwit) input.");

	other_outputs = AMOUNT_SAT(0);
	has_change_address = false;
	for (i = 0; i < tal_count(remote_outputs); i++) {
		if (amount_sat_eq(AMOUNT_SAT(0), remote_outputs[i]->output_satoshis)) {
			if (has_change_address)
				peer_failed(state->pps,
					    &state->channel_id,
					    "Peer sent more than one change outputs.");

			has_change_address = true;
		}
		if (!amount_sat_add(&other_outputs, other_outputs, remote_outputs[i]->output_satoshis))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Overflow in remote outher_outputs satoshis %s + %s",
			               type_to_string(tmpctx, struct amount_sat,
						      &other_outputs),
			               type_to_string(tmpctx, struct amount_sat,
				                      &remote_outputs[i]->output_satoshis));

		/* TODO: add BOLT reference when merged
		 * - MUST ensure the `output_info`.`script` is a standard script
		 */
		if (!is_known_scripttype(remote_outputs[i]->script))
			peer_failed(state->pps,
				    &state->channel_id,
				    "Peer sent non-standard output script.");

	}

	/** TODO: add BOLT reference when merged
	* The receiving node:
	* - if the total `input_info`.`satoshis` is less than the total `output_info`.`satoshis`
	*   - MUST fail the channel.
	*/
	if (!amount_sat_sub(&funding_tx_sats, funding, other_outputs))
		peer_failed(state->pps,
			    &state->channel_id,
			    "Total remote input satoshi less than output satoshis. change:%s inputs:%s",
			    type_to_string(tmpctx, struct amount_sat,
					   &other_outputs),
			    type_to_string(tmpctx, struct amount_sat,
					   &funding));

	if (!amount_sat_greater_eq(funding_tx_sats, stated_funding_sats))
		peer_failed(state->pps,
			    &state->channel_id,
			    "Input amounts won't afford "
			    "funding amount (desired: %s, provided: %s).",
			    type_to_string(tmpctx, struct amount_sat,
					   &stated_funding_sats),
			    type_to_string(tmpctx, struct amount_sat,
					   &funding_tx_sats));

	return true;
}
#endif

static u8 *funder_finalize_channel_setup2(struct state *state,
					  struct utxo **utxos,
					  struct bitcoin_signature *sig,
					  struct bitcoin_tx **tx)
{
#if EXPERIMENTAL_FEATURES
	u8 *msg;
	struct channel_id id_in;
	const u8 *wscript;
	char *err_reason;
	struct input_info **local_ins, **remote_ins;
	struct output_info **local_outs, **remote_outs;
	struct amount_sat total_funding, opener_change;
	struct bitcoin_signature their_sig, our_sig;
	struct amount_msat local_funding_msat;

	size_t i, input_count;
	struct bitcoin_tx *funding_tx, *remote_commit, *local_commit;
	const struct witness_stack **remote_witnesses;

	/* Derive components, omitting the funding output */
	derive_input_output_info(state, *tx, utxos, true,
				 &local_ins, &local_outs);

	/* Send them to the peer */
	msg = towire_funding_compose(tmpctx, &state->channel_id,
				     cast_const2(const struct input_info **, local_ins),
				     cast_const2(const struct output_info **, local_outs));

	sync_crypto_write(state->pps, take(msg));

	peer_billboard(false,
		       "Opening channel: funding_compose sent, "
		       "waiting for funding_compose reply");

	msg = opening_negotiate_msg(tmpctx, state, false);
	if (!msg)
		return NULL;

	/* The next message is "funding_compose", which tells us the funding
	 * inputs and outputs they've selected. */
	if (!fromwire_funding_compose(state, msg, &id_in,
				      &remote_ins,
				      &remote_outs))
		peer_failed(state->pps,
			    &state->channel_id,
			    "Parsing received funding_compose %s", tal_hex(msg, msg));

	if (!check_remote_input_outputs(state, ACCEPTER,
					remote_ins, remote_outs,
					state->accepter_funding))
		return NULL;

	/* FIXME: send their inputs master to verify via bitcoind */

	input_count = tal_count(local_ins) + tal_count(remote_ins);
	const void *map[input_count];
	for (i = 0; i < input_count; i++)
		map[i] = int2ptr(i);

	/* Build the funding transaction */
	funding_tx = dual_funding_funding_tx(state, chainparams,
					     &state->funding_txout,
					     state->feerate_per_kw_funding,
					     &state->opener_funding,
					     state->accepter_funding,
					     local_ins, remote_ins,
					     local_outs, remote_outs,
					     &state->our_funding_pubkey,
					     &state->their_funding_pubkey,
					     &total_funding,
					     &opener_change,
					     (const void **)&map);

	if (!funding_tx)
		peer_failed(state->pps,
			    &state->channel_id,
			    "Unable to afford funding transaction");

	bitcoin_txid(funding_tx, &state->funding_txid);

	/* Move our push_msat over to the other peer */
	if (!amount_sat_sub_msat(&local_funding_msat, state->opener_funding, state->push_msat))
		peer_failed(state->pps,
			    &state->channel_id,
			    "Unable to afford funding transaction, pushed to much");

	state->channel = new_initial_channel(state,
					     &state->funding_txid,
					     state->funding_txout,
					     state->minimum_depth,
					     total_funding,
					     local_funding_msat,
					     take(new_fee_states(NULL, LOCAL,
								 &state->feerate_per_kw)),
					     &state->localconf,
					     &state->remoteconf,
					     &state->our_points,
					     &state->their_points,
					     &state->our_funding_pubkey,
					     &state->their_funding_pubkey,
					     state->option_static_remotekey,
					     true,
					     LOCAL);

	/* We don't expect this to fail, but it does do some additional
	 * internal sanity checks. */
	if (!state->channel)
		peer_failed(state->pps,
			    &state->channel_id,
			    "We could not create channel with given config");

	/* We switch over to using the funding_tx derived channel_id */
	derive_channel_id(&state->channel_id,
			  &state->funding_txid, state->funding_txout);

	/* We need to send them the signatures for their commitment tx */
	remote_commit = initial_channel_tx(state, &wscript, state->channel,
					   &state->first_per_commitment_point[REMOTE],
					   REMOTE, &err_reason);

	if (!remote_commit)
		negotiation_failed(state, true,
				   "Could not meet fees and reserve: %s", err_reason);

	msg = towire_hsm_sign_remote_commitment_tx(NULL,
						   remote_commit,
						   &state->channel->funding_pubkey[REMOTE],
						   state->channel->funding,
						   (const struct witscript **) remote_commit->output_witscripts,
						   &state->first_per_commitment_point[REMOTE],
						   state->channel->option_static_remotekey);

	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_sign_tx_reply(msg, &our_sig))
		status_failed(STATUS_FAIL_HSM_IO, "Bad sign_tx_reply %s",
			      tal_hex(tmpctx, msg));

	peer_billboard(false, "Opening channel: sending commitment_signed");

	/* Now we send it */
	msg = towire_commitment_signed(tmpctx, &state->channel_id,
				       &our_sig.s, NULL);

	sync_crypto_write(state->pps, take(msg));
	msg = opening_negotiate_msg(tmpctx, state, true);
	if (!msg)
		return NULL;

	their_sig.sighash_type = SIGHASH_ALL;
	if (!fromwire_accepter_sigs(state, msg, &id_in,
				    &their_sig.s,
				    (struct witness_stack ***)&remote_witnesses))
		peer_failed(state->pps,
			    &state->channel_id,
			    "Bad accepter_sigs in %s", tal_hex(msg, msg));

	peer_billboard(false,
		       "Opening channel: accepter_sigs received");

	/* Check that they're using the right channel_id */
	check_channel_id(state, &id_in, &state->channel_id);

	/* Check that they sent the right count of witnesses */
	if (tal_count(remote_witnesses) != tal_count(remote_ins))
		peer_failed(state->pps,
			    &state->channel_id,
			    "Received %zu witnesses for %zu inputs",
			    tal_count(remote_witnesses),
			    tal_count(remote_ins));

	/* We create *our* initial commitment transaction, and check the
	 * signature they sent against that. */
	local_commit = initial_channel_tx(state, &wscript, state->channel,
					  &state->first_per_commitment_point[LOCAL],
					  LOCAL, &err_reason);
	if (!local_commit)
		negotiation_failed(state, false,
				   "Did not meet fees and reserve: %s", err_reason);

	if (!check_tx_sig(local_commit, 0, NULL, wscript, &state->their_funding_pubkey, &their_sig))
		peer_failed(state->pps,
			    &state->channel_id,
			    "Bad signature %s on tx %s using key %s",
			    type_to_string(tmpctx, struct bitcoin_signature,
					   &their_sig),
			    type_to_string(tmpctx, struct bitcoin_tx, local_commit),
			    type_to_string(tmpctx, struct pubkey,
					   &state->their_funding_pubkey));

	peer_billboard(false,
		       "Opening channel: accepter sigs are acceptable, moving to sign tx %s",
		       type_to_string(state, struct bitcoin_tx, funding_tx));

	u32 *i_map = tal_arr(state, u32, input_count);
	for (size_t i = 0; i < input_count; i++) {
		i_map[i] = ptr2int(map[i]);
	}

	return towire_opening_dual_funding_signed(state,
						  state->pps,
						  local_commit,
						  &their_sig,
						  funding_tx,
					          state->funding_txout,
						  opener_change,
						  remote_witnesses,
						  i_map,
						  state->opener_funding,
						  &state->remoteconf,
					          &state->their_points.revocation,
					          &state->their_points.payment,
					          &state->their_points.htlc,
					          &state->their_points.delayed_payment,
					          &state->first_per_commitment_point[REMOTE],
					          &state->their_funding_pubkey,
						  state->feerate_per_kw,
						  state->feerate_per_kw_funding,
					          state->localconf.channel_reserve,
					          state->upfront_shutdown_script[REMOTE]);
#else
	return NULL;
#endif /* EXPERIMENTAL_FEATURES */
}

static bool funder_finalize_channel_setup(struct state *state,
					  struct amount_msat local_msat,
					  struct bitcoin_signature *sig,
					  struct bitcoin_tx **tx)
{
	u8 *msg;
	struct channel_id id_in;
	const u8 *wscript;
	char *err_reason;

	/*~ Now we can initialize the `struct channel`.  This represents
	 * the current channel state and is how we can generate the current
	 * commitment transaction.
	 *
	 * The routines to support `struct channel` are split into a common
	 * part (common/initial_channel) which doesn't support HTLCs and is
	 * enough for us here, and the complete channel support required by
	 * `channeld` which lives in channeld/full_channel. */
	state->channel = new_initial_channel(state,
					     &state->funding_txid,
					     state->funding_txout,
					     state->minimum_depth,
					     total_funding(state),
					     local_msat,
					     take(new_fee_states(NULL, LOCAL,
								 &state->feerate_per_kw)),
					     &state->localconf,
					     &state->remoteconf,
					     &state->our_points,
					     &state->their_points,
					     &state->our_funding_pubkey,
					     &state->their_funding_pubkey,
					     state->option_static_remotekey,
					     true,
					     LOCAL);
	/* We were supposed to do enough checks above, but just in case,
	 * new_initial_channel will fail to create absurd channels */
	if (!state->channel)
		peer_failed(state->pps,
			    &state->channel_id,
			    "could not create channel with given config");

	/* BOLT #2:
	 *
	 * ### The `funding_created` Message
	 *
	 * This message describes the outpoint which the funder has created
	 * for the initial commitment transactions.  After receiving the
	 * peer's signature, via `funding_signed`, it will broadcast the funding
	 * transaction.
	 */
	/* This gives us their first commitment transaction. */
	*tx = initial_channel_tx(state, &wscript, state->channel,
				&state->first_per_commitment_point[REMOTE],
				REMOTE, &err_reason);
	if (!*tx) {
		/* This should not happen: we should never create channels we
		 * can't afford the fees for after reserve. */
		negotiation_failed(state, true,
				   "Could not meet their fees and reserve: %s", err_reason);
		goto fail;
	}

	/* We ask the HSM to sign their commitment transaction for us: it knows
	 * our funding key, it just needs the remote funding key to create the
	 * witness script.  It also needs the amount of the funding output,
	 * as segwit signatures commit to that as well, even though it doesn't
	 * explicitly appear in the transaction itself. */
	msg = towire_hsm_sign_remote_commitment_tx(NULL,
						   *tx,
						   &state->channel->funding_pubkey[REMOTE],
						   state->channel->funding,
						   (const struct witscript **) (*tx)->output_witscripts,
						   &state->first_per_commitment_point[REMOTE],
						   state->channel->option_static_remotekey);

	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_sign_tx_reply(msg, sig))
		status_failed(STATUS_FAIL_HSM_IO, "Bad sign_tx_reply %s",
			      tal_hex(tmpctx, msg));

	/* You can tell this has been a problem before, since there's a debug
	 * message here: */
	status_debug("signature %s on tx %s using key %s",
		     type_to_string(tmpctx, struct bitcoin_signature, sig),
		     type_to_string(tmpctx, struct bitcoin_tx, *tx),
		     type_to_string(tmpctx, struct pubkey,
				    &state->our_funding_pubkey));

	/* Now we give our peer the signature for their first commitment
	 * transaction. */
	msg = towire_funding_created(state, &state->channel_id,
				     &state->funding_txid,
				     state->funding_txout,
				     &sig->s);
	sync_crypto_write(state->pps, msg);

	/* BOLT #2:
	 *
	 * ### The `funding_signed` Message
	 *
	 * This message gives the funder the signature it needs for the first
	 * commitment transaction, so it can broadcast the transaction knowing
	 * that funds can be redeemed, if need be.
	 */
	peer_billboard(false,
		       "Funding channel: create first tx, now waiting for their signature");

	/* Now they send us their signature for that first commitment
	 * transaction. */
	msg = opening_negotiate_msg(tmpctx, state, true);
	if (!msg)
		goto fail;

	sig->sighash_type = SIGHASH_ALL;
	if (!fromwire_funding_signed(msg, &id_in, &sig->s))
		peer_failed(state->pps,
			    &state->channel_id,
			    "Parsing funding_signed: %s", tal_hex(msg, msg));

	/* BOLT #2:
	 *
	 * This message introduces the `channel_id` to identify the channel.
	 * It's derived from the funding transaction by combining the
	 * `funding_txid` and the `funding_output_index`, using big-endian
	 * exclusive-OR (i.e. `funding_output_index` alters the last 2
	 * bytes).
	 */

	/*~ Back in Milan, we chose to allow multiple channels between peers in
	 * the protocol.  I insisted that we multiplex these over the same
	 * socket, and (even though I didn't plan on implementing it anytime
	 * soon) that we put it into the first version of the protocol
	 * because it would be painful to add in later.
	 *
	 * My logic seemed sound: we treat new connections as an implication
	 * that the old connection has disconnected, which happens more often
	 * than you'd hope on modern networks.  However, supporting multiple
	 * channels via multiple connections would be far easier for us to
	 * support with our (introduced-since) separate daemon model.
	 *
	 * Let this be a lesson: beware premature specification, even if you
	 * suspect "we'll need it later!". */
	derive_channel_id(&state->channel_id,
			  &state->funding_txid, state->funding_txout);

	if (!channel_id_eq(&id_in, &state->channel_id))
		peer_failed(state->pps, &id_in,
			    "funding_signed ids don't match: expected %s got %s",
			    type_to_string(msg, struct channel_id,
					   &state->channel_id),
			    type_to_string(msg, struct channel_id, &id_in));

	/* BOLT #2:
	 *
	 * The recipient:
	 *   - if `signature` is incorrect:
	 *     - MUST fail the channel.
	 */
	/* So we create *our* initial commitment transaction, and check the
	 * signature they sent against that. */
	*tx = initial_channel_tx(state, &wscript, state->channel,
				 &state->first_per_commitment_point[LOCAL],
				 LOCAL, &err_reason);
	if (!*tx) {
		negotiation_failed(state, true,
				   "Could not meet our fees and reserve: %s", err_reason);
		goto fail;
	}

	if (!check_tx_sig(*tx, 0, NULL, wscript, &state->their_funding_pubkey, sig)) {
		peer_failed(state->pps,
			    &state->channel_id,
			    "Bad signature %s on tx %s using key %s",
			    type_to_string(tmpctx, struct bitcoin_signature,
					   sig),
			    type_to_string(tmpctx, struct bitcoin_tx, *tx),
			    type_to_string(tmpctx, struct pubkey,
					   &state->their_funding_pubkey));
	}

	peer_billboard(false, "Funding channel: opening negotiation succeeded");

	return true;

fail:
	tal_free(wscript);
	return false;
}

static u8 *funder_channel_complete(struct state *state,
				   struct bitcoin_tx *tx,
				   struct utxo **utxos)
{
	struct bitcoin_signature sig;
	struct amount_msat local_msat;

	/* Update the billboard about what we're doing*/
	peer_billboard(false,
		       "Funding channel con't: continuing with funding_txid %s",
		       type_to_string(tmpctx, struct bitcoin_txid, &state->funding_txid));

	/* We recalculate the local_msat from cached values; should
	 * succeed because we checked it earlier */
	if (!amount_sat_sub_msat(&local_msat, state->opener_funding, state->push_msat))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "push_msat %s > funding %s?",
			      type_to_string(tmpctx, struct amount_msat,
					     &state->push_msat),
			      type_to_string(tmpctx, struct amount_sat,
					     &state->opener_funding));

	if (state->use_v2)
		return funder_finalize_channel_setup2(state, utxos, &sig, &tx);

	if (!funder_finalize_channel_setup(state, local_msat, &sig, &tx))
		return NULL;

	return towire_opening_funder_reply(state,
					   &state->remoteconf,
					   tx,
					   &sig,
					   state->pps,
					   &state->their_points.revocation,
					   &state->their_points.payment,
					   &state->their_points.htlc,
					   &state->their_points.delayed_payment,
					   &state->first_per_commitment_point[REMOTE],
					   state->minimum_depth,
					   &state->their_funding_pubkey,
					   &state->funding_txid,
					   state->funding_txout,
					   state->feerate_per_kw,
					   state->localconf.channel_reserve,
					   state->upfront_shutdown_script[REMOTE]);
}

/*~ The peer sent us an `open_channel`, that means we're the fundee. */
static u8 *fundee_channel(struct state *state, const u8 *open_channel_msg)
{
	struct channel_id id_in;
	struct basepoints theirs;
	struct pubkey their_funding_pubkey;
	struct bitcoin_signature theirsig, sig;
	struct bitcoin_tx *local_commit, *remote_commit;
	struct bitcoin_blkid chain_hash;
	u8 *msg;
	const u8 *wscript;
	u8 channel_flags;
	char* err_reason;

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `funding_pubkey`, `revocation_basepoint`, `htlc_basepoint`,
	 *    `payment_basepoint`, or `delayed_payment_basepoint` are not valid
	 *     secp256k1 pubkeys in compressed format.
	 */
	if (feature_negotiated(state->our_features, state->their_features,
			       OPT_UPFRONT_SHUTDOWN_SCRIPT)) {
		if (!fromwire_open_channel_option_upfront_shutdown_script(state,
			    open_channel_msg, &chain_hash,
			    &state->channel_id,
			    &state->opener_funding,
			    &state->push_msat,
			    &state->remoteconf.dust_limit,
			    &state->remoteconf.max_htlc_value_in_flight,
			    &state->remoteconf.channel_reserve,
			    &state->remoteconf.htlc_minimum,
			    &state->feerate_per_kw,
			    &state->remoteconf.to_self_delay,
			    &state->remoteconf.max_accepted_htlcs,
			    &their_funding_pubkey,
			    &theirs.revocation,
			    &theirs.payment,
			    &theirs.delayed_payment,
			    &theirs.htlc,
			    &state->first_per_commitment_point[REMOTE],
			    &channel_flags,
			    &state->upfront_shutdown_script[REMOTE]))
		    peer_failed(state->pps,
				&state->channel_id,
				"Parsing open_channel with option_upfront_shutdown_script %s", tal_hex(tmpctx, open_channel_msg));
	} else if (!fromwire_open_channel(open_channel_msg, &chain_hash,
				      &state->channel_id,
				      &state->opener_funding,
				      &state->push_msat,
				      &state->remoteconf.dust_limit,
				      &state->remoteconf.max_htlc_value_in_flight,
				      &state->remoteconf.channel_reserve,
				      &state->remoteconf.htlc_minimum,
				      &state->feerate_per_kw,
				      &state->remoteconf.to_self_delay,
				      &state->remoteconf.max_accepted_htlcs,
				      &their_funding_pubkey,
				      &theirs.revocation,
				      &theirs.payment,
				      &theirs.delayed_payment,
				      &theirs.htlc,
				      &state->first_per_commitment_point[REMOTE],
				      &channel_flags))
		peer_failed(state->pps, NULL,
			    "Bad open_channel %s",
			    tal_hex(open_channel_msg, open_channel_msg));

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *  - the `chain_hash` value is set to a hash of a chain
	 *  that is unknown to the receiver.
	 */
	if (!bitcoin_blkid_eq(&chain_hash, &chainparams->genesis_blockhash)) {
		negotiation_failed(state, false,
				   "Unknown chain-hash %s",
				   type_to_string(tmpctx,
						  struct bitcoin_blkid,
						  &chain_hash));
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 * - `funding_satoshis` is greater than or equal to 2^24 and the receiver does not support
	 *   `option_support_large_channel`. */
	/* We choose to require *negotiation*, not just support! */
	if (!feature_negotiated(state->our_features, state->their_features,
				OPT_LARGE_CHANNELS)
	    && amount_sat_greater(state->opener_funding, chainparams->max_funding)) {
		negotiation_failed(state, false,
				   "funding_satoshis %s too large",
				   type_to_string(tmpctx, struct amount_sat,
						  &state->opener_funding));
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 * ...
	 *   - `push_msat` is greater than `funding_satoshis` * 1000.
	 */
	if (amount_msat_greater_sat(state->push_msat, state->opener_funding)) {
		peer_failed(state->pps,
			    &state->channel_id,
			    "Their push_msat %s"
			    " would be too large for funding_satoshis %s",
			    type_to_string(tmpctx, struct amount_msat,
					   &state->push_msat),
			    type_to_string(tmpctx, struct amount_sat,
					   &state->opener_funding));
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - it considers `feerate_per_kw` too small for timely processing or
	 *    unreasonably large.
	 */
	if (state->feerate_per_kw < state->min_feerate) {
		negotiation_failed(state, false,
				   "feerate_per_kw %u below minimum %u",
				   state->feerate_per_kw, state->min_feerate);
		return NULL;
	}

	if (state->feerate_per_kw > state->max_feerate) {
		negotiation_failed(state, false,
				   "feerate_per_kw %u above maximum %u",
				   state->feerate_per_kw, state->max_feerate);
		return NULL;
	}

	/* This reserves 1% of the channel (rounded up) */
	set_reserve(state);

	/* BOLT #2:
	 *
	 * The sender:
	 *...
	 * - MUST set `channel_reserve_satoshis` greater than or equal to
	 *   `dust_limit_satoshis` from the `open_channel` message.
	 * - MUST set `dust_limit_satoshis` less than or equal to
         *   `channel_reserve_satoshis` from the `open_channel` message.
	 */
	if (amount_sat_greater(state->remoteconf.dust_limit,
			       state->localconf.channel_reserve)) {
		negotiation_failed(state, false,
				   "Our channel reserve %s"
				   " would be below their dust %s",
				   type_to_string(tmpctx, struct amount_sat,
						  &state->localconf.channel_reserve),
				   type_to_string(tmpctx, struct amount_sat,
						  &state->remoteconf.dust_limit));
		return NULL;
	}
	if (amount_sat_greater(state->localconf.dust_limit,
			       state->remoteconf.channel_reserve)) {
		negotiation_failed(state, false,
				   "Our dust limit %s"
				   " would be above their reserve %s",
				   type_to_string(tmpctx, struct amount_sat,
						  &state->localconf.dust_limit),
				   type_to_string(tmpctx, struct amount_sat,
						  &state->remoteconf.channel_reserve));
		return NULL;
	}

	/* These checks are the same whether we're opener or accepter... */
	if (!check_config_bounds(state, &state->remoteconf, false))
		return NULL;

	/* Check with lightningd that we can accept this?  In particular,
	 * if we have an existing channel, we don't support it. */
	msg = towire_opening_got_offer(NULL,
				       state->use_v2,
				       state->opener_funding,
				       state->push_msat,
				       state->remoteconf.dust_limit,
				       state->remoteconf.max_htlc_value_in_flight,
				       state->remoteconf.channel_reserve,
				       state->remoteconf.htlc_minimum,
				       state->feerate_per_kw,
				       state->feerate_per_kw,
				       state->remoteconf.to_self_delay,
				       state->remoteconf.max_accepted_htlcs,
				       channel_flags,
				       state->upfront_shutdown_script[REMOTE]);
	wire_sync_write(REQ_FD, take(msg));
	msg = wire_sync_read(tmpctx, REQ_FD);

	/* We don't allocate off tmpctx, because that's freed inside
	 * opening_negotiate_msg */
	if (!fromwire_opening_got_offer_reply(state, msg, &err_reason,
					      &state->upfront_shutdown_script[LOCAL]))
		master_badmsg(WIRE_OPENING_GOT_OFFER_REPLY, msg);

	/* If they give us a reason to reject, do so. */
	if (err_reason) {
		u8 *errmsg = towire_errorfmt(NULL, &state->channel_id,
					     "%s", err_reason);
		sync_crypto_write(state->pps, take(errmsg));
		tal_free(err_reason);
		return NULL;
	}

	if (!state->upfront_shutdown_script[LOCAL])
		state->upfront_shutdown_script[LOCAL] = dev_upfront_shutdown_script(state);

	/* OK, we accept! */
	msg = towire_accept_channel_option_upfront_shutdown_script(NULL, &state->channel_id,
				    state->localconf.dust_limit,
				    state->localconf.max_htlc_value_in_flight,
				    state->localconf.channel_reserve,
				    state->localconf.htlc_minimum,
				    state->minimum_depth,
				    state->localconf.to_self_delay,
				    state->localconf.max_accepted_htlcs,
				    &state->our_funding_pubkey,
				    &state->our_points.revocation,
				    &state->our_points.payment,
				    &state->our_points.delayed_payment,
				    &state->our_points.htlc,
				    &state->first_per_commitment_point[LOCAL],
				    state->upfront_shutdown_script[LOCAL]);

	sync_crypto_write(state->pps, take(msg));

	peer_billboard(false,
		       "Incoming channel: accepted, now waiting for them to create funding tx");

	/* This is a loop which handles gossip until we get a non-gossip msg */
	msg = opening_negotiate_msg(tmpctx, state, false);
	if (!msg)
		return NULL;

	/* The message should be "funding_created" which tells us what funding
	 * tx they generated; the sighash type is implied, so we set it here. */
	theirsig.sighash_type = SIGHASH_ALL;
	if (!fromwire_funding_created(msg, &id_in,
				      &state->funding_txid,
				      &state->funding_txout,
				      &theirsig.s))
		peer_failed(state->pps,
			    &state->channel_id,
			    "Parsing funding_created");

	/* BOLT #2:
	 *
	 * The `temporary_channel_id` MUST be the same as the
	 * `temporary_channel_id` in the `open_channel` message.
	 */
	if (!channel_id_eq(&id_in, &state->channel_id))
		peer_failed(state->pps, &id_in,
			    "funding_created ids don't match: sent %s got %s",
			    type_to_string(msg, struct channel_id,
					   &state->channel_id),
			    type_to_string(msg, struct channel_id, &id_in));

	/* Now we can create the channel structure. */
	state->channel = new_initial_channel(state,
					     &state->funding_txid,
					     state->funding_txout,
					     state->minimum_depth,
					     state->opener_funding,
					     state->push_msat,
					     take(new_fee_states(NULL, REMOTE,
								 &state->feerate_per_kw)),
					     &state->localconf,
					     &state->remoteconf,
					     &state->our_points, &theirs,
					     &state->our_funding_pubkey,
					     &their_funding_pubkey,
					     state->option_static_remotekey,
					     false,
					     REMOTE);
	/* We don't expect this to fail, but it does do some additional
	 * internal sanity checks. */
	if (!state->channel)
		peer_failed(state->pps,
			    &state->channel_id,
			    "We could not create channel with given config");

	/* BOLT #2:
	 *
	 * The recipient:
	 *   - if `signature` is incorrect:
	 *     - MUST fail the channel.
	 */
	local_commit = initial_channel_tx(state, &wscript, state->channel,
					  &state->first_per_commitment_point[LOCAL],
					  LOCAL, &err_reason);
	/* This shouldn't happen either, AFAICT. */
	if (!local_commit) {
		negotiation_failed(state, false,
				   "Could not meet our fees and reserve: %s", err_reason);
		return NULL;
	}

	if (!check_tx_sig(local_commit, 0, NULL, wscript, &their_funding_pubkey,
			  &theirsig)) {
		/* BOLT #1:
		 *
		 * ### The `error` Message
		 *...
		 * - when failure was caused by an invalid signature check:
		 *    - SHOULD include the raw, hex-encoded transaction in reply
		 *      to a `funding_created`, `funding_signed`,
		 *      `closing_signed`, or `commitment_signed` message.
		 */
		/*~ This verbosity is not only useful for our own testing, but
		 * a courtesy to other implementaters whose brains may be so
		 * twisted by coding in Go, Scala and Rust that they can no
		 * longer read C code. */
		peer_failed(state->pps,
			    &state->channel_id,
			    "Bad signature %s on tx %s using key %s",
			    type_to_string(tmpctx, struct bitcoin_signature,
					   &theirsig),
			    type_to_string(tmpctx, struct bitcoin_tx, local_commit),
			    type_to_string(tmpctx, struct pubkey,
					   &their_funding_pubkey));
	}

	/* BOLT #2:
	 *
	 * This message introduces the `channel_id` to identify the
	 * channel. It's derived from the funding transaction by combining the
	 * `funding_txid` and the `funding_output_index`, using big-endian
	 * exclusive-OR (i.e. `funding_output_index` alters the last 2 bytes).
	 */
	derive_channel_id(&state->channel_id,
			  &state->funding_txid, state->funding_txout);

	/*~ We generate the `funding_signed` message here, since we have all
	 * the data and it's only applicable in the fundee case.
	 *
	 * FIXME: Perhaps we should have channeld generate this, so we
	 * can't possibly send before channel committed to disk?
	 */

	/* BOLT #2:
	 *
	 * ### The `funding_signed` Message
	 *
	 * This message gives the funder the signature it needs for the first
	 * commitment transaction, so it can broadcast the transaction knowing
	 * that funds can be redeemed, if need be.
	 */
	remote_commit = initial_channel_tx(state, &wscript, state->channel,
					   &state->first_per_commitment_point[REMOTE],
					   REMOTE, &err_reason);
	if (!remote_commit) {
		negotiation_failed(state, false,
				   "Could not meet their fees and reserve: %s", err_reason);
		return NULL;
	}

	/* Make HSM sign it */
	msg = towire_hsm_sign_remote_commitment_tx(NULL,
						   remote_commit,
						   &state->channel->funding_pubkey[REMOTE],
						   state->channel->funding,
						   (const struct witscript **) remote_commit->output_witscripts,
						   &state->first_per_commitment_point[REMOTE],
						   state->channel->option_static_remotekey);

	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_sign_tx_reply(msg, &sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad sign_tx_reply %s", tal_hex(tmpctx, msg));

	/* We don't send this ourselves: channeld does, because master needs
	 * to save state to disk before doing so. */
	assert(sig.sighash_type == SIGHASH_ALL);
	msg = towire_funding_signed(state, &state->channel_id, &sig.s);

	return towire_opening_fundee(state,
				     &state->remoteconf,
				     local_commit,
				     &theirsig,
				     state->pps,
				     &theirs.revocation,
				     &theirs.payment,
				     &theirs.htlc,
				     &theirs.delayed_payment,
				     &state->first_per_commitment_point[REMOTE],
				     &their_funding_pubkey,
				     &state->funding_txid,
				     state->funding_txout,
				     state->opener_funding,
				     AMOUNT_SAT(0),
				     state->push_msat,
				     channel_flags,
				     state->feerate_per_kw,
				     msg,
				     state->localconf.channel_reserve,
				     state->upfront_shutdown_script[LOCAL],
				     state->upfront_shutdown_script[REMOTE]);
}

/*~ Standard "peer sent a message, handle it" demuxer.  Though it really only
 * handles one message, we use the standard form as principle of least
 * surprise. */
static u8 *handle_peer_in(struct state *state)
{
	u8 *msg = sync_crypto_read(tmpctx, state->pps);
	enum wire_type t = fromwire_peektype(msg);
	struct channel_id channel_id;

	if (t == WIRE_OPEN_CHANNEL)
		return fundee_channel(state, msg);

#if DEVELOPER
	/* Handle custommsgs */
	enum wire_type type = fromwire_peektype(msg);
	if (type % 2 == 1 && !wire_type_is_defined(type)) {
		/* The message is not part of the messages we know how to
		 * handle. Assuming this is a custommsg, we just forward it to the
		 * master. */
		wire_sync_write(REQ_FD, take(towire_custommsg_in(NULL, msg)));
		return NULL;
	}
#endif

	/* Handles standard cases, and legal unknown ones. */
	if (handle_peer_gossip_or_error(state->pps,
					&state->channel_id, false, msg))
		return NULL;

	sync_crypto_write(state->pps,
			  take(towire_errorfmt(NULL,
					       extract_channel_id(msg, &channel_id) ? &channel_id : NULL,
					       "Unexpected message %s: %s",
					       wire_type_name(t),
					       tal_hex(tmpctx, msg))));

	/* FIXME: We don't actually want master to try to send an
	 * error, since peer is transient.  This is a hack.
	 */
	status_broken("Unexpected message %s", wire_type_name(t));
	peer_failed_connection_lost();
}

/*~ If we see the gossip_fd readable, we read a whole message.  Sure, we might
 * block, but we trust gossipd. */
static void handle_gossip_in(struct state *state)
{
	u8 *msg = wire_sync_read(NULL, state->pps->gossip_fd);

	if (!msg)
		status_failed(STATUS_FAIL_GOSSIP_IO,
			      "Reading gossip: %s", strerror(errno));

	handle_gossip_msg(state->pps, take(msg));
}

/*~ Is this message of type `error` with the special zero-id
 * "fail-everything"?  If lightningd asked us to send such a thing, we're
 * done. */
static void fail_if_all_error(const u8 *inner)
{
	struct channel_id channel_id;
	u8 *data;

	if (!fromwire_error(tmpctx, inner, &channel_id, &data)
	    || !channel_id_is_all(&channel_id)) {
		return;
	}

	status_info("Master said send err: %s",
		    sanitize_error(tmpctx, inner, NULL));
	exit(0);
}

/* Memory leak detection is DEVELOPER-only because we go to great lengths to
 * record the backtrace when allocations occur: without that, the leak
 * detection tends to be useless for diagnosing where the leak came from, but
 * it has significant overhead. */
#if DEVELOPER
static void handle_dev_memleak(struct state *state, const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	/* Populate a hash table with all our allocations (except msg, which
	 * is in use right now). */
	memtable = memleak_enter_allocations(tmpctx, msg, msg);

	/* Now delete state and things it has pointers to. */
	memleak_remove_referenced(memtable, state);

	/* If there's anything left, dump it to logs, and return true. */
	found_leak = dump_memleak(memtable);
	wire_sync_write(REQ_FD,
			take(towire_opening_dev_memleak_reply(NULL,
							      found_leak)));
}

/* We were told to send a custommsg to the peer by `lightningd`. All the
 * verification is done on the side of `lightningd` so we should be good to
 * just forward it here. */
static void openingd_send_custommsg(struct state *state, const u8 *msg)
{
	sync_crypto_write(state->pps, take(msg));
}
#endif /* DEVELOPER */

/* Standard lightningd-fd-is-ready-to-read demux code.  Again, we could hang
 * here, but if we can't trust our parent, who can we trust? */
static u8 *handle_master_in(struct state *state)
{
	u8 *msg = wire_sync_read(tmpctx, REQ_FD);
	enum opening_wire_type t = fromwire_peektype(msg);
	u8 channel_flags;
	struct bitcoin_txid funding_txid;
	struct bitcoin_tx *tx;
	struct utxo **utxos;
	u16 funding_txout;

	switch (t) {
	case WIRE_OPENING_FUNDER_START:
		if (!fromwire_opening_funder_start(tmpctx, msg, &state->opener_funding,
						   &state->push_msat,
						   &state->upfront_shutdown_script[LOCAL],
						   &state->feerate_per_kw,
						   &channel_flags,
						   &state->use_v2))
			master_badmsg(WIRE_OPENING_FUNDER_START, msg);
		msg = funder_channel_start(state, channel_flags);

		/* We want to keep openingd alive, since we're not done yet */
		if (msg)
			wire_sync_write(REQ_FD, take(msg));
		return NULL;
	case WIRE_OPENING_FUNDER_COMPLETE:
		if (!fromwire_opening_funder_complete(tmpctx, msg,
						      &funding_txid,
						      &funding_txout,
						      &utxos,
						      &tx))
			master_badmsg(WIRE_OPENING_FUNDER_COMPLETE, msg);
		state->funding_txid = funding_txid;
		state->funding_txout = funding_txout;
		return funder_channel_complete(state, tx, utxos);
	case WIRE_OPENING_FUNDER_CANCEL:
		/* We're aborting this, simple */
		if (!fromwire_opening_funder_cancel(msg))
			master_badmsg(WIRE_OPENING_FUNDER_CANCEL, msg);

		msg = towire_errorfmt(NULL, &state->channel_id, "Channel open canceled by us");
		sync_crypto_write(state->pps, take(msg));
		negotiation_aborted(state, true, "Channel open canceled by RPC");
		return NULL;
	case WIRE_OPENING_DEV_MEMLEAK:
#if DEVELOPER
		handle_dev_memleak(state, msg);
		return NULL;
#endif
	case WIRE_OPENING_DEV_MEMLEAK_REPLY:
	case WIRE_OPENING_INIT:
	case WIRE_OPENING_FUNDER_REPLY:
	case WIRE_OPENING_DUAL_FUNDING_SIGNED:
	case WIRE_OPENING_FUNDER_START_REPLY:
	case WIRE_OPENING_FUNDEE:
	case WIRE_OPENING_FUNDER_FAILED:
	case WIRE_OPENING_GOT_OFFER:
	case WIRE_OPENING_GOT_OFFER_REPLY:
		break;
	}

	/* Now handle common messages. */
	switch ((enum common_wire_type)t) {
#if DEVELOPER
	case WIRE_CUSTOMMSG_OUT:
		openingd_send_custommsg(state, msg);
		return NULL;
#else
	case WIRE_CUSTOMMSG_OUT:
#endif
	/* We send these. */
	case WIRE_CUSTOMMSG_IN:
		break;
	}

	status_failed(STATUS_FAIL_MASTER_IO,
		      "Unknown msg %s", tal_hex(tmpctx, msg));
}

static void try_read_gossip_store(struct state *state)
{
	u8 *msg = gossip_store_next(tmpctx, state->pps);

	if (msg)
		sync_crypto_write(state->pps, take(msg));
}

int main(int argc, char *argv[])
{
	setup_locale();

	u8 *msg, *inner;
	struct pollfd pollfd[3];
	struct state *state = tal(NULL, struct state);
	struct secret *none;
	struct channel_id *force_tmp_channel_id;

	subdaemon_setup(argc, argv);

	/*~ This makes status_failed, status_debug etc work synchronously by
	 * writing to REQ_FD */
	status_setup_sync(REQ_FD);

	/*~ The very first thing we read from lightningd is our init msg */
	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_opening_init(state, msg,
				   &chainparams,
				   &state->our_features,
				   &state->localconf,
				   &state->max_to_self_delay,
				   &state->min_effective_htlc_capacity,
				   &state->pps,
				   &state->our_points,
				   &state->our_funding_pubkey,
				   &state->minimum_depth,
				   &state->min_feerate, &state->max_feerate,
				   &state->their_features,
				   &state->option_static_remotekey,
				   &inner,
				   &force_tmp_channel_id,
				   &dev_fast_gossip))
		master_badmsg(WIRE_OPENING_INIT, msg);

#if DEVELOPER
	dev_force_tmp_channel_id = force_tmp_channel_id;
#endif

	/* 3 == peer, 4 == gossipd, 5 = gossip_store, 6 = hsmd */
	per_peer_state_set_fds(state->pps, 3, 4, 5);

	/*~ If lightningd wanted us to send a msg, do so before we waste time
	 * doing work.  If it's a global error, we'll close immediately. */
	if (inner != NULL) {
		sync_crypto_write(state->pps, inner);
		fail_if_all_error(inner);
		tal_free(inner);
	}

	/*~ Initially we're not associated with a channel, but
	 * handle_peer_gossip_or_error compares this. */
	memset(&state->channel_id, 0, sizeof(state->channel_id));
	state->channel = NULL;

	/*~ We set these to NULL, meaning no requirements on shutdown */
	state->upfront_shutdown_script[LOCAL]
		= state->upfront_shutdown_script[REMOTE]
		= NULL;

	/*~ We need an initial per-commitment point whether we're funding or
	 * they are, and lightningd has reserved a unique dbid for us already,
	 * so we might as well get the hsm daemon to generate it now. */
	wire_sync_write(HSM_FD,
			take(towire_hsm_get_per_commitment_point(NULL, 0)));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_get_per_commitment_point_reply(tmpctx, msg,
							 &state->first_per_commitment_point[LOCAL],
							 &none))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad get_per_commitment_point_reply %s",
			      tal_hex(tmpctx, msg));
	/*~ The HSM gives us the N-2'th per-commitment secret when we get the
	 * N'th per-commitment point.  But since N=0, it won't give us one. */
	assert(none == NULL);

	/*~ Turns out this is useful for testing, to make sure we're ready. */
	status_debug("Handed peer, entering loop");

	/*~ We manually run a little poll() loop here.  With only three fds */
	pollfd[0].fd = REQ_FD;
	pollfd[0].events = POLLIN;
	pollfd[1].fd = state->pps->gossip_fd;
	pollfd[1].events = POLLIN;
	pollfd[2].fd = state->pps->peer_fd;
	pollfd[2].events = POLLIN;

	/* We exit when we get a conclusion to write to lightningd: either
	 * opening_funder_reply or opening_fundee. */
	msg = NULL;
	while (!msg) {
		int t;
		struct timerel trel;
		if (time_to_next_gossip(state->pps, &trel))
			t = time_to_msec(trel);
		else
			t = -1;

		/*~ If we get a signal which aborts the poll() call, valgrind
		 * complains about revents being uninitialized.  I'm not sure
		 * that's correct, but it's easy to be sure. */
		pollfd[0].revents = pollfd[1].revents = pollfd[2].revents = 0;

		poll(pollfd, ARRAY_SIZE(pollfd), t);
		/* Subtle: handle_master_in can do its own poll loop, so
		 * don't try to service more than one fd per loop. */
		/* First priority: messages from lightningd. */
		if (pollfd[0].revents & POLLIN)
			msg = handle_master_in(state);
		/* Second priority: messages from peer. */
		else if (pollfd[2].revents & POLLIN)
			msg = handle_peer_in(state);
		/* Last priority: chit-chat from gossipd. */
		else if (pollfd[1].revents & POLLIN)
			handle_gossip_in(state);
		else
			try_read_gossip_store(state);

		/* Since we're the top-level event loop, we clean up */
		clean_tmpctx();
	}

	/*~ Write message and hand back the peer fd and gossipd fd.  This also
	 * means that if the peer or gossipd wrote us any messages we didn't
	 * read yet, it will simply be read by the next daemon. */
	wire_sync_write(REQ_FD, msg);
	per_peer_state_fdpass_send(REQ_FD, state->pps);
	status_debug("Sent %s with fds",
		     opening_wire_type_name(fromwire_peektype(msg)));

	/* This frees the entire tal tree. */
	tal_free(state);

	/* This frees up everything else. */
	daemon_shutdown();
	return 0;
}

/*~ Note that there are no other source files in openingd: it really is a fairly
 * straight-line daemon.
 *
 * From here the channel is established: lightningd hands the peer off to
 * channeld/channeld.c which runs the normal channel routine for this peer.
 */
