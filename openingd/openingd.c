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
#include <ccan/tal/str/str.h>
#include <common/crypto_sync.h>
#include <common/derive_basepoints.h>
#include <common/features.h>
#include <common/funding_tx.h>
#include <common/gen_peer_status_wire.h>
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
#include <hsmd/gen_hsm_wire.h>
#include <inttypes.h>
#include <openingd/gen_opening_wire.h>
#include <poll.h>
#include <secp256k1.h>
#include <stdio.h>
#include <wally_bip32.h>
#include <wire/gen_peer_wire.h>
#include <wire/peer_wire.h>
#include <wire/wire.h>
#include <wire/wire_sync.h>

/* stdin == lightningd, 3 == peer, 4 == gossipd, 5 = hsmd */
#define REQ_FD STDIN_FILENO
#define PEER_FD 3
#define GOSSIP_FD 4
#define HSM_FD 5

/* Global state structure.  This is only for the one specific peer and channel */
struct state {
	/* Cryptographic state needed to exchange messages with the peer (as
	 * featured in BOLT #8) */
	struct crypto_state cs;

	/* Features they offered */
	u8 *localfeatures;

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

	/* hsmd gives us our first per-commitment point, and peer tells us
	 * theirs */
	struct pubkey first_per_commitment_point[NUM_SIDES];

	/* Initially temporary, then final channel id. */
	struct channel_id channel_id;

	/* Funding and feerate: set by opening peer. */
	struct amount_sat funding;
	struct amount_msat push_msat;
	u32 feerate_per_kw;
	struct bitcoin_txid funding_txid;
	u16 funding_txout;
	/* If set, this is the scriptpubkey they *must* close with */
	u8 *remote_upfront_shutdown_script;

	/* This is a cluster of fields in open_channel and accept_channel which
	 * indicate the restrictions each side places on the channel. */
	struct channel_config localconf, remoteconf;

	/* The channel structure, as defined in common/initial_channel.h.  While
	 * the structure has room for HTLCs, those routines are channeld-specific
	 * as initial channels never have HTLCs. */
	struct channel *channel;

	/*~ We only allow one active channel at a time per peer.  Otherwise
	 * all our per-peer daemons would have to handle multiple channels,
	 * or we would need some other daemon to demux the messages.
	 * Thus, lightningd tells is if/when there's no active channel. */
	bool can_accept_channel;

	/* Which chain we're on, so we can check/set `chain_hash` fields */
	const struct chainparams *chainparams;
};

/*~ If we can't agree on parameters, we fail to open the channel.  If we're
 * the funder, we need to tell lightningd, otherwise it never really notices. */
static void negotiation_aborted(struct state *state, bool am_funder,
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
	if (am_funder) {
		u8 *msg = towire_opening_funder_failed(NULL, why);
		wire_sync_write(REQ_FD, take(msg));
	}

	/*~ Reset state.  We keep gossipping with them, even though this open
	* failed. */
	memset(&state->channel_id, 0, sizeof(state->channel_id));
	state->channel = tal_free(state->channel);
}

/*~ For negotiation failures: we tell them the parameter we didn't like. */
static void negotiation_failed(struct state *state, bool am_funder,
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
	sync_crypto_write(&state->cs, PEER_FD, take(msg));

	negotiation_aborted(state, am_funder, errmsg);
}

/*~ This is the key function that checks that their configuration is reasonable:
 * it applied for both the case where they're trying to open a channel, and when
 * they've accepted our open. */
static bool check_config_bounds(struct state *state,
				const struct channel_config *remoteconf,
				bool am_funder)
{
	struct amount_sat capacity;
	struct amount_sat reserve;

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `to_self_delay` is unreasonably large.
	 */
	if (remoteconf->to_self_delay > state->max_to_self_delay) {
		negotiation_failed(state, am_funder,
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
		negotiation_failed(state, am_funder,
				   "channel_reserve_satoshis %s"
				   " too large",
				   type_to_string(tmpctx, struct amount_sat,
						  &remoteconf->channel_reserve));
		return false;
	}

	/* If reserves are larger than total sat, we fail. */
	if (!amount_sat_sub(&capacity, state->funding, reserve)) {
		negotiation_failed(state, am_funder,
				   "channel_reserve_satoshis %s"
				   " and %s too large for funding %s",
				   type_to_string(tmpctx, struct amount_sat,
						  &remoteconf->channel_reserve),
				   type_to_string(tmpctx, struct amount_sat,
						  &state->localconf.channel_reserve),
				   type_to_string(tmpctx, struct amount_sat,
						  &state->funding));
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
		negotiation_failed(state, am_funder,
				   "htlc_minimum_msat %s"
				   " too large for funding %s"
				   " capacity_msat %s",
				   type_to_string(tmpctx, struct amount_msat,
						  &remoteconf->htlc_minimum),
				   type_to_string(tmpctx, struct amount_sat,
						  &state->funding),
				   type_to_string(tmpctx, struct amount_sat,
						  &capacity));
		return false;
	}

	/* If the resulting channel doesn't meet our minimum "effective capacity"
	 * set by lightningd, don't bother opening it. */
	if (amount_msat_greater_sat(state->min_effective_htlc_capacity,
				    capacity)) {
		negotiation_failed(state, am_funder,
				   "channel capacity with funding %s,"
				   " reserves %s/%s,"
				   " max_htlc_value_in_flight_msat is %s,"
				   " channel capacity is %s, which is below %s",
				   type_to_string(tmpctx, struct amount_sat,
						  &state->funding),
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
		negotiation_failed(state, am_funder,
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
		negotiation_failed(state, am_funder,
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
		negotiation_failed(state, am_funder,
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

/* We always set channel_reserve_satoshis to 1%, rounded up. */
static void set_reserve(struct state *state)
{
	state->localconf.channel_reserve.satoshis  /* Raw: rounding. */
		= (state->funding.satoshis + 99) / 100;   /* Raw: rounding. */

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
				 bool am_funder)
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
		msg = peer_or_gossip_sync_read(ctx, PEER_FD, GOSSIP_FD,
					       &state->cs, &from_gossipd);
		/* Use standard helper for gossip msgs (forwards, if it's an
		 * error, exits). */
		if (from_gossipd) {
			handle_gossip_msg(PEER_FD, &state->cs, take(msg));
			continue;
		}

		/* Some messages go straight to gossipd. */
		if (is_msg_for_gossipd(msg)) {
			wire_sync_write(GOSSIP_FD, take(msg));
			continue;
		}

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
				if (am_funder) {
					msg = towire_opening_funder_failed(NULL,
									   err);
					wire_sync_write(REQ_FD, take(msg));
				}
				peer_failed_received_errmsg(PEER_FD, GOSSIP_FD,
							    &state->cs, err,
							    NULL);
			}
			negotiation_aborted(state, am_funder,
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
			status_trace("Rejecting %s for unknown channel_id %s",
				     wire_type_name(fromwire_peektype(msg)),
				     type_to_string(tmpctx, struct channel_id,
						    &actual));
			sync_crypto_write(&state->cs, PEER_FD,
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

/*~ OK, let's fund a channel!  Returns the reply for lightningd on success,
 * or NULL if something goes wrong. */
static u8 *funder_channel(struct state *state,
			  struct amount_sat change,
			  u32 change_keyindex,
			  u8 channel_flags,
			  struct utxo **utxos TAKES,
			  const struct ext_key *bip32_base)
{
	struct channel_id id_in;
	u8 *msg;
	struct bitcoin_tx *tx;
	struct basepoints theirs;
	struct pubkey their_funding_pubkey;
	struct pubkey *changekey;
	struct bitcoin_signature sig;
	u32 minimum_depth;
	struct bitcoin_tx *funding;
	const u8 *wscript;
	struct amount_msat local_msat;
	char* err_reason;

	/*~ For symmetry, we calculate our own reserve even though lightningd
	 * could do it for the we-are-funding case. */
	set_reserve(state);

	/*~ Grab a random ID until the funding tx is created (we can't do that
	 * until we know their funding_pubkey) */
	temporary_channel_id(&state->channel_id);

	/* BOLT #2:
	 *
	 * The sending node:
	 *...
	 *   - MUST set `funding_satoshis` to less than 2^24 satoshi.
	 */
	if (amount_sat_greater(state->funding, state->chainparams->max_funding))
		status_failed(STATUS_FAIL_MASTER_IO,
			      "funding_satoshis must be < %s, not %s",
			      type_to_string(tmpctx, struct amount_sat,
					     &state->chainparams->max_funding),
			      type_to_string(tmpctx, struct amount_sat,
					     &state->funding));

	/* BOLT #2:
	 *
	 * The sending node:
	 *...
	 *  - MUST set `push_msat` to equal or less than 1000 *
	 *   `funding_satoshis`.
	 */
	if (!amount_sat_sub_msat(&local_msat, state->funding, state->push_msat))
		status_failed(STATUS_FAIL_MASTER_IO,
			      "push-msat must be < %s",
			      type_to_string(tmpctx, struct amount_sat,
					     &state->funding));
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
				  &state->chainparams->genesis_blockhash,
				  &state->channel_id,
				  state->funding,
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
				  channel_flags, NULL);
	sync_crypto_write(&state->cs, PEER_FD, take(msg));

	/* This is usually a very transient state... */
	peer_billboard(false,
		       "Funding channel: offered, now waiting for accept_channel");
	/* ... since their reply should be immediate. */
	msg = opening_negotiate_msg(tmpctx, state, true);
	if (!msg)
		goto fail;

	/* Default is no shutdown_scriptpubkey: free any leftover one. */
	state->remote_upfront_shutdown_script
		= tal_free(state->remote_upfront_shutdown_script);

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `funding_pubkey`, `revocation_basepoint`, `htlc_basepoint`,
	 *    `payment_basepoint`, or `delayed_payment_basepoint` are not
	 *    valid DER-encoded compressed secp256k1 pubkeys.
	 */
	if (local_feature_negotiated(state->localfeatures,
				     LOCAL_UPFRONT_SHUTDOWN_SCRIPT)) {
		if (!fromwire_accept_channel_option_upfront_shutdown_script(state,
				     msg, &id_in,
				     &state->remoteconf.dust_limit,
				     &state->remoteconf.max_htlc_value_in_flight,
				     &state->remoteconf.channel_reserve,
				     &state->remoteconf.htlc_minimum,
				     &minimum_depth,
				     &state->remoteconf.to_self_delay,
				     &state->remoteconf.max_accepted_htlcs,
				     &their_funding_pubkey,
				     &theirs.revocation,
				     &theirs.payment,
				     &theirs.delayed_payment,
				     &theirs.htlc,
				     &state->first_per_commitment_point[REMOTE],
				     &state->remote_upfront_shutdown_script))
			peer_failed(&state->cs,
				    &state->channel_id,
				    "Parsing accept_channel with option_upfront_shutdown_script %s", tal_hex(msg, msg));
	} else if (!fromwire_accept_channel(msg, &id_in,
				     &state->remoteconf.dust_limit,
				     &state->remoteconf.max_htlc_value_in_flight,
				     &state->remoteconf.channel_reserve,
				     &state->remoteconf.htlc_minimum,
				     &minimum_depth,
				     &state->remoteconf.to_self_delay,
				     &state->remoteconf.max_accepted_htlcs,
				     &their_funding_pubkey,
				     &theirs.revocation,
				     &theirs.payment,
				     &theirs.delayed_payment,
				     &theirs.htlc,
				     &state->first_per_commitment_point[REMOTE]))
		peer_failed(&state->cs,
			    &state->channel_id,
			    "Parsing accept_channel %s", tal_hex(msg, msg));

	/* BOLT #2:
	 *
	 * The `temporary_channel_id` MUST be the same as the
	 * `temporary_channel_id` in the `open_channel` message. */
	if (!channel_id_eq(&id_in, &state->channel_id))
		/* In this case we exit, since we don't know what's going on. */
		peer_failed(&state->cs,
			    &state->channel_id,
			    "accept_channel ids don't match: sent %s got %s",
			    type_to_string(msg, struct channel_id, &id_in),
			    type_to_string(msg, struct channel_id,
					   &state->channel_id));

	/* BOLT #2:
	 *
	 * The receiver:
	 *  - if `minimum_depth` is unreasonably large:
	 *    - MAY reject the channel.
	 */
	if (minimum_depth > 10) {
		/* negotiation_failed just tells peer and lightningd
		 * (hence fundchannel call) that this opening failed. */
		negotiation_failed(state, true,
				   "minimum_depth %u larger than %u",
				   minimum_depth, 10);
		goto fail;
	}

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
		goto fail;
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
		goto fail;
	}

	if (!check_config_bounds(state, &state->remoteconf, true))
		goto fail;

	/*~ If lightningd told us to create change, use change index to do
	 * that. */
	if (!amount_sat_eq(change, AMOUNT_SAT(0))) {
		changekey = tal(tmpctx, struct pubkey);
		if (!bip32_pubkey(bip32_base, changekey, change_keyindex))
			status_failed(STATUS_FAIL_MASTER_IO,
				      "Bad change key %u", change_keyindex);
	} else
		changekey = NULL;

	/*~ We (and they) actually just need the funding txid and output
	 * number, so we can create the commitment transaction which spends
	 * it; lightningd will recreate it (and have the HSM sign it) when
	 * we've completed opening negotiation.
	 */
	funding = funding_tx(state, &state->funding_txout,
			     cast_const2(const struct utxo **, utxos),
			     state->funding,
			     &state->our_funding_pubkey,
			     &their_funding_pubkey,
			     change, changekey,
			     bip32_base);
	bitcoin_txid(funding, &state->funding_txid);

	/*~ Now we can initialize the `struct channel`.  This represents
	 * the current channel state and is how we can generate the current
	 * commitment transaction.
	 *
	 * The routines to support `struct channel` are split into a common
	 * part (common/initial_channel) which doesn't support HTLCs and is
	 * enough for us here, and the complete channel support required by
	 * `channeld` which lives in channeld/full_channel. */
	state->channel = new_initial_channel(state,
					     &state->chainparams->genesis_blockhash,
					     &state->funding_txid,
					     state->funding_txout,
					     minimum_depth,
					     state->funding,
					     local_msat,
					     state->feerate_per_kw,
					     &state->localconf,
					     &state->remoteconf,
					     &state->our_points, &theirs,
					     &state->our_funding_pubkey,
					     &their_funding_pubkey,
					     /* Funder is local */
					     LOCAL);
	/* We were supposed to do enough checks above, but just in case,
	 * new_initial_channel will fail to create absurd channels */
	if (!state->channel)
		peer_failed(&state->cs,
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
	tx = initial_channel_tx(state, &wscript, state->channel,
				&state->first_per_commitment_point[REMOTE],
				REMOTE, &err_reason);
	if (!tx) {
		/* This should not happen: we should never create channels we
		 * can't afford the fees for after reserve. */
		negotiation_failed(state, true,
				   "Could not meet their fees and reserve: %s", err_reason);
		goto fail_2;
	}

	/* We ask the HSM to sign their commitment transaction for us: it knows
	 * our funding key, it just needs the remote funding key to create the
	 * witness script.  It also needs the amount of the funding output,
	 * as segwit signatures commit to that as well, even though it doesn't
	 * explicitly appear in the transaction itself. */
	msg = towire_hsm_sign_remote_commitment_tx(NULL,
						   tx,
						   &state->channel->funding_pubkey[REMOTE],
						   state->channel->funding);

	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_sign_tx_reply(msg, &sig))
		status_failed(STATUS_FAIL_HSM_IO, "Bad sign_tx_reply %s",
			      tal_hex(tmpctx, msg));

	/* You can tell this has been a problem before, since there's a debug
	 * message here: */
	status_trace("signature %s on tx %s using key %s",
		     type_to_string(tmpctx, struct bitcoin_signature, &sig),
		     type_to_string(tmpctx, struct bitcoin_tx, tx),
		     type_to_string(tmpctx, struct pubkey,
				    &state->our_funding_pubkey));

	/* Now we give our peer the signature for their first commitment
	 * transaction. */
	msg = towire_funding_created(state, &state->channel_id,
				     &state->funding_txid,
				     state->funding_txout,
				     &sig.s);
	sync_crypto_write(&state->cs, PEER_FD, msg);

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
		goto fail_2;

	sig.sighash_type = SIGHASH_ALL;
	if (!fromwire_funding_signed(msg, &id_in, &sig.s))
		peer_failed(&state->cs,
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
		peer_failed(&state->cs, &id_in,
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
	tx = initial_channel_tx(state, &wscript, state->channel,
				&state->first_per_commitment_point[LOCAL],
				LOCAL, &err_reason);
	if (!tx) {
		negotiation_failed(state, true,
				   "Could not meet our fees and reserve: %s", err_reason);
		goto fail_2;
	}

	if (!check_tx_sig(tx, 0, NULL, wscript, &their_funding_pubkey, &sig)) {
		peer_failed(&state->cs,
			    &state->channel_id,
			    "Bad signature %s on tx %s using key %s",
			    type_to_string(tmpctx, struct bitcoin_signature,
					   &sig),
			    type_to_string(tmpctx, struct bitcoin_tx, tx),
			    type_to_string(tmpctx, struct pubkey,
					   &their_funding_pubkey));
	}

	peer_billboard(false, "Funding channel: opening negotiation succeeded");

	if (taken(utxos))
		tal_free(utxos);

	/* BOLT #2:
	 *
	 * The recipient:
	 *...
	 *   - on receipt of a valid `funding_signed`:
	 *     - SHOULD broadcast the funding transaction.
	 */
	/*~ lightningd will save the new channel to the database, and
	 *  broadcast the tx. */
	return towire_opening_funder_reply(state,
					   &state->remoteconf,
					   tx,
					   &sig,
					   &state->cs,
					   &theirs.revocation,
					   &theirs.payment,
					   &theirs.htlc,
					   &theirs.delayed_payment,
					   &state->first_per_commitment_point[REMOTE],
					   minimum_depth,
					   &their_funding_pubkey,
					   &state->funding_txid,
					   state->feerate_per_kw,
					   state->localconf.channel_reserve,
					   state->remote_upfront_shutdown_script);

fail_2:
	tal_free(wscript);
	tal_free(funding);
fail:
	if (taken(utxos))
		tal_free(utxos);
	return NULL;
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

	/* Default is no shutdown_scriptpubkey: free any leftover one. */
	state->remote_upfront_shutdown_script
		= tal_free(state->remote_upfront_shutdown_script);

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `funding_pubkey`, `revocation_basepoint`, `htlc_basepoint`,
	 *    `payment_basepoint`, or `delayed_payment_basepoint` are not valid
	 *     DER-encoded compressed secp256k1 pubkeys.
	 */
	if (local_feature_negotiated(state->localfeatures,
				     LOCAL_UPFRONT_SHUTDOWN_SCRIPT)) {
		if (!fromwire_open_channel_option_upfront_shutdown_script(state,
			    open_channel_msg, &chain_hash,
			    &state->channel_id,
			    &state->funding,
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
			    &state->remote_upfront_shutdown_script))
		    peer_failed(&state->cs,
				&state->channel_id,
				"Parsing open_channel with option_upfront_shutdown_script %s", tal_hex(tmpctx, open_channel_msg));
	} else if (!fromwire_open_channel(open_channel_msg, &chain_hash,
				      &state->channel_id,
				      &state->funding,
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
		peer_failed(&state->cs, NULL,
			    "Bad open_channel %s",
			    tal_hex(open_channel_msg, open_channel_msg));

	/* We can't handle talking about more than one channel at once. */
	if (!state->can_accept_channel) {
		u8 *errmsg;
		errmsg = towire_errorfmt(NULL, &state->channel_id,
					 "Already have active channel");

		sync_crypto_write(&state->cs, PEER_FD, take(errmsg));
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *  - the `chain_hash` value is set to a hash of a chain
	 *  that is unknown to the receiver.
	 */
	if (!bitcoin_blkid_eq(&chain_hash,
			      &state->chainparams->genesis_blockhash)) {
		negotiation_failed(state, false,
				   "Unknown chain-hash %s",
				   type_to_string(tmpctx,
						  struct bitcoin_blkid,
						  &chain_hash));
		return NULL;
	}

	/* BOLT #2 FIXME:
	 *
	 * The receiving node ... MUST fail the channel if `funding-satoshis`
	 * is greater than or equal to 2^24 */
	if (amount_sat_greater(state->funding, state->chainparams->max_funding)) {
		negotiation_failed(state, false,
				   "funding_satoshis %s too large",
				   type_to_string(tmpctx, struct amount_sat,
						  &state->funding));
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 * ...
	 *   - `push_msat` is greater than `funding_satoshis` * 1000.
	 */
	if (amount_msat_greater_sat(state->push_msat, state->funding)) {
		peer_failed(&state->cs,
			    &state->channel_id,
			    "Our push_msat %s"
			    " would be too large for funding_satoshis %s",
			    type_to_string(tmpctx, struct amount_msat,
					   &state->push_msat),
			    type_to_string(tmpctx, struct amount_sat,
					   &state->funding));
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

	/* These checks are the same whether we're funder or fundee... */
	if (!check_config_bounds(state, &state->remoteconf, false))
		return NULL;

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
				    NULL);

	sync_crypto_write(&state->cs, PEER_FD, take(msg));

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
		peer_failed(&state->cs,
			    &state->channel_id,
			    "Parsing funding_created");

	/* BOLT #2:
	 *
	 * The `temporary_channel_id` MUST be the same as the
	 * `temporary_channel_id` in the `open_channel` message.
	 */
	if (!channel_id_eq(&id_in, &state->channel_id))
		peer_failed(&state->cs, &id_in,
			    "funding_created ids don't match: sent %s got %s",
			    type_to_string(msg, struct channel_id,
					   &state->channel_id),
			    type_to_string(msg, struct channel_id, &id_in));

	/* Now we can create the channel structure. */
	state->channel = new_initial_channel(state,
					     &chain_hash,
					     &state->funding_txid,
					     state->funding_txout,
					     state->minimum_depth,
					     state->funding,
					     state->push_msat,
					     state->feerate_per_kw,
					     &state->localconf,
					     &state->remoteconf,
					     &state->our_points, &theirs,
					     &state->our_funding_pubkey,
					     &their_funding_pubkey,
					     REMOTE);
	/* We don't expect this to fail, but it does do some additional
	 * internal sanity checks. */
	if (!state->channel)
		peer_failed(&state->cs,
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
		peer_failed(&state->cs,
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
						   state->channel->funding);

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
				     &state->cs,
				     &theirs.revocation,
				     &theirs.payment,
				     &theirs.htlc,
				     &theirs.delayed_payment,
				     &state->first_per_commitment_point[REMOTE],
				     &their_funding_pubkey,
				     &state->funding_txid,
				     state->funding_txout,
				     state->funding,
				     state->push_msat,
				     channel_flags,
				     state->feerate_per_kw,
				     msg,
				     state->localconf.channel_reserve,
				     state->remote_upfront_shutdown_script);
}

/*~ Standard "peer sent a message, handle it" demuxer.  Though it really only
 * handles one message, we use the standard form as principle of least
 * surprise. */
static u8 *handle_peer_in(struct state *state)
{
	u8 *msg = sync_crypto_read(tmpctx, &state->cs, PEER_FD);
	enum wire_type t = fromwire_peektype(msg);
	struct channel_id channel_id;

	switch (t) {
	case WIRE_OPEN_CHANNEL:
		return fundee_channel(state, msg);

	/* These are handled by handle_peer_gossip_or_error. */
	case WIRE_PING:
	case WIRE_PONG:
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
	case WIRE_QUERY_CHANNEL_RANGE:
	case WIRE_REPLY_CHANNEL_RANGE:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
	case WIRE_ERROR:
	case WIRE_CHANNEL_REESTABLISH:
	/* These are all protocol violations at this stage. */
	case WIRE_INIT:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_FUNDING_LOCKED:
	case WIRE_SHUTDOWN:
	case WIRE_CLOSING_SIGNED:
	case WIRE_UPDATE_ADD_HTLC:
	case WIRE_UPDATE_FULFILL_HTLC:
	case WIRE_UPDATE_FAIL_HTLC:
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
	case WIRE_COMMITMENT_SIGNED:
	case WIRE_REVOKE_AND_ACK:
	case WIRE_UPDATE_FEE:
	case WIRE_ANNOUNCEMENT_SIGNATURES:
		/* Standard cases */
		if (handle_peer_gossip_or_error(PEER_FD, GOSSIP_FD, &state->cs,
						&state->channel_id, msg))
			return NULL;
		break;
	}

	sync_crypto_write(&state->cs, PEER_FD,
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

/*~ If we see the GOSSIP_FD readable, we read a whole message.  Sure, we might
 * block, but we trust gossipd. */
static void handle_gossip_in(struct state *state)
{
	u8 *msg = wire_sync_read(NULL, GOSSIP_FD);

	if (!msg)
		status_failed(STATUS_FAIL_GOSSIP_IO,
			      "Reading gossip: %s", strerror(errno));

	handle_gossip_msg(PEER_FD, &state->cs, take(msg));
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
#endif /* DEVELOPER */

/* Standard lightningd-fd-is-ready-to-read demux code.  Again, we could hang
 * here, but if we can't trust our parent, who can we trust? */
static u8 *handle_master_in(struct state *state)
{
	u8 *msg = wire_sync_read(tmpctx, REQ_FD);
	enum opening_wire_type t = fromwire_peektype(msg);
	struct amount_sat change;
	u32 change_keyindex;
	u8 channel_flags;
	struct utxo **utxos;
	struct ext_key bip32_base;

	switch (t) {
	case WIRE_OPENING_FUNDER:
		if (!fromwire_opening_funder(state, msg,
					     &state->funding,
					     &state->push_msat,
					     &state->feerate_per_kw,
					     &change,
					     &change_keyindex,
					     &channel_flags, &utxos,
					     &bip32_base))
			master_badmsg(WIRE_OPENING_FUNDER, msg);

		msg = funder_channel(state,
				     change,
				     change_keyindex, channel_flags,
				     take(utxos), &bip32_base);
		return msg;

	case WIRE_OPENING_CAN_ACCEPT_CHANNEL:
		if (!fromwire_opening_can_accept_channel(msg))
			master_badmsg(WIRE_OPENING_CAN_ACCEPT_CHANNEL, msg);
		state->can_accept_channel = true;
		return NULL;

	case WIRE_OPENING_DEV_MEMLEAK:
#if DEVELOPER
		handle_dev_memleak(state, msg);
		return NULL;
#endif
	case WIRE_OPENING_DEV_MEMLEAK_REPLY:
	case WIRE_OPENING_INIT:
	case WIRE_OPENING_FUNDER_REPLY:
	case WIRE_OPENING_FUNDEE:
	case WIRE_OPENING_FUNDER_FAILED:
		break;
	}

	status_failed(STATUS_FAIL_MASTER_IO,
		      "Unknown msg %s", tal_hex(tmpctx, msg));
}

int main(int argc, char *argv[])
{
	setup_locale();

	u8 *msg, *inner;
	struct pollfd pollfd[3];
	struct state *state = tal(NULL, struct state);
	struct bitcoin_blkid chain_hash;
	struct secret *none;

	subdaemon_setup(argc, argv);

	/*~ This makes status_failed, status_debug etc work synchronously by
	 * writing to REQ_FD */
	status_setup_sync(REQ_FD);

	/*~ The very first thing we read from lightningd is our init msg */
	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_opening_init(state, msg,
				   &chain_hash,
				   &state->localconf,
				   &state->max_to_self_delay,
				   &state->min_effective_htlc_capacity,
				   &state->cs,
				   &state->our_points,
				   &state->our_funding_pubkey,
				   &state->minimum_depth,
				   &state->min_feerate, &state->max_feerate,
				   &state->can_accept_channel,
				   &state->localfeatures,
				   &inner))
		master_badmsg(WIRE_OPENING_INIT, msg);

	/*~ If lightningd wanted us to send a msg, do so before we waste time
	 * doing work.  If it's a global error, we'll close immediately. */
	if (inner != NULL) {
		sync_crypto_write(&state->cs, PEER_FD, inner);
		fail_if_all_error(inner);
		tal_free(inner);
	}

	/*~ Even though I only care about bitcoin, there's still testnet and
	 * regtest modes, so we have a general "parameters for this chain"
	 * function. */
	state->chainparams = chainparams_by_chainhash(&chain_hash);
	/*~ Initially we're not associated with a channel, but
	 * handle_peer_gossip_or_error compares this. */
	memset(&state->channel_id, 0, sizeof(state->channel_id));
	state->channel = NULL;

	/*~ We set this to NULL, meaning no requirements on shutdown */
	state->remote_upfront_shutdown_script = NULL;

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
	status_trace("Handed peer, entering loop");

	/*~ We manually run a little poll() loop here.  With only three fds */
	pollfd[0].fd = REQ_FD;
	pollfd[0].events = POLLIN;
	pollfd[1].fd = GOSSIP_FD;
	pollfd[1].events = POLLIN;
	pollfd[2].fd = PEER_FD;
	pollfd[2].events = POLLIN;

	/* We exit when we get a conclusion to write to lightningd: either
	 * opening_funder_reply or opening_fundee. */
	msg = NULL;
	while (!msg) {
		poll(pollfd, ARRAY_SIZE(pollfd), -1);
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

		/* Since we're the top-level event loop, we clean up */
		clean_tmpctx();
	}

	/*~ Write message and hand back the peer fd and gossipd fd.  This also
	 * means that if the peer or gossipd wrote us any messages we didn't
	 * read yet, it will simply be read by the next daemon. */
	wire_sync_write(REQ_FD, msg);
	fdpass_send(REQ_FD, PEER_FD);
	fdpass_send(REQ_FD, GOSSIP_FD);
	status_trace("Sent %s with fd",
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
