/*~ Welcome to the opening daemon: gateway to channels!
 *
 * This daemon handles a single peer.  It's happy to trade gossip with the
 * peer until either lightningd asks it to fund a channel, or the peer itself
 * asks to fund a channel.  Then it goes through with the channel opening
 * negotiations.  It's important to note that until this negotiation is complete,
 * there's nothing permanent about the channel: lightningd will only have to
 * commit to the database once openingd succeeds.
 */
#include "config.h"
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/tal/str/str.h>
#include <common/channel_type.h>
#include <common/fee_states.h>
#include <common/gossip_store.h>
#include <common/initial_channel.h>
#include <common/memleak.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/peer_io.h>
#include <common/per_peer_state.h>
#include <common/read_peer_msg.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <openingd/common.h>
#include <openingd/openingd_wiregen.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

/* stdin == lightningd, 3 == peer, 4 = hsmd */
#define REQ_FD STDIN_FILENO
#define HSM_FD 4

/* Global state structure.  This is only for the one specific peer and channel */
struct state {
	struct per_peer_state *pps;

	/* --developer? */
	bool developer;

	/* If --dev-force-tmp-channel-id is set, it ends up here */
	struct channel_id *dev_force_tmp_channel_id;

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
	struct amount_sat funding_sats;
	struct amount_msat push_msat;
	u32 feerate_per_kw;
	struct bitcoin_outpoint funding;

	/* If non-NULL, this is the scriptpubkey we/they *must* close with */
	u8 *upfront_shutdown_script[NUM_SIDES];

	/* If non-NULL, the wallet index for the LOCAL script */
	u32 *local_upfront_shutdown_wallet_index;

	/* This is a cluster of fields in open_channel and accept_channel which
	 * indicate the restrictions each side places on the channel. */
	struct channel_config localconf, remoteconf;

	/* The channel structure, as defined in common/initial_channel.h.  While
	 * the structure has room for HTLCs, those routines are channeld-specific
	 * as initial channels never have HTLCs. */
	struct channel *channel;

	/* Channel type we agreed on (even before channel populated) */
	struct channel_type *channel_type;

	struct feature_set *our_features;

	struct amount_sat *reserve;

	bool allowdustreserve;
};

/*~ If we can't agree on parameters, we fail to open the channel.
 *  Tell lightningd why. */
static void NORETURN negotiation_aborted(struct state *state, const char *why)
{
	status_debug("aborted opening negotiation: %s", why);
	/*~ The "billboard" (exposed as "status" in the JSON listpeers RPC
	 * call) is a transient per-channel area which indicates important
	 * information about what is happening.  It has a "permanent" area for
	 * each state, which can be used to indicate what went wrong in that
	 * state (such as here), and a single transient area for current
	 * status. */
	peer_billboard(true, why);

	/* Tell master that funding failed. */
	wire_sync_write(REQ_FD, take(towire_openingd_failed(NULL, why)));
	exit(0);
}

/*~ For negotiation failures: we tell them the parameter we didn't like. */
static void NORETURN negotiation_failed(struct state *state,
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
	peer_write(state->pps, take(msg));

	negotiation_aborted(state, errmsg);
}

static void set_reserve_absolute(struct state * state, const struct amount_sat dust_limit, struct amount_sat reserve_sat)
{
	status_debug("Setting their reserve to %s",
		     type_to_string(tmpctx, struct amount_sat, &reserve_sat));
	if (state->allowdustreserve) {
		state->localconf.channel_reserve = reserve_sat;
	} else {
		/* BOLT #2:
		 *
		 * The sending node:
		 *...
		 * - MUST set `channel_reserve_satoshis` greater than or equal
		 *to `dust_limit_satoshis` from the `open_channel` message.
		 */
		if (amount_sat_greater(dust_limit, reserve_sat)) {
			status_debug("Their reserve is too small, bumping to "
				     "dust_limit: %s < %s",
				     type_to_string(tmpctx, struct amount_sat,
						    &reserve_sat),
				     type_to_string(tmpctx, struct amount_sat,
						    &dust_limit));
			state->localconf.channel_reserve = dust_limit;
		} else {
			state->localconf.channel_reserve = reserve_sat;
		}
	}
}

/* We always set channel_reserve_satoshis to 1%, rounded down. */
static void set_reserve(struct state *state, const struct amount_sat dust_limit)
{
	set_reserve_absolute(state, dust_limit,
			     amount_sat_div(state->funding_sats, 100));
}

/*~ Handle random messages we might get during opening negotiation, (eg. gossip)
 * returning the first non-handled one, or NULL if we aborted negotiation. */
static u8 *opening_negotiate_msg(const tal_t *ctx, struct state *state,
				 const struct channel_id *alternate)
{
	/* This is an event loop of its own.  That's generally considered poor
	 * form, but we use it in a very limited way. */
	for (;;) {
		u8 *msg;
		const char *err;

		/* The event loop is responsible for freeing tmpctx, so our
		 * temporary allocations don't grow unbounded. */
		clean_tmpctx();

		/* This helper routine polls both the peer and gossipd. */
		msg = peer_read(ctx, state->pps);

		/* BOLT #1:
		 *
		 * A receiving node:
		 *   - upon receiving a message of _odd_, unknown type:
		 *     - MUST ignore the received message.
		 */
		if (is_unknown_msg_discardable(msg))
			continue;

		/* A helper which decodes an error. */
		err = is_peer_error(tmpctx, msg);
		if (err) {
			negotiation_aborted(state,
					    tal_fmt(tmpctx, "They sent %s",
						    err));
			/* Return NULL so caller knows to stop negotiating. */
			return tal_free(msg);
		}

		err = is_peer_warning(tmpctx, msg);
		if (err) {
			status_info("They sent %s", err);
			tal_free(msg);
			continue;
		}

		/* If we get here, it's an interesting message. */
		return msg;
	}
}

static bool setup_channel_funder(struct state *state)
{
	/* --dev-force-tmp-channel-id specified */
	if (state->dev_force_tmp_channel_id)
		state->channel_id = *state->dev_force_tmp_channel_id;

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
	    && amount_sat_greater(state->funding_sats,
				  chainparams->max_funding)) {
		status_failed(STATUS_FAIL_MASTER_IO,
			      "funding_satoshis must be < %s, not %s",
			      type_to_string(tmpctx, struct amount_sat,
					     &chainparams->max_funding),
			      type_to_string(tmpctx, struct amount_sat,
					     &state->funding_sats));
		return false;
	}

	return true;
}

static void set_remote_upfront_shutdown(struct state *state,
					u8 *shutdown_scriptpubkey STEALS)
{
	char *err;

	err = validate_remote_upfront_shutdown(state, state->our_features,
					       state->their_features,
					       shutdown_scriptpubkey,
					       &state->upfront_shutdown_script[REMOTE]);

	if (err)
		peer_failed_err(state->pps, &state->channel_id, "%s", err);
}

/* Since we can't send OPT_SCID_ALIAS due to compat issues, intuit whether
 * we really actually want it anyway, we just can't say that. */
static bool intuit_scid_alias_type(struct state *state, u8 channel_flags,
				   bool peer_sent_channel_type)
{
	/* Don't need to intuit if actually set */
	if (channel_type_has(state->channel_type, OPT_SCID_ALIAS))
		return false;

	/* Old clients didn't send channel_type at all */
	if (!peer_sent_channel_type)
		return false;

	/* Modern peer: no intuit hacks necessary. */
	if (channel_type_has(state->channel_type, OPT_ANCHORS_ZERO_FEE_HTLC_TX))
		return false;

	/* Public channel: don't want OPT_SCID_ALIAS which means "only use
	 * alias". */
	if (channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL)
		return false;

	/* If we both support it, presumably we want it? */
	return feature_negotiated(state->our_features, state->their_features,
				  OPT_SCID_ALIAS);
}

/* We start the 'open a channel' negotation with the supplied peer, but
 * stop when we get to the part where we need the funding txid */
static u8 *funder_channel_start(struct state *state, u8 channel_flags,
				u32 nonanchor_feerate, u32 anchor_feerate)
{
	u8 *msg;
	u8 *funding_output_script;
	struct channel_id id_in;
	struct tlv_open_channel_tlvs *open_tlvs;
	struct tlv_accept_channel_tlvs *accept_tlvs;
	char *err_reason;
	u32 their_mindepth;

	status_debug("funder_channel_start");
	if (!setup_channel_funder(state))
		return NULL;

	/* If we have a reserve override we use that, otherwise we'll
	 * use our default of 1% of the funding value. */
	if (state->reserve != NULL) {
		set_reserve_absolute(state, state->localconf.dust_limit,
				     *state->reserve);
	} else {
		set_reserve(state, state->localconf.dust_limit);
	}

	if (!state->upfront_shutdown_script[LOCAL])
		state->upfront_shutdown_script[LOCAL]
			= no_upfront_shutdown_script(state, state->developer,
						     state->our_features,
						     state->their_features);

	state->channel_type = default_channel_type(state,
						   state->our_features,
						   state->their_features);

	/* Spec says we should use the option_scid_alias variation if we
	 * want them to *only* use the scid_alias (which we do for unannounced
	 * channels!).
	 *
	 * But:
	 * 1. We didn't accept this in CLN prior to v23.05.
	 * 2. LND won't accept that without OPT_ANCHORS_ZERO_FEE_HTLC_TX.
	 *
	 * So we keep it off for now, until anchors merge.
	 */
	if (channel_type_has(state->channel_type, OPT_ANCHORS_ZERO_FEE_HTLC_TX)) {
		if (!(channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL))
			channel_type_set_scid_alias(state->channel_type);
	}

	/* Which feerate do we use?  (We can lowball fees if using anchors!) */
	if (channel_type_has(state->channel_type, OPT_ANCHOR_OUTPUTS)
	    || channel_type_has(state->channel_type, OPT_ANCHORS_ZERO_FEE_HTLC_TX)) {
		state->feerate_per_kw = anchor_feerate;
	} else {
		state->feerate_per_kw = nonanchor_feerate;
	}

	open_tlvs = tlv_open_channel_tlvs_new(tmpctx);
	open_tlvs->upfront_shutdown_script
		= state->upfront_shutdown_script[LOCAL];

	/* BOLT #2:
	 *  - if it includes `channel_type`:
	 *     - MUST set it to a defined type representing the type it wants.
	 *     - MUST use the smallest bitmap possible to represent the channel
	 *       type.
	 *     - SHOULD NOT set it to a type containing a feature which was not
	 *       negotiated.
	 */
	open_tlvs->channel_type = state->channel_type->features;

	msg = towire_open_channel(NULL,
				  &chainparams->genesis_blockhash,
				  &state->channel_id,
				  state->funding_sats,
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
				  open_tlvs);
	peer_write(state->pps, take(msg));

	/* This is usually a very transient state... */
	peer_billboard(false,
		       "Funding channel start: offered, now waiting for accept_channel");

	/* ... since their reply should be immediate. */
	msg = opening_negotiate_msg(tmpctx, state, NULL);
	if (!msg)
		return NULL;

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `funding_pubkey`, `revocation_basepoint`, `htlc_basepoint`,
	 *    `payment_basepoint`, or `delayed_payment_basepoint` are not
	 *    valid secp256k1 pubkeys in compressed format.
	 */
	if (!fromwire_accept_channel(tmpctx, msg, &id_in,
				     &state->remoteconf.dust_limit,
				     &state->remoteconf.max_htlc_value_in_flight,
				     &state->remoteconf.channel_reserve,
				     &state->remoteconf.htlc_minimum,
				     &their_mindepth,
				     &state->remoteconf.to_self_delay,
				     &state->remoteconf.max_accepted_htlcs,
				     &state->their_funding_pubkey,
				     &state->their_points.revocation,
				     &state->their_points.payment,
				     &state->their_points.delayed_payment,
				     &state->their_points.htlc,
				     &state->first_per_commitment_point[REMOTE],
				     &accept_tlvs)) {
		peer_failed_err(state->pps,
				&state->channel_id,
				"Parsing accept_channel %s", tal_hex(msg, msg));
	}
	set_remote_upfront_shutdown(state, accept_tlvs->upfront_shutdown_script);

	status_debug(
	    "accept_channel: max_htlc_value_in_flight=%s, channel_reserve=%s, "
	    "htlc_minimum=%s, minimum_depth=%d",
	    type_to_string(tmpctx, struct amount_msat,
			   &state->remoteconf.max_htlc_value_in_flight),
	    type_to_string(tmpctx, struct amount_sat,
			   &state->remoteconf.channel_reserve),
	    type_to_string(tmpctx, struct amount_msat,
			   &state->remoteconf.htlc_minimum),
	    their_mindepth);

	/* BOLT #2:
	 * - if `channel_type` is set, and `channel_type` was set in
	 *   `open_channel`, and they are not equal types:
	 *    - MUST fail the channel.
	 */
	if (accept_tlvs->channel_type) {
		/* Except that v23.05 could set OPT_SCID_ALIAS in reply! */
		struct channel_type *atype;

		atype = channel_type_from(tmpctx, accept_tlvs->channel_type);
		if (!channel_type_has(atype, OPT_ANCHORS_ZERO_FEE_HTLC_TX))
			featurebits_unset(&atype->features, OPT_SCID_ALIAS);

		if (!channel_type_eq(atype, state->channel_type)) {
			negotiation_failed(state,
					   "Return unoffered channel_type: %s",
					   fmt_featurebits(tmpctx,
							   accept_tlvs->channel_type));
			return NULL;
		}

		/* If they "accepted" SCID_ALIAS, roll with it. */
		tal_free(state->channel_type);
		state->channel_type = channel_type_from(state,
							accept_tlvs->channel_type);
	}

	/* BOLT #2:
	 *
	 * The `temporary_channel_id` MUST be the same as the
	 * `temporary_channel_id` in the `open_channel` message. */
	if (!channel_id_eq(&id_in, &state->channel_id))
		/* In this case we exit, since we don't know what's going on. */
		peer_failed_err(state->pps, &id_in,
				"accept_channel ids don't match: sent %s got %s",
				type_to_string(msg, struct channel_id, &id_in),
				type_to_string(msg, struct channel_id,
					       &state->channel_id));

	if (!state->allowdustreserve &&
	    amount_sat_greater(state->remoteconf.dust_limit,
			       state->localconf.channel_reserve)) {
		negotiation_failed(state,
				   "dust limit %s"
				   " would be above our reserve %s",
				   type_to_string(tmpctx, struct amount_sat,
						  &state->remoteconf.dust_limit),
				   type_to_string(tmpctx, struct amount_sat,
						  &state->localconf.channel_reserve));
		return NULL;
	}

	/* If we allow dust reserves, we might end up in a situation
	 * in which all the channel funds are allocated to HTLCs,
	 * leaving just dust to_us and to_them outputs. If the HTLCs
	 * themselves are dust as well, our commitment transaction is
	 * now invalid since it has no outputs at all, putting us in a
	 * weird situation where the channel cannot be closed
	 * unilaterally at all. (Thanks Rusty for identifying this
	 * edge case). */
	struct amount_sat alldust, mindust =
	    amount_sat_greater(state->remoteconf.dust_limit,
			       state->localconf.dust_limit)
		? state->localconf.dust_limit
		: state->remoteconf.dust_limit;
	size_t maxhtlcs = state->remoteconf.max_accepted_htlcs +
			  state->localconf.max_accepted_htlcs;
	if (!amount_sat_mul(&alldust, mindust, maxhtlcs + 2)) {
		negotiation_failed(
		    state,
		    "Overflow while computing total possible dust amount");
		return NULL;
	}

	if (state->allowdustreserve &&
	    feature_negotiated(state->our_features, state->their_features,
			       OPT_ZEROCONF) &&
	    amount_sat_greater_eq(alldust, state->funding_sats)) {
		negotiation_failed(
		    state,
		    "channel funding %s too small for chosen "
		    "parameters: a total of %zu HTLCs with dust value %s would "
		    "result in a commitment_transaction without outputs. "
		    "Please increase the funding amount or reduce the "
		    "max_accepted_htlcs to ensure at least one non-dust "
		    "output.",
		    type_to_string(tmpctx, struct amount_sat,
				   &state->funding_sats),
		    maxhtlcs,
		    type_to_string(tmpctx, struct amount_sat, &mindust));
		return NULL;
	}

	if (!check_config_bounds(tmpctx, state->funding_sats,
				 state->feerate_per_kw,
				 state->max_to_self_delay,
				 state->min_effective_htlc_capacity,
				 &state->remoteconf,
				 &state->localconf,
				 feature_negotiated(state->our_features,
						    state->their_features,
						    OPT_ANCHOR_OUTPUTS),
				 feature_negotiated(state->our_features,
						    state->their_features,
						    OPT_ANCHORS_ZERO_FEE_HTLC_TX),
				 &err_reason)) {
		negotiation_failed(state, "%s", err_reason);
		return NULL;
	}

	funding_output_script =
		scriptpubkey_p2wsh(tmpctx,
				   bitcoin_redeem_2of2(tmpctx,
						       &state->our_funding_pubkey,
						       &state->their_funding_pubkey));

	/* If we have negotiated `option_zeroconf` then we're allowed
	 * to send `channel_ready` whenever we want. So ignore their
	 * `minimum_depth` and use ours instead. Otherwise we use the
	 * old behavior of using their value and both side will wait
	 * for that number of confirmations. */
	if (feature_negotiated(state->our_features, state->their_features,
			       OPT_ZEROCONF)) {
		status_debug(
		    "We negotiated option_zeroconf, using our minimum_depth=%d",
		    state->minimum_depth);
	} else {
		state->minimum_depth = their_mindepth;
	}

	/* Update the billboard with our infos */
	peer_billboard(false,
		       "Funding channel start: awaiting funding_txid with output to %s",
		       tal_hex(tmpctx, funding_output_script));

	/* Backwards/cross compat hack */
	if (intuit_scid_alias_type(state, channel_flags,
				   accept_tlvs->channel_type != NULL)) {
		channel_type_set_scid_alias(state->channel_type);
	}

	return towire_openingd_funder_start_reply(state,
						  funding_output_script,
						  feature_negotiated(
							  state->our_features,
							  state->their_features,
							  OPT_UPFRONT_SHUTDOWN_SCRIPT),
						  state->channel_type);
}

static bool funder_finalize_channel_setup(struct state *state,
					  struct amount_msat local_msat,
					  struct bitcoin_signature *sig,
					  struct bitcoin_tx **tx,
					  struct penalty_base **pbase)
{
	u8 *msg;
	struct channel_id id_in;
	const u8 *wscript;
	struct channel_id cid;
	char *err_reason;
	struct wally_tx_output *direct_outputs[NUM_SIDES];

	/*~ Channel is ready; Report the channel parameters to the signer. */
	msg = towire_hsmd_ready_channel(NULL,
				       true,	/* is_outbound */
				       state->funding_sats,
				       state->push_msat,
				       &state->funding.txid,
				       state->funding.n,
				       state->localconf.to_self_delay,
				       state->upfront_shutdown_script[LOCAL],
				       state->local_upfront_shutdown_wallet_index,
				       &state->their_points,
				       &state->their_funding_pubkey,
				       state->remoteconf.to_self_delay,
				       state->upfront_shutdown_script[REMOTE],
				       state->channel_type);
	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_ready_channel_reply(msg))
		status_failed(STATUS_FAIL_HSM_IO, "Bad ready_channel_reply %s",
			      tal_hex(tmpctx, msg));

	/*~ Now we can initialize the `struct channel`.  This represents
	 * the current channel state and is how we can generate the current
	 * commitment transaction.
	 *
	 * The routines to support `struct channel` are split into a common
	 * part (common/initial_channel) which doesn't support HTLCs and is
	 * enough for us here, and the complete channel support required by
	 * `channeld` which lives in channeld/full_channel. */
	derive_channel_id(&cid, &state->funding);

	state->channel = new_initial_channel(state,
					     &cid,
					     &state->funding,
					     state->minimum_depth,
					     NULL, 0, /* No channel lease */
					     state->funding_sats,
					     local_msat,
					     take(new_fee_states(NULL, LOCAL,
								 &state->feerate_per_kw)),
					     &state->localconf,
					     &state->remoteconf,
					     &state->our_points,
					     &state->their_points,
					     &state->our_funding_pubkey,
					     &state->their_funding_pubkey,
					     state->channel_type,
					     feature_offered(state->their_features,
							     OPT_LARGE_CHANNELS),
					     /* Opener is local */
					     LOCAL);
	/* We were supposed to do enough checks above, but just in case,
	 * new_initial_channel will fail to create absurd channels */
	if (!state->channel)
		peer_failed_err(state->pps,
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
				REMOTE, direct_outputs, &err_reason);
	if (!*tx) {
		/* This should not happen: we should never create channels we
		 * can't afford the fees for after reserve. */
		negotiation_failed(state,
				   "Could not meet their fees and reserve: %s", err_reason);
		goto fail;
	}

	if (direct_outputs[LOCAL])
		*pbase = penalty_base_new(state, 0, *tx, direct_outputs[LOCAL]);
	else
		*pbase = NULL;

	/* We ask the HSM to sign their commitment transaction for us: it knows
	 * our funding key, it just needs the remote funding key to create the
	 * witness script.  It also needs the amount of the funding output,
	 * as segwit signatures commit to that as well, even though it doesn't
	 * explicitly appear in the transaction itself. */
	struct simple_htlc **htlcs = tal_arr(tmpctx, struct simple_htlc *, 0);
	u32 feerate = 0; // unused since there are no htlcs
	u64 commit_num = 0;
	msg = towire_hsmd_sign_remote_commitment_tx(NULL,
						   *tx,
						   &state->channel->funding_pubkey[REMOTE],
						   &state->first_per_commitment_point[REMOTE],
						    channel_has(state->channel,
								OPT_STATIC_REMOTEKEY),
						    commit_num,
						    (const struct simple_htlc **) htlcs,
						    feerate);

	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_sign_tx_reply(msg, sig))
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
				     &state->funding.txid,
				     state->funding.n,
				     &sig->s);
	peer_write(state->pps, msg);

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
	 * transaction.  Note that errors may refer to the temporary channel
	 * id (state->channel_id), but success should refer to the new
	 * "cid" */
	msg = opening_negotiate_msg(tmpctx, state, &cid);
	if (!msg)
		goto fail;

	sig->sighash_type = SIGHASH_ALL;
	if (!fromwire_funding_signed(msg, &id_in, &sig->s))
		peer_failed_err(state->pps, &state->channel_id,
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
	state->channel_id = cid;

	if (!channel_id_eq(&id_in, &state->channel_id))
		peer_failed_err(state->pps, &id_in,
				"funding_signed ids don't match: expected %s got %s",
				type_to_string(msg, struct channel_id,
					       &state->channel_id),
				type_to_string(msg, struct channel_id, &id_in));

	/* BOLT #2:
	 *
	 * The recipient:
	 *   - if `signature` is incorrect OR non-compliant with LOW-S-standard rule...:
	 *     - MUST fail the channel
	 */
	/* So we create *our* initial commitment transaction, and check the
	 * signature they sent against that. */
	*tx = initial_channel_tx(state, &wscript, state->channel,
				 &state->first_per_commitment_point[LOCAL],
				 LOCAL, direct_outputs, &err_reason);
	if (!*tx) {
		negotiation_failed(state,
				   "Could not meet our fees and reserve: %s", err_reason);
		goto fail;
	}

	validate_initial_commitment_signature(HSM_FD, *tx, sig);

	if (!check_tx_sig(*tx, 0, NULL, wscript, &state->their_funding_pubkey, sig)) {
		peer_failed_err(state->pps, &state->channel_id,
				"Bad signature %s on tx %s using key %s (channel_type=%s)",
				type_to_string(tmpctx, struct bitcoin_signature,
					       sig),
				type_to_string(tmpctx, struct bitcoin_tx, *tx),
				type_to_string(tmpctx, struct pubkey,
					       &state->their_funding_pubkey),
				fmt_featurebits(tmpctx,
						state->channel->type->features));
	}

	/* We save their sig to our first commitment tx */
	if (!psbt_input_set_signature((*tx)->psbt, 0,
				      &state->their_funding_pubkey,
				      sig))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Unable to set signature internally");

	peer_billboard(false, "Funding channel: opening negotiation succeeded");

	return true;

fail:
	tal_free(wscript);
	return false;
}

static u8 *funder_channel_complete(struct state *state)
{
	/* Remote commitment tx */
	struct bitcoin_tx *tx;
	struct bitcoin_signature sig;
	struct amount_msat local_msat;
	struct penalty_base *pbase;

	/* Update the billboard about what we're doing*/
	peer_billboard(false,
		       "Funding channel con't: continuing with funding_txid %s",
		       type_to_string(tmpctx, struct bitcoin_txid, &state->funding.txid));

	/* We recalculate the local_msat from cached values; should
	 * succeed because we checked it earlier */
	if (!amount_sat_sub_msat(&local_msat, state->funding_sats, state->push_msat))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "push_msat %s > funding %s?",
			      type_to_string(tmpctx, struct amount_msat,
					     &state->push_msat),
			      type_to_string(tmpctx, struct amount_sat,
					     &state->funding_sats));

	if (!funder_finalize_channel_setup(state, local_msat, &sig, &tx,
					   &pbase))
		return NULL;

	return towire_openingd_funder_reply(state,
					   &state->remoteconf,
					   tx,
					   pbase,
					   &sig,
					   &state->their_points.revocation,
					   &state->their_points.payment,
					   &state->their_points.htlc,
					   &state->their_points.delayed_payment,
					   &state->first_per_commitment_point[REMOTE],
					   state->minimum_depth,
					   &state->their_funding_pubkey,
					   &state->funding,
					   state->feerate_per_kw,
					   state->localconf.channel_reserve,
					   state->upfront_shutdown_script[REMOTE],
					   state->channel_type);
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
	u16 funding_txout;
	char* err_reason;
	struct wally_tx_output *direct_outputs[NUM_SIDES];
	struct penalty_base *pbase;
	struct tlv_accept_channel_tlvs *accept_tlvs;
	struct tlv_open_channel_tlvs *open_tlvs;
	struct amount_sat *reserve;
	bool open_channel_had_channel_type;

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `funding_pubkey`, `revocation_basepoint`, `htlc_basepoint`,
	 *    `payment_basepoint`, or `delayed_payment_basepoint` are not valid
	 *     secp256k1 pubkeys in compressed format.
	 */
	if (!fromwire_open_channel(tmpctx, open_channel_msg, &chain_hash,
			    &state->channel_id,
			    &state->funding_sats,
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
			    &open_tlvs))
		    peer_failed_err(state->pps,
				    &state->channel_id,
				    "Parsing open_channel %s", tal_hex(tmpctx, open_channel_msg));
	set_remote_upfront_shutdown(state, open_tlvs->upfront_shutdown_script);

	/* BOLT #2:
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - It supports `channel_type` and `channel_type` was set:
	 *     - if `type` is not suitable.
	 *     - if `type` includes `option_zeroconf` and it does not trust the sender to open an unconfirmed channel.
	 */
	if (open_tlvs->channel_type) {
		open_channel_had_channel_type = true;
		state->channel_type = channel_type_accept(
		    state, open_tlvs->channel_type, state->our_features,
		    state->their_features);
		if (!state->channel_type) {
			negotiation_failed(state,
					   "Did not support channel_type %s",
					   fmt_featurebits(tmpctx,
							   open_tlvs->channel_type));
			return NULL;
		}
	} else {
		open_channel_had_channel_type = false;
		state->channel_type
			= default_channel_type(state,
					       state->our_features,
					       state->their_features);
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *  - the `chain_hash` value is set to a hash of a chain
	 *  that is unknown to the receiver.
	 */
	if (!bitcoin_blkid_eq(&chain_hash, &chainparams->genesis_blockhash)) {
		negotiation_failed(state,
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
	    && amount_sat_greater(state->funding_sats, chainparams->max_funding)) {
		negotiation_failed(state,
				   "funding_satoshis %s too large",
				   type_to_string(tmpctx, struct amount_sat,
						  &state->funding_sats));
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 * ...
	 *   - `push_msat` is greater than `funding_satoshis` * 1000.
	 */
	if (amount_msat_greater_sat(state->push_msat, state->funding_sats)) {
		peer_failed_err(state->pps, &state->channel_id,
				"Their push_msat %s"
				" would be too large for funding_satoshis %s",
				type_to_string(tmpctx, struct amount_msat,
					       &state->push_msat),
				type_to_string(tmpctx, struct amount_sat,
					       &state->funding_sats));
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
		negotiation_failed(state,
				   "feerate_per_kw %u below minimum %u",
				   state->feerate_per_kw, state->min_feerate);
		return NULL;
	}

	if (state->feerate_per_kw > state->max_feerate) {
		negotiation_failed(state,
				   "feerate_per_kw %u above maximum %u",
				   state->feerate_per_kw, state->max_feerate);
		return NULL;
	}

	/* This reserves 1% of the channel (rounded up) */
	set_reserve(state, state->remoteconf.dust_limit);

	/* Pending proposal to remove these limits. */
	/* BOLT #2:
	 *
	 * The sender:
	 *...
	 * - MUST set `channel_reserve_satoshis` greater than or equal to
	 *   `dust_limit_satoshis` from the `open_channel` message.
	 * - MUST set `dust_limit_satoshis` less than or equal to
         *   `channel_reserve_satoshis` from the `open_channel` message.
	 */
	if (!state->allowdustreserve &&
	    amount_sat_greater(state->remoteconf.dust_limit,
			       state->localconf.channel_reserve)) {
		negotiation_failed(state,
				   "Our channel reserve %s"
				   " would be below their dust %s",
				   type_to_string(tmpctx, struct amount_sat,
						  &state->localconf.channel_reserve),
				   type_to_string(tmpctx, struct amount_sat,
						  &state->remoteconf.dust_limit));
		return NULL;
	}

	/* These checks are the same whether we're opener or accepter... */
	if (!check_config_bounds(tmpctx, state->funding_sats,
				 state->feerate_per_kw,
				 state->max_to_self_delay,
				 state->min_effective_htlc_capacity,
				 &state->remoteconf,
				 &state->localconf,
				 feature_negotiated(state->our_features,
						    state->their_features,
						    OPT_ANCHOR_OUTPUTS),
				 feature_negotiated(state->our_features,
						    state->their_features,
						    OPT_ANCHORS_ZERO_FEE_HTLC_TX),
				 &err_reason)) {
		negotiation_failed(state, "%s", err_reason);
		return NULL;
	}

	/* Check with lightningd that we can accept this?  In particular,
	 * if we have an existing channel, we don't support it. */
	msg = towire_openingd_got_offer(NULL,
				       state->funding_sats,
				       state->push_msat,
				       state->remoteconf.dust_limit,
				       state->remoteconf.max_htlc_value_in_flight,
				       state->remoteconf.channel_reserve,
				       state->remoteconf.htlc_minimum,
				       state->feerate_per_kw,
				       state->remoteconf.to_self_delay,
				       state->remoteconf.max_accepted_htlcs,
				       channel_flags,
				       state->upfront_shutdown_script[REMOTE]);
	wire_sync_write(REQ_FD, take(msg));
	msg = wire_sync_read(tmpctx, REQ_FD);

	/* We don't allocate off tmpctx, because that's freed inside
	 * opening_negotiate_msg */
	if (!fromwire_openingd_got_offer_reply(state, msg, &err_reason,
					       &state->upfront_shutdown_script[LOCAL],
					       &state->local_upfront_shutdown_wallet_index,
					       &reserve,
					       &state->minimum_depth))
		master_badmsg(WIRE_OPENINGD_GOT_OFFER_REPLY, msg);

	/* If they give us a reason to reject, do so. */
	if (err_reason) {
		negotiation_failed(state, "%s", err_reason);
		tal_free(err_reason);
		return NULL;
	}

	/* BOLT #2:
	 * The receiving node MUST fail the channel if:
	 *...
	 *     - if `type` includes `option_zeroconf` and it does not trust the
	 *       sender to open an unconfirmed channel.
	 */
	if (channel_type_has(state->channel_type, OPT_ZEROCONF) &&
	    state->minimum_depth > 0) {
		negotiation_failed(
		    state,
		    "You required zeroconf, but you're not on our allowlist");
		return NULL;
	}

	if (!state->upfront_shutdown_script[LOCAL])
		state->upfront_shutdown_script[LOCAL]
			= no_upfront_shutdown_script(state, state->developer,
						     state->our_features,
						     state->their_features);

	if (reserve != NULL) {
		set_reserve_absolute(state, state->remoteconf.dust_limit,
				     *reserve);
	}

	/* OK, we accept! */
	accept_tlvs = tlv_accept_channel_tlvs_new(tmpctx);
	accept_tlvs->upfront_shutdown_script
		= state->upfront_shutdown_script[LOCAL];
	/* BOLT #2:
	 * - if `option_channel_type` was negotiated:
	 *    - MUST set `channel_type` to the `channel_type` from `open_channel`
	 */
	accept_tlvs->channel_type = state->channel_type->features;

	msg = towire_accept_channel(NULL, &state->channel_id,
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
				    accept_tlvs);

	peer_write(state->pps, take(msg));

	peer_billboard(false,
		       "Incoming channel: accepted, now waiting for them to create funding tx");

	/* This is a loop which handles gossip until we get a non-gossip msg */
	msg = opening_negotiate_msg(tmpctx, state, NULL);
	if (!msg)
		return NULL;

	/* The message should be "funding_created" which tells us what funding
	 * tx they generated; the sighash type is implied, so we set it here. */
	theirsig.sighash_type = SIGHASH_ALL;
	if (!fromwire_funding_created(msg, &id_in,
				      &state->funding.txid,
				      &funding_txout,
				      &theirsig.s))
		peer_failed_err(state->pps, &state->channel_id,
			    "Parsing funding_created");
	/* We only allow 16 bits for this on the wire. */
	state->funding.n = funding_txout;

	/* BOLT #2:
	 *
	 * The `temporary_channel_id` MUST be the same as the
	 * `temporary_channel_id` in the `open_channel` message.
	 */
	if (!channel_id_eq(&id_in, &state->channel_id))
		peer_failed_err(state->pps, &id_in,
				"funding_created ids don't match: sent %s got %s",
				type_to_string(msg, struct channel_id,
					       &state->channel_id),
				type_to_string(msg, struct channel_id, &id_in));

	/* Backwards/cross compat hack */
	if (intuit_scid_alias_type(state, channel_flags,
				   open_channel_had_channel_type)) {
		channel_type_set_scid_alias(state->channel_type);
	}

	/*~ Channel is ready; Report the channel parameters to the signer. */
	msg = towire_hsmd_ready_channel(NULL,
				       false,	/* is_outbound */
				       state->funding_sats,
				       state->push_msat,
				       &state->funding.txid,
				       state->funding.n,
				       state->localconf.to_self_delay,
				       state->upfront_shutdown_script[LOCAL],
				       state->local_upfront_shutdown_wallet_index,
				       &theirs,
				       &their_funding_pubkey,
				       state->remoteconf.to_self_delay,
				       state->upfront_shutdown_script[REMOTE],
				       state->channel_type);
	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_ready_channel_reply(msg))
		status_failed(STATUS_FAIL_HSM_IO, "Bad ready_channel_reply %s",
			      tal_hex(tmpctx, msg));

	/* Now we can create the channel structure. */
	state->channel = new_initial_channel(state,
					     &state->channel_id,
					     &state->funding,
					     state->minimum_depth,
					     NULL, 0, /* No channel lease */
					     state->funding_sats,
					     state->push_msat,
					     take(new_fee_states(NULL, REMOTE,
								 &state->feerate_per_kw)),
					     &state->localconf,
					     &state->remoteconf,
					     &state->our_points, &theirs,
					     &state->our_funding_pubkey,
					     &their_funding_pubkey,
					     state->channel_type,
					     feature_offered(state->their_features,
							     OPT_LARGE_CHANNELS),
					     REMOTE);
	/* We don't expect this to fail, but it does do some additional
	 * internal sanity checks. */
	if (!state->channel)
		peer_failed_err(state->pps, &state->channel_id,
				"We could not create channel with given config");

	/* BOLT #2:
	 *
	 * The recipient:
	 *   - if `signature` is incorrect OR non-compliant with LOW-S-standard
	 *     rule...:
	 *     - MUST send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */
	local_commit = initial_channel_tx(state, &wscript, state->channel,
					  &state->first_per_commitment_point[LOCAL],
					  LOCAL, NULL, &err_reason);
	/* This shouldn't happen either, AFAICT. */
	if (!local_commit) {
		negotiation_failed(state,
				   "Could not meet our fees and reserve: %s", err_reason);
		return NULL;
	}

	validate_initial_commitment_signature(HSM_FD, local_commit, &theirsig);

	if (!check_tx_sig(local_commit, 0, NULL, wscript, &their_funding_pubkey,
			  &theirsig)) {
		/* BOLT #1:
		 *
		 * ### The `error` and `warning` Messages
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
		peer_failed_err(state->pps, &state->channel_id,
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
	derive_channel_id(&state->channel_id, &state->funding);

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
					   REMOTE, direct_outputs, &err_reason);
	if (!remote_commit) {
		negotiation_failed(state,
				   "Could not meet their fees and reserve: %s", err_reason);
		return NULL;
	}

	/* Make HSM sign it */
	struct simple_htlc **htlcs = tal_arr(tmpctx, struct simple_htlc *, 0);
	u32 feerate = 0; // unused since there are no htlcs
	u64 commit_num = 0;
	msg = towire_hsmd_sign_remote_commitment_tx(NULL,
						   remote_commit,
						   &state->channel->funding_pubkey[REMOTE],
						   &state->first_per_commitment_point[REMOTE],
						    channel_has(state->channel,
								OPT_STATIC_REMOTEKEY),
						   commit_num,
						   (const struct simple_htlc **) htlcs,
						   feerate);

	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_sign_tx_reply(msg, &sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad sign_tx_reply %s", tal_hex(tmpctx, msg));

	/* We don't send this ourselves: channeld does, because master needs
	 * to save state to disk before doing so. */
	assert(sig.sighash_type == SIGHASH_ALL);
	msg = towire_funding_signed(state, &state->channel_id, &sig.s);

	if (direct_outputs[LOCAL] != NULL)
		pbase = penalty_base_new(tmpctx, 0, remote_commit,
					 direct_outputs[LOCAL]);
	else
		pbase = NULL;

	return towire_openingd_fundee(state,
				     &state->remoteconf,
				     local_commit,
				     pbase,
				     &theirsig,
				     &theirs.revocation,
				     &theirs.payment,
				     &theirs.htlc,
				     &theirs.delayed_payment,
				     &state->first_per_commitment_point[REMOTE],
				     &their_funding_pubkey,
				     &state->funding,
				     state->funding_sats,
				     state->push_msat,
				     channel_flags,
				     state->feerate_per_kw,
				     msg,
				     state->localconf.channel_reserve,
				     state->upfront_shutdown_script[LOCAL],
				     state->upfront_shutdown_script[REMOTE],
				     state->channel_type);
}

/*~ Standard "peer sent a message, handle it" demuxer.  Though it really only
 * handles one message, we use the standard form as principle of least
 * surprise. */
static u8 *handle_peer_in(struct state *state)
{
	u8 *msg = peer_read(tmpctx, state->pps);
	enum peer_wire t = fromwire_peektype(msg);
	struct channel_id channel_id;
	bool extracted;

	if (t == WIRE_OPEN_CHANNEL)
		return fundee_channel(state, msg);

	/* Handles error cases. */
	if (handle_peer_error_or_warning(state->pps, msg))
		return NULL;

	extracted = extract_channel_id(msg, &channel_id);

	peer_write(state->pps,
			  take(towire_warningfmt(NULL,
						 extracted ? &channel_id : NULL,
						 "Unexpected message %s: %s",
						 peer_wire_name(t),
						 tal_hex(tmpctx, msg))));

	/* FIXME: We don't actually want master to try to send an
	 * error, since peer is transient.  This is a hack.
	 */
	status_broken("Unexpected message %s", peer_wire_name(t));
	peer_failed_connection_lost();
}

static void handle_dev_memleak(struct state *state, const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	/* Populate a hash table with all our allocations (except msg, which
	 * is in use right now). */
	memtable = memleak_start(tmpctx);
	memleak_ptr(memtable, msg);

	/* Now delete state and things it has pointers to. */
	memleak_scan_obj(memtable, state);

	/* If there's anything left, dump it to logs, and return true. */
	found_leak = dump_memleak(memtable, memleak_status_broken);
	wire_sync_write(REQ_FD,
			take(towire_openingd_dev_memleak_reply(NULL,
							      found_leak)));
}

/* Standard lightningd-fd-is-ready-to-read demux code.  Again, we could hang
 * here, but if we can't trust our parent, who can we trust? */
static u8 *handle_master_in(struct state *state)
{
	u8 *msg = wire_sync_read(tmpctx, REQ_FD);
	enum openingd_wire t = fromwire_peektype(msg);
	u8 channel_flags;
	struct bitcoin_txid funding_txid;
	u16 funding_txout;
	u32 nonanchor_feerate, anchor_feerate;

	switch (t) {
	case WIRE_OPENINGD_FUNDER_START:
		if (!fromwire_openingd_funder_start(state, msg,
						    &state->funding_sats,
						    &state->push_msat,
						    &state->upfront_shutdown_script[LOCAL],
						    &state->local_upfront_shutdown_wallet_index,
						    &nonanchor_feerate,
						    &anchor_feerate,
						    &state->channel_id,
						    &channel_flags,
						    &state->reserve))
			master_badmsg(WIRE_OPENINGD_FUNDER_START, msg);
		msg = funder_channel_start(state, channel_flags, nonanchor_feerate, anchor_feerate);

		/* We want to keep openingd alive, since we're not done yet */
		if (msg)
			wire_sync_write(REQ_FD, take(msg));
		return NULL;
	case WIRE_OPENINGD_FUNDER_COMPLETE:
		if (!fromwire_openingd_funder_complete(state, msg,
						       &funding_txid,
						       &funding_txout,
						       &state->channel_type))
			master_badmsg(WIRE_OPENINGD_FUNDER_COMPLETE, msg);
		state->funding.txid = funding_txid;
		state->funding.n = funding_txout;
		return funder_channel_complete(state);
	case WIRE_OPENINGD_FUNDER_CANCEL:
		/* We're aborting this, simple */
		if (!fromwire_openingd_funder_cancel(msg))
			master_badmsg(WIRE_OPENINGD_FUNDER_CANCEL, msg);

		msg = towire_errorfmt(NULL, &state->channel_id, "Channel open canceled by us");
		peer_write(state->pps, take(msg));
		negotiation_aborted(state, "Channel open canceled by RPC");
		return NULL;
	case WIRE_OPENINGD_DEV_MEMLEAK:
		if (state->developer) {
			handle_dev_memleak(state, msg);
			return NULL;
		}
		/* fall thru */
	case WIRE_OPENINGD_DEV_MEMLEAK_REPLY:
	case WIRE_OPENINGD_INIT:
	case WIRE_OPENINGD_FUNDER_REPLY:
	case WIRE_OPENINGD_FUNDER_START_REPLY:
	case WIRE_OPENINGD_FUNDEE:
	case WIRE_OPENINGD_FAILED:
	case WIRE_OPENINGD_GOT_OFFER:
	case WIRE_OPENINGD_GOT_OFFER_REPLY:
		break;
	}

	status_failed(STATUS_FAIL_MASTER_IO,
		      "Unknown msg %s", tal_hex(tmpctx, msg));
}

int main(int argc, char *argv[])
{
	setup_locale();

	u8 *msg;
	struct pollfd pollfd[2];
	struct state *state = tal(NULL, struct state);
	struct secret *none;

	state->developer = subdaemon_setup(argc, argv);

	/*~ This makes status_failed, status_debug etc work synchronously by
	 * writing to REQ_FD */
	status_setup_sync(REQ_FD);

	/*~ The very first thing we read from lightningd is our init msg */
	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_openingd_init(state, msg,
				    &chainparams,
				    &state->our_features,
				    &state->their_features,
				    &state->localconf,
				    &state->max_to_self_delay,
				    &state->min_effective_htlc_capacity,
				    &state->our_points,
				    &state->our_funding_pubkey,
				    &state->minimum_depth,
				    &state->min_feerate, &state->max_feerate,
				    &state->dev_force_tmp_channel_id,
				    &state->allowdustreserve))
		master_badmsg(WIRE_OPENINGD_INIT, msg);

	/* 3 == peer, 4 = hsmd */
	state->pps = new_per_peer_state(state);
	per_peer_state_set_fd(state->pps, 3);

	/*~ Initially we're not associated with a channel, but
	 * handle_peer_gossip_or_error compares this. */
	memset(&state->channel_id, 0, sizeof(state->channel_id));
	state->channel = NULL;

	/* Default this to zero, we only ever look at the local */
	state->remoteconf.max_dust_htlc_exposure_msat = AMOUNT_MSAT(0);

	/*~ We set these to NULL, meaning no requirements on shutdown */
	state->upfront_shutdown_script[LOCAL]
		= state->upfront_shutdown_script[REMOTE]
		= NULL;

	/*~ We need an initial per-commitment point whether we're funding or
	 * they are, and lightningd has reserved a unique dbid for us already,
	 * so we might as well get the hsm daemon to generate it now. */
	wire_sync_write(HSM_FD,
			take(towire_hsmd_get_per_commitment_point(NULL, 0)));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_get_per_commitment_point_reply(tmpctx, msg,
							 &state->first_per_commitment_point[LOCAL],
							 &none))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad get_per_commitment_point_reply %s",
			      tal_hex(tmpctx, msg));
	/*~ The HSM gives us the N-2'th per-commitment secret when we get the
	 * N'th per-commitment point.  But since N=0, it won't give us one. */
	assert(none == NULL);

	/*~ We manually run a little poll() loop here.  With only three fds */
	pollfd[0].fd = REQ_FD;
	pollfd[0].events = POLLIN;
	pollfd[1].fd = state->pps->peer_fd;
	pollfd[1].events = POLLIN;

	/* We exit when we get a conclusion to write to lightningd: either
	 * opening_funder_reply or opening_fundee. */
	msg = NULL;
	while (!msg) {
		/*~ If we get a signal which aborts the poll() call, valgrind
		 * complains about revents being uninitialized.  I'm not sure
		 * that's correct, but it's easy to be sure. */
		pollfd[0].revents = pollfd[1].revents = 0;

		poll(pollfd, ARRAY_SIZE(pollfd), -1);
		/* Subtle: handle_master_in can do its own poll loop, so
		 * don't try to service more than one fd per loop. */
		/* First priority: messages from lightningd. */
		if (pollfd[0].revents & POLLIN)
			msg = handle_master_in(state);
		/* Second priority: messages from peer. */
		else if (pollfd[1].revents & POLLIN)
			msg = handle_peer_in(state);

		/* Since we're the top-level event loop, we clean up */
		clean_tmpctx();
	}

	/*~ Write message and hand back the peer fd.  This also means that if
	 * the peer wrote us any messages we didn't read yet, it will simply
	 * be read by the next daemon. */
	wire_sync_write(REQ_FD, msg);
	per_peer_state_fdpass_send(REQ_FD, state->pps);
	status_debug("Sent %s with fd",
		     openingd_wire_name(fromwire_peektype(msg)));

	/* Give master a chance to pass the fd along */
	sleep(1);

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
