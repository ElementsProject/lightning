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
#include <common/funding_tx.h>
#include <common/gen_peer_status_wire.h>
#include <common/initial_channel.h>
#include <common/key_derive.h>
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

/* stdin == requests, 3 == peer, 4 == gossip */
#define REQ_FD STDIN_FILENO
#define PEER_FD 3
#define GOSSIP_FD 4
#define HSM_FD 5

struct state {
	struct crypto_state cs;
	struct pubkey next_per_commit[NUM_SIDES];

	/* Constriants on a channel they open. */
	u32 minimum_depth;
	u32 min_feerate, max_feerate;

	struct basepoints our_points;
	struct pubkey our_funding_pubkey;

	/* Initially temporary, then final channel id. */
	struct channel_id channel_id;

	/* Funding and feerate: set by opening peer. */
	u64 funding_satoshis, push_msat;
	u32 feerate_per_kw;
	struct bitcoin_txid funding_txid;
	u16 funding_txout;

	struct channel_config localconf, remoteconf;

	/* Limits on what remote config we accept */
	u32 max_to_self_delay;
	u64 min_effective_htlc_capacity_msat;

	struct channel *channel;

	bool can_accept_channel;
	const struct chainparams *chainparams;
};

static void negotiation_aborted(struct state *state, bool am_funder,
				const char *why)
{
	status_debug("aborted opening negotiaion: %s", why);
	peer_billboard(true, why);

	/* If necessary, tell master that funding failed. */
	if (am_funder) {
		u8 *msg = towire_opening_funder_failed(NULL, why);
		wire_sync_write(REQ_FD, take(msg));
	}

	/* Reset state. */
	memset(&state->channel_id, 0, sizeof(state->channel_id));
	state->channel = tal_free(state->channel);
}

/* For negotiation failures: we tell them it's their fault. */
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

static bool check_config_bounds(struct state *state,
				const struct channel_config *remoteconf,
				bool am_funder)
{
	u64 capacity_msat;
	u64 reserve_msat;

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

	/* Overflow check before capacity calc. */
	if (remoteconf->channel_reserve_satoshis > state->funding_satoshis) {
		negotiation_failed(state, am_funder,
				   "channel_reserve_satoshis %"PRIu64
				   " too large for funding_satoshis %"PRIu64,
				   remoteconf->channel_reserve_satoshis,
				   state->funding_satoshis);
		return false;
	}

	/* Consider highest reserve. */
	reserve_msat = remoteconf->channel_reserve_satoshis * 1000;
	if (state->localconf.channel_reserve_satoshis * 1000 > reserve_msat)
		reserve_msat = state->localconf.channel_reserve_satoshis * 1000;

	capacity_msat = state->funding_satoshis * 1000 - reserve_msat;

	if (remoteconf->max_htlc_value_in_flight_msat < capacity_msat)
		capacity_msat = remoteconf->max_htlc_value_in_flight_msat;

	if (remoteconf->htlc_minimum_msat * (u64)1000 > capacity_msat) {
		negotiation_failed(state, am_funder,
				   "htlc_minimum_msat %"PRIu64
				   " too large for funding_satoshis %"PRIu64
				   " capacity_msat %"PRIu64,
				   remoteconf->htlc_minimum_msat,
				   state->funding_satoshis,
				   capacity_msat);
		return false;
	}

	if (capacity_msat < state->min_effective_htlc_capacity_msat) {
		negotiation_failed(state, am_funder,
				   "channel capacity with funding %"PRIu64" msat,"
				   " reserves %"PRIu64"/%"PRIu64" msat,"
				   " max_htlc_value_in_flight_msat %"PRIu64
				   " is %"PRIu64" msat, which is below %"PRIu64" msat",
				   state->funding_satoshis * 1000,
				   remoteconf->channel_reserve_satoshis * 1000,
				   state->localconf.channel_reserve_satoshis * 1000,
				   remoteconf->max_htlc_value_in_flight_msat,
				   capacity_msat,
				   state->min_effective_htlc_capacity_msat);
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
	if (remoteconf->dust_limit_satoshis
	    > remoteconf->channel_reserve_satoshis) {
		negotiation_failed(state, am_funder,
				   "dust_limit_satoshis %"PRIu64
				   " too large for channel_reserve_satoshis %"
				   PRIu64,
				   remoteconf->dust_limit_satoshis,
				   remoteconf->channel_reserve_satoshis);
		return false;
	}

	return true;
}

/* We always set channel_reserve_satoshis to 1%, rounded up. */
static void set_reserve(struct state *state)
{
	state->localconf.channel_reserve_satoshis
		= (state->funding_satoshis + 99) / 100;

	/* BOLT #2:
	 *
	 * The sending node:
	 *...
	 * - MUST set `channel_reserve_satoshis` greater than or equal to
         *   `dust_limit_satoshis`.
	 */
	if (state->localconf.channel_reserve_satoshis
	    < state->localconf.dust_limit_satoshis)
		state->localconf.channel_reserve_satoshis
			= state->localconf.dust_limit_satoshis;
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

	for (i = 0; i < sizeof(*channel_id); i++)
		channel_id->id[i] = pseudorand(256);
}

/* Handle random messages we might get during opening negotiation,
 * returning the first non-handled one, or NULL if we aborted negotiation. */
static u8 *opening_negotiate_msg(const tal_t *ctx, struct state *state,
				 bool am_funder)
{
	for (;;) {
		u8 *msg;
		bool from_gossipd;
		char *err;
		bool all_channels;
		struct channel_id actual;

		clean_tmpctx();
		msg = peer_or_gossip_sync_read(ctx, PEER_FD, GOSSIP_FD,
					       &state->cs, &from_gossipd);
		if (from_gossipd) {
			handle_gossip_msg(PEER_FD, &state->cs, take(msg));
			continue;
		}

		if (is_msg_for_gossipd(msg)) {
			wire_sync_write(GOSSIP_FD, take(msg));
			continue;
		}

		if (is_peer_error(tmpctx, msg, &state->channel_id,
				  &err, &all_channels)) {
			/* BOLT #1:
			 *
			 *  - if no existing channel is referred to by the
			 *    message:
			 *    - MUST ignore the message.
			 */
			if (!err) {
				tal_free(msg);
				continue;
			}
			if (am_funder) {
				msg = towire_opening_funder_failed(NULL, err);
				wire_sync_write(REQ_FD, take(msg));
			}
			/* Close connection on all_channels error. */
			if (all_channels)
				peer_failed_received_errmsg(PEER_FD, GOSSIP_FD,
							    &state->cs, err,
							    NULL);
			negotiation_aborted(state, am_funder,
					    tal_fmt(tmpctx, "They sent error %s",
						    err));
			/* Return NULL so caller knows to stop negotiating. */
			return NULL;
		}

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

		return msg;
	}
}
static u8 *funder_channel(struct state *state,
			  u64 change_satoshis, u32 change_keyindex,
			  u8 channel_flags,
			  struct utxo **utxos,
			  const struct ext_key *bip32_base)
{
	struct channel_id id_in;
	u8 *msg;
	struct bitcoin_tx *tx;
	struct basepoints theirs;
	struct pubkey their_funding_pubkey;
	struct pubkey *changekey;
	secp256k1_ecdsa_signature sig;
	u32 minimum_depth;
	const u8 *wscript;
	struct bitcoin_tx *funding;

	set_reserve(state);

	temporary_channel_id(&state->channel_id);

	if (state->funding_satoshis > state->chainparams->max_funding_satoshi)
		status_failed(STATUS_FAIL_MASTER_IO,
			      "funding_satoshis must be < %"PRIu64", not %"PRIu64,
			      state->chainparams->max_funding_satoshi,
			      state->funding_satoshis);

	/* BOLT #2:
	 *
	 * The sending node:
	 *...
	 *  - MUST set `push_msat` to equal or less than 1000 *
	 *   `funding_satoshis`.
	 */
	if (state->push_msat > 1000 * state->funding_satoshis)
		status_failed(STATUS_FAIL_MASTER_IO,
			      "push-msat must be < %"PRIu64,
			      1000 * state->funding_satoshis);

	msg = towire_open_channel(state,
				  &state->chainparams->genesis_blockhash,
				  &state->channel_id,
				  state->funding_satoshis, state->push_msat,
				  state->localconf.dust_limit_satoshis,
				  state->localconf.max_htlc_value_in_flight_msat,
				  state->localconf.channel_reserve_satoshis,
				  state->localconf.htlc_minimum_msat,
				  state->feerate_per_kw,
				  state->localconf.to_self_delay,
				  state->localconf.max_accepted_htlcs,
				  &state->our_funding_pubkey,
				  &state->our_points.revocation,
				  &state->our_points.payment,
				  &state->our_points.delayed_payment,
				  &state->our_points.htlc,
				  &state->next_per_commit[LOCAL],
				  channel_flags);
	sync_crypto_write(&state->cs, PEER_FD, msg);

	peer_billboard(false,
		       "Funding channel: offered, now waiting for accept_channel");
	msg = opening_negotiate_msg(tmpctx, state, true);
	if (!msg)
		return NULL;

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `funding_pubkey`, `revocation_basepoint`, `htlc_basepoint`,
	 *    `payment_basepoint`, or `delayed_payment_basepoint` are not
	 *    valid DER-encoded compressed secp256k1 pubkeys.
	 */
	if (!fromwire_accept_channel(msg, &id_in,
				     &state->remoteconf.dust_limit_satoshis,
				     &state->remoteconf
				     .max_htlc_value_in_flight_msat,
				     &state->remoteconf
				     .channel_reserve_satoshis,
				     &state->remoteconf.htlc_minimum_msat,
				     &minimum_depth,
				     &state->remoteconf.to_self_delay,
				     &state->remoteconf.max_accepted_htlcs,
				     &their_funding_pubkey,
				     &theirs.revocation,
				     &theirs.payment,
				     &theirs.delayed_payment,
				     &theirs.htlc,
				     &state->next_per_commit[REMOTE]))
		peer_failed(&state->cs,
			    &state->channel_id,
			    "Parsing accept_channel %s", tal_hex(msg, msg));

	/* BOLT #2:
	 *
	 * The `temporary_channel_id` MUST be the same as the
	 * `temporary_channel_id` in the `open_channel` message. */
	if (!channel_id_eq(&id_in, &state->channel_id))
		peer_failed(&state->cs,
			    &state->channel_id,
			    "accept_channel ids don't match: sent %s got %s",
			    type_to_string(msg, struct channel_id, &id_in),
			    type_to_string(msg, struct channel_id,
					   &state->channel_id));

	/* BOLT #2:
	 *
	 * The receiver:
	 *...
	 *  - if `minimum_depth` is unreasonably large:
	 *    - MAY reject the channel.
	 */
	if (minimum_depth > 10) {
		negotiation_failed(state, true,
				   "minimum_depth %u larger than %u",
				   minimum_depth, 10);
		return NULL;
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
	if (state->remoteconf.channel_reserve_satoshis
	    < state->localconf.dust_limit_satoshis) {
		negotiation_failed(state, true,
				   "channel reserve %"PRIu64
				   " would be below our dust %"PRIu64,
				   state->remoteconf.channel_reserve_satoshis,
				   state->localconf.dust_limit_satoshis);
		return NULL;
	}
	if (state->localconf.channel_reserve_satoshis
	    < state->remoteconf.dust_limit_satoshis) {
		negotiation_failed(state, true,
				   "dust limit %"PRIu64
				   " would be above our reserve %"PRIu64,
				   state->remoteconf.dust_limit_satoshis,
				   state->localconf.channel_reserve_satoshis);
		return NULL;
	}

	if (!check_config_bounds(state, &state->remoteconf, true))
		return NULL;

	/* Now, ask create funding transaction to pay those two addresses. */
	if (change_satoshis) {
		changekey = tal(tmpctx, struct pubkey);
		if (!bip32_pubkey(bip32_base, changekey, change_keyindex))
			status_failed(STATUS_FAIL_MASTER_IO,
				      "Bad change key %u", change_keyindex);
	} else
		changekey = NULL;

	funding = funding_tx(state, &state->funding_txout,
			     cast_const2(const struct utxo **, utxos),
			     state->funding_satoshis,
			     &state->our_funding_pubkey,
			     &their_funding_pubkey,
			     change_satoshis, changekey,
			     bip32_base);
	bitcoin_txid(funding, &state->funding_txid);

	state->channel = new_initial_channel(state,
					     &state->chainparams->genesis_blockhash,
					     &state->funding_txid,
					     state->funding_txout,
					     state->funding_satoshis,
					     state->funding_satoshis * 1000
					     - state->push_msat,
					     state->feerate_per_kw,
					     &state->localconf,
					     &state->remoteconf,
					     &state->our_points, &theirs,
					     &state->our_funding_pubkey,
					     &their_funding_pubkey,
					     LOCAL);
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
	tx = initial_channel_tx(state, &wscript, state->channel,
				&state->next_per_commit[REMOTE], REMOTE);
	if (!tx) {
		negotiation_failed(state, true,
				   "Could not meet their fees and reserve");
		return NULL;
	}

	msg = towire_hsm_sign_remote_commitment_tx(NULL,
						   tx,
						   &state->channel->funding_pubkey[REMOTE],
						   state->channel->funding_msat / 1000);

	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_sign_tx_reply(msg, &sig))
		status_failed(STATUS_FAIL_HSM_IO, "Bad sign_tx_reply %s",
			      tal_hex(tmpctx, msg));

	status_trace("signature %s on tx %s using key %s",
		     type_to_string(tmpctx, secp256k1_ecdsa_signature, &sig),
		     type_to_string(tmpctx, struct bitcoin_tx, tx),
		     type_to_string(tmpctx, struct pubkey,
				    &state->our_funding_pubkey));

	msg = towire_funding_created(state, &state->channel_id,
				     &state->funding_txid,
				     state->funding_txout,
				     &sig);
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

	msg = opening_negotiate_msg(tmpctx, state, true);
	if (!msg)
		return NULL;

	if (!fromwire_funding_signed(msg, &id_in, &sig))
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
	tx = initial_channel_tx(state, &wscript, state->channel,
				&state->next_per_commit[LOCAL], LOCAL);
	if (!tx) {
		negotiation_failed(state, true,
				   "Could not meet our fees and reserve");
		return NULL;
	}

	if (!check_tx_sig(tx, 0, NULL, wscript, &their_funding_pubkey, &sig)) {
		peer_failed(&state->cs,
			    &state->channel_id,
			    "Bad signature %s on tx %s using key %s",
			    type_to_string(tmpctx, secp256k1_ecdsa_signature,
					   &sig),
			    type_to_string(tmpctx, struct bitcoin_tx, tx),
			    type_to_string(tmpctx, struct pubkey,
					   &their_funding_pubkey));
	}

	peer_billboard(false, "Funding channel: opening negotiation succeeded");

	/* BOLT #2:
	 *
	 * The recipient:
	 *...
	 *   - on receipt of a valid `funding_signed`:
	 *     - SHOULD broadcast the funding transaction.
	 */
	return towire_opening_funder_reply(state,
					   &state->remoteconf,
					   tx,
					   &sig,
					   &state->cs,
					   &theirs.revocation,
					   &theirs.payment,
					   &theirs.htlc,
					   &theirs.delayed_payment,
					   &state->next_per_commit[REMOTE],
					   minimum_depth,
					   &their_funding_pubkey,
					   &state->funding_txid,
					   state->feerate_per_kw,
					   state->localconf.channel_reserve_satoshis);
}

static u8 *fundee_channel(struct state *state, const u8 *open_channel_msg)
{
	struct channel_id id_in;
	struct basepoints theirs;
	struct pubkey their_funding_pubkey;
	secp256k1_ecdsa_signature theirsig, sig;
	struct bitcoin_tx *local_commit, *remote_commit;
	struct bitcoin_blkid chain_hash;
	u8 *msg;
	const u8 *wscript;
	u8 channel_flags;

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `funding_pubkey`, `revocation_basepoint`, `htlc_basepoint`,
	 *    `payment_basepoint`, or `delayed_payment_basepoint` are not valid
	 *     DER-encoded compressed secp256k1 pubkeys.
	 */
	if (!fromwire_open_channel(open_channel_msg, &chain_hash,
				   &state->channel_id,
				   &state->funding_satoshis, &state->push_msat,
				   &state->remoteconf.dust_limit_satoshis,
				   &state->remoteconf.max_htlc_value_in_flight_msat,
				   &state->remoteconf.channel_reserve_satoshis,
				   &state->remoteconf.htlc_minimum_msat,
				   &state->feerate_per_kw,
				   &state->remoteconf.to_self_delay,
				   &state->remoteconf.max_accepted_htlcs,
				   &their_funding_pubkey,
				   &theirs.revocation,
				   &theirs.payment,
				   &theirs.delayed_payment,
				   &theirs.htlc,
				   &state->next_per_commit[REMOTE],
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
	 * The receiver:
	 *  - if the `chain_hash` value, within the `open_channel`, message is
	 *    set to a hash of a chain that is unknown to the receiver:
	 *     - MUST reject the channel.
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
	if (state->funding_satoshis > state->chainparams->max_funding_satoshi) {
		negotiation_failed(state, false,
				   "funding_satoshis %"PRIu64" too large",
				   state->funding_satoshis);
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *   - `push_msat` is greater than `funding_satoshis` * 1000.
	 */
	if (state->push_msat > state->funding_satoshis * 1000) {
		peer_failed(&state->cs,
			    &state->channel_id,
			    "Our push_msat %"PRIu64
			    " would be too large for funding_satoshis %"PRIu64,
			    state->push_msat, state->funding_satoshis);
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
	if (state->localconf.channel_reserve_satoshis
	    < state->remoteconf.dust_limit_satoshis) {
		negotiation_failed(state, false,
				   "Our channel reserve %"PRIu64
				   " would be below their dust %"PRIu64,
				   state->localconf.channel_reserve_satoshis,
				   state->remoteconf.dust_limit_satoshis);
		return NULL;
	}
	if (state->localconf.dust_limit_satoshis
	    > state->remoteconf.channel_reserve_satoshis) {
		negotiation_failed(state, false,
				   "Our dust limit %"PRIu64
				   " would be above their reserve %"PRIu64,
				   state->localconf.dust_limit_satoshis,
				   state->remoteconf.channel_reserve_satoshis);
		return NULL;
	}

	if (!check_config_bounds(state, &state->remoteconf, false))
		return NULL;

	msg = towire_accept_channel(state, &state->channel_id,
				    state->localconf.dust_limit_satoshis,
				    state->localconf
				      .max_htlc_value_in_flight_msat,
				    state->localconf.channel_reserve_satoshis,
				    state->localconf.htlc_minimum_msat,
				    state->minimum_depth,
				    state->localconf.to_self_delay,
				    state->localconf.max_accepted_htlcs,
				    &state->our_funding_pubkey,
				    &state->our_points.revocation,
				    &state->our_points.payment,
				    &state->our_points.delayed_payment,
				    &state->our_points.htlc,
				    &state->next_per_commit[LOCAL]);

	sync_crypto_write(&state->cs, PEER_FD, take(msg));

	peer_billboard(false,
		       "Incoming channel: accepted, now waiting for them to create funding tx");

	msg = opening_negotiate_msg(tmpctx, state, false);
	if (!msg)
		return NULL;

	if (!fromwire_funding_created(msg, &id_in,
				      &state->funding_txid,
				      &state->funding_txout,
				      &theirsig))
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

	state->channel = new_initial_channel(state,
					     &chain_hash,
					     &state->funding_txid,
					     state->funding_txout,
					     state->funding_satoshis,
					     state->push_msat,
					     state->feerate_per_kw,
					     &state->localconf,
					     &state->remoteconf,
					     &state->our_points, &theirs,
					     &state->our_funding_pubkey,
					     &their_funding_pubkey,
					     REMOTE);
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
					  &state->next_per_commit[LOCAL], LOCAL);
	if (!local_commit) {
		negotiation_failed(state, false,
				   "Could not meet our fees and reserve");
		return NULL;
	}

	if (!check_tx_sig(local_commit, 0, NULL, wscript, &their_funding_pubkey,
			  &theirsig)) {
		peer_failed(&state->cs,
			    &state->channel_id,
			    "Bad signature %s on tx %s using key %s",
			    type_to_string(tmpctx, secp256k1_ecdsa_signature,
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

	/* BOLT #2:
	 *
	 * ### The `funding_signed` Message
	 *
	 * This message gives the funder the signature it needs for the first
	 * commitment transaction, so it can broadcast the transaction knowing
	 * that funds can be redeemed, if need be.
	 */
	remote_commit = initial_channel_tx(state, &wscript, state->channel,
					   &state->next_per_commit[REMOTE],
					   REMOTE);
	if (!remote_commit) {
		negotiation_failed(state, false,
				   "Could not meet their fees and reserve");
		return NULL;
	}

	/* FIXME: Perhaps we should have channeld generate this, so we
	 * can't possibly send before channel committed? */
	msg = towire_hsm_sign_remote_commitment_tx(NULL,
						   remote_commit,
						   &state->channel->funding_pubkey[REMOTE],
						   state->channel->funding_msat / 1000);

	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_sign_tx_reply(msg, &sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad sign_tx_reply %s", tal_hex(tmpctx, msg));

	/* We don't send this ourselves: channeld does, because master needs
	 * to save state to disk before doing so. */
	msg = towire_funding_signed(state, &state->channel_id, &sig);

	return towire_opening_fundee(state,
				     &state->remoteconf,
				     local_commit,
				     &theirsig,
				     &state->cs,
				     &theirs.revocation,
				     &theirs.payment,
				     &theirs.htlc,
				     &theirs.delayed_payment,
				     &state->next_per_commit[REMOTE],
				     &their_funding_pubkey,
				     &state->funding_txid,
				     state->funding_txout,
				     state->funding_satoshis,
				     state->push_msat,
				     channel_flags,
				     state->feerate_per_kw,
				     msg,
				     state->localconf.channel_reserve_satoshis);
}

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

static void handle_gossip_in(struct state *state)
{
	u8 *msg = wire_sync_read(NULL, GOSSIP_FD);

	if (!msg)
		status_failed(STATUS_FAIL_GOSSIP_IO,
			      "Reading gossip: %s", strerror(errno));

	handle_gossip_msg(PEER_FD, &state->cs, take(msg));
}

static bool is_all_channel_error(const u8 *msg)
{
	struct channel_id channel_id;
	u8 *data;

	if (!fromwire_error(msg, msg, &channel_id, &data))
		return false;
	tal_free(data);
	return channel_id_is_all(&channel_id);
}

static void fail_if_all_error(const u8 *inner)
{
	if (!is_all_channel_error(inner))
		return;

	status_info("Master said send err: %s",
		    sanitize_error(tmpctx, inner, NULL));
	exit(0);
}

static u8 *handle_master_in(struct state *state)
{
	u8 *msg = wire_sync_read(tmpctx, REQ_FD);
	enum opening_wire_type t = fromwire_peektype(msg);
	u64 change_satoshis;
	u32 change_keyindex;
	u8 channel_flags;
	struct utxo **utxos;
	struct ext_key bip32_base;

	switch (t) {
	case WIRE_OPENING_FUNDER:
		if (!fromwire_opening_funder(state, msg,
					     &state->funding_satoshis,
					     &state->push_msat,
					     &state->feerate_per_kw,
					     &change_satoshis, &change_keyindex,
					     &channel_flags, &utxos,
					     &bip32_base))
			master_badmsg(WIRE_OPENING_FUNDER, msg);

		msg = funder_channel(state,
				     change_satoshis,
				     change_keyindex, channel_flags,
				     utxos, &bip32_base);
		return msg;

	case WIRE_OPENING_CAN_ACCEPT_CHANNEL:
		if (!fromwire_opening_can_accept_channel(msg))
			master_badmsg(WIRE_OPENING_CAN_ACCEPT_CHANNEL, msg);
		state->can_accept_channel = true;
		return NULL;

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

	status_setup_sync(REQ_FD);

	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_opening_init(tmpctx, msg,
				   &chain_hash,
				   &state->localconf,
				   &state->max_to_self_delay,
				   &state->min_effective_htlc_capacity_msat,
				   &state->cs,
				   &state->our_points,
				   &state->our_funding_pubkey,
				   &state->minimum_depth,
				   &state->min_feerate, &state->max_feerate,
				   &state->can_accept_channel,
				   &inner))
		master_badmsg(WIRE_OPENING_INIT, msg);

	/* If they wanted to send an msg, do so before we waste time
	 * doing work.  If it's a global error, we'll close
	 * immediately. */
	if (inner != NULL) {
		sync_crypto_write(&state->cs, PEER_FD, inner);
		fail_if_all_error(inner);
	}

	state->chainparams = chainparams_by_chainhash(&chain_hash);
	/* Initially we're not associated with a channel, but
	 * handle_peer_gossip_or_error wants this. */
	memset(&state->channel_id, 0, sizeof(state->channel_id));
	state->channel = NULL;

	wire_sync_write(HSM_FD,
			take(towire_hsm_get_per_commitment_point(NULL, 0)));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsm_get_per_commitment_point_reply(tmpctx, msg,
							 &state->next_per_commit[LOCAL],
							 &none))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad get_per_commitment_point_reply %s",
			      tal_hex(tmpctx, msg));
	assert(none == NULL);
	status_trace("Handed peer, entering loop");

	pollfd[0].fd = REQ_FD;
	pollfd[0].events = POLLIN;
	pollfd[1].fd = GOSSIP_FD;
	pollfd[1].events = POLLIN;
	pollfd[2].fd = PEER_FD;
	pollfd[2].events = POLLIN;

	msg = NULL;
	while (!msg) {
		poll(pollfd, ARRAY_SIZE(pollfd), -1);
		/* Subtle: handle_master_in can do its own poll loop, so
		 * don't try to service more than one fd per loop. */
		if (pollfd[0].revents & POLLIN)
			msg = handle_master_in(state);
		else if (pollfd[2].revents & POLLIN)
			msg = handle_peer_in(state);
		else if (pollfd[1].revents & POLLIN)
			handle_gossip_in(state);

		clean_tmpctx();
	}

	/* Write message and hand back the fd. */
	wire_sync_write(REQ_FD, msg);
	fdpass_send(REQ_FD, PEER_FD);
	fdpass_send(REQ_FD, GOSSIP_FD);
	status_trace("Sent %s with fd",
		     opening_wire_type_name(fromwire_peektype(msg)));
	tal_free(state);
	daemon_shutdown();
	return 0;
}
