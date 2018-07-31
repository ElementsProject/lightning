#include <bitcoin/block.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
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
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <openingd/gen_opening_wire.h>
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

	/* Initially temporary, then final channel id. */
	struct channel_id channel_id;

	/* Funding and feerate: set by opening peer. */
	u64 funding_satoshis, push_msat;
	u32 feerate_per_kw;
	struct bitcoin_txid funding_txid;
	u16 funding_txout;

	struct channel_config localconf, *remoteconf;

	/* Limits on what remote config we accept */
	u32 max_to_self_delay;
	u64 min_effective_htlc_capacity_msat;

	struct channel *channel;

	const struct chainparams *chainparams;
};

/* For negotiation failures: we tell them it's their fault.  Same
 * as peer_failed, with slightly different local and remote wording. */
static void negotiation_failed(struct state *state, const char *fmt, ...)
{
	va_list ap;
	const char *errmsg;
	u8 *msg;

	va_start(ap, fmt);
	errmsg = tal_vfmt(state, fmt, ap);
	va_end(ap);

	peer_billboard(true, errmsg);
	msg = towire_status_peer_error(NULL, &state->channel_id,
				       errmsg, &state->cs,
				       towire_errorfmt(errmsg,
						       &state->channel_id,
						       "You gave bad parameters:%s",
						       errmsg));
	tal_free(errmsg);
	status_send_fatal(take(msg), PEER_FD, GOSSIP_FD);
	peer_failed(&state->cs, &state->channel_id,
		    "You gave bad parameters: %s", errmsg);
}

static void check_config_bounds(struct state *state,
				const struct channel_config *remoteconf)
{
	u64 capacity_msat;
	u64 reserve_msat;

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `to_self_delay` is unreasonably large.
	 */
	if (remoteconf->to_self_delay > state->max_to_self_delay)
		negotiation_failed(state,
				   "to_self_delay %u larger than %u",
				   remoteconf->to_self_delay,
				   state->max_to_self_delay);

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
	if (remoteconf->channel_reserve_satoshis > state->funding_satoshis)
		negotiation_failed(state,
				   "channel_reserve_satoshis %"PRIu64
				   " too large for funding_satoshis %"PRIu64,
				   remoteconf->channel_reserve_satoshis,
				   state->funding_satoshis);

	/* Consider highest reserve. */
	reserve_msat = remoteconf->channel_reserve_satoshis * 1000;
	if (state->localconf.channel_reserve_satoshis * 1000 > reserve_msat)
		reserve_msat = state->localconf.channel_reserve_satoshis * 1000;

	capacity_msat = state->funding_satoshis * 1000 - reserve_msat;

	if (remoteconf->max_htlc_value_in_flight_msat < capacity_msat)
		capacity_msat = remoteconf->max_htlc_value_in_flight_msat;

	if (remoteconf->htlc_minimum_msat * (u64)1000 > capacity_msat)
		negotiation_failed(state,
				   "htlc_minimum_msat %"PRIu64
				   " too large for funding_satoshis %"PRIu64
				   " capacity_msat %"PRIu64,
				   remoteconf->htlc_minimum_msat,
				   state->funding_satoshis,
				   capacity_msat);

	if (capacity_msat < state->min_effective_htlc_capacity_msat)
		negotiation_failed(state,
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

	/* We don't worry about how many HTLCs they accept, as long as > 0! */
	if (remoteconf->max_accepted_htlcs == 0)
		negotiation_failed(state,
				   "max_accepted_htlcs %u invalid",
				   remoteconf->max_accepted_htlcs);

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `max_accepted_htlcs` is greater than 483.
	 */
	if (remoteconf->max_accepted_htlcs > 483)
		negotiation_failed(state,
				   "max_accepted_htlcs %u too large",
				   remoteconf->max_accepted_htlcs);

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `dust_limit_satoshis` is greater than `channel_reserve_satoshis`.
	 */
	if (remoteconf->dust_limit_satoshis
	    > remoteconf->channel_reserve_satoshis)
		negotiation_failed(state,
				   "dust_limit_satoshis %"PRIu64
				   " too large for channel_reserve_satoshis %"
				   PRIu64,
				   remoteconf->dust_limit_satoshis,
				   remoteconf->channel_reserve_satoshis);
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

/* Handle random messages we might get, returning the first non-handled one. */
static u8 *opening_read_peer_msg(const tal_t *ctx, struct state *state)
{
	for (;;) {
		u8 *msg;
		bool from_gossipd;

		clean_tmpctx();
		msg = peer_or_gossip_sync_read(ctx, PEER_FD, GOSSIP_FD,
					       &state->cs, &from_gossipd);
		if (from_gossipd) {
			handle_gossip_msg(PEER_FD, &state->cs, take(msg));
			continue;
		}
		if (!handle_peer_gossip_or_error(PEER_FD, GOSSIP_FD, &state->cs,
						 &state->channel_id, msg))
			return msg;
	}
}

static u8 *funder_channel(struct state *state,
			  const struct pubkey *our_funding_pubkey,
			  const struct basepoints *ours,
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

	if (state->funding_satoshis > MAX_FUNDING_SATOSHI)
		status_failed(STATUS_FAIL_MASTER_IO,
			      "funding_satoshis must be < 2^24, not %"PRIu64,
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
				  our_funding_pubkey,
				  &ours->revocation,
				  &ours->payment,
				  &ours->delayed_payment,
				  &ours->htlc,
				  &state->next_per_commit[LOCAL],
				  channel_flags);
	sync_crypto_write(&state->cs, PEER_FD, msg);

	state->remoteconf = tal(state, struct channel_config);

	peer_billboard(false,
		       "Funding channel: offered, now waiting for accept_channel");
	msg = opening_read_peer_msg(tmpctx, state);

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `funding_pubkey`, `revocation_basepoint`, `htlc_basepoint`,
	 *    `payment_basepoint`, or `delayed_payment_basepoint` are not
	 *    valid DER-encoded compressed secp256k1 pubkeys.
	 */
	if (!fromwire_accept_channel(msg, &id_in,
				     &state->remoteconf->dust_limit_satoshis,
				     &state->remoteconf
				     ->max_htlc_value_in_flight_msat,
				     &state->remoteconf
				     ->channel_reserve_satoshis,
				     &state->remoteconf->htlc_minimum_msat,
				     &minimum_depth,
				     &state->remoteconf->to_self_delay,
				     &state->remoteconf->max_accepted_htlcs,
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
	if (minimum_depth > 10)
		negotiation_failed(state,
				   "minimum_depth %u larger than %u",
				   minimum_depth, 10);

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
	if (state->remoteconf->channel_reserve_satoshis
	    < state->localconf.dust_limit_satoshis)
		negotiation_failed(state,
				   "channel reserve %"PRIu64
				   " would be below our dust %"PRIu64,
				   state->remoteconf->channel_reserve_satoshis,
				   state->localconf.dust_limit_satoshis);
	if (state->localconf.channel_reserve_satoshis
	    < state->remoteconf->dust_limit_satoshis)
		negotiation_failed(state,
				   "dust limit %"PRIu64
				   " would be above our reserve %"PRIu64,
				   state->remoteconf->dust_limit_satoshis,
				   state->localconf.channel_reserve_satoshis);

	check_config_bounds(state, state->remoteconf);

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
			     our_funding_pubkey,
			     &their_funding_pubkey,
			     change_satoshis, changekey,
			     bip32_base);
	bitcoin_txid(funding, &state->funding_txid);

	state->channel = new_initial_channel(state,
					     &state->funding_txid,
					     state->funding_txout,
					     state->funding_satoshis,
					     state->funding_satoshis * 1000
					     - state->push_msat,
					     state->feerate_per_kw,
					     &state->localconf,
					     state->remoteconf,
					     ours, &theirs,
					     our_funding_pubkey,
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
	if (!tx)
		negotiation_failed(state,
				   "Could not meet their fees and reserve");

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
		     type_to_string(tmpctx, struct pubkey, our_funding_pubkey));

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

	msg = opening_read_peer_msg(tmpctx, state);

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
	if (!tx)
		negotiation_failed(state,
				   "Could not meet our fees and reserve");

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

	/* BOLT #2:
	 *
	 * The recipient:
	 *...
	 *   - on receipt of a valid `funding_signed`:
	 *     - SHOULD broadcast the funding transaction.
	 */
	return towire_opening_funder_reply(state,
					   state->remoteconf,
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

/* This is handed the message the peer sent which caused gossip to stop:
 * it should be an open_channel */
static u8 *fundee_channel(struct state *state,
			  const struct pubkey *our_funding_pubkey,
			  const struct basepoints *ours,
			  u32 minimum_depth,
			  u32 min_feerate, u32 max_feerate, const u8 *peer_msg)
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

	state->remoteconf = tal(state, struct channel_config);

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `funding_pubkey`, `revocation_basepoint`, `htlc_basepoint`,
	 *    `payment_basepoint`, or `delayed_payment_basepoint` are not valid
	 *     DER-encoded compressed secp256k1 pubkeys.
	 */
	if (!fromwire_open_channel(peer_msg, &chain_hash,
				   &state->channel_id,
				   &state->funding_satoshis, &state->push_msat,
				   &state->remoteconf->dust_limit_satoshis,
				   &state->remoteconf->max_htlc_value_in_flight_msat,
				   &state->remoteconf->channel_reserve_satoshis,
				   &state->remoteconf->htlc_minimum_msat,
				   &state->feerate_per_kw,
				   &state->remoteconf->to_self_delay,
				   &state->remoteconf->max_accepted_htlcs,
				   &their_funding_pubkey,
				   &theirs.revocation,
				   &theirs.payment,
				   &theirs.delayed_payment,
				   &theirs.htlc,
				   &state->next_per_commit[REMOTE],
				   &channel_flags))
		peer_failed(&state->cs, NULL,
			    "Bad open_channel %s",
			    tal_hex(peer_msg, peer_msg));

	/* BOLT #2:
	 *
	 * The receiver:
	 *  - if the `chain_hash` value, within the `open_channel`, message is
	 *    set to a hash of a chain that is unknown to the receiver:
	 *     - MUST reject the channel.
	 */
	if (!bitcoin_blkid_eq(&chain_hash,
			      &state->chainparams->genesis_blockhash)) {
		negotiation_failed(state,
				   "Unknown chain-hash %s",
				   type_to_string(peer_msg,
						  struct bitcoin_blkid,
						  &chain_hash));
	}

	/* BOLT #2 FIXME:
	 *
	 * The receiving node ... MUST fail the channel if `funding-satoshis`
	 * is greater than or equal to 2^24 */
	if (state->funding_satoshis > MAX_FUNDING_SATOSHI)
		negotiation_failed(state,
				   "funding_satoshis %"PRIu64" too large",
				   state->funding_satoshis);

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *   - `push_msat` is greater than `funding_satoshis` * 1000.
	 */
	if (state->push_msat > state->funding_satoshis * 1000)
		peer_failed(&state->cs,
			    &state->channel_id,
			    "Our push_msat %"PRIu64
			    " would be too large for funding_satoshis %"PRIu64,
			    state->push_msat, state->funding_satoshis);

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - it considers `feerate_per_kw` too small for timely processing or
	 *    unreasonably large.
	 */
	if (state->feerate_per_kw < min_feerate)
		negotiation_failed(state,
				   "feerate_per_kw %u below minimum %u",
				   state->feerate_per_kw, min_feerate);

	if (state->feerate_per_kw > max_feerate)
		negotiation_failed(state,
				   "feerate_per_kw %u above maximum %u",
				   state->feerate_per_kw, max_feerate);

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
	    < state->remoteconf->dust_limit_satoshis)
		negotiation_failed(state,
				   "Our channel reserve %"PRIu64
				   " would be below their dust %"PRIu64,
				   state->localconf.channel_reserve_satoshis,
				   state->remoteconf->dust_limit_satoshis);
	if (state->localconf.dust_limit_satoshis
	    > state->remoteconf->channel_reserve_satoshis)
		negotiation_failed(state,
				   "Our dust limit %"PRIu64
				   " would be above their reserve %"PRIu64,
				   state->localconf.dust_limit_satoshis,
				   state->remoteconf->channel_reserve_satoshis);

	check_config_bounds(state, state->remoteconf);

	msg = towire_accept_channel(state, &state->channel_id,
				    state->localconf.dust_limit_satoshis,
				    state->localconf
				      .max_htlc_value_in_flight_msat,
				    state->localconf.channel_reserve_satoshis,
				    state->localconf.htlc_minimum_msat,
				    minimum_depth,
				    state->localconf.to_self_delay,
				    state->localconf.max_accepted_htlcs,
				    our_funding_pubkey,
				    &ours->revocation,
				    &ours->payment,
				    &ours->delayed_payment,
				    &ours->htlc,
				    &state->next_per_commit[LOCAL]);

	sync_crypto_write(&state->cs, PEER_FD, take(msg));

	peer_billboard(false,
		       "Incoming channel: accepted, now waiting for them to create funding tx");

	msg = opening_read_peer_msg(tmpctx, state);

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
					     &state->funding_txid,
					     state->funding_txout,
					     state->funding_satoshis,
					     state->push_msat,
					     state->feerate_per_kw,
					     &state->localconf,
					     state->remoteconf,
					     ours, &theirs,
					     our_funding_pubkey,
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
	if (!local_commit)
		negotiation_failed(state,
				   "Could not meet our fees and reserve");

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
	if (!remote_commit)
		negotiation_failed(state,
				   "Could not meet their fees and reserve");

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

	return towire_opening_fundee_reply(state,
					   state->remoteconf,
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

#ifndef TESTING
int main(int argc, char *argv[])
{
	setup_locale();

	u8 *msg, *peer_msg;
	struct state *state = tal(NULL, struct state);
	struct basepoints our_points;
	struct pubkey our_funding_pubkey;
	u32 minimum_depth;
	u32 min_feerate, max_feerate;
	u64 change_satoshis;
	u32 change_keyindex;
	u8 channel_flags;
	struct utxo **utxos;
	struct ext_key bip32_base;
	u32 network_index;
	struct secret *none;

	subdaemon_setup(argc, argv);

	status_setup_sync(REQ_FD);

	msg = wire_sync_read(state, REQ_FD);
	if (!fromwire_opening_init(msg,
				   &network_index,
				   &state->localconf,
				   &state->max_to_self_delay,
				   &state->min_effective_htlc_capacity_msat,
				   &state->cs,
				   &our_points,
				   &our_funding_pubkey))
		master_badmsg(WIRE_OPENING_INIT, msg);

	tal_free(msg);

	state->chainparams = chainparams_by_index(network_index);

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
	status_trace("First per_commit_point = %s",
		     type_to_string(tmpctx, struct pubkey,
				    &state->next_per_commit[LOCAL]));
	msg = wire_sync_read(state, REQ_FD);
	if (fromwire_opening_funder(state, msg,
				    &state->funding_satoshis,
				    &state->push_msat,
				    &state->feerate_per_kw,
				    &change_satoshis, &change_keyindex,
				    &channel_flags, &utxos, &bip32_base)) {
		msg = funder_channel(state, &our_funding_pubkey, &our_points,
				     change_satoshis,
				     change_keyindex, channel_flags,
				     utxos, &bip32_base);
		peer_billboard(false,
			       "Funding channel: opening negotiation succeeded");
	} else if (fromwire_opening_fundee(state, msg, &minimum_depth,
					   &min_feerate, &max_feerate, &peer_msg)) {
		msg = fundee_channel(state, &our_funding_pubkey, &our_points,
				   minimum_depth, min_feerate, max_feerate,
				   peer_msg);
		peer_billboard(false,
			       "Incoming channel: opening negotiation succeeded");
	} else
		status_failed(STATUS_FAIL_MASTER_IO,
			      "neither funder nor fundee: %s",
			      tal_hex(msg, msg));

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
#endif /* TESTING */
