#include <bitcoin/block.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/cast/cast.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <common/crypto_sync.h>
#include <common/derive_basepoints.h>
#include <common/funding_tx.h>
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

struct state {
	struct crypto_state cs;
	u64 gossip_index;
	struct pubkey next_per_commit[NUM_SIDES];

	/* Initially temporary, then final channel id. */
	struct channel_id channel_id;

	/* Funding and feerate: set by opening peer. */
	u64 funding_satoshis, push_msat;
	u32 feerate_per_kw;
	struct bitcoin_txid funding_txid;
	u16 funding_txout;

	/* Secret keys and basepoint secrets. */
	struct secrets our_secrets;

	/* Our shaseed for generating per-commitment-secrets. */
	struct sha256 shaseed;
	struct channel_config localconf, *remoteconf;

	/* Limits on what remote config we accept */
	u32 max_to_self_delay;
	u64 min_effective_htlc_capacity_msat;

	struct channel *channel;

	const struct chainparams *chainparams;
};

/* For negotiation failures: we can still gossip with client. */
static void negotiation_failed(struct state *state, const char *fmt, ...)
{
	va_list ap;
	const char *errmsg;

	va_start(ap, fmt);
	errmsg = tal_vfmt(state, fmt, ap);
	va_end(ap);

	peer_failed(&state->cs, state->gossip_index, &state->channel_id,
		    "%s", errmsg);
}

static void check_config_bounds(struct state *state,
				const struct channel_config *remoteconf)
{
	u64 capacity_msat;
	u64 reserve_msat;

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if `to_self_delay` is
	 * unreasonably large.
	 */
	if (remoteconf->to_self_delay > state->max_to_self_delay)
		negotiation_failed(state,
				   "to_self_delay %u larger than %u",
				   remoteconf->to_self_delay,
				   state->max_to_self_delay);

	/* BOLT #2:
	 *
	 * The receiver MAY fail the channel if `funding_satoshis` is too
	 * small, and MUST fail the channel if `push_msat` is greater than
	 * `funding_satoshis` * 1000.  The receiving node MAY fail the channel
	 * if it considers `htlc_minimum_msat` too large,
	 * `max_htlc_value_in_flight_msat` too small, `channel_reserve_satoshis`
	 * too large, or `max_accepted_htlcs` too small.
	 */
	/* We accumulate this into an effective bandwidth minimum. */

	/* Overflow check before capacity calc. */
	if (remoteconf->channel_reserve_satoshis > state->funding_satoshis)
		negotiation_failed(state,
				   "Invalid channel_reserve_satoshis %"PRIu64
				   " for funding_satoshis %"PRIu64,
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
				   "Invalid htlc_minimum_msat %"PRIu64
				   " for funding_satoshis %"PRIu64
				   " capacity_msat %"PRIu64,
				   remoteconf->htlc_minimum_msat,
				   state->funding_satoshis,
				   capacity_msat);

	if (capacity_msat < state->min_effective_htlc_capacity_msat)
		negotiation_failed(state,
				   "Channel capacity with funding %"PRIu64" msat,"
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
	 * It MUST fail the channel if `max_accepted_htlcs` is greater
	 * than 483.
	 */
	if (remoteconf->max_accepted_htlcs > 483)
		peer_failed(&state->cs, state->gossip_index,
			    &state->channel_id,
			    "max_accepted_htlcs %u too large",
			    remoteconf->max_accepted_htlcs);
}

/* We always set channel_reserve_satoshis to 1%, rounded up. */
static void set_reserve(u64 *reserve, u64 funding)
{
	*reserve = (funding + 99) / 100;
}

/* BOLT #2:
 *
 * A sending node MUST ensure `temporary_channel_id` is unique from any other
 * channel id with the same peer.
 */
static void temporary_channel_id(struct channel_id *channel_id)
{
	size_t i;

	for (i = 0; i < sizeof(*channel_id); i++)
		channel_id->id[i] = pseudorand(256);
}

/* Handle random messages we might get, returning the first non-handled one. */
static u8 *opening_read_peer_msg(struct state *state)
{
	u8 *msg;

	while ((msg = read_peer_msg(state, &state->cs, state->gossip_index,
				    &state->channel_id,
				    sync_crypto_write_arg,
				    status_fail_io,
				    state)) == NULL)
		clean_tmpctx();

	return msg;
}

static u8 *funder_channel(struct state *state,
			  const struct pubkey *our_funding_pubkey,
			  const struct basepoints *ours,
			  u32 max_minimum_depth,
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

	set_reserve(&state->localconf.channel_reserve_satoshis,
		    state->funding_satoshis);

	temporary_channel_id(&state->channel_id);

	if (state->funding_satoshis > MAX_FUNDING_SATOSHI)
		status_failed(STATUS_FAIL_MASTER_IO,
			      "funding_satoshis must be < 2^24, not %"PRIu64,
			      state->funding_satoshis);

	/* BOLT #2:
	 *
	 * The sender MUST set `push_msat` to equal or less than to 1000 *
	 * `funding_satoshis`.
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
	if (!sync_crypto_write(&state->cs, PEER_FD, msg))
		peer_failed_connection_lost();

	state->remoteconf = tal(state, struct channel_config);

	peer_billboard(false,
		       "Funding channel: offered, now waiting for accept_channel");
	msg = opening_read_peer_msg(state);

	/* BOLT #2:
	 *
	 * The receiver MUST fail the channel if `funding_pubkey`,
	 * `revocation_basepoint`, `htlc_basepoint`, `payment_basepoint` or
	 * `delayed_payment_basepoint` are not valid DER-encoded compressed
	 * secp256k1 pubkeys.
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
		peer_failed(&state->cs, state->gossip_index,
			    &state->channel_id,
			    "Parsing accept_channel %s", tal_hex(msg, msg));

	/* BOLT #2:
	 *
	 * The `temporary_channel_id` MUST be the same as the
	 * `temporary_channel_id` in the `open_channel` message. */
	if (!structeq(&id_in, &state->channel_id))
		peer_failed(&state->cs, state->gossip_index,
			    &state->channel_id,
			    "accept_channel ids don't match: sent %s got %s",
			    type_to_string(msg, struct channel_id, &id_in),
			    type_to_string(msg, struct channel_id,
					   &state->channel_id));

	/* BOLT #2:
	 *
	 * The receiver MAY reject the `minimum_depth` if it considers it
	 * unreasonably large.
	 *
	 * Other fields have the same requirements as their counterparts in
	 * `open_channel`.
	 */
	if (minimum_depth > max_minimum_depth)
		negotiation_failed(state,
				   "minimum_depth %u larger than %u",
				   minimum_depth, max_minimum_depth);
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
		peer_failed(&state->cs, state->gossip_index,
			    &state->channel_id,
			    "could not create channel with given config");

	/* BOLT #2:
	 *
	 * ### The `funding_created` message
	 *
	 * This message describes the outpoint which the funder has created
	 * for the initial commitment transactions.  After receiving the
	 * peer's signature, it will broadcast the funding transaction.
	 */
	tx = initial_channel_tx(state, &wscript, state->channel,
				&state->next_per_commit[REMOTE], REMOTE);

	sign_tx_input(tx, 0, NULL, wscript,
		      &state->our_secrets.funding_privkey,
		      our_funding_pubkey, &sig);
	status_trace("signature %s on tx %s using key %s",
		     type_to_string(tmpctx, secp256k1_ecdsa_signature, &sig),
		     type_to_string(tmpctx, struct bitcoin_tx, tx),
		     type_to_string(tmpctx, struct pubkey, our_funding_pubkey));

	msg = towire_funding_created(state, &state->channel_id,
				     &state->funding_txid,
				     state->funding_txout,
				     &sig);
	if (!sync_crypto_write(&state->cs, PEER_FD, msg))
		peer_failed_connection_lost();

	/* BOLT #2:
	 *
	 * ### The `funding_signed` message
	 *
	 * This message gives the funder the signature they need for the first
	 * commitment transaction, so they can broadcast it knowing they can
	 * redeem their funds if they need to.
	 */
	peer_billboard(false,
		       "Funding channel: create first tx, now waiting for their signature");

	msg = opening_read_peer_msg(state);

	if (!fromwire_funding_signed(msg, &id_in, &sig))
		peer_failed(&state->cs, state->gossip_index,
			    &state->channel_id,
			    "Parsing funding_signed: %s", tal_hex(msg, msg));

	/* BOLT #2:
	 *
	 * This message introduces the `channel_id` to identify the channel, which
	 * is derived from the funding transaction by combining the
	 * `funding_txid` and the `funding_output_index` using big-endian
	 * exclusive-OR (ie. `funding_output_index` alters the last two
	 * bytes).
	 */
	derive_channel_id(&state->channel_id,
			  &state->funding_txid, state->funding_txout);

	if (!structeq(&id_in, &state->channel_id))
		peer_failed(&state->cs, state->gossip_index, &id_in,
			    "funding_signed ids don't match: expected %s got %s",
			    type_to_string(msg, struct channel_id,
					   &state->channel_id),
			    type_to_string(msg, struct channel_id, &id_in));

	/* BOLT #2:
	 *
	 * The recipient MUST fail the channel if `signature` is incorrect.
	 */
	tx = initial_channel_tx(state, &wscript, state->channel,
				&state->next_per_commit[LOCAL], LOCAL);

	if (!check_tx_sig(tx, 0, NULL, wscript, &their_funding_pubkey, &sig)) {
		peer_failed(&state->cs, state->gossip_index,
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
	 * Once the channel funder receives the `funding_signed` message, they
	 * must broadcast the funding transaction to the Bitcoin network.
	 */
	return towire_opening_funder_reply(state,
					   state->remoteconf,
					   tx,
					   &sig,
					   &state->cs, state->gossip_index,
					   &theirs.revocation,
					   &theirs.payment,
					   &theirs.htlc,
					   &theirs.delayed_payment,
					   &state->next_per_commit[REMOTE],
					   minimum_depth,
					   &their_funding_pubkey,
					   &state->funding_txid,
					   state->feerate_per_kw);
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
	struct bitcoin_tx *their_commit, *our_commit;
	struct bitcoin_blkid chain_hash;
	u8 *msg;
	const u8 *wscript;
	u8 channel_flags;

	state->remoteconf = tal(state, struct channel_config);

	/* BOLT #2:
	 *
	 * The receiver MUST fail the channel if `funding_pubkey`,
	 * `revocation_basepoint`, `htlc_basepoint`, `payment_basepoint` or
	 * `delayed_payment_basepoint` are not valid DER-encoded compressed
	 * secp256k1 pubkeys.
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
		peer_failed(&state->cs, state->gossip_index, NULL,
			    "Bad open_channel %s",
			    tal_hex(peer_msg, peer_msg));

	/* BOLT #2:
	 *
	 * The receiving node MUST reject the channel if the `chain_hash` value
	 * within the `open_channel` message is set to a hash of a chain
	 * unknown to the receiver.
	 */
	if (!structeq(&chain_hash, &state->chainparams->genesis_blockhash)) {
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
		peer_failed(&state->cs, state->gossip_index,
			    &state->channel_id,
			    "funding_satoshis %"PRIu64" too large",
			    state->funding_satoshis);

	/* BOLT #2:
	 *
	 * The receiving node ... MUST fail the channel if `push_msat` is
	 * greater than `funding_satoshis` * 1000.
	 */
	if (state->push_msat > state->funding_satoshis * 1000)
		peer_failed(&state->cs, state->gossip_index,
			    &state->channel_id,
			    "push_msat %"PRIu64
			    " too large for funding_satoshis %"PRIu64,
			    state->push_msat, state->funding_satoshis);

	/* BOLT #2:
	 *
	 * The receiver MUST fail the channel if it considers `feerate_per_kw`
	 * too small for timely processing, or unreasonably large.
	 */
	if (state->feerate_per_kw < min_feerate)
		negotiation_failed(state,
				   "feerate_per_kw %u below minimum %u",
				   state->feerate_per_kw, min_feerate);

	if (state->feerate_per_kw > max_feerate)
		negotiation_failed(state,
				   "feerate_per_kw %u above maximum %u",
				   state->feerate_per_kw, max_feerate);

	set_reserve(&state->localconf.channel_reserve_satoshis,
		    state->funding_satoshis);
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

	if (!sync_crypto_write(&state->cs, PEER_FD, take(msg)))
		peer_failed_connection_lost();

	peer_billboard(false,
		       "Incoming channel: accepted, now waiting for them to create funding tx");

	msg = opening_read_peer_msg(state);

	if (!fromwire_funding_created(msg, &id_in,
				      &state->funding_txid,
				      &state->funding_txout,
				      &theirsig))
		peer_failed(&state->cs, state->gossip_index,
			    &state->channel_id,
			    "Parsing funding_created");

	/* BOLT #2:
	 *
	 * The sender MUST set `temporary_channel_id` the same as the
	 * `temporary_channel_id` in the `open_channel` message. */
	if (!structeq(&id_in, &state->channel_id))
		peer_failed(&state->cs, state->gossip_index, &id_in,
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
		peer_failed(&state->cs, state->gossip_index,
			    &state->channel_id,
			    "could not create channel with given config");

	/* BOLT #2:
	 *
	 * The recipient MUST fail the channel if `signature` is incorrect.
	 */
	their_commit = initial_channel_tx(state, &wscript, state->channel,
					  &state->next_per_commit[LOCAL], LOCAL);

	if (!check_tx_sig(their_commit, 0, NULL, wscript, &their_funding_pubkey,
			  &theirsig)) {
		peer_failed(&state->cs, state->gossip_index,
			    &state->channel_id,
			    "Bad signature %s on tx %s using key %s",
			    type_to_string(tmpctx, secp256k1_ecdsa_signature,
					   &theirsig),
			    type_to_string(tmpctx, struct bitcoin_tx, their_commit),
			    type_to_string(tmpctx, struct pubkey,
					   &their_funding_pubkey));
	}

	/* BOLT #2:
	 *
	 * This message introduces the `channel_id` to identify the channel,
	 * which is derived from the funding transaction by combining the
	 * `funding_txid` and the `funding_output_index` using big-endian
	 * exclusive-OR (ie. `funding_output_index` alters the last two
	 * bytes).
	 */
	derive_channel_id(&state->channel_id,
			  &state->funding_txid, state->funding_txout);

	/* BOLT #2:
	 *
	 * ### The `funding_signed` message
	 *
	 * This message gives the funder the signature they need for the first
	 * commitment transaction, so they can broadcast it knowing they can
	 * redeem their funds if they need to.
	 */
	our_commit = initial_channel_tx(state, &wscript, state->channel,
					&state->next_per_commit[REMOTE], REMOTE);
	sign_tx_input(our_commit, 0, NULL, wscript,
		      &state->our_secrets.funding_privkey,
		      our_funding_pubkey, &sig);

	/* We don't send this ourselves: channeld does, because master needs
	 * to save state to disk before doing so. */
	msg = towire_funding_signed(state, &state->channel_id, &sig);

	return towire_opening_fundee_reply(state,
					   state->remoteconf,
					   their_commit,
					   &theirsig,
					   &state->cs,
					   state->gossip_index,
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
					   msg);
}

#ifndef TESTING
int main(int argc, char *argv[])
{
	u8 *msg, *peer_msg;
	struct state *state = tal(NULL, struct state);
	struct privkey seed;
	struct basepoints our_points;
	struct pubkey our_funding_pubkey;
	u32 minimum_depth, max_minimum_depth;
	u32 min_feerate, max_feerate;
	u64 change_satoshis;
	u32 change_keyindex;
	u8 channel_flags;
	struct utxo **utxos;
	struct ext_key bip32_base;
	u32 network_index;

	subdaemon_setup(argc, argv);

	status_setup_sync(REQ_FD);

	msg = wire_sync_read(state, REQ_FD);
	if (!fromwire_opening_init(msg,
				   &network_index,
				   &state->localconf,
				   &state->max_to_self_delay,
				   &state->min_effective_htlc_capacity_msat,
				   &state->cs,
				   &state->gossip_index,
				   &seed))
		master_badmsg(WIRE_OPENING_INIT, msg);

	tal_free(msg);

	state->chainparams = chainparams_by_index(network_index);

	/* We derive everything from the one secret seed. */
	if (!derive_basepoints(&seed, &our_funding_pubkey,
			       &our_points, &state->our_secrets,
			       &state->shaseed))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Secret derivation failed, secret = %s",
			      type_to_string(tmpctx, struct privkey, &seed));

	if (!per_commit_point(&state->shaseed, &state->next_per_commit[LOCAL],
			      0))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "First per_commitment_point derivation failed,"
			      " secret = %s",
			      type_to_string(tmpctx, struct privkey, &seed));

	status_trace("First per_commit_point = %s",
		     type_to_string(tmpctx, struct pubkey,
				    &state->next_per_commit[LOCAL]));
	msg = wire_sync_read(state, REQ_FD);
	if (fromwire_opening_funder(state, msg,
				    &state->funding_satoshis,
				    &state->push_msat,
				    &state->feerate_per_kw, &max_minimum_depth,
				    &change_satoshis, &change_keyindex,
				    &channel_flags, &utxos, &bip32_base)) {
		msg = funder_channel(state, &our_funding_pubkey, &our_points,
				     max_minimum_depth, change_satoshis,
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
