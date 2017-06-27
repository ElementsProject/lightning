#include <bitcoin/block.h>
#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/structeq/structeq.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/channel.h>
#include <lightningd/commit_tx.h>
#include <lightningd/crypto_sync.h>
#include <lightningd/debug.h>
#include <lightningd/derive_basepoints.h>
#include <lightningd/funding_tx.h>
#include <lightningd/key_derive.h>
#include <lightningd/opening/gen_opening_wire.h>
#include <lightningd/peer_failed.h>
#include <lightningd/ping.h>
#include <lightningd/status.h>
#include <secp256k1.h>
#include <signal.h>
#include <stdio.h>
#include <type_to_string.h>
#include <version.h>
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
	struct pubkey next_per_commit[NUM_SIDES];

	/* Funding and feerate: set by opening peer. */
	u64 funding_satoshis, push_msat;
	u32 feerate_per_kw;
	struct sha256_double funding_txid;
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
};

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
		peer_failed(PEER_FD, &state->cs, NULL,
			    WIRE_OPENING_PEER_BAD_CONFIG,
			    "to_self_delay %u larger than %u",
			    remoteconf->to_self_delay, state->max_to_self_delay);

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
		peer_failed(PEER_FD, &state->cs, NULL,
			    WIRE_OPENING_PEER_BAD_CONFIG,
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
		peer_failed(PEER_FD, &state->cs, NULL,
			    WIRE_OPENING_PEER_BAD_CONFIG,
			    "Invalid htlc_minimum_msat %"PRIu64
			    " for funding_satoshis %"PRIu64
			    " capacity_msat %"PRIu64,
			    remoteconf->htlc_minimum_msat,
			    state->funding_satoshis,
			    capacity_msat);

	if (capacity_msat < state->min_effective_htlc_capacity_msat)
		peer_failed(PEER_FD, &state->cs, NULL,
			    WIRE_OPENING_PEER_BAD_CONFIG,
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
		peer_failed(PEER_FD, &state->cs, NULL,
			    WIRE_OPENING_PEER_BAD_CONFIG,
			    "max_accepted_htlcs %u invalid",
			    remoteconf->max_accepted_htlcs);

	/* BOLT #2:
	 *
	 * It MUST fail the channel if `max_accepted_htlcs` is greater
	 * than 483.
	 */
	if (remoteconf->max_accepted_htlcs > 483)
		peer_failed(PEER_FD, &state->cs, NULL,
			    WIRE_OPENING_PEER_BAD_CONFIG,
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

/* We have to handle random gossip message and pings. */
static u8 *read_next_peer_msg(struct state *state, const tal_t *ctx)
{
	for (;;) {
		u8 *msg = sync_crypto_read(ctx, &state->cs, PEER_FD);
		if (!msg)
			return NULL;

		if (fromwire_peektype(msg) == WIRE_PING) {
			u8 *pong;
			if (!check_ping_make_pong(ctx, msg, &pong)) {
				status_trace("Bad ping message");
				return tal_free(msg);
			}
			if (pong && !sync_crypto_write(&state->cs, PEER_FD,
						       take(pong)))
				peer_failed(PEER_FD, &state->cs, NULL,
					    WIRE_OPENING_PEER_WRITE_FAILED,
					    "Sending pong");
		} else if (is_gossip_msg(msg)) {
			/* We relay gossip to gossipd, but don't relay from */
			if (!wire_sync_write(GOSSIP_FD, take(msg)))
				peer_failed(PEER_FD, &state->cs, NULL,
					    WIRE_OPENING_PEER_WRITE_FAILED,
					    "Relaying gossip message");
		} else {
			return msg;
		}
	}
}

static u8 *funder_channel(struct state *state,
			  const struct pubkey *our_funding_pubkey,
			  const struct basepoints *ours,
			  u32 max_minimum_depth,
			  u64 change_satoshis, u32 change_keyindex,
			  u8 channel_flags,
			  const struct utxo *utxos,
			  const u8 *bip32_seed)
{
	const tal_t *tmpctx = tal_tmpctx(state);
	struct channel_id channel_id, id_in;
	u8 *msg;
	struct bitcoin_tx **txs;
	struct basepoints theirs;
	struct pubkey their_funding_pubkey, changekey;
	secp256k1_ecdsa_signature sig;
	u32 minimum_depth;
	const u8 **wscripts;
	struct bitcoin_tx *funding;
	struct ext_key bip32_base;
	const struct utxo **utxomap;

	if (bip32_key_unserialize(bip32_seed, tal_len(bip32_seed), &bip32_base)
	    != WALLY_OK)
		status_failed(WIRE_OPENING_BAD_PARAM,
			      "Bad BIP32 key %s", tal_hex(trc, bip32_seed));

	set_reserve(&state->localconf.channel_reserve_satoshis,
		    state->funding_satoshis);

	temporary_channel_id(&channel_id);

	/* BOLT #2:
	 *
	 * The sender MUST set `funding_satoshis` to less than 2^24 satoshi. */
	if (state->funding_satoshis >= 1 << 24)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_BAD_PARAM,
			      "funding_satoshis must be < 2^24");

	/* BOLT #2:
	 *
	 * The sender MUST set `push_msat` to equal or less than to 1000 *
	 * `funding_satoshis`.
	 */
	if (state->push_msat > 1000 * state->funding_satoshis)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_BAD_PARAM,
			      "push-msat must be < %"PRIu64,
			      1000 * state->funding_satoshis);

	msg = towire_open_channel(tmpctx, &genesis_blockhash.sha, &channel_id,
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
				  &state->next_per_commit[LOCAL],
				  channel_flags);
	if (!sync_crypto_write(&state->cs, PEER_FD, msg))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_WRITE_FAILED,
			      "Writing open_channel");

	state->remoteconf = tal(state, struct channel_config);

	msg = read_next_peer_msg(state, tmpctx);
	if (!msg)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			      "Reading accept_channel");

	/* BOLT #2:
	 *
	 * The receiver MUST fail the channel if `funding_pubkey`,
	 * `revocation_basepoint`, `payment_basepoint` or
	 * `delayed_payment_basepoint` are not valid DER-encoded compressed
	 * secp256k1 pubkeys.
	 */
	if (!fromwire_accept_channel(msg, NULL, &id_in,
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
				     &state->next_per_commit[REMOTE]))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			      "Parsing accept_channel %s", tal_hex(msg, msg));

	/* BOLT #2:
	 *
	 * The `temporary_channel_id` MUST be the same as the
	 * `temporary_channel_id` in the `open_channel` message. */
	if (!structeq(&id_in, &channel_id))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			      "accept_channel ids don't match: sent %s got %s",
			      type_to_string(msg, struct channel_id, &id_in),
			      type_to_string(msg, struct channel_id, &channel_id));

	/* BOLT #2:
	 *
	 * The receiver MAY reject the `minimum_depth` if it considers it
	 * unreasonably large.
	 *
	 * Other fields have the same requirements as their counterparts in
	 * `open_channel`.
	 */
	if (minimum_depth > max_minimum_depth)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_BAD_PARAM,
			    "minimum_depth %u larger than %u",
			    minimum_depth, max_minimum_depth);
	check_config_bounds(state, state->remoteconf);

	/* Now, ask create funding transaction to pay those two addresses. */
	if (change_satoshis) {
		if (!bip32_pubkey(&bip32_base, &changekey, change_keyindex))
			status_failed(WIRE_OPENING_BAD_PARAM,
				      "Bad change key %u", change_keyindex);
	}

	utxomap = to_utxoptr_arr(state, utxos);
	funding = funding_tx(state, &state->funding_txout,
			     utxomap, state->funding_satoshis,
			     our_funding_pubkey,
			     &their_funding_pubkey,
			     change_satoshis, &changekey,
			     &bip32_base);
	bitcoin_txid(funding, &state->funding_txid);

	state->channel = new_channel(state,
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
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_BAD_PARAM,
			      "could not create channel with given config");

	/* BOLT #2:
	 *
	 * ### The `funding_created` message
	 *
	 * This message describes the outpoint which the funder has created
	 * for the initial commitment transactions.  After receiving the
	 * peer's signature, it will broadcast the funding transaction.
	 */
	txs = channel_txs(tmpctx, NULL, &wscripts, state->channel,
			  &state->next_per_commit[REMOTE], 0, REMOTE);

	sign_tx_input(txs[0], 0, NULL, wscripts[0],
		      &state->our_secrets.funding_privkey,
		      our_funding_pubkey, &sig);
	status_trace("signature %s on tx %s using key %s",
		     type_to_string(trc, secp256k1_ecdsa_signature, &sig),
		     type_to_string(trc, struct bitcoin_tx, txs[0]),
		     type_to_string(trc, struct pubkey, our_funding_pubkey));

	msg = towire_funding_created(tmpctx, &channel_id,
				     &state->funding_txid.sha,
				     state->funding_txout,
				     &sig);
	if (!sync_crypto_write(&state->cs, PEER_FD, msg))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_WRITE_FAILED,
			      "Writing funding_created");

	/* BOLT #2:
	 *
	 * ### The `funding_signed` message
	 *
	 * This message gives the funder the signature they need for the first
	 * commitment transaction, so they can broadcast it knowing they can
	 * redeem their funds if they need to.
	 */
	msg = read_next_peer_msg(state, tmpctx);
	if (!msg)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			      "Reading funding_signed");

	if (!fromwire_funding_signed(msg, NULL, &id_in, &sig))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			    "Parsing funding_signed (%s)",
			    wire_type_name(fromwire_peektype(msg)));

	/* BOLT #2:
	 *
	 * This message introduces the `channel_id` to identify the channel, which
	 * is derived from the funding transaction by combining the
	 * `funding_txid` and the `funding_output_index` using big-endian
	 * exclusive-OR (ie. `funding_output_index` alters the last two
	 * bytes).
	 */
	derive_channel_id(&channel_id,
			  &state->funding_txid, state->funding_txout);

	if (!structeq(&id_in, &channel_id))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			      "funding_signed ids don't match: expceted %s got %s",
			      type_to_string(msg, struct channel_id, &channel_id),
			      type_to_string(msg, struct channel_id, &id_in));

	/* BOLT #2:
	 *
	 * The recipient MUST fail the channel if `signature` is incorrect.
	 */
	txs = channel_txs(tmpctx, NULL, &wscripts, state->channel,
			  &state->next_per_commit[LOCAL], 0, LOCAL);

	if (!check_tx_sig(txs[0], 0, NULL, wscripts[0], &their_funding_pubkey,
			  &sig)) {
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			      "Bad signature %s on tx %s using key %s",
			      type_to_string(trc, secp256k1_ecdsa_signature,
					     &sig),
			      type_to_string(trc, struct bitcoin_tx, txs[0]),
			      type_to_string(trc, struct pubkey,
					     &their_funding_pubkey));
	}

	tal_free(tmpctx);

	/* BOLT #2:
	 *
	 * Once the channel funder receives the `funding_signed` message, they
	 * must broadcast the funding transaction to the Bitcoin network.
	 */
	return towire_opening_funder_reply(state,
					   state->remoteconf,
					   &sig,
					   &state->cs,
					   &theirs.revocation,
					   &theirs.payment,
					   &theirs.delayed_payment,
					   &state->next_per_commit[REMOTE],
					   minimum_depth,
					   &their_funding_pubkey,
					   &state->funding_txid);
}

/* This is handed the message the peer sent which caused gossip to stop:
 * it should be an open_channel */
static u8 *fundee_channel(struct state *state,
			  const struct pubkey *our_funding_pubkey,
			  const struct basepoints *ours,
			  u32 minimum_depth,
			  u32 min_feerate, u32 max_feerate, const u8 *peer_msg)
{
	struct channel_id id_in, channel_id;
	struct basepoints theirs;
	struct pubkey their_funding_pubkey;
	secp256k1_ecdsa_signature theirsig, sig;
	struct bitcoin_tx **txs;
	struct sha256_double chain_hash;
	u8 *msg;
	const u8 **wscripts;
	u8 channel_flags;

	state->remoteconf = tal(state, struct channel_config);

	/* BOLT #2:
	 *
	 * The receiver MUST fail the channel if `funding_pubkey`,
	 * `revocation_basepoint`, `payment_basepoint` or
	 * `delayed_payment_basepoint` are not valid DER-encoded compressed
	 * secp256k1 pubkeys.
	 */
	if (!fromwire_open_channel(peer_msg, NULL, &chain_hash.sha, &channel_id,
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
				   &state->next_per_commit[REMOTE],
				   &channel_flags))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_BAD_INITIAL_MESSAGE,
			      "Parsing open_channel %s",
			      tal_hex(peer_msg, peer_msg));

	/* BOLT #2:
	 *
	 * The receiving MUST reject the channel if the `chain_hash` value
	 * within the `open_channel` message is set to a hash of a chain
	 * unknown to the receiver.
	 */
	if (!structeq(&chain_hash, &genesis_blockhash)) {
		peer_failed(PEER_FD, &state->cs, NULL,
			    WIRE_OPENING_PEER_BAD_INITIAL_MESSAGE,
			    "Unknown chain-hash %s",
			    type_to_string(peer_msg, struct sha256_double,
					   &chain_hash));
	}

	/* BOLT #2 FIXME:
	 *
	 * The receiving node ... MUST fail the channel if `funding-satoshis`
	 * is greater than or equal to 2^24 */
	if (state->funding_satoshis >= 1 << 24)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_BAD_FUNDING,
			      "funding_satoshis %"PRIu64" too large",
			      state->funding_satoshis);

	/* BOLT #2:
	 *
	 * The receiving node ... MUST fail the channel if `push_msat` is
	 * greater than `funding_satoshis` * 1000.
	 */
	if (state->push_msat > state->funding_satoshis * 1000)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_BAD_FUNDING,
			      "push_msat %"PRIu64
			      " too large for funding_satoshis %"PRIu64,
			      state->push_msat, state->funding_satoshis);

	/* BOLT #2:
	 *
	 * The receiver MUST fail the channel if it considers `feerate_per_kw`
	 * too small for timely processing, or unreasonably large.
	 */
	if (state->feerate_per_kw < min_feerate)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_BAD_FUNDING,
			    "feerate_per_kw %u below minimum %u",
			    state->feerate_per_kw, min_feerate);

	if (state->feerate_per_kw > max_feerate)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_BAD_FUNDING,
			    "feerate_per_kw %u above maximum %u",
			    state->feerate_per_kw, max_feerate);

	set_reserve(&state->localconf.channel_reserve_satoshis,
		    state->funding_satoshis);
	check_config_bounds(state, state->remoteconf);

	msg = towire_accept_channel(state, &channel_id,
				    state->localconf.dust_limit_satoshis,
				    state->localconf
				      .max_htlc_value_in_flight_msat,
				    state->localconf.channel_reserve_satoshis,
				    minimum_depth,
				    state->localconf.htlc_minimum_msat,
				    state->localconf.to_self_delay,
				    state->localconf.max_accepted_htlcs,
				    our_funding_pubkey,
				    &ours->revocation,
				    &ours->payment,
				    &ours->delayed_payment,
				    &state->next_per_commit[LOCAL]);

	if (!sync_crypto_write(&state->cs, PEER_FD, take(msg)))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_WRITE_FAILED,
			      "Writing accept_channel");

	msg = read_next_peer_msg(state, state);
	if (!msg)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			      "Reading funding_created");

	if (!fromwire_funding_created(msg, NULL, &id_in,
				      &state->funding_txid.sha,
				      &state->funding_txout,
				      &theirsig))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			      "Parsing funding_created");

	/* BOLT #2:
	 *
	 * The sender MUST set `temporary_channel_id` the same as the
	 * `temporary_channel_id` in the `open_channel` message. */
	if (!structeq(&id_in, &channel_id))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			    "funding_created ids don't match: sent %s got %s",
			    type_to_string(msg, struct channel_id, &channel_id),
			    type_to_string(msg, struct channel_id, &id_in));

	state->channel = new_channel(state,
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
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_BAD_PARAM,
			      "could not create channel with given config");

	/* BOLT #2:
	 *
	 * The recipient MUST fail the channel if `signature` is incorrect.
	 */
	txs = channel_txs(state, NULL, &wscripts, state->channel,
			  &state->next_per_commit[LOCAL], 0, LOCAL);

	if (!check_tx_sig(txs[0], 0, NULL, wscripts[0], &their_funding_pubkey,
			  &theirsig)) {
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			      "Bad signature %s on tx %s using key %s",
			      type_to_string(trc, secp256k1_ecdsa_signature,
					     &theirsig),
			      type_to_string(trc, struct bitcoin_tx, txs[0]),
			      type_to_string(trc, struct pubkey,
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
	derive_channel_id(&channel_id,
			  &state->funding_txid, state->funding_txout);

	/* BOLT #2:
	 *
	 * ### The `funding_signed` message
	 *
	 * This message gives the funder the signature they need for the first
	 * commitment transaction, so they can broadcast it knowing they can
	 * redeem their funds if they need to.
	 */
	txs = channel_txs(state, NULL, &wscripts, state->channel,
			  &state->next_per_commit[REMOTE], 0, REMOTE);
	sign_tx_input(txs[0], 0, NULL, wscripts[0],
		      &state->our_secrets.funding_privkey,
		      our_funding_pubkey, &sig);

	/* We don't send this ourselves: channeld does, because master needs
	 * to save state to disk before doing so. */
	msg = towire_funding_signed(state, &channel_id, &sig);

	return towire_opening_fundee_reply(state,
					   state->remoteconf,
					   &theirsig,
					   &state->cs,
					   &theirs.revocation,
					   &theirs.payment,
					   &theirs.delayed_payment,
					   &state->next_per_commit[REMOTE],
					   &their_funding_pubkey,
					   &state->funding_txid,
					   state->funding_txout,
					   state->funding_satoshis,
					   state->push_msat,
					   channel_flags,
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
	struct utxo *utxos;
	u8 *bip32_seed;

	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	subdaemon_debug(argc, argv);

	/* We handle write returning errors! */
	signal(SIGCHLD, SIG_IGN);
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);
	status_setup_sync(REQ_FD);

	msg = wire_sync_read(state, REQ_FD);
	if (!msg)
		status_failed(WIRE_OPENING_BAD_COMMAND, "%s", strerror(errno));

	if (!fromwire_opening_init(msg, NULL,
				   &state->localconf,
				   &state->max_to_self_delay,
				   &state->min_effective_htlc_capacity_msat,
				   &state->cs,
				   &seed))
		status_failed(WIRE_OPENING_BAD_COMMAND, "%s", strerror(errno));
	tal_free(msg);

	/* We derive everything from the one secret seed. */
	if (!derive_basepoints(&seed, &our_funding_pubkey,
			       &our_points, &state->our_secrets,
			       &state->shaseed))
		status_failed(WIRE_OPENING_KEY_DERIVATION_FAILED,
			      "Secret derivation failed, secret = %s",
			      type_to_string(trc, struct privkey, &seed));

	if (!per_commit_point(&state->shaseed, &state->next_per_commit[LOCAL],
			      0))
		status_failed(WIRE_OPENING_KEY_DERIVATION_FAILED,
			      "First per_commitment_point derivation failed,"
			      " secret = %s",
			      type_to_string(trc, struct privkey, &seed));

	status_trace("First per_commit_point = %s",
		     type_to_string(trc, struct pubkey,
				    &state->next_per_commit[LOCAL]));
	msg = wire_sync_read(state, REQ_FD);
	if (fromwire_opening_funder(state, msg, NULL,
				    &state->funding_satoshis,
				    &state->push_msat,
				    &state->feerate_per_kw, &max_minimum_depth,
				    &change_satoshis, &change_keyindex,
				    &channel_flags, &utxos, &bip32_seed))
		msg = funder_channel(state, &our_funding_pubkey, &our_points,
				     max_minimum_depth, change_satoshis,
				     change_keyindex, channel_flags,
				     utxos, bip32_seed);
	else if (fromwire_opening_fundee(state, msg, NULL, &minimum_depth,
					 &min_feerate, &max_feerate, &peer_msg))
		msg = fundee_channel(state, &our_funding_pubkey, &our_points,
				   minimum_depth, min_feerate, max_feerate,
				   peer_msg);

	/* Write message and hand back the fd. */
	wire_sync_write(REQ_FD, msg);
	fdpass_send(REQ_FD, PEER_FD);
	fdpass_send(REQ_FD, GOSSIP_FD);
	status_trace("Sent %s with fd",
		     opening_wire_type_name(fromwire_peektype(msg)));
	tal_free(state);
	return 0;
}
#endif /* TESTING */
