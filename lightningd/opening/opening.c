/* FIXME: Handle incoming gossip messages! */
#include <bitcoin/block.h>
#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/structeq/structeq.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/channel.h>
#include <lightningd/commit_tx.h>
#include <lightningd/crypto_sync.h>
#include <lightningd/debug.h>
#include <lightningd/derive_basepoints.h>
#include <lightningd/key_derive.h>
#include <lightningd/opening/gen_opening_wire.h>
#include <lightningd/peer_failed.h>
#include <lightningd/status.h>
#include <secp256k1.h>
#include <signal.h>
#include <stdio.h>
#include <type_to_string.h>
#include <version.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire.h>
#include <wire/wire_sync.h>

/* stdin == requests, 3 == peer */
#define REQ_FD STDIN_FILENO
#define PEER_FD 3

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
	 * The receiving node MUST fail the channel if `to-self-delay` is
	 * unreasonably large.
	 */
	if (remoteconf->to_self_delay > state->max_to_self_delay)
		peer_failed(PEER_FD, &state->cs, NULL,
			    WIRE_OPENING_PEER_BAD_CONFIG,
			    "to_self_delay %u larger than %u",
			    remoteconf->to_self_delay, state->max_to_self_delay);

	/* BOLT #2:
	 *
	 * The receiver MAY fail the channel if `funding-satoshis` is too
	 * small, and MUST fail the channel if `push-msat` is greater than
	 * `funding-amount` * 1000.  The receiving node MAY fail the channel
	 * if it considers `htlc-minimum-msat` too large,
	 * `max-htlc-value-in-flight` too small, `channel-reserve-satoshis`
	 * too large, or `max-accepted-htlcs` too small.
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
			    "Invalid htlc_minimum_msat %u"
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
	 * It MUST fail the channel if `max-accepted-htlcs` is greater
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
 * This message introduces the `channel-id` which identifies , which is
 * derived from the funding transaction by combining the `funding-txid` and
 * the `funding-output-index` using big-endian exclusive-OR
 * (ie. `funding-output-index` alters the last two bytes).
 */
static void derive_channel_id(struct channel_id *channel_id,
			      struct sha256_double *txid, u16 txout)
{
	BUILD_ASSERT(sizeof(*channel_id) == sizeof(*txid));
	memcpy(channel_id, txid, sizeof(*channel_id));
	channel_id->id[sizeof(*channel_id)-2] ^= txout >> 8;
	channel_id->id[sizeof(*channel_id)-1] ^= txout;
}

/* BOLT #2:
 *
 * A sending node MUST ensure `temporary-channel-id` is unique from any other
 * channel id with the same peer.
 */
static void temporary_channel_id(struct channel_id *channel_id)
{
	size_t i;

	for (i = 0; i < sizeof(*channel_id); i++)
		channel_id->id[i] = pseudorand(256);
}

static u8 *open_channel(struct state *state,
			const struct pubkey *our_funding_pubkey,
			const struct basepoints *ours,
			u32 max_minimum_depth)
{
	const tal_t *tmpctx = tal_tmpctx(state);
	struct channel_id channel_id, id_in;
	u8 *msg;
	struct bitcoin_tx **txs;
	struct basepoints theirs;
	struct pubkey their_funding_pubkey;
	secp256k1_ecdsa_signature sig;
	const u8 **wscripts;

	set_reserve(&state->localconf.channel_reserve_satoshis,
		    state->funding_satoshis);

	temporary_channel_id(&channel_id);

	/* BOLT #2:
	 *
	 * The sender MUST set `funding-satoshis` to less than 2^24 satoshi. */
	if (state->funding_satoshis >= 1 << 24)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_BAD_PARAM,
			      "funding_satoshis must be < 2^24");

	/* BOLT #2:
	 *
	 * The sender MUST set `push-msat` to equal or less than to 1000 *
	 * `funding-satoshis`.
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
				  &state->next_per_commit[LOCAL]);
	if (!sync_crypto_write(&state->cs, PEER_FD, msg))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_WRITE_FAILED,
			      "Writing open_channel");

	state->remoteconf = tal(state, struct channel_config);

	msg = sync_crypto_read(tmpctx, &state->cs, PEER_FD);
	if (!msg)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			      "Reading accept_channel");

	/* BOLT #2:
	 *
	 * The receiver MUST fail the channel if `funding-pubkey`,
	 * `revocation-basepoint`, `payment-basepoint` or
	 * `delayed-payment-basepoint` are not valid DER-encoded compressed
	 * secp256k1 pubkeys.
	 */
	if (!fromwire_accept_channel(msg, NULL, &id_in,
				     &state->remoteconf->dust_limit_satoshis,
				     &state->remoteconf
					->max_htlc_value_in_flight_msat,
				     &state->remoteconf
					->channel_reserve_satoshis,
				     &state->remoteconf->minimum_depth,
				     &state->remoteconf->htlc_minimum_msat,
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
	 * The `temporary-channel-id` MUST be the same as the
	 * `temporary-channel-id` in the `open_channel` message. */
	if (!structeq(&id_in, &channel_id))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			      "accept_channel ids don't match: sent %s got %s",
			      type_to_string(msg, struct channel_id, &id_in),
			      type_to_string(msg, struct channel_id, &channel_id));

	/* BOLT #2:
	 *
	 * The receiver MAY reject the `minimum-depth` if it considers it
	 * unreasonably large.
	 *
	 * Other fields have the same requirements as their counterparts in
	 * `open_channel`.
	 */
	if (state->remoteconf->minimum_depth > max_minimum_depth)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_BAD_PARAM,
			    "minimum_depth %u larger than %u",
			    state->remoteconf->minimum_depth, max_minimum_depth);
	check_config_bounds(state, state->remoteconf);

	/* Now, ask master create a transaction to pay those two addresses. */
	msg = towire_opening_open_reply(tmpctx, our_funding_pubkey,
					&their_funding_pubkey);
	wire_sync_write(REQ_FD, msg);

	/* Expect funding tx. */
	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_opening_open_funding(msg, NULL,
					   &state->funding_txid,
					   &state->funding_txout))
		peer_failed(PEER_FD, &state->cs, NULL,
			    WIRE_OPENING_PEER_READ_FAILED,
			    "Expected valid opening_open_funding: %s",
			    tal_hex(trc, msg));

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
			  &state->next_per_commit[REMOTE], REMOTE);

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
	msg = sync_crypto_read(tmpctx, &state->cs, PEER_FD);
	if (!msg)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			      "Reading funding_signed");

	if (!fromwire_funding_signed(msg, NULL, &id_in, &sig))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_READ_FAILED,
			    "Parsing funding_signed (%s)",
			    wire_type_name(fromwire_peektype(msg)));

	/* BOLT #2:
	 *
	 * This message introduces the `channel-id` which identifies , which
	 * is derived from the funding transaction by combining the
	 * `funding-txid` and the `funding-output-index` using big-endian
	 * exclusive-OR (ie. `funding-output-index` alters the last two
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
			  &state->next_per_commit[LOCAL], LOCAL);

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
	return towire_opening_open_funding_reply(state,
						 state->remoteconf,
						 &sig,
						 &state->cs,
						 &theirs.revocation,
						 &theirs.payment,
						 &theirs.delayed_payment,
						 &state->next_per_commit[REMOTE]);
}

/* This is handed the message the peer sent which caused gossip to stop:
 * it should be an open_channel */
static u8 *recv_channel(struct state *state,
			const struct pubkey *our_funding_pubkey,
			const struct basepoints *ours,
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

	state->remoteconf = tal(state, struct channel_config);

	/* BOLT #2:
	 *
	 * The receiver MUST fail the channel if `funding-pubkey`,
	 * `revocation-basepoint`, `payment-basepoint` or
	 * `delayed-payment-basepoint` are not valid DER-encoded compressed
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
				   &state->next_per_commit[REMOTE]))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_BAD_INITIAL_MESSAGE,
			      "Parsing open_channel %s",
			      tal_hex(peer_msg, peer_msg));

	/* BOLT #2:
	 *
	 * The receiving MUST reject the channel if the `chain-hash` value
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
	 * The receiving node ... MUST fail the channel if `push-msat` is
	 * greater than `funding-amount` * 1000.
	 */
	if (state->push_msat > state->funding_satoshis * 1000)
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_BAD_FUNDING,
			      "push_msat %"PRIu64
			      " too large for funding_satoshis %"PRIu64,
			      state->push_msat, state->funding_satoshis);

	/* BOLT #2:
	 *
	 * The receiver MUST fail the channel if it considers `feerate-per-kw`
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
				    state->localconf.minimum_depth,
				    state->localconf.htlc_minimum_msat,
				    state->localconf.to_self_delay,
				    state->localconf.max_accepted_htlcs,
				    our_funding_pubkey,
				    &ours->revocation,
				    &ours->payment,
				    &ours->delayed_payment,
				    &state->next_per_commit[LOCAL]);

	if (!sync_crypto_write(&state->cs, PEER_FD, msg))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_WRITE_FAILED,
			      "Writing accept_channel");

	msg = sync_crypto_read(state, &state->cs, PEER_FD);
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
	 * The sender MUST set `temporary-channel-id` the same as the
	 * `temporary-channel-id` in the `open_channel` message. */
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

	/* Now, ask master to watch. */
	status_trace("asking master to watch funding %s",
		     type_to_string(trc, struct sha256_double, &state->funding_txid));
	msg = towire_opening_accept_reply(state, &state->funding_txid);
	wire_sync_write(REQ_FD, msg);

	msg = wire_sync_read(state, REQ_FD);
	if (!fromwire_opening_accept_finish(msg, NULL))
		status_failed(WIRE_OPENING_BAD_PARAM,
			      "Expected valid opening_accept_finish: %s",
			      tal_hex(trc, msg));

	status_trace("master said to finish");

	/* BOLT #2:
	 *
	 * The recipient MUST fail the channel if `signature` is incorrect.
	 */
	txs = channel_txs(state, NULL, &wscripts, state->channel,
			  &state->next_per_commit[LOCAL], LOCAL);

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
	 * This message introduces the `channel-id` which identifies , which
	 * is derived from the funding transaction by combining the
	 * `funding-txid` and the `funding-output-index` using big-endian
	 * exclusive-OR (ie. `funding-output-index` alters the last two
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
			  &state->next_per_commit[REMOTE], REMOTE);
	sign_tx_input(txs[0], 0, NULL, wscripts[0],
		      &state->our_secrets.funding_privkey,
		      our_funding_pubkey, &sig);

	msg = towire_funding_signed(state, &channel_id, &sig);
	if (!sync_crypto_write(&state->cs, PEER_FD, msg))
		peer_failed(PEER_FD, &state->cs, NULL, WIRE_OPENING_PEER_WRITE_FAILED,
			      "Writing funding_signed");

	return towire_opening_accept_finish_reply(state,
						  state->funding_txout,
						  state->remoteconf,
						  &theirsig,
						  &state->cs,
						  &their_funding_pubkey,
						  &theirs.revocation,
						  &theirs.payment,
						  &theirs.delayed_payment,
						  &state->next_per_commit[REMOTE],
						  state->funding_satoshis,
						  state->push_msat);
}

#ifndef TESTING
int main(int argc, char *argv[])
{
	u8 *msg, *peer_msg;
	struct state *state = tal(NULL, struct state);
	struct privkey seed;
	struct basepoints our_points;
	struct pubkey our_funding_pubkey;
	u32 max_minimum_depth;
	u32 min_feerate, max_feerate;

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
			       &state->shaseed, &state->next_per_commit[LOCAL],
			       0))
		status_failed(WIRE_OPENING_KEY_DERIVATION_FAILED,
			      "Secret derivation failed, secret = %s",
			      type_to_string(trc, struct privkey, &seed));

	msg = wire_sync_read(state, REQ_FD);
	if (fromwire_opening_open(msg, NULL,
				  &state->funding_satoshis,
				  &state->push_msat,
				  &state->feerate_per_kw, &max_minimum_depth))
		msg = open_channel(state, &our_funding_pubkey, &our_points,
				   max_minimum_depth);
	else if (fromwire_opening_accept(state, msg, NULL, &min_feerate,
					 &max_feerate, &peer_msg))
		msg = recv_channel(state, &our_funding_pubkey, &our_points,
				   min_feerate, max_feerate, peer_msg);

	/* Write message and hand back the fd. */
	wire_sync_write(REQ_FD, msg);
	fdpass_send(REQ_FD, PEER_FD);
	status_trace("Sent %s with fd",
		     opening_wire_type_name(fromwire_peektype(msg)));
	tal_free(state);
	return 0;
}
#endif /* TESTING */
