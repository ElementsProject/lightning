/* FIXME: Handle incoming gossip messages! */
/* FIXME: send peer PKT_ERR when failing! */
#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/structeq/structeq.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/channel.h>
#include <lightningd/commit_tx.h>
#include <lightningd/crypto_sync.h>
#include <lightningd/key_derive.h>
#include <lightningd/opening/gen_opening_control_wire.h>
#include <lightningd/opening/gen_opening_status_wire.h>
#include <secp256k1.h>
#include <signal.h>
#include <status.h>
#include <stdio.h>
#include <type_to_string.h>
#include <version.h>
#include <wire/gen_peer_wire.h>
#include <wire/wire.h>
#include <wire/wire_sync.h>

/* Stdout == status, stdin == requests, 3 == peer */
#define STATUS_FD STDOUT_FILENO
#define REQ_FD STDIN_FILENO
#define PEER_FD 3

struct points {
	struct pubkey funding_pubkey;
	struct pubkey revocation_basepoint;
	struct pubkey payment_basepoint;
	struct pubkey delayed_payment_basepoint;
};

struct secrets {
	struct privkey funding_privkey;
	struct privkey revocation_basepoint_secret;
	struct privkey payment_basepoint_secret;
	struct privkey delayed_payment_basepoint_secret;
};

struct state {
	struct crypto_state cs;
	struct pubkey next_per_commit[NUM_SIDES];

	/* Funding and feerate: set by opening peer. */
	u64 funding_satoshis, push_msat;
	u32 feerate_per_kw;
	struct sha256_double funding_txid;
	u8 funding_txout;

	/* Secret keys and basepoint secrets. */
	struct secrets our_secrets;

	/* Our shaseed for generating per-commitment-secrets. */
	struct sha256 shaseed;
	struct channel_config localconf, *remoteconf, minconf, maxconf;

	struct channel *channel;
};

static void derive_our_basepoints(const struct sha256 *seed,
				  struct points *points,
				  struct secrets *secrets,
				  struct sha256 *shaseed,
				  struct pubkey *first_per_commit)
{
	struct sha256 per_commit_secret;
	struct keys {
		struct privkey f, r, p, d;
		struct sha256 shaseed;
	} keys;

	hkdf_sha256(&keys, sizeof(keys), NULL, 0, seed, sizeof(seed),
		    "c-lightning", strlen("c-lightning"));

	secrets->funding_privkey = keys.f;
	secrets->revocation_basepoint_secret = keys.r;
	secrets->payment_basepoint_secret = keys.p;
	secrets->delayed_payment_basepoint_secret = keys.d;

	if (!pubkey_from_privkey(&keys.f, &points->funding_pubkey)
	    || !pubkey_from_privkey(&keys.r, &points->revocation_basepoint)
	    || !pubkey_from_privkey(&keys.p, &points->payment_basepoint)
	    || !pubkey_from_privkey(&keys.d, &points->delayed_payment_basepoint))
		status_failed(WIRE_OPENING_KEY_DERIVATION_FAILED,
			      "seed = %s",
			      type_to_string(trc, struct sha256, seed));

	/* BOLT #3:
	 *
	 * A node MUST select an unguessable 256-bit seed for each connection,
	 * and MUST NOT reveal the seed.
	 */
	*shaseed = keys.shaseed;

	/* BOLT #3:
	 *
	 * the first secret used MUST be index 281474976710655, and then the
	 * index decremented. */
	shachain_from_seed(shaseed, 281474976710655ULL, &per_commit_secret);

	/* BOLT #3:
	 *
	 * The `per-commitment-point` is generated using EC multiplication:
	 *
	 * 	per-commitment-point = per-commitment-secret * G
	 */
	if (secp256k1_ec_pubkey_create(secp256k1_ctx,
				       &first_per_commit->pubkey,
				       per_commit_secret.u.u8) != 1)
		status_failed(WIRE_OPENING_KEY_DERIVATION_FAILED,
			      "first_per_commit create failed, secret = %s",
			      type_to_string(trc, struct sha256,
					     &per_commit_secret));
}

/* Yes, this multi-evaluates, and isn't do-while wrapped. */
#define test_config_inrange(conf, min, max, field, fmt)			\
	if ((conf)->field < (min)->field || (conf)->field > (max)->field) \
		status_failed(WIRE_OPENING_PEER_BAD_CONFIG,		\
			      #field " %"fmt" too large (%"fmt"-%"fmt")", \
			      (conf)->field, (min)->field, (max)->field)

#define test_config_inrange_u64(conf, min, max, field)	\
	test_config_inrange(conf, min, max, field, PRIu64)
#define test_config_inrange_u32(conf, min, max, field)	\
	test_config_inrange(conf, min, max, field, "u")
#define test_config_inrange_u16(conf, min, max, field)	\
	test_config_inrange(conf, min, max, field, "u")

static void check_config_bounds(const struct channel_config *remoteconf,
				const struct channel_config *minc,
				const struct channel_config *maxc)
{
	/* BOLT #2:
	 *
	 * It MUST fail the channel if `max-accepted-htlcs` is greater than
	 * 511.
	 */
	if (maxc->max_accepted_htlcs > 511)
		status_failed(WIRE_OPENING_BAD_PARAM,
			      "max->max_accepted_htlcs %u too large",
			      maxc->max_accepted_htlcs);

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if `to-self-delay` is
	 * unreasonably large.  The receiver MAY fail the channel if
	 * `funding-satoshis` is too small....  The receiving node MAY fail
	 * the channel if it considers `htlc-minimum-msat` too large,
	 * `max-htlc-value-in-flight` too small, `channel-reserve-satoshis`
	 * too large, or `max-accepted-htlcs` too small.
	 *
	 * The receiver MUST fail the channel if it considers `feerate-per-kw`
	 * too small for timely processing, or unreasonably large.
	 */
	/* We simply compare every field, and let the master daemon sort out
	   the bounds. */
	test_config_inrange_u64(remoteconf, minc, maxc, dust_limit_satoshis);
	test_config_inrange_u64(remoteconf, minc, maxc, channel_reserve_satoshis);
	test_config_inrange_u32(remoteconf, minc, maxc, minimum_depth);
	test_config_inrange_u32(remoteconf, minc, maxc, htlc_minimum_msat);
	test_config_inrange_u16(remoteconf, minc, maxc, to_self_delay);
	test_config_inrange_u16(remoteconf, minc, maxc, max_accepted_htlcs);
}

static bool check_commit_sig(const struct state *state,
			     const struct pubkey *our_funding_key,
			     const struct pubkey *their_funding_key,
			     struct bitcoin_tx *tx,
			     const secp256k1_ecdsa_signature *remotesig)
{
	u8 *wscript;
	bool ret;

	wscript = bitcoin_redeem_2of2(state,
				      our_funding_key, their_funding_key);

	ret = check_tx_sig(tx, 0, NULL, wscript, their_funding_key, remotesig);
	tal_free(wscript);
	return ret;
}

static secp256k1_ecdsa_signature
sign_remote_commit(const struct state *state,
		   const struct pubkey *our_funding_key,
		   const struct pubkey *their_funding_key,
		   struct bitcoin_tx *tx)
{
	u8 *wscript;
	secp256k1_ecdsa_signature sig;

	wscript = bitcoin_redeem_2of2(state,
				      our_funding_key, their_funding_key);

	/* Commit tx only has one input: funding tx. */
	sign_tx_input(tx, 0, NULL, wscript, &state->our_secrets.funding_privkey,
		      our_funding_key, &sig);
	tal_free(wscript);
	return sig;
}

static void open_channel(struct state *state, const struct points *ours)
{
	struct channel_id tmpid, tmpid2;
	u8 *msg;
	struct bitcoin_tx *tx;
	struct points theirs;
	secp256k1_ecdsa_signature sig;

	/* BOLT #2:
	 *
	 * A sending node MUST set the most significant bit in
	 * `temporary-channel-id`, and MUST ensure it is unique from any other
	 * channel id with the same peer.
	 */
	/* We don't support more than one channel, so this is easy. */
	memset(&tmpid, 0xFF, sizeof(tmpid));

	/* BOLT #2:
	 *
	 * The sender MUST set `funding-satoshis` to less than 2^24 satoshi. */
	if (state->funding_satoshis >= 1 << 24)
		status_failed(WIRE_OPENING_BAD_PARAM,
			      "funding_satoshis must be < 2^24");

	/* BOLT #2:
	 *
	 * The sender MUST set `push-msat` to equal or less than to 1000 *
	 * `funding-satoshis`.
	 */
	if (state->push_msat > 1000 * state->funding_satoshis)
		status_failed(WIRE_OPENING_BAD_PARAM,
			      "push-msat must be < %"PRIu64,
			      1000 * state->funding_satoshis);

	msg = towire_open_channel(state, &tmpid,
				  state->funding_satoshis, state->push_msat,
				  state->localconf.dust_limit_satoshis,
				  state->localconf.max_htlc_value_in_flight_msat,
				  state->localconf.channel_reserve_satoshis,
				  state->localconf.htlc_minimum_msat,
				  state->feerate_per_kw,
				  state->localconf.to_self_delay,
				  state->localconf.max_accepted_htlcs,
				  &ours->funding_pubkey,
				  &ours->revocation_basepoint,
				  &ours->payment_basepoint,
				  &ours->delayed_payment_basepoint,
				  &state->next_per_commit[LOCAL]);
	if (!sync_crypto_write(&state->cs, PEER_FD, msg))
		status_failed(WIRE_OPENING_PEER_WRITE_FAILED,
			      "Writing open_channel");

	state->remoteconf = tal(state, struct channel_config);

	msg = sync_crypto_read(state, &state->cs, PEER_FD);
	if (!msg)
		status_failed(WIRE_OPENING_PEER_READ_FAILED,
			      "Reading accept_channel");

	/* BOLT #2:
	 *
	 * The receiver MUST fail the channel if `funding-pubkey`,
	 * `revocation-basepoint`, `payment-basepoint` or
	 * `delayed-payment-basepoint` are not valid DER-encoded compressed
	 * secp256k1 pubkeys.
	 */
	if (!fromwire_accept_channel(msg, NULL, &tmpid2,
				     &state->remoteconf->dust_limit_satoshis,
				     &state->remoteconf
					->max_htlc_value_in_flight_msat,
				     &state->remoteconf
					->channel_reserve_satoshis,
				     &state->remoteconf->htlc_minimum_msat,
				     &state->feerate_per_kw,
				     &state->remoteconf->to_self_delay,
				     &state->remoteconf->max_accepted_htlcs,
				     &theirs.funding_pubkey,
				     &theirs.revocation_basepoint,
				     &theirs.payment_basepoint,
				     &theirs.delayed_payment_basepoint,
				     &state->next_per_commit[REMOTE]))
		status_failed(WIRE_OPENING_PEER_READ_FAILED,
			      "Parsing accept_channel %s", tal_hex(msg, msg));

	/* BOLT #2:
	 *
	 * The `temporary-channel-id` MUST be the same as the
	 * `temporary-channel-id` in the `open_channel` message. */
	if (!structeq(&tmpid, &tmpid2))
		status_failed(WIRE_OPENING_PEER_READ_FAILED,
			      "accept_channel ids don't match: sent %s got %s",
			      type_to_string(msg, struct channel_id, &tmpid),
			      type_to_string(msg, struct channel_id, &tmpid2));

	check_config_bounds(state->remoteconf,
			    &state->minconf, &state->maxconf);

	/* Now, ask master create a transaction to pay those two addresses. */
	msg = towire_opening_open_resp(state, &ours->funding_pubkey,
				       &theirs.funding_pubkey);
	wire_sync_write(STATUS_FD, msg);

	/* Expect funding tx. */
	msg = wire_sync_read(state, REQ_FD);
	if (!fromwire_opening_open_funding(msg, NULL,
					   &state->funding_txid,
					   &state->funding_txout))
		status_failed(WIRE_BAD_COMMAND, "reading opening_open_funding");

	state->channel = new_channel(state,
				      &state->funding_txid,
				      state->funding_txout,
				      state->funding_satoshis,
				      state->push_msat,
				      state->feerate_per_kw,
				      &state->localconf,
				      state->remoteconf,
				      &ours->revocation_basepoint,
				      &theirs.revocation_basepoint,
				      &ours->payment_basepoint,
				      &theirs.payment_basepoint,
				      &ours->delayed_payment_basepoint,
				      &theirs.delayed_payment_basepoint,
				      LOCAL);
	if (!state->channel)
		status_failed(WIRE_OPENING_BAD_PARAM,
			      "could not create channel with given config");

	/* BOLT #2:
	 *
	 * ### The `funding_created` message
	 *
	 * This message describes the outpoint which the funder has created
	 * for the initial commitment transactions.  After receiving the
	 * peer's signature, it will broadcast the funding transaction.
	 */
	tx = channel_tx(state, state->channel,
			&state->next_per_commit[REMOTE],
			NULL, REMOTE);
	sig = sign_remote_commit(state,
				 &ours->funding_pubkey, &theirs.funding_pubkey,
				 tx);
	msg = towire_funding_created(state, &tmpid,
				     &state->funding_txid.sha,
				     state->funding_txout,
				     &sig);
	if (!sync_crypto_write(&state->cs, PEER_FD, msg))
		status_failed(WIRE_OPENING_PEER_WRITE_FAILED,
			      "Writing funding_created");

	/* BOLT #2:
	 *
	 * ### The `funding_signed` message
	 *
	 * This message gives the funder the signature they need for the first
	 * commitment transaction, so they can broadcast it knowing they can
	 * redeem their funds if they need to.
	 */
	msg = sync_crypto_read(state, &state->cs, PEER_FD);
	if (!msg)
		status_failed(WIRE_OPENING_PEER_READ_FAILED,
			      "Reading funding_signed");

	if (!fromwire_funding_signed(msg, NULL, &tmpid2, &sig))
		status_failed(WIRE_OPENING_PEER_READ_FAILED,
			      "Parsing funding_signed");
	if (!structeq(&tmpid, &tmpid2))
		status_failed(WIRE_OPENING_PEER_READ_FAILED,
			      "funding_signed ids don't match: sent %s got %s",
			      type_to_string(msg, struct channel_id, &tmpid),
			      type_to_string(msg, struct channel_id, &tmpid2));

	/* BOLT #2:
	 *
	 * The recipient MUST fail the channel if `signature` is incorrect.
	 */
	tx = channel_tx(state, state->channel,
		       &state->next_per_commit[LOCAL], NULL, LOCAL);

	if (!check_commit_sig(state, &ours->funding_pubkey,
			      &theirs.funding_pubkey, tx, &sig))
		status_failed(WIRE_OPENING_PEER_READ_FAILED,
			      "Bad signature %s on tx %s using key %s",
			      type_to_string(trc, secp256k1_ecdsa_signature,
					     &sig),
			      type_to_string(trc, struct bitcoin_tx, tx),
			      type_to_string(trc, struct pubkey,
					     &theirs.funding_pubkey));

	/* BOLT #2:
	 *
	 * Once the channel funder receives the `funding_signed` message, they
	 * must broadcast the funding transaction to the Bitcoin network.
	 */
	msg = towire_opening_open_funding_resp(state,
					       state->remoteconf,
					       &sig,
					       &state->cs,
					       &theirs.revocation_basepoint,
					       &theirs.payment_basepoint,
					       &theirs.delayed_payment_basepoint,
					       &state->next_per_commit[REMOTE]);

	status_send(msg);
}

/* This is handed the message the peer sent which caused gossip to stop:
 * it should be an open_channel */
static void recv_channel(struct state *state, const struct points *ours,
			 const u8 *peer_msg)
{
	struct channel_id tmpid, tmpid2;
	struct points theirs;
	secp256k1_ecdsa_signature theirsig, sig;
	struct bitcoin_tx *tx;
	u8 *msg;

	state->remoteconf = tal(state, struct channel_config);

	/* BOLT #2:
	 *
	 * The receiver MUST fail the channel if `funding-pubkey`,
	 * `revocation-basepoint`, `payment-basepoint` or
	 * `delayed-payment-basepoint` are not valid DER-encoded compressed
	 * secp256k1 pubkeys.
	 */
	if (!fromwire_open_channel(peer_msg, NULL, &tmpid,
				   &state->funding_satoshis, &state->push_msat,
				   &state->remoteconf->dust_limit_satoshis,
				   &state->remoteconf->max_htlc_value_in_flight_msat,
				   &state->remoteconf->channel_reserve_satoshis,
				   &state->remoteconf->htlc_minimum_msat,
				   &state->feerate_per_kw,
				   &state->remoteconf->to_self_delay,
				   &state->remoteconf->max_accepted_htlcs,
				   &theirs.funding_pubkey,
				   &theirs.revocation_basepoint,
				   &theirs.payment_basepoint,
				   &theirs.delayed_payment_basepoint,
				   &state->next_per_commit[REMOTE]))
		status_failed(WIRE_OPENING_PEER_BAD_INITIAL_MESSAGE,
			      "Parsing open_channel %s",
			      tal_hex(peer_msg, peer_msg));

	/* BOLT #2:
	 *
	 * The receiving node ... MUST fail the channel if `funding-satoshis`
	 * is greater than or equal to 2^24 */
	if (state->funding_satoshis >= 1 << 24)
		status_failed(WIRE_OPENING_PEER_BAD_FUNDING,
			      "funding_satoshis %"PRIu64" too large",
			      state->funding_satoshis);

	/* BOLT #2:
	 *
	 * The receiving node ... MUST fail the channel if `push-msat` is
	 * greater than `funding-satoshis` * 1000.
	 */
	if (state->push_msat > state->funding_satoshis * 1000)
		status_failed(WIRE_OPENING_PEER_BAD_FUNDING,
			      "push_msat %"PRIu64
			      " too large for funding_satoshis %"PRIu64,
			      state->push_msat, state->funding_satoshis);

	check_config_bounds(state->remoteconf,
			    &state->minconf, &state->maxconf);

	msg = towire_accept_channel(state, &tmpid,
				    state->localconf.dust_limit_satoshis,
				    state->localconf
				      .max_htlc_value_in_flight_msat,
				    state->localconf.channel_reserve_satoshis,
				    state->localconf.htlc_minimum_msat,
				    state->feerate_per_kw,
				    state->localconf.to_self_delay,
				    state->localconf.max_accepted_htlcs,
				    &ours->funding_pubkey,
				    &ours->revocation_basepoint,
				    &ours->payment_basepoint,
				    &ours->delayed_payment_basepoint,
				    &state->next_per_commit[REMOTE]);

	if (!sync_crypto_write(&state->cs, PEER_FD, msg))
		status_failed(WIRE_OPENING_PEER_WRITE_FAILED,
			      "Writing accept_channel");

	msg = sync_crypto_read(state, &state->cs, PEER_FD);
	if (!msg)
		status_failed(WIRE_OPENING_PEER_READ_FAILED,
			      "Reading funding_created");

	if (!fromwire_funding_created(msg, NULL, &tmpid2,
				      &state->funding_txid.sha,
				      &state->funding_txout,
				      &theirsig))
		status_failed(WIRE_OPENING_PEER_READ_FAILED,
			      "Parsing funding_created");

	/* BOLT #2:
	 *
	 * The sender MUST set `temporary-channel-id` the same as the
	 * `temporary-channel-id` in the `open_channel` message. */
	if (!structeq(&tmpid, &tmpid2))
		status_failed(WIRE_OPENING_PEER_READ_FAILED,
			      "funding_created ids don't match: sent %s got %s",
			      type_to_string(msg, struct channel_id, &tmpid),
			      type_to_string(msg, struct channel_id, &tmpid2));

	state->channel = new_channel(state,
				      &state->funding_txid,
				      state->funding_txout,
				      state->funding_satoshis,
				      state->push_msat,
				      state->feerate_per_kw,
				      &state->localconf,
				      state->remoteconf,
				      &ours->revocation_basepoint,
				      &theirs.revocation_basepoint,
				      &ours->payment_basepoint,
				      &theirs.payment_basepoint,
				      &ours->delayed_payment_basepoint,
				      &theirs.delayed_payment_basepoint,
				      REMOTE);
	if (!state->channel)
		status_failed(WIRE_OPENING_BAD_PARAM,
			      "could not create channel with given config");

	/* BOLT #2:
	 *
	 * The recipient MUST fail the channel if `signature` is incorrect.
	 */
	tx = channel_tx(state, state->channel,
		       &state->next_per_commit[LOCAL], NULL, LOCAL);

	if (!check_commit_sig(state, &ours->funding_pubkey,
			      &theirs.funding_pubkey, tx, &theirsig))
		status_failed(WIRE_OPENING_PEER_READ_FAILED,
			      "Bad signature %s on tx %s using key %s",
			      type_to_string(trc, secp256k1_ecdsa_signature,
					     &sig),
			      type_to_string(trc, struct bitcoin_tx, tx),
			      type_to_string(trc, struct pubkey,
					     &theirs.funding_pubkey));

	/* BOLT #2:
	 *
	 * ### The `funding_signed` message
	 *
	 * This message gives the funder the signature they need for the first
	 * commitment transaction, so they can broadcast it knowing they can
	 * redeem their funds if they need to.
	 */
	tx = channel_tx(state, state->channel,
			&state->next_per_commit[REMOTE], NULL, REMOTE);
	sig = sign_remote_commit(state,
				 &ours->funding_pubkey, &theirs.funding_pubkey,
				 tx);

	msg = towire_funding_signed(state, &tmpid, &sig);
	if (!sync_crypto_write(&state->cs, PEER_FD, msg))
		status_failed(WIRE_OPENING_PEER_WRITE_FAILED,
			      "Writing funding_signed");

	msg = towire_opening_accept_resp(state,
					 &state->funding_txid,
					 state->funding_txout,
					 state->remoteconf,
					 &theirsig,
					 &state->cs,
					 &theirs.funding_pubkey,
					 &theirs.revocation_basepoint,
					 &theirs.payment_basepoint,
					 &theirs.delayed_payment_basepoint,
					 &state->next_per_commit[REMOTE]);

	status_send(msg);
}

#ifndef TESTING
int main(int argc, char *argv[])
{
	u8 *msg, *peer_msg;
	struct state *state = tal(NULL, struct state);
	struct sha256 seed;
	struct points our_points;

	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	breakpoint();

	/* We handle write returning errors! */
	signal(SIGCHLD, SIG_IGN);
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);
	status_setup(STATUS_FD);

	msg = wire_sync_read(state, REQ_FD);
	if (!msg)
		status_failed(WIRE_BAD_COMMAND, "%s", strerror(errno));

	if (!fromwire_opening_init(msg, NULL,
				   &state->localconf,
				   &state->minconf,
				   &state->maxconf,
				   &state->cs,
				   &seed))
		status_failed(WIRE_BAD_COMMAND, "%s", strerror(errno));
	tal_free(msg);

	/* We derive everything from the one secret seed. */
	derive_our_basepoints(&seed, &our_points, &state->our_secrets,
			      &state->shaseed, &state->next_per_commit[LOCAL]);

	msg = wire_sync_read(state, REQ_FD);
	if (fromwire_opening_open(msg, NULL,
				  &state->funding_satoshis,
				  &state->push_msat,
				  &state->feerate_per_kw))
		open_channel(state, &our_points);
	else if (fromwire_opening_accept(state, msg, NULL, &peer_msg))
		recv_channel(state, &our_points, peer_msg);

	/* Hand back the fd. */
	fdpass_send(REQ_FD, PEER_FD);

	/* Wait for exit command (avoid state close being read before reqfd) */
	msg = wire_sync_read(state, REQ_FD);
	if (!msg)
		status_failed(WIRE_BAD_COMMAND, "%s", strerror(errno));
	if (!fromwire_opening_exit_req(msg, NULL))
		status_failed(WIRE_BAD_COMMAND, "Expected exit req not %i",
			      fromwire_peektype(msg));
	tal_free(state);
	return 0;
}
#endif /* TESTING */
