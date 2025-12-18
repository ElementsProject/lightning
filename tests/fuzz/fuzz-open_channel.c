#include "config.h"
#include <fcntl.h>
#include <stdio.h>
#include <setjmp.h>
#include <common/setup.h>
#include <common/status.h>
#include <tests/fuzz/libfuzz.h>

jmp_buf fuzz_env;

/* We don't want to actually do io! */
#define wire_sync_read test_sync_read
#define wire_sync_write test_sync_write
#define peer_read test_peer_read
#define peer_write test_peer_write
#define validate_initial_commitment_signature test_validate_initial_commitment_signature
#define exit(status) longjmp(fuzz_env, status + 1);

#define PEER_FD -1

static u8 *test_sync_read(const tal_t *ctx, int fd);
static bool test_sync_write(int fd, const void *msg TAKES);
static void test_peer_write(struct per_peer_state *pps, const void *msg TAKES);
static u8 *test_peer_read(const tal_t *ctx, struct per_peer_state *pps);

static u8 *create_fuzz_msg(const tal_t *ctx);

#define main openingd_main
int main(int argc, char *argv[]);
#include "../../openingd/openingd.c"
#undef main

struct state *state;
static int hsmd_reads, hsmd_writes, ld_writes;
static struct privkey dummy_privkey;
static struct pubkey dummy_pubkey;

static const u8 **cursor;
static size_t *max;

static u8 *test_sync_read(const tal_t *ctx, int fd)
{
	if (fd == REQ_FD) /* lightningd message */
	{
		u32 mindepth = 10;
		return towire_openingd_got_offer_reply(ctx, NULL, NULL, NULL, NULL, mindepth);
	}
	else if (fd == HSM_FD) /* HSMD message */
	{
		hsmd_reads++;
		if (hsmd_reads == 1)
			return towire_hsmd_setup_channel_reply(ctx);
		else if (hsmd_reads == 2)
			return towire_hsmd_validate_commitment_tx_reply(ctx, NULL, &dummy_pubkey);
		else if (hsmd_reads == 3) {
			struct sha256_double h;
			struct bitcoin_signature sig;

			memset(&h, 0, sizeof(h));
			sign_hash(&dummy_privkey, &h, &sig.s);
			sig.sighash_type = SIGHASH_ALL;

			return towire_hsmd_sign_tx_reply(ctx, &sig);
		}
		else
			assert(false && "Too many HSMD reads!");
	}
	else if (fd == PEER_FD) /* Peer message */
	{
		/* Choose between creating a valid message and a fuzzed one. */
		if (fromwire_u8(cursor, max) % 2 == 0) {
			struct sha256_double h;
			struct bitcoin_signature sig;
			struct bitcoin_outpoint out;

			memset(&h, 1, sizeof(h));
			sign_hash(&dummy_privkey, &h, &sig.s);
			memset(&out.txid, 1, sizeof(out.txid));
			out.n = 0;

			return towire_funding_created(ctx, &state->channel_id,
					&out.txid, out.n, &sig.s);
		}
		else
			return create_fuzz_msg(ctx);
	}
	else
		assert(false && "Unknown caller!");
}

static bool test_sync_write(int fd, const void *msg TAKES)
{
	if (fd == REQ_FD) /* lightningd message */
	{
		ld_writes++;
		/* Subsequent calls to this are from
		 * negotiation_aborted, so we ignore those.
		 */
		if (ld_writes == 1) {
			struct amount_sat funding_satoshis;
			struct amount_msat push_msat;
			struct amount_sat dust_limit_satoshis;
			struct amount_msat max_htlc_value_in_flight_msat;
			struct amount_sat channel_reserve_satoshis;
			struct amount_msat htlc_minimum_msat;
			u32 feerate_per_kw;
			u16 to_self_delay;
			u16 max_accepted_htlcs;
			u8 channel_flags;
			u8 *shutdown_scriptpubkey;
			struct channel_type *ctype;

			assert(fromwire_openingd_got_offer(tmpctx, msg,
						&funding_satoshis,
						&push_msat,
						&dust_limit_satoshis,
						&max_htlc_value_in_flight_msat,
						&channel_reserve_satoshis,
						&htlc_minimum_msat,
						&feerate_per_kw,
						&to_self_delay,
						&max_accepted_htlcs,
						&channel_flags,
						&shutdown_scriptpubkey,
						&ctype));
		}
	}
	else if (fd == HSM_FD) /* HSMD message */
	{
		hsmd_writes++;
		if (hsmd_writes == 1) {
			bool is_outbound;
			struct amount_sat channel_value;
			struct amount_msat push_value;
			struct bitcoin_txid funding_txid;
			u16 funding_txout, local_to_self_delay, remote_to_self_delay;
			u8 *local_shutdown_script, *remote_shutdown_script;
			u32 *local_shutdown_wallet_index;
			struct basepoints remote_basepoints;
			struct pubkey remote_funding_pubkey;
			struct channel_type *channel_type;

			assert(fromwire_hsmd_setup_channel(tmpctx, msg,
						&is_outbound,
						&channel_value,
						&push_value,
						&funding_txid,
						&funding_txout,
						&local_to_self_delay,
						&local_shutdown_script,
						&local_shutdown_wallet_index,
						&remote_basepoints,
						&remote_funding_pubkey,
						&remote_to_self_delay,
						&remote_shutdown_script,
						&channel_type));
		} else if (hsmd_writes == 2) {
			struct bitcoin_tx *tx;
			struct hsm_htlc *htlcs;
			u64 commit_num;
			u32 feerate;
			struct bitcoin_signature sig;
			struct bitcoin_signature *htlc_sigs;

			assert(fromwire_hsmd_validate_commitment_tx(tmpctx, msg,
								&tx,
								&htlcs,
								&commit_num,
								&feerate,
								&sig,
								&htlc_sigs));
		} else if (hsmd_writes == 3) {
			struct bitcoin_tx *tx;
			struct pubkey remote_funding_key, remote_per_commit;
			bool option_static_remotekey;
			u64 commit_num;
			struct hsm_htlc *htlcs;
			u32 feerate;

			assert(fromwire_hsmd_sign_remote_commitment_tx(tmpctx, msg,
								&tx,
								&remote_funding_key,
								&remote_per_commit,
								&option_static_remotekey,
								&commit_num,
								&htlcs,
								&feerate));
		}
		else
			assert(false && "Too many HSMD writes!");
	}
	else if (fd == PEER_FD)
	{
		struct channel_id temporary_channel_id;
		struct amount_sat dust_limit_satoshis;
		struct amount_msat max_htlc_value_in_flight_msat;
		struct amount_sat channel_reserve_satoshis;
		struct amount_msat htlc_minimum_msat;
		u32 minimum_depth;
		u16 to_self_delay;
		u16 max_accepted_htlcs;
		struct pubkey funding_pubkey;
		struct pubkey revocation_basepoint;
		struct pubkey payment_basepoint;
		struct pubkey delayed_payment_basepoint;
		struct pubkey htlc_basepoint;
		struct pubkey first_per_commitment_point;
		struct tlv_accept_channel_tlvs *tlvs;

		assert(fromwire_accept_channel(tmpctx, msg,
					&temporary_channel_id,
					&dust_limit_satoshis,
					&max_htlc_value_in_flight_msat,
					&channel_reserve_satoshis,
					&htlc_minimum_msat,
					&minimum_depth,
					&to_self_delay,
					&max_accepted_htlcs,
					&funding_pubkey,
					&revocation_basepoint,
					&payment_basepoint,
					&delayed_payment_basepoint,
					&htlc_basepoint,
					&first_per_commitment_point,
					&tlvs));
	}
	return true;
}
/* These have the same definitions as their original definitions. We reiterate
 * these here because we want them to use test_sync_write and test_sync_read.
 */
static void test_peer_write(struct per_peer_state *pps, const void *msg TAKES)
{
	/* Abort the run when called by `negotiation_aborted`. */
	if (is_peer_error(tmpctx, msg))
		longjmp(fuzz_env, 1);

        status_peer_io(LOG_IO_OUT, NULL, msg);
	test_sync_write(pps->peer_fd, msg);
}

static u8 *test_peer_read(const tal_t *ctx, struct per_peer_state *pps)
{
        u8 *msg = test_sync_read(ctx, pps->peer_fd);
        if (!msg)
                peer_failed_connection_lost();

        status_peer_io(LOG_IO_IN, NULL, msg);

        return msg;
}

void test_validate_initial_commitment_signature(int hsm_fd,
                                           struct bitcoin_tx *tx,
                                           struct bitcoin_signature *sig)
{
	u32 feerate;
	u64 commit_num;
	const u8 *msg;
	struct secret *old_secret;
	struct pubkey next_point;

	feerate = 0;
	commit_num = 0;
	msg = towire_hsmd_validate_commitment_tx(NULL, tx, NULL, commit_num, feerate, sig, NULL);
	test_sync_write(hsm_fd, take(msg));
	msg = test_sync_read(tmpctx, hsm_fd);
	if (!fromwire_hsmd_validate_commitment_tx_reply(tmpctx, msg, &old_secret, &next_point))
		status_failed(STATUS_FAIL_HSM_IO, "Reading validate_commitment_tx reply: %s",
			tal_hex(tmpctx, msg));
}

/* AUTOGENERATED MOCKS START */
/* Generated stub for fromwire_hsm_utxo */
struct hsm_utxo *fromwire_hsm_utxo(const tal_t *ctx UNNEEDED, const u8 **ptr UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_hsm_utxo called!\n"); abort(); }
/* Generated stub for fromwire_side */
enum side fromwire_side(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_side called!\n"); abort(); }
/* Generated stub for peer_failed_received_errmsg */
void peer_failed_received_errmsg(struct per_peer_state *pps UNNEEDED,
				 bool disconnect UNNEEDED,
				 const char *desc)

{ fprintf(stderr, "peer_failed_received_errmsg called!\n"); abort(); }
/* Generated stub for subdaemon_setup */
bool subdaemon_setup(int argc UNNEEDED, char *argv[])
{ fprintf(stderr, "subdaemon_setup called!\n"); abort(); }
/* Generated stub for towire_hsm_utxo */
void towire_hsm_utxo(u8 **pptr UNNEEDED, const struct hsm_utxo *utxo UNNEEDED)
{ fprintf(stderr, "towire_hsm_utxo called!\n"); abort(); }
/* Generated stub for towire_side */
void towire_side(u8 **pptr UNNEEDED, const enum side side UNNEEDED)
{ fprintf(stderr, "towire_side called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

void peer_failed_err(struct per_peer_state *pps,
		     const struct channel_id *channel_id,
		     const char *fmt, ...)
{
	longjmp(fuzz_env, 1);
}

void peer_failed_connection_lost(void)
{
	longjmp(fuzz_env, 1);
}

static u8 *create_fuzz_msg(const tal_t *ctx)
{
	u8 *msg = tal_arr(ctx, u8, 0);
	u8 msg_len = fromwire_u16(cursor, max);
	if (msg_len > *max)
		msg_len = *max;
	towire_u8_array(&msg, *cursor, msg_len);
	return msg;
}

static struct state *fromwire_new_state(const tal_t *ctx)
{
	struct state *state = talz(ctx, struct state);

	state->pps = new_per_peer_state(state);
	per_peer_state_set_fd(state->pps, PEER_FD);

	if (!fromwire_channel_id(cursor, max, &state->channel_id))
		return NULL;

	state->first_per_commitment_point[LOCAL]
		= state->first_per_commitment_point[REMOTE]
		= dummy_pubkey;

	/* We set these to NULL, meaning no requirements on shutdown */
	state->upfront_shutdown_script[LOCAL]
		= state->upfront_shutdown_script[REMOTE]
		= NULL;

	/* This is almost a reiteration of fromwire_openingd_init() */
	state->our_features = fromwire_feature_set(ctx, cursor, max);
	u8 their_init_features_len = fromwire_u8(cursor, max);
	state->their_features = their_init_features_len ? tal_arr(ctx, u8, their_init_features_len) : NULL;
	fromwire_u8_array(cursor, max, state->their_features, their_init_features_len);
	fromwire_channel_config(cursor, max, &state->localconf);
	state->max_to_self_delay = fromwire_u32(cursor, max);
	state->min_effective_htlc_capacity = fromwire_amount_msat(cursor, max);
	fromwire_basepoints(cursor, max, &state->our_points);
	state->minimum_depth = fromwire_u32(cursor, max);
	state->min_feerate = fromwire_u32(cursor, max);
	state->max_feerate = fromwire_u32(cursor, max);
	state->our_funding_pubkey = dummy_pubkey;

	/* Set developer options to false. */
	state->developer = false;
	state->allowdustreserve = false;
	state->dev_accept_any_channel_type = false;
	state->dev_force_tmp_channel_id = NULL;

	/* The default value for CLN. */
	state->localconf.dust_limit = amount_sat(546);

	return state;
}

static u8 *create_open_channel_msg(const tal_t *ctx, struct state *state)
{
	struct amount_sat funding_satoshis = fromwire_amount_sat(cursor, max);
	struct amount_msat push_msat = fromwire_amount_msat(cursor, max);
	struct amount_sat dust_limit_satoshis = fromwire_amount_sat(cursor, max);
	struct amount_msat max_htlc_value_in_flight_msat = fromwire_amount_msat(cursor, max);
	struct amount_sat channel_reserve_satoshis = fromwire_amount_sat(cursor, max);
	struct amount_msat htlc_minimum_msat = fromwire_amount_msat(cursor, max);
	u32 feerate_per_kw = fromwire_u32(cursor, max);
	u16 to_self_delay = fromwire_u16(cursor, max);
	u16 max_accepted_htlcs = fromwire_u16(cursor, max);
	u8 channel_flags = fromwire_u8(cursor, max);

	/* These checks get us past check_config_bounds() in fundee_channel(). */
	if (amount_sat_greater(funding_satoshis, chainparams->max_funding) &&
		!feature_negotiated(state->our_features, state->their_features, OPT_LARGE_CHANNELS))
		funding_satoshis = chainparams->max_funding;

	if (amount_msat_greater_sat(push_msat, funding_satoshis) &&
		!amount_sat_to_msat(&push_msat, funding_satoshis))
		return NULL;

	if (feerate_per_kw < state->min_feerate)
		feerate_per_kw = state->min_feerate;
	if (feerate_per_kw > state->max_feerate)
		feerate_per_kw = state->max_feerate;

	if (max_accepted_htlcs > 483 || max_accepted_htlcs == 0)
		max_accepted_htlcs = 483;

	if (to_self_delay > state->max_to_self_delay)
		to_self_delay = state->max_to_self_delay;

	struct amount_sat total_reserve;
	if (!amount_sat_add(&total_reserve,
			channel_reserve_satoshis,
			state->localconf.channel_reserve))
		return NULL;

	if (amount_sat_greater(total_reserve, funding_satoshis))
		return NULL;

	struct tlv_open_channel_tlvs *tlvs = tlv_open_channel_tlvs_new(ctx);

	return towire_open_channel(ctx,
				&chainparams->genesis_blockhash,
				&state->channel_id,
				funding_satoshis,
				push_msat,
				dust_limit_satoshis,
				max_htlc_value_in_flight_msat,
				channel_reserve_satoshis,
				htlc_minimum_msat,
				feerate_per_kw,
				to_self_delay,
				max_accepted_htlcs,
				&dummy_pubkey, &dummy_pubkey, &dummy_pubkey,
				&dummy_pubkey, &dummy_pubkey, &dummy_pubkey,
				channel_flags,
				tlvs);
}

void init(int *argc, char ***argv)
{
	/* Don't call this if we're in unit-test mode, as libfuzz.c does it */
	if (!tmpctx)
		common_setup("fuzzer");
	int devnull = open("/dev/null", O_WRONLY);
	status_setup_sync(devnull);
	chainparams = chainparams_for_network("bitcoin");

	memset(&dummy_privkey, 2, sizeof(dummy_privkey));
	pubkey_from_privkey(&dummy_privkey, &dummy_pubkey);
}

void run(const u8 *data, size_t size)
{
	if (setjmp(fuzz_env) != 0)
		goto cleanup;

	/* The function under test: fundee_channel(), calls
	 * clean_tmpctx() mid-run, so create a separate context.
	 */
	const tal_t *run_ctx = tal(NULL, tal_t);

	/* Initialize the global pointers to the fuzz data. */
	cursor = &data;
	max = &size;

	state = fromwire_new_state(run_ctx);
	if (!state)
		goto cleanup;

	u8 *open_channel_msg;
	/* Choose between creating a valid message and a fuzzed one. */
	if (fromwire_u8(cursor, max) % 2)
		open_channel_msg = create_open_channel_msg(run_ctx, state);
	else {
		u8 *fuzz_msg = create_fuzz_msg(run_ctx);

		open_channel_msg = tal_arr(run_ctx, u8, 0);
		towire_u16(&open_channel_msg, WIRE_OPEN_CHANNEL);
		towire_u8_array(&open_channel_msg, fuzz_msg, tal_bytelen(fuzz_msg));
	}

	if (!open_channel_msg)
		goto cleanup;

	hsmd_reads = hsmd_writes = ld_writes = 0;
	/* We received an `open_channel` msg, so we're the fundee. */
	fundee_channel(state, open_channel_msg);

cleanup:
	tal_free(run_ctx);
	clean_tmpctx();
}
