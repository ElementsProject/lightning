#include "config.h"
#include <fcntl.h>
#include <stdio.h>
#include <setjmp.h>
#include <common/setup.h>
#include <common/status.h>
#include <tests/fuzz/libfuzz.h>

/* We don't want to actually do io! */
#define wire_sync_read test_sync_read
#define wire_sync_write test_sync_write
#define peer_read test_peer_read
#define peer_write test_peer_write

#define PEER_FD -1
#define MAX_SATS ((u64)WALLY_SATOSHI_PER_BTC * WALLY_BTC_MAX)

static u8 *test_sync_read(const tal_t *ctx, int fd);
static bool test_sync_write(int fd, const void *msg TAKES);
static void test_peer_write(struct per_peer_state *pps, const void *msg TAKES);
static u8 *test_peer_read(const tal_t *ctx, struct per_peer_state *pps);

#define main openingd_main
int main(int argc, char *argv[]);
#include "../../openingd/openingd.c"
#undef main

struct state *state;
jmp_buf fuzz_env;
static int hsmd_reads, hsmd_writes;

static u8 *test_sync_read(const tal_t *ctx, int fd)
{
	if (fd == REQ_FD) /* lightningd message */
	{
		struct amount_sat reserve = amount_sat(100);
		u32 mindepth = 10;
		return towire_openingd_got_offer_reply(ctx, NULL, NULL, NULL,
							&reserve, mindepth);
	}
	else if (fd == HSM_FD) /* HSMD message */
	{
		if (hsmd_reads++ == 0)
			return towire_hsmd_setup_channel_reply(ctx);
		else if (hsmd_reads++ == 1) {
			struct privkey p;
			struct sha256_double h;
			struct bitcoin_signature sig;

			memset(&h, 0, sizeof(h));
			memset(&p, 1, sizeof(p));
			sign_hash(&p, &h, &sig.s);
			sig.sighash_type = SIGHASH_ALL;

			return towire_hsmd_sign_tx_reply(ctx, &sig);
		}
		else
			assert(false && "Too many HSMD reads!");
	}
	else if (fd == PEER_FD) /* Peer message */
	{
		struct privkey p;
		struct sha256_double h;
		struct bitcoin_signature sig;

		memset(&h, 1, sizeof(h));
		memset(&p, 2, sizeof(p));
		sign_hash(&p, &h, &sig.s);
		return towire_funding_created(ctx, &state->channel_id,
				&state->funding.txid, state->funding.n, &sig.s);
	}
	else
		assert(false && "Unknown caller!");
}

static bool test_sync_write(int fd, const void *msg TAKES)
{
	if (fd == REQ_FD) /* lightningd message */
	{
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
					&shutdown_scriptpubkey));
	}
	else if (fd == HSM_FD) /* HSMD message */
	{
		if (hsmd_writes++ == 0) {
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

		} else if (hsmd_writes++ == 1) {
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
/* These have the same definitions as the original peer_reed and peer_write.
 * We reiterate these here because we want them to use test_sync_write and
 * test_sync_read.
 */
static void test_peer_write(struct per_peer_state *pps, const void *msg TAKES)
{
        status_peer_io(LOG_IO_OUT, NULL, msg);
	wire_sync_write(pps->peer_fd, msg);
}

static u8 *test_peer_read(const tal_t *ctx, struct per_peer_state *pps)
{
        u8 *msg = wire_sync_read(ctx, pps->peer_fd);
        if (!msg)
                peer_failed_connection_lost();

        status_peer_io(LOG_IO_IN, NULL, msg);

        return msg;
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
/* Generated stub for towire_warningfmt */
u8 *towire_warningfmt(const tal_t *ctx UNNEEDED,
		      const struct channel_id *channel UNNEEDED,
		      const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "towire_warningfmt called!\n"); abort(); }
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

u8 *towire_errorfmt(const tal_t *ctx,
                    const struct channel_id *channel,
                    const char *fmt, ...)
{
	longjmp(fuzz_env, 1);
}

const char *is_peer_warning(const tal_t *ctx, const u8 *msg)
{
    if (fromwire_peektype(msg) != WIRE_WARNING)
        return NULL;
    return tal_fmt(ctx, "true");
}

const char *is_peer_error(const tal_t *ctx, const u8 *msg)
{
    if (fromwire_peektype(msg) != WIRE_ERROR)
        return NULL;
    return tal_fmt(ctx, "true");
}

static struct state *fromwire_new_state(const tal_t *ctx, const u8 **cursor, size_t *max)
{
	struct state *state = talz(ctx, struct state);

	state->developer = fromwire_bool(cursor, max);
	state->pps = new_per_peer_state(state);
	per_peer_state_set_fd(state->pps, PEER_FD);

	if (!fromwire_channel_id(cursor, max, &state->channel_id))
		return NULL;

	struct pubkey dummy_key;
	memset(&dummy_key, 1, sizeof(dummy_key));
	state->first_per_commitment_point[LOCAL]
		= state->first_per_commitment_point[REMOTE]
		= dummy_key;

	/* We set these to NULL, meaning no requirements on shutdown */
	state->upfront_shutdown_script[LOCAL]
		= state->upfront_shutdown_script[REMOTE]
		= NULL;

	fromwire_bitcoin_outpoint(cursor, max, &state->funding);
	return state;
}

static u8 *create_open_channel_msg(const tal_t *ctx, const u8 **cursor, size_t *max, struct state *state)
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

	/* These checks get us past check_config_bounds */
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

	struct pubkey dummy_key;
	memset(&dummy_key, 2, sizeof(dummy_key));

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
				&dummy_key, &dummy_key, &dummy_key,
				&dummy_key, &dummy_key, &dummy_key,
				channel_flags,
				tlvs);
}

void init(int *argc, char ***argv)
{
	common_setup("fuzzer");
	int devnull = open("/dev/null", O_WRONLY);
	status_setup_sync(devnull);
	chainparams = chainparams_for_network("bitcoin");
}

void run(const u8 *data, size_t size)
{
	if (setjmp(fuzz_env) != 0)
		goto cleanup;

	const tal_t *run_ctx = tal(NULL, tal_t);

	state = fromwire_new_state(run_ctx, &data, &size);
	if (!state)
		goto cleanup;

	u8 *openingd_init_msg = tal_arr(run_ctx, u8, 0);

	/* Create the first few fields of the openingd_init_msg.
	 * This makes discovering interesting paths faster.
	 */
	struct feature_set *our_features = fromwire_feature_set(run_ctx, &data, &size);
	if (!our_features)
		goto cleanup;

	towire_u16(&openingd_init_msg, WIRE_OPENINGD_INIT);
	towire_chainparams(&openingd_init_msg, chainparams);
	towire_feature_set(&openingd_init_msg, our_features);
	towire_u16(&openingd_init_msg, /*their_init_features_len*/ 0);

	/* Use fuzzer input for rest of the message. */
	u8 remaining_len = fromwire_u8(&data, &size);
	if (remaining_len > size)
		remaining_len = size;
	towire_u8_array(&openingd_init_msg, data, remaining_len);
	if (size)
		data += remaining_len, size -= remaining_len;

	const struct chainparams *chprms;
	if (!fromwire_openingd_init(run_ctx, openingd_init_msg,
					&chprms,
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
					&state->allowdustreserve,
					&state->dev_accept_any_channel_type))
		goto cleanup;

	u8 *open_channel_msg = create_open_channel_msg(run_ctx, &data, &size, state);
	if (!open_channel_msg)
		goto cleanup;

	hsmd_reads = hsmd_writes = 0;
	/* We received an `open_channel` msg, so we're the fundee. */
	fundee_channel(state, open_channel_msg);

cleanup:
	tal_free(run_ctx);
	clean_tmpctx();
}
