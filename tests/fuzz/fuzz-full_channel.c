/* This test is a fuzz version of channeld/test/run-full_channel.
 * A lot of the helper functions and setup have been copied over
 * from that test.
 */
#include "config.h"
#include <ccan/ccan/array_size/array_size.h>
#include <channeld/full_channel.h>
#include <common/blockheight_states.h>
#include <common/channel_type.h>
#include <common/fee_states.h>
#include <common/htlc_wire.h>
#include <common/setup.h>
#include <common/status.h>
#include <fcntl.h>
#include <tests/fuzz/libfuzz.h>

/* MOCKS START */
const struct siphash_seed *siphash_seed(void)
{
	struct siphash_seed *siphashseed = tal(tmpctx, struct siphash_seed);
	memset(siphashseed, 1, sizeof(*siphashseed));
	return siphashseed;
}
/* MOCKS END */

#define MAX_SATS ((u64)WALLY_SATOSHI_PER_BTC * WALLY_BTC_MAX)
#define MAX_MSATS (MAX_SATS * 1000)
#define MAX_HTLCS 1000000

static struct amount_msat fromwire_amount_msat_bounded(const u8 **cursor, size_t *max)
{
	u64 amt = fromwire_u64(cursor, max) % (MAX_MSATS + 1);
	return amount_msat(amt);
}

static u32 fromwire_bounded_feerate(const u8 **cursor, size_t *max)
{
	/* fee_states doesn't allow a feerate < 253. */
	u32 min_feerate = 253, max_feerate = 1000000;
	return (min_feerate + fromwire_u32(cursor, max) % max_feerate);
}

static struct bitcoin_txid txid_from_hex(const char *hex)
{
	struct bitcoin_txid txid;
	if (!bitcoin_txid_from_hex(hex, strlen(hex), &txid))
		assert(false && "bitcoin_txid_from_hex failed");
	return txid;
}

static struct pubkey pubkey_from_hex(const char *hex)
{
	struct pubkey pubkey;
	if (strstarts(hex, "0x"))
		hex += 2;
	if (!pubkey_from_hexstr(hex, strlen(hex), &pubkey))
		assert(false && "pubkey_from_hexstr failed");
	return pubkey;
}

/* These helpers invoke the underlying full_channel API and then drive
 * the full commitment dance (the four steps of sending_commit ->
 * recv_revoke_and_ack -> recv_commit -> sending_revoke_and_ack)
 * in the correct opener vs. accepter order.
 */
static void exchange_commits(struct channel *channel, enum side side, const struct htlc ***changed_htlcs)
{
	if (side == LOCAL) {
		channel_sending_commit(channel, changed_htlcs);
		channel_rcvd_revoke_and_ack(channel, changed_htlcs);
		channel_rcvd_commit(channel, changed_htlcs);
		channel_sending_revoke_and_ack(channel);
	} else {
		channel_rcvd_commit(channel, changed_htlcs);
		channel_sending_revoke_and_ack(channel);
		channel_sending_commit(channel, changed_htlcs);
		channel_rcvd_revoke_and_ack(channel, changed_htlcs);
	}
}

/* Randomize the commitment dance order. */
static void fuzz_exchange_commits(struct channel *channel, const struct htlc ***changed_htlcs,
								const u8 **cursor, size_t *max)
{
	int order[] = {0, 1, 2, 3};

	/* Shuffle the call order using fuzzer data. */
	for (size_t i = ARRAY_SIZE(order) - 1; i > 0 && *max > 0; i--) {
		size_t j = fromwire_u8(cursor, max) % (i + 1);
		int temp = order[i];
		order[i] = order[j];
		order[j] = temp;
	}

	for (size_t i = 0; i < ARRAY_SIZE(order); i++) {
		switch (order[i]) {
		case 0:
			channel_sending_commit(channel, changed_htlcs);
			break;
		case 1:
			channel_rcvd_revoke_and_ack(channel, changed_htlcs);
			break;
		case 2:
			channel_rcvd_commit(channel, changed_htlcs);
			break;
		case 3:
			channel_sending_revoke_and_ack(channel);
			break;
		}
	}
}

static bool update_feerate(struct channel *channel, u32 feerate)
{
	if (!channel_update_feerate(channel, feerate))
		return false;
	return true;
}

static void update_blockheight(struct channel *channel, u32 blockheight)
{
	channel_update_blockheight(channel, blockheight);
}

static bool add_htlc(struct channel *channel, enum side sender, u64 id,
		     const struct preimage *preimage,
		     struct amount_msat msatoshi, u32 cltv)
{
	struct sha256 rhash;
	u8 *dummy_routing;

	dummy_routing = tal_arr(channel, u8, TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE));
	sha256(&rhash, preimage, sizeof(*preimage));

	if (channel_add_htlc(channel, sender, id, msatoshi, cltv, &rhash,
			     dummy_routing, NULL, NULL, NULL, NULL, true) != CHANNEL_ERR_ADD_OK) {
		tal_free(dummy_routing);
		return false;
	}

	tal_free(dummy_routing);
	return true;
}

static bool fulfill_htlc(struct channel *channel, enum side original_sender,
			 u64 id, const struct preimage *preimage)
{
	if (channel_fulfill_htlc(channel, original_sender, id, preimage, NULL)
	    != CHANNEL_ERR_REMOVE_OK)
		return false;
	return true;
}

static bool fail_htlc(struct channel *channel, enum side original_sender, u64 id)
{
	if (channel_fail_htlc(channel, original_sender, id, NULL)
	    != CHANNEL_ERR_REMOVE_OK)
		return false;
	return true;
}

static void init_channels(const tal_t *ctx, const u8 **cursor, size_t *max,
			  struct pubkey *local_per_commitment_point,
			  struct bitcoin_outpoint *funding,
			  struct amount_sat *funding_amount,
			  u32 *blockheight,
			  struct channel **lchannel,
			  struct channel **rchannel)
{
	struct channel_id cid;
	u32 feerate_per_kw[NUM_SIDES] = {fromwire_bounded_feerate(cursor, max),
                                     fromwire_bounded_feerate(cursor, max)};
	struct pubkey local_funding_pubkey, remote_funding_pubkey;
	struct basepoints localbase, remotebase;
	struct pubkey *unknown = tal(ctx, struct pubkey);
	struct channel_config *local_config = tal(ctx, struct channel_config);
	struct channel_config *remote_config = tal(ctx, struct channel_config);
	struct amount_msat to_local = fromwire_amount_msat_bounded(cursor, max);
	struct amount_msat to_remote = fromwire_amount_msat_bounded(cursor, max);
	UNUSED const u8 *funding_wscript;

	/* Fixed values from BOLT #3 appendix. */
	funding->txid = txid_from_hex("8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be");
	funding->n = 0;

	*funding_amount = AMOUNT_SAT(10000000);
	remote_config->to_self_delay = 144;
	local_config->dust_limit = AMOUNT_SAT(546);
	remote_config->dust_limit = AMOUNT_SAT(546);
	local_config->max_htlc_value_in_flight = AMOUNT_MSAT(-1ULL);
	remote_config->max_htlc_value_in_flight = AMOUNT_MSAT(-1ULL);
	local_config->max_dust_htlc_exposure_msat = AMOUNT_MSAT(-1ULL);
	remote_config->max_dust_htlc_exposure_msat = AMOUNT_MSAT(-1ULL);
	local_config->channel_reserve = AMOUNT_SAT(0);
	remote_config->channel_reserve = AMOUNT_SAT(0);
	local_config->htlc_minimum = AMOUNT_MSAT(0);
	remote_config->htlc_minimum = AMOUNT_MSAT(0);
	local_config->max_accepted_htlcs = 0xFFFF;
	remote_config->max_accepted_htlcs = 0xFFFF;

	remotebase.revocation = pubkey_from_hex("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27");
	localbase.delayed_payment = pubkey_from_hex("023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1");
	localbase.payment = pubkey_from_hex("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
	remotebase.payment = pubkey_from_hex("032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991");
	localbase.htlc = localbase.payment;
	remotebase.htlc = remotebase.payment;
	localbase.revocation = *unknown;
	remotebase.delayed_payment = *unknown;

	local_funding_pubkey = pubkey_from_hex("023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb");
	remote_funding_pubkey = pubkey_from_hex("030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c1");
	funding_wscript = tal_hexdata(ctx, "5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb2103"
					   "0e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae",
				      strlen("5221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb2103"
					     "0e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae"));
	*local_per_commitment_point = pubkey_from_hex("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486");

	derive_channel_id(&cid, funding);

	*lchannel = new_full_channel(ctx, &cid, funding, 0,
				    take(new_height_states(NULL, LOCAL, blockheight)),
				    0, *funding_amount, to_local,
				    take(new_fee_states(NULL, LOCAL, &feerate_per_kw[LOCAL])),
				    local_config, remote_config,
				    &localbase, &remotebase,
				    &local_funding_pubkey, &remote_funding_pubkey,
				    take(channel_type_static_remotekey(NULL)), false, LOCAL);
	*rchannel = new_full_channel(ctx, &cid, funding, 0,
				    take(new_height_states(NULL, REMOTE, blockheight)),
				    0, *funding_amount, to_remote,
				    take(new_fee_states(NULL, REMOTE, &feerate_per_kw[REMOTE])),
				    remote_config, local_config,
				    &remotebase, &localbase,
				    &remote_funding_pubkey, &local_funding_pubkey,
				    take(channel_type_static_remotekey(NULL)), false, REMOTE);
}

void init(int *argc, char ***argv)
{
	/* Don't call this if we're in unit-test mode, as libfuzz.c does it */
	if (!tmpctx)
		common_setup("fuzzer");
	chainparams = chainparams_for_network("bitcoin");
	int devnull = open("/dev/null", O_WRONLY);
	status_setup_sync(devnull);
}

struct pending_htlc {
	enum side sender;
	u64 id;
	struct preimage preimage;
};

void run(const u8 *data, size_t size)
{
	struct pubkey local_per_commitment_point;
	struct bitcoin_outpoint funding;
	struct amount_sat funding_amount;
	struct channel *lchannel, *rchannel;
	const struct htlc **htlc_map;
	const u8 *funding_wscript_alt;
	int anchor;
	struct pending_htlc *pending_htlcs = tal_arr(tmpctx, struct pending_htlc, 0);
	u64 next_htlc_id = 0;
	u32 current_blockheight = fromwire_u32(&data, &size);

	init_channels(tmpctx, &data, &size, &local_per_commitment_point, &funding, &funding_amount,
		      &current_blockheight, &lchannel, &rchannel);

	if (!lchannel || !rchannel)
		goto cleanup;

	while (size > 0) {
		enum side commit_side = LOCAL;
		int op = fromwire_u8(&data, &size) % 7;
		switch (op) {
		case 0: /* ADD_HTLC */
		{
			if (tal_count(pending_htlcs) > MAX_HTLCS)
				break;

			enum side sender = (fromwire_u8(&data, &size) % 2) ? REMOTE : LOCAL;
			struct amount_msat msat = fromwire_amount_msat_bounded(&data, &size);
			u32 cltv = current_blockheight + fromwire_u16(&data, &size);
			struct pending_htlc p_htlc;

			p_htlc.sender = sender;
			p_htlc.id = next_htlc_id;
			memset(&p_htlc.preimage, (int)p_htlc.id, sizeof(p_htlc.preimage));

			if (add_htlc(lchannel, sender, p_htlc.id, &p_htlc.preimage, msat, cltv)) {
				add_htlc(rchannel, sender, p_htlc.id, &p_htlc.preimage, msat, cltv);
				tal_arr_expand(&pending_htlcs, p_htlc);
				next_htlc_id++;
			}
			commit_side = sender;
			break;
		}
		case 1: /* FULFILL_HTLC */
		{
			if (tal_count(pending_htlcs) == 0)
				break;

			size_t idx = fromwire_u64(&data, &size) % tal_count(pending_htlcs);
			struct pending_htlc p_htlc = pending_htlcs[idx];

			if (fromwire_u8(&data, &size) % 2) {
				if (fulfill_htlc(lchannel, p_htlc.sender, p_htlc.id, &p_htlc.preimage)) {
					fulfill_htlc(rchannel, p_htlc.sender, p_htlc.id, &p_htlc.preimage);
					tal_arr_remove(&pending_htlcs, idx);
				}
			} else {
				struct preimage preimage;
				fromwire_preimage(&data, &size, &preimage);

				fulfill_htlc(lchannel, fromwire_side(&data, &size),
							 fromwire_u64(&data, &size), &preimage);
				fulfill_htlc(rchannel, fromwire_side(&data, &size),
							 fromwire_u64(&data, &size), &preimage);
			}
			commit_side = !p_htlc.sender;
			break;
		}
		case 2: /* FAIL_HTLC */
		{
			if (tal_count(pending_htlcs) == 0)
				break;

			size_t idx = fromwire_u64(&data, &size) % tal_count(pending_htlcs);
			struct pending_htlc p_htlc = pending_htlcs[idx];

			if (fromwire_u8(&data, &size) % 2) {
				if (fail_htlc(lchannel, p_htlc.sender, p_htlc.id)) {
					fail_htlc(rchannel, p_htlc.sender, p_htlc.id);
					tal_arr_remove(&pending_htlcs, idx);
				}
			}
			else {
				fail_htlc(lchannel, fromwire_side(&data, &size), fromwire_u64(&data, &size));
				fail_htlc(rchannel, fromwire_side(&data, &size), fromwire_u64(&data, &size));
			}
			commit_side = !p_htlc.sender;
			break;
		}
		case 3: /* UPDATE_FEE */
		{
			u32 feerate = fromwire_bounded_feerate(&data, &size);
			if (update_feerate(lchannel, feerate))
				assert(update_feerate(rchannel, feerate));
			commit_side = rchannel->opener;
			break;
		}
		case 4: /* UPDATE_BLOCKHEIGHT */
		{
			current_blockheight = fromwire_u32(&data, &size);
			update_blockheight(lchannel, current_blockheight);
			update_blockheight(rchannel, current_blockheight);
			commit_side = rchannel->opener;
			break;
		}
		case 5: /* EXCHANGE_COMMITS */
		{
			const struct htlc **changed_htlcs = tal_arr(tmpctx, const struct htlc *, 0);
			exchange_commits(lchannel, commit_side, &changed_htlcs);
			exchange_commits(rchannel, commit_side, &changed_htlcs);
			break;
		}
		case 6: /* FUZZ_EXCHANGE_COMMITS */
		{
			const struct htlc **changed_htlcs = tal_arr(tmpctx, const struct htlc *, 0);
			fuzz_exchange_commits(lchannel, &changed_htlcs, &data, &size);
			fuzz_exchange_commits(rchannel, &changed_htlcs, &data, &size);
			break;
		}
		}

		/* Generate transactions to ensure no crashes from final state */
		channel_txs(tmpctx, &funding, funding_amount, &htlc_map, NULL, &funding_wscript_alt,
				lchannel, &local_per_commitment_point, 42, LOCAL, 0, 0, &anchor, NULL);
		channel_txs(tmpctx, &funding, funding_amount, &htlc_map, NULL, &funding_wscript_alt,
				rchannel, &local_per_commitment_point, 42, REMOTE, 0, 0, &anchor, NULL);
	}

cleanup:
	clean_tmpctx();
}
