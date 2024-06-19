#include "config.h"

#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>
#include <common/blockheight_states.h>
#include <common/channel_type.h>
#include <common/fee_states.h>
#include <common/initial_channel.h>
#include <common/setup.h>
#include <common/status.h>
#include <common/utils.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tests/fuzz/libfuzz.h>
#include <wire/wire.h>

void init(int *argc, char ***argv)
{
	common_setup("fuzzer");
	int devnull = open("/dev/null", O_WRONLY);
	status_setup_sync(devnull);
	chainparams = chainparams_for_network("bitcoin");
}

void run(const uint8_t *data, size_t size)
{
	struct channel_id cid;
	struct bitcoin_outpoint funding;
	u32 minimum_depth;
	struct amount_sat funding_sats, max;
	struct amount_msat local_msatoshi;
	u32 feerate_per_kw, blockheight, lease_expiry;
	struct channel_config local, remote;
	struct basepoints local_basepoints, remote_basepoints;
	struct pubkey local_funding_pubkey, remote_funding_pubkey;
	bool option_anchor_outputs, wumbo;
	struct channel_type *channel_type;
	struct channel *channel;

	fromwire_channel_id(&data, &size, &cid);
	fromwire_bitcoin_outpoint(&data, &size, &funding);
	minimum_depth = fromwire_u32(&data, &size);
	funding_sats = fromwire_amount_sat(&data, &size);
	local_msatoshi = fromwire_amount_msat(&data, &size);
	max = AMOUNT_SAT((u32)WALLY_SATOSHI_PER_BTC * WALLY_BTC_MAX);
	if (amount_sat_greater(funding_sats, max))
		funding_sats = max;
	feerate_per_kw = fromwire_u32(&data, &size);
	blockheight = fromwire_u32(&data, &size);
	lease_expiry = fromwire_u32(&data, &size);
	fromwire_channel_config(&data, &size, &local);
	fromwire_channel_config(&data, &size, &remote);
	fromwire_basepoints(&data, &size, &local_basepoints);
	fromwire_basepoints(&data, &size, &remote_basepoints);
	fromwire_pubkey(&data, &size, &local_funding_pubkey);
	fromwire_pubkey(&data, &size, &remote_funding_pubkey);
	wumbo = fromwire_bool(&data, &size);
	option_anchor_outputs = fromwire_bool(&data, &size);

	if (option_anchor_outputs)
		channel_type = channel_type_anchors_zero_fee_htlc(tmpctx);
	else
		channel_type = channel_type_static_remotekey(tmpctx);

	/* TODO: determine if it makes sense to check at each step for libfuzzer
	 * to deduce pertinent inputs */
	if (!data || !size)
		return;

	for (enum side opener = 0; opener < NUM_SIDES; opener++) {
		channel = new_initial_channel(tmpctx, &cid, &funding,
					      minimum_depth,
					      take(new_height_states(NULL, opener,
								     &blockheight)),
					      lease_expiry,
					      funding_sats, local_msatoshi,
					      take(new_fee_states(NULL, opener,
								  &feerate_per_kw)),
					      &local, &remote,
					      &local_basepoints,
					      &remote_basepoints,
					      &local_funding_pubkey,
					      &remote_funding_pubkey,
					      channel_type,
					      wumbo, opener);

		/* TODO: make initial_channel_tx() work with ASAN.. */
		(void)channel;
	}

	clean_tmpctx();
}
