#include "config.h"
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <tests/fuzz/libfuzz.h>

#include <bitcoin/pubkey.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>
#include <common/fee_states.h>
#include <common/initial_channel.h>
#include <common/setup.h>
#include <common/status.h>
#include <common/utils.h>
#include <stdio.h>
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
	struct bitcoin_txid funding_txid;
	u32 funding_txout, minimum_depth;
	struct amount_sat funding, max;
	struct amount_msat local_msatoshi;
	u32 feerate_per_kw;
	struct channel_config local, remote;
	struct basepoints local_basepoints, remote_basepoints;
	struct pubkey local_funding_pubkey, remote_funding_pubkey;
	bool option_static_remotekey, option_anchor_outputs;
	struct channel *channel;

	fromwire_channel_id(&data, &size, &cid);
	fromwire_bitcoin_txid(&data, &size, &funding_txid);
	funding_txout = fromwire_u32(&data, &size);
	minimum_depth = fromwire_u32(&data, &size);
	funding = fromwire_amount_sat(&data, &size);
	local_msatoshi = fromwire_amount_msat(&data, &size);
	max = AMOUNT_SAT((u32)WALLY_SATOSHI_PER_BTC * WALLY_BTC_MAX);
	if (amount_sat_greater(funding, max))
		funding = max;
	feerate_per_kw = fromwire_u32(&data, &size);
	fromwire_channel_config(&data, &size, &local);
	fromwire_channel_config(&data, &size, &remote);
	fromwire_basepoints(&data, &size, &local_basepoints);
	fromwire_basepoints(&data, &size, &remote_basepoints);
	fromwire_pubkey(&data, &size, &local_funding_pubkey);
	fromwire_pubkey(&data, &size, &remote_funding_pubkey);
	option_anchor_outputs = fromwire_bool(&data, &size);
	option_static_remotekey = option_anchor_outputs || fromwire_bool(&data, &size);

	/* TODO: determine if it makes sense to check at each step for libfuzzer
	 * to deduce pertinent inputs */
	if (!data || !size)
		return;

	for (enum side opener = 0; opener < NUM_SIDES; opener++) {
		channel = new_initial_channel(tmpctx, &cid, &funding_txid, funding_txout,
					      minimum_depth, funding, local_msatoshi,
					      take(new_fee_states(NULL, opener, &feerate_per_kw)),
					      &local, &remote, &local_basepoints,
					      &remote_basepoints, &local_funding_pubkey,
					      &remote_funding_pubkey, option_static_remotekey,
					      option_anchor_outputs, opener);

		/* TODO: make initial_channel_tx() work with ASAN.. */
	}

	clean_tmpctx();
}
