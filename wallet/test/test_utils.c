#include "config.h"
#include "test_utils.h"

/*
 * Copy of lightnind/options.c testnet_config
 * To reduce code duplication move testnet_config from options.c to options.h.
 */
const struct config test_config = {
	.locktime_blocks = 6,
	.locktime_max = 14 * 24 * 6,
	.anchor_confirms = 1,
	.commitment_fee_min_percent = 0,
	.commitment_fee_max_percent = 0,
	.cltv_expiry_delta = 6,
	.cltv_final = 10,
	.commit_time_ms = 10,
	.fee_base = 1,
	.fee_per_satoshi = 10,
	.broadcast_interval_msec = 60000,
	.channel_update_interval = 1209600/2,
	.ignore_fee_limits = true,
	.rescan = 30,
	.max_fee_multiplier = 10,
	.use_dns = true,
	.min_capacity_sat = 10000,
	.use_v3_autotor = true,
};
