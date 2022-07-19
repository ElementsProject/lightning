#ifndef LIGHTNING_PLUGINS_BKPR_CHANNELSAPY_H
#define LIGHTNING_PLUGINS_BKPR_CHANNELSAPY_H
#include "config.h"

#include <ccan/tal/tal.h>

struct channel_apy {
	char *acct_name;

	struct amount_msat routed_in;
	struct amount_msat routed_out;
	struct amount_msat fees_in;
	struct amount_msat fees_out;

	struct amount_msat push_in;
	struct amount_msat push_out;
	struct amount_msat lease_in;
	struct amount_msat lease_out;

	struct amount_msat our_start_bal;
	struct amount_msat total_start_bal;

	/* Blockheight the channel opened */
	u32 start_blockheight;

	/* If channel_close, the channel_close event's blockheight,
	 * otherwise the current blockheight */
	u32 end_blockheight;
};

struct channel_apy *new_channel_apy(const tal_t *ctx);

WARN_UNUSED_RESULT bool channel_apy_sum(struct channel_apy *sum_apy,
					const struct channel_apy *entry);

struct channel_apy **compute_channel_apys(const tal_t *ctx, struct db *db,
					  u64 start_time,
					  u64 end_time,
					  u32 current_blockheight);

void json_add_channel_apy(struct json_stream *res,
			  const struct channel_apy *apy);
#endif /* LIGHTNING_PLUGINS_BKPR_CHANNELSAPY_H */
