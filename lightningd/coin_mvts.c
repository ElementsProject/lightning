#include <lightningd/coin_mvts.h>
#include <lightningd/notification.h>

void notify_channel_mvt(struct lightningd *ld, const struct channel_coin_mvt *mvt)
{
	const struct coin_mvt *cm;
	u32 timestamp;

	timestamp = time_now().ts.tv_sec;
	cm = finalize_channel_mvt(mvt, mvt, timestamp,
				  get_block_height(ld->topology),
				  &ld->id);
	notify_coin_mvt(ld, cm);
}

void notify_chain_mvt(struct lightningd *ld, const struct chain_coin_mvt *mvt)
{
	const struct coin_mvt *cm;
	u32 timestamp;

	timestamp = time_now().ts.tv_sec;
	cm = finalize_chain_mvt(mvt, mvt, timestamp,
				get_block_height(ld->topology),
				&ld->id);
	notify_coin_mvt(ld, cm);
}
