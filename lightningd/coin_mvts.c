#include "config.h"
#include <lightningd/channel.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/notification.h>

void notify_channel_mvt(struct lightningd *ld, const struct channel_coin_mvt *mvt)
{
	const struct coin_mvt *cm;
	u32 timestamp;

	timestamp = time_now().ts.tv_sec;
	cm = finalize_channel_mvt(mvt, mvt, chainparams->lightning_hrp,
				  timestamp, &ld->id);

	notify_coin_mvt(ld, cm);
}

void notify_chain_mvt(struct lightningd *ld, const struct chain_coin_mvt *mvt)
{
	const struct coin_mvt *cm;
	u32 timestamp;

	timestamp = time_now().ts.tv_sec;
	cm = finalize_chain_mvt(mvt, mvt, chainparams->onchain_hrp,
				timestamp, &ld->id);
	notify_coin_mvt(ld, cm);
}

struct channel_coin_mvt *new_channel_mvt_invoice_hin(const tal_t *ctx,
						     struct htlc_in *hin,
						     struct channel *channel)
{
	return new_channel_coin_mvt(ctx, &channel->cid,
				    hin->payment_hash, NULL,
				    hin->msat, INVOICE,
				    true);
}

struct channel_coin_mvt *new_channel_mvt_routed_hin(const tal_t *ctx,
						    struct htlc_in *hin,
						    struct channel *channel)
{
	return new_channel_coin_mvt(ctx, &channel->cid,
				    hin->payment_hash, NULL,
				    hin->msat, ROUTED,
				    true);
}

struct channel_coin_mvt *new_channel_mvt_invoice_hout(const tal_t *ctx,
						      struct htlc_out *hout,
						      struct channel *channel)
{
	return new_channel_coin_mvt(ctx, &channel->cid,
				    hout->payment_hash, &hout->partid,
				    hout->msat, INVOICE,
				    false);
}

struct channel_coin_mvt *new_channel_mvt_routed_hout(const tal_t *ctx,
						     struct htlc_out *hout,
						     struct channel *channel)
{
	return new_channel_coin_mvt(ctx, &channel->cid,
				    hout->payment_hash, NULL,
				    hout->msat, ROUTED,
				    false);
}
