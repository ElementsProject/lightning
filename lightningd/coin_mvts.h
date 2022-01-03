#ifndef LIGHTNING_LIGHTNINGD_COIN_MVTS_H
#define LIGHTNING_LIGHTNINGD_COIN_MVTS_H
#include "config.h"

#include <common/coin_mvt.h>

struct lightningd;

struct account_balance {
	const char *acct_id;
	const char *bip173_name;
	struct amount_msat balance;
};

struct balance_snapshot {
	struct node_id *node_id;
	u32 blockheight;
	u32 timestamp;

	struct account_balance **accts;
};

void notify_channel_mvt(struct lightningd *ld, const struct channel_coin_mvt *mvt);
void notify_chain_mvt(struct lightningd *ld, const struct chain_coin_mvt *mvt);

struct channel_coin_mvt *new_channel_mvt_invoice_hin(const tal_t *ctx,
						     struct htlc_in *hin,
						     struct channel *channel);
struct channel_coin_mvt *new_channel_mvt_routed_hin(const tal_t *ctx,
						    struct htlc_in *hin,
						    struct channel *channel);
struct channel_coin_mvt *new_channel_mvt_invoice_hout(const tal_t *ctx,
						      struct htlc_out *hout,
						      struct channel *channel);
struct channel_coin_mvt *new_channel_mvt_routed_hout(const tal_t *ctx,
						     struct htlc_out *hout,
						     struct channel *channel);

void send_account_balance_snapshot(struct lightningd *ld, u32 blockheight);
#endif /* LIGHTNING_LIGHTNINGD_COIN_MVTS_H */
