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

struct channel_coin_mvt *new_channel_mvt_invoice_hin(const tal_t *ctx,
						     const struct htlc_in *hin,
						     const struct channel *channel);
struct channel_coin_mvt *new_channel_mvt_routed_hin(const tal_t *ctx,
						    const struct htlc_in *hin,
						    const struct channel *channel);
struct channel_coin_mvt *new_channel_mvt_invoice_hout(const tal_t *ctx,
						      const struct htlc_out *hout,
						      const struct channel *channel);
struct channel_coin_mvt *new_channel_mvt_routed_hout(const tal_t *ctx,
						     const struct htlc_out *hout,
						     const struct channel *channel);
struct channel_coin_mvt *new_channel_mvt_penalty_adj(const tal_t *ctx,
						     const struct channel *channel,
						     struct amount_msat amount,
						     enum coin_mvt_dir direction);

void send_account_balance_snapshot(struct lightningd *ld);

/* Shared by listcoinmoves and notifications code */
void json_add_chain_mvt_fields(struct json_stream *stream,
			       bool include_tags_arr,
			       bool include_old_utxo_fields,
			       bool include_old_txid_field,
			       const struct chain_coin_mvt *chain_mvt);
void json_add_channel_mvt_fields(struct json_stream *stream,
				 bool include_tags_arr,
				 const struct channel_coin_mvt *chan_mvt,
				 bool extra_tags_field);
#endif /* LIGHTNING_LIGHTNINGD_COIN_MVTS_H */
