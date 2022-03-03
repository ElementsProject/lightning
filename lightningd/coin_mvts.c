#include "config.h"
#include <ccan/array_size/array_size.h>
#include <common/onion.h>
#include <common/type_to_string.h>
#include <lightningd/channel.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/notification.h>
#include <lightningd/peer_control.h>


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
				    &hin->payment_hash, NULL,
				    hin->msat, new_tag_arr(ctx, INVOICE),
				    true, AMOUNT_MSAT(0));
}

struct channel_coin_mvt *new_channel_mvt_routed_hin(const tal_t *ctx,
						    struct htlc_in *hin,
						    struct channel *channel)
{
	struct amount_msat fees_collected;

	if (!hin->payload)
		return NULL;

	if (!amount_msat_sub(&fees_collected, hin->msat,
			     hin->payload->amt_to_forward))
		return NULL;

	return new_channel_coin_mvt(ctx, &channel->cid,
				    &hin->payment_hash, NULL,
				    hin->msat, new_tag_arr(ctx, ROUTED),
				    true, fees_collected);
}

struct channel_coin_mvt *new_channel_mvt_invoice_hout(const tal_t *ctx,
						      struct htlc_out *hout,
						      struct channel *channel)
{
	return new_channel_coin_mvt(ctx, &channel->cid,
				    &hout->payment_hash, &hout->partid,
				    hout->msat, new_tag_arr(ctx, INVOICE),
				    false, hout->fees);
}

struct channel_coin_mvt *new_channel_mvt_routed_hout(const tal_t *ctx,
						     struct htlc_out *hout,
						     struct channel *channel)
{
	return new_channel_coin_mvt(ctx, &channel->cid,
				    &hout->payment_hash, NULL,
				    hout->msat, new_tag_arr(ctx, ROUTED),
				    false,
				    hout->fees);
}

void send_account_balance_snapshot(struct lightningd *ld, u32 blockheight)
{
	struct balance_snapshot *snap = tal(NULL, struct balance_snapshot);
	struct account_balance *bal;
	struct utxo **utxos;
	struct channel *chan;
	struct peer *p;
	/* Available + reserved utxos are A+, as reserved things have not yet
	 * been spent */
	enum output_status utxo_states[] = {OUTPUT_STATE_AVAILABLE,
					    OUTPUT_STATE_RESERVED};

	snap->blockheight = blockheight;
	snap->timestamp = time_now().ts.tv_sec;
	snap->node_id = &ld->id;

	/* Add the 'wallet' account balance */
	snap->accts = tal_arr(snap, struct account_balance *, 1);
	bal = tal(snap, struct account_balance);
	bal->balance = AMOUNT_MSAT(0);
	bal->acct_id = WALLET;
	bal->bip173_name = chainparams->lightning_hrp;

	for (size_t i = 0; i < ARRAY_SIZE(utxo_states); i++) {
		utxos = wallet_get_utxos(NULL, ld->wallet, utxo_states[i]);
		for (size_t j = 0; j < tal_count(utxos); j++) {
			/* Don't count unconfirmed utxos! */
			if (!utxos[j]->spendheight && !utxos[j]->blockheight)
				continue;
			if (!amount_msat_add_sat(&bal->balance,
						 bal->balance, utxos[j]->amount))
				fatal("Overflow adding node balance");
		}
		tal_free(utxos);
	}
	snap->accts[0] = bal;

	/* Add channel balances */
	list_for_each(&ld->peers, p, list) {
		list_for_each(&p->channels, chan, list) {
			if (channel_active(chan)) {
				bal = tal(snap, struct account_balance);
				bal->bip173_name = chainparams->lightning_hrp;
				bal->acct_id = type_to_string(bal,
							   struct channel_id,
							   &chan->cid);
				bal->balance = chan->our_msat;
				tal_arr_expand(&snap->accts, bal);
			}
		}
	}

	notify_balance_snapshot(ld, snap);
	tal_free(snap);
}
