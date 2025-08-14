#include "config.h"
#include <ccan/array_size/array_size.h>
#include <lightningd/channel.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/notification.h>
#include <lightningd/peer_control.h>


struct channel_coin_mvt *new_channel_mvt_invoice_hin(const tal_t *ctx,
						     const struct htlc_in *hin,
						     const struct channel *channel)
{
	return new_channel_coin_mvt(ctx, channel, time_now().ts.tv_sec,
				    &hin->payment_hash, NULL, NULL,
				    COIN_CREDIT, hin->msat,
				    mk_mvt_tags(MVT_INVOICE),
				    AMOUNT_MSAT(0));
}

struct channel_coin_mvt *new_channel_mvt_routed_hin(const tal_t *ctx,
						    const struct htlc_in *hin,
						    const struct channel *channel)
{
	struct amount_msat fees_collected;

	if (!hin->payload)
		return NULL;

	if (!amount_msat_sub(&fees_collected, hin->msat,
			     hin->payload->amt_to_forward))
		return NULL;

	return new_channel_coin_mvt(ctx, channel, time_now().ts.tv_sec,
				    &hin->payment_hash, NULL, NULL,
				    COIN_CREDIT, hin->msat,
				    mk_mvt_tags(MVT_ROUTED),
				    fees_collected);
}

struct channel_coin_mvt *new_channel_mvt_invoice_hout(const tal_t *ctx,
						      const struct htlc_out *hout,
						      const struct channel *channel)
{
	return new_channel_coin_mvt(ctx, channel, time_now().ts.tv_sec,
				    &hout->payment_hash,
				    &hout->partid,
				    &hout->groupid,
				    COIN_DEBIT, hout->msat,
				    mk_mvt_tags(MVT_INVOICE),
				    hout->fees);
}

struct channel_coin_mvt *new_channel_mvt_routed_hout(const tal_t *ctx,
						     const struct htlc_out *hout,
						     const struct channel *channel)
{
	return new_channel_coin_mvt(ctx, channel, time_now().ts.tv_sec,
				    &hout->payment_hash, NULL, NULL,
				    COIN_DEBIT, hout->msat,
				    mk_mvt_tags(MVT_ROUTED),
				    hout->fees);
}

struct channel_coin_mvt *new_channel_mvt_penalty_adj(const tal_t *ctx,
						     const struct channel *channel,
						     struct amount_msat amount,
						     enum coin_mvt_dir direction)
{
	return new_channel_coin_mvt(ctx, channel, time_now().ts.tv_sec,
				    NULL, NULL, NULL,
				    direction, amount,
				    mk_mvt_tags(MVT_PENALTY_ADJ),
				    AMOUNT_MSAT(0));
}

static bool report_chan_balance(const struct channel *chan)
{
	switch (chan->state) {
	case CHANNELD_AWAITING_LOCKIN:
	case DUALOPEND_OPEN_INIT:
	case DUALOPEND_OPEN_COMMIT_READY:
	case DUALOPEND_OPEN_COMMITTED:
	case DUALOPEND_AWAITING_LOCKIN:
	case CLOSINGD_COMPLETE:
	case AWAITING_UNILATERAL:
	case ONCHAIN:
	case CLOSED:
		return false;

	case CHANNELD_NORMAL:
	case CHANNELD_AWAITING_SPLICE:
	case CHANNELD_SHUTTING_DOWN:
	case CLOSINGD_SIGEXCHANGE:
	case FUNDING_SPEND_SEEN:
		return true;
	}
	abort();
}

void send_account_balance_snapshot(struct lightningd *ld)
{
	struct balance_snapshot *snap = tal(NULL, struct balance_snapshot);
	struct account_balance *bal;
	struct utxo **utxos;
	struct channel *chan;
	struct peer *p;
	struct peer_node_id_map_iter it;

	snap->blockheight = get_block_height(ld->topology);
	snap->timestamp = time_now().ts.tv_sec;
	snap->node_id = &ld->our_nodeid;

	/* Add the 'wallet' account balance */
	snap->accts = tal_arr(snap, struct account_balance *, 1);
	bal = tal(snap, struct account_balance);
	bal->balance = AMOUNT_MSAT(0);
	bal->acct_id = ACCOUNT_NAME_WALLET;
	bal->bip173_name = chainparams->lightning_hrp;

	utxos = wallet_get_unspent_utxos(NULL, ld->wallet);
	for (size_t j = 0; j < tal_count(utxos); j++) {
		/* Don't count unconfirmed utxos! */
		if (!utxos[j]->spendheight && !utxos[j]->blockheight)
			continue;
		if (!amount_msat_add_sat(&bal->balance,
					 bal->balance, utxos[j]->amount))
			fatal("Overflow adding node balance");
	}
	tal_free(utxos);

	snap->accts[0] = bal;

	/* Add channel balances */
	for (p = peer_node_id_map_first(ld->peers, &it);
	     p;
	     p = peer_node_id_map_next(ld->peers, &it)) {
		list_for_each(&p->channels, chan, list) {
			if (report_chan_balance(chan)) {
				bal = tal(snap, struct account_balance);
				bal->bip173_name = chainparams->lightning_hrp;
				bal->acct_id = fmt_channel_id(bal, &chan->cid);
				bal->balance = chan->our_msat;
				tal_arr_expand(&snap->accts, bal);
			}
		}
	}

	notify_balance_snapshot(ld, snap);
	tal_free(snap);
}

static void add_movement_tags(struct json_stream *stream,
			      bool include_tags_arr,
			      const struct mvt_tags tags,
			      bool extra_tags_field)
{
	const char **tagstrs = mvt_tag_strs(tmpctx, tags);

	if (include_tags_arr) {
		json_array_start(stream, "tags");
		for (size_t i = 0; i < tal_count(tagstrs); i++)
			json_add_string(stream, NULL, tagstrs[i]);
		json_array_end(stream);
	}

	json_add_string(stream, "primary_tag", tagstrs[0]);
	if (extra_tags_field) {
		json_array_start(stream, "extra_tags");
		for (size_t i = 1; i < tal_count(tagstrs); i++)
			json_add_string(stream, NULL, tagstrs[i]);
		json_array_end(stream);
	} else {
		assert(tal_count(tagstrs) == 1);
	}
}

static void json_add_mvt_account_id(struct json_stream *stream,
				    const char *fieldname,
				    const struct mvt_account_id *account_id)
{
	if (account_id->channel)
		json_add_channel_id(stream, fieldname, &account_id->channel->cid);
	else
		json_add_string(stream, fieldname, account_id->alt_account);
}

void json_add_chain_mvt_fields(struct json_stream *stream,
			       bool include_tags_arr,
			       bool include_old_utxo_fields,
			       bool include_old_txid_field,
			       const struct chain_coin_mvt *chain_mvt)
{
	if (chain_mvt->peer_id)
		json_add_node_id(stream, "peer_id", chain_mvt->peer_id);
	json_add_mvt_account_id(stream, "account_id", &chain_mvt->account);

	if (chain_mvt->originating_acct)
		json_add_mvt_account_id(stream, "originating_account", chain_mvt->originating_acct);

	if (chain_mvt->spending_txid) {
		if (include_old_txid_field)
			json_add_txid(stream, "txid",
				      chain_mvt->spending_txid);
		json_add_txid(stream, "spending_txid", chain_mvt->spending_txid);
	}

	if (include_old_utxo_fields) {
		json_add_string(stream, "utxo_txid",
				fmt_bitcoin_txid(tmpctx,
						 &chain_mvt->outpoint.txid));
		json_add_u32(stream, "vout", chain_mvt->outpoint.n);
	}
	json_add_outpoint(stream, "utxo", &chain_mvt->outpoint);

	/* on-chain htlcs include a payment hash */
	if (chain_mvt->payment_hash)
		json_add_sha256(stream, "payment_hash", chain_mvt->payment_hash);
	json_add_amount_msat(stream, "credit_msat", chain_mvt->credit);
	json_add_amount_msat(stream, "debit_msat", chain_mvt->debit);

	json_add_amount_sat_msat(stream,
				 "output_msat", chain_mvt->output_val);
	if (chain_mvt->output_count > 0)
		json_add_num(stream, "output_count", chain_mvt->output_count);

	add_movement_tags(stream, include_tags_arr, chain_mvt->tags, true);
	json_add_u32(stream, "blockheight", chain_mvt->blockheight);
	json_add_u64(stream, "timestamp", chain_mvt->timestamp);
}

void json_add_channel_mvt_fields(struct json_stream *stream,
				 bool include_tags_arr,
				 const struct channel_coin_mvt *chan_mvt,
				 bool extra_tags_field)
{
	json_add_mvt_account_id(stream, "account_id", &chan_mvt->account);
	/* push funding / leases don't have a payment_hash */
	if (chan_mvt->payment_hash)
		json_add_sha256(stream, "payment_hash", chan_mvt->payment_hash);
	if (chan_mvt->part_and_group) {
		json_add_u64(stream, "part_id", chan_mvt->part_and_group->part_id);
		json_add_u64(stream, "group_id", chan_mvt->part_and_group->group_id);
	}
	json_add_amount_msat(stream, "credit_msat", chan_mvt->credit);
	json_add_amount_msat(stream, "debit_msat", chan_mvt->debit);
	json_add_amount_msat(stream, "fees_msat", chan_mvt->fees);

	add_movement_tags(stream, include_tags_arr, chan_mvt->tags, extra_tags_field);
	json_add_u64(stream, "timestamp", chan_mvt->timestamp);
}
