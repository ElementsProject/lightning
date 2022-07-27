#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/coin_mvt.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/type_to_string.h>
#include <db/exec.h>
#include <plugins/bkpr/account.h>
#include <plugins/bkpr/account_entry.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/channel_event.h>
#include <plugins/bkpr/db.h>
#include <plugins/bkpr/onchain_fee.h>
#include <plugins/bkpr/recorder.h>
#include <plugins/libplugin.h>

#define CHAIN_MOVE "chain_mvt"
#define CHANNEL_MOVE "channel_mvt"

/* The database that we store all the accounting data in */
static struct db *db ;

// FIXME: make relative to directory we're loaded into
static char *db_dsn = "sqlite3://accounts.sqlite3";

static void json_add_channel_event(struct json_stream *out,
				   struct channel_event *ev)
{
	json_object_start(out, NULL);
	json_add_string(out, "account", ev->acct_name);
	json_add_string(out, "type", "channel");
	json_add_string(out, "tag", ev->tag);
	json_add_amount_msat_only(out, "credit", ev->credit);
	json_add_amount_msat_only(out, "debit", ev->debit);
	json_add_string(out, "currency", ev->currency);
	if (ev->payment_id)
		json_add_sha256(out, "payment_id", ev->payment_id);
	json_add_u64(out, "timestamp", ev->timestamp);
	json_object_end(out);
}

static void json_add_chain_event(struct json_stream *out,
				 struct chain_event *ev)
{
	json_object_start(out, NULL);
	json_add_string(out, "account", ev->acct_name);
	json_add_string(out, "type", "chain");
	json_add_string(out, "tag", ev->tag);
	json_add_amount_msat_only(out, "credit", ev->credit);
	json_add_amount_msat_only(out, "debit", ev->debit);
	json_add_string(out, "currency", ev->currency);
	json_add_outpoint(out, "outpoint", &ev->outpoint);
	if (ev->spending_txid)
		json_add_txid(out, "txid", ev->spending_txid);
	if (ev->payment_id)
		json_add_sha256(out, "payment_id", ev->payment_id);
	json_add_u64(out, "timestamp", ev->timestamp);
	json_add_u32(out, "blockheight", ev->blockheight);
	json_object_end(out);
}

static void json_add_onchain_fee(struct json_stream *out,
				 struct onchain_fee *fee)
{
	json_object_start(out, NULL);
	json_add_string(out, "account", fee->acct_name);
	json_add_string(out, "type", "onchain_fee");
	json_add_string(out, "tag", "onchain_fee");
	json_add_amount_msat_only(out, "credit", fee->credit);
	json_add_amount_msat_only(out, "debit", fee->debit);
	json_add_string(out, "currency", fee->currency);
	json_add_u64(out, "timestamp", fee->timestamp);
	json_add_txid(out, "txid", &fee->txid);
	json_object_end(out);
}

static struct fee_sum *find_sum_for_txid(struct fee_sum **sums,
					 struct bitcoin_txid *txid)
{
	for (size_t i = 0; i < tal_count(sums); i++) {
		if (bitcoin_txid_eq(txid, sums[i]->txid))
			return sums[i];
	}
	return NULL;
}

static struct command_result *json_inspect(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *params)
{
	struct json_stream *res;
	struct account *acct;
	const char *acct_name;
	struct fee_sum **fee_sums;
	struct txo_set **txos;

	/* Only available for channel accounts? */
	if (!param(cmd, buf, params,
		   p_opt("account", param_string, &acct_name),
		   NULL))
		return command_param_failed();

	if (!acct_name)
		return command_fail(cmd, PLUGIN_ERROR,
				    "Account not provided");

	if (streq(acct_name, WALLET_ACCT)
	    || streq(acct_name, EXTERNAL_ACCT))
		return command_fail(cmd, PLUGIN_ERROR,
				    "`inspect` not supported for"
				    " non-channel accounts");

	db_begin_transaction(db);
	acct = find_account(cmd, db, acct_name);
	db_commit_transaction(db);

	if (!acct)
		return command_fail(cmd, PLUGIN_ERROR,
				    "Account %s not found",
				    acct_name);

	db_begin_transaction(db);
	find_txo_chain(cmd, db, acct, &txos);
	fee_sums = find_account_onchain_fees(cmd, db, acct);
	db_commit_transaction(db);

	res = jsonrpc_stream_success(cmd);
	json_array_start(res, "txs");
	for (size_t i = 0; i < tal_count(txos); i++) {
		struct txo_set *set = txos[i];
		struct fee_sum *fee_sum;

		json_object_start(res, NULL);
		json_add_txid(res, "txid", set->txid);

		/* annoyting, but we can only add the block height
		 * if we have a txo for it */
		for (size_t j = 0; j < tal_count(set->pairs); j++) {
			if (set->pairs[j]->txo
			    && set->pairs[j]->txo->blockheight > 0) {
				json_add_num(res, "blockheight",
				     set->pairs[j]->txo->blockheight);
				break;
			}
		}

		fee_sum = find_sum_for_txid(fee_sums, set->txid);
		if (fee_sum)
			json_add_amount_msat_only(res, "fees_paid",
						  fee_sum->fees_paid);
		else
			json_add_amount_msat_only(res, "fees_paid",
						  AMOUNT_MSAT(0));

		json_array_start(res, "outputs");
		for (size_t j = 0; j < tal_count(set->pairs); j++) {
			struct txo_pair *pr = set->pairs[j];

			/* Is this an event that belongs to this account? */
			if (pr->txo) {
				if (pr->txo->origin_acct) {
					if (!streq(pr->txo->origin_acct, acct->name))
						continue;
				} else if (pr->txo->acct_db_id != acct->db_id
					   /* We make an exception for wallet events */
					   && !streq(pr->txo->acct_name, WALLET_ACCT))
					continue;
			} else if (pr->spend
				   && pr->spend->acct_db_id != acct->db_id)
				continue;

			json_object_start(res, NULL);
			if (set->pairs[j]->txo) {
				struct chain_event *ev = set->pairs[j]->txo;

				json_add_string(res, "account", ev->acct_name);
				json_add_num(res, "outnum",
					     ev->outpoint.n);
				json_add_string(res, "output_tag", ev->tag);
				json_add_amount_msat_only(res, "output_value",
							  ev->output_value);
				json_add_amount_msat_only(res, "credit",
							  ev->credit);
				json_add_string(res, "currency", ev->currency);
				if (ev->origin_acct)
					json_add_string(res, "originating_account",
							ev->origin_acct);
			}
			if (set->pairs[j]->spend) {
				struct chain_event *ev = set->pairs[j]->spend;
				/* If we didn't already populate this info */
				if (!set->pairs[j]->txo) {
					json_add_string(res, "account",
							ev->acct_name);
					json_add_num(res, "outnum",
						     ev->outpoint.n);
					json_add_amount_msat_only(res, "output_value",
								  ev->output_value);
					json_add_string(res, "currency",
							ev->currency);
				}
				json_add_string(res, "spend_tag", ev->tag);
				json_add_txid(res, "spending_txid",
					      ev->spending_txid);
				json_add_amount_msat_only(res, "debit", ev->debit);
				if (ev->payment_id)
					json_add_sha256(res, "payment_id",
							ev->payment_id);
			}
			json_object_end(res);
		}
		json_array_end(res);
		json_object_end(res);
	}
	json_array_end(res);

	return command_finished(cmd, res);
}

/* Find all the events for this account, ordered by timestamp */
static struct command_result *json_list_account_events(struct command *cmd,
						       const char *buf,
						       const jsmntok_t *params)
{
	struct json_stream *res;
	struct account *acct;
	const char *acct_name;
	struct channel_event **channel_events;
	struct chain_event **chain_events;
	struct onchain_fee **onchain_fees;

	if (!param(cmd, buf, params,
		   p_opt("account", param_string, &acct_name),
		   NULL))
		return command_param_failed();

	if (acct_name) {
		db_begin_transaction(db);
		acct = find_account(cmd, db, acct_name);
		db_commit_transaction(db);

		if (!acct)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Account '%s' not found",
					    acct_name);
	} else
		acct = NULL;

	db_begin_transaction(db);
	if (acct) {
		channel_events = account_get_channel_events(cmd, db, acct);
		chain_events = account_get_chain_events(cmd, db, acct);
		onchain_fees = account_get_chain_fees(cmd, db, acct);
	} else {
		channel_events = list_channel_events(cmd, db);
		chain_events = list_chain_events(cmd, db);
		onchain_fees = list_chain_fees(cmd, db);
	}
	db_commit_transaction(db);

	res = jsonrpc_stream_success(cmd);
	json_array_start(res, "events");
	for (size_t i = 0, j = 0, k = 0;
	     i < tal_count(chain_events)
	     || j < tal_count(channel_events)
	     || k < tal_count(onchain_fees);
	     /* Incrementing happens inside loop */) {
		struct channel_event *chan;
		struct chain_event *chain;
		struct onchain_fee *fee;
		u64 lowest = 0;

		if (i < tal_count(chain_events))
			chain = chain_events[i];
		else
			chain = NULL;
		if (j < tal_count(channel_events))
			chan = channel_events[j];
		else
			chan = NULL;
		if (k < tal_count(onchain_fees))
			fee = onchain_fees[k];
		else
			fee = NULL;

		if (chain)
			lowest = chain->timestamp;

		if (chan
		    && (lowest == 0 || lowest > chan->timestamp))
			lowest = chan->timestamp;

		if (fee
		    && (lowest == 0 || lowest > fee->timestamp))
			lowest = fee->timestamp;

		/* chain events first, then channel events, then fees. */
		if (chain && chain->timestamp == lowest) {
			json_add_chain_event(res, chain);
			i++;
			continue;
		}

		if (chan && chan->timestamp == lowest) {
			json_add_channel_event(res, chan);
			j++;
			continue;
		}

		/* Last thing left is the fee */
		json_add_onchain_fee(res, fee);
		k++;
	}
	json_array_end(res);
	return command_finished(cmd, res);
}

static struct command_result *json_list_balances(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	struct json_stream *res;
	struct account **accts;
	char *err;

	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	res = jsonrpc_stream_success(cmd);
	/* List of accts */
	db_begin_transaction(db);
	accts = list_accounts(cmd, db);

	json_array_start(res, "accounts");
	for (size_t i = 0; i < tal_count(accts); i++) {
		struct acct_balance **balances;

		err = account_get_balance(cmd, db,
					  accts[i]->name,
					  true,
					  &balances);

		if (err)
			plugin_err(cmd->plugin,
				   "Get account balance returned err"
				   " for account %s: %s",
				   accts[i]->name, err);

		/* Skip the external acct balance, it's effectively
		 * meaningless */
		if (streq(accts[i]->name, EXTERNAL_ACCT))
			continue;

		/* Add it to the result data */
		json_object_start(res, NULL);

		json_add_string(res, "account", accts[i]->name);
		json_array_start(res, "balances");
		for (size_t j = 0; j < tal_count(balances); j++) {
			json_object_start(res, NULL);
			json_add_amount_msat_only(res, "balance",
						  balances[j]->balance);
			json_add_string(res, "coin_type",
					balances[j]->currency);
			json_object_end(res);
		}
		json_array_end(res);

		json_object_end(res);
	}
	json_array_end(res);
	db_commit_transaction(db);

	return command_finished(cmd, res);
}

struct new_account_info {
	struct account *acct;
	struct amount_msat curr_bal;
	u32 timestamp;
	char *currency;
};

static void try_update_open_fees(struct command *cmd,
				 struct account *acct)
{
	struct chain_event *ev;
	char *err;

	assert(acct->closed_event_db_id);
	ev = find_chain_event_by_id(cmd, db, *acct->closed_event_db_id);
	assert(ev);

	err = maybe_update_onchain_fees(cmd, db, ev->spending_txid);
	if (err)
		plugin_err(cmd->plugin,
			   "failure updating chain fees:"
			   " %s", err);

}

static bool new_missed_channel_account(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *result,
				       struct account *acct,
				       const char *currency,
				       u64 timestamp)
{
	struct chain_event *chain_ev;
	size_t i, j;
	const jsmntok_t *curr_peer, *curr_chan,
	      *peer_arr_tok, *chan_arr_tok;

	peer_arr_tok = json_get_member(buf, result, "peers");
	assert(peer_arr_tok->type == JSMN_ARRAY);
	/* There should only be one peer */
	json_for_each_arr(i, curr_peer, peer_arr_tok) {
		chan_arr_tok = json_get_member(buf, curr_peer,
					       "channels");
		assert(chan_arr_tok->type == JSMN_ARRAY);
		json_for_each_arr(j, curr_chan, chan_arr_tok) {
			struct bitcoin_outpoint opt;
			struct amount_msat amt, remote_amt, push_amt,
					   push_credit, push_debit;
			char *opener, *chan_id;
			const char *err;
			enum mvt_tag *tags;
			bool ok;

			err = json_scan(tmpctx, buf, curr_chan,
					"{channel_id:%,"
					"funding_txid:%,"
					"funding_outnum:%,"
					"funding:{local_msat:%,"
						 "remote_msat:%,"
						 "pushed_msat:%},"
					"opener:%}",
					JSON_SCAN_TAL(tmpctx, json_strdup, &chan_id),
					JSON_SCAN(json_to_txid, &opt.txid),
					JSON_SCAN(json_to_number, &opt.n),
					JSON_SCAN(json_to_msat, &amt),
					JSON_SCAN(json_to_msat, &remote_amt),
					JSON_SCAN(json_to_msat, &push_amt),
					JSON_SCAN_TAL(tmpctx, json_strdup, &opener));
			if (err)
				plugin_err(cmd->plugin,
					   "failure scanning listpeer"
					   " result: %s", err);

			if (!streq(chan_id, acct->name))
				continue;

			chain_ev = tal(cmd, struct chain_event);
			chain_ev->tag = mvt_tag_str(CHANNEL_OPEN);
			chain_ev->debit = AMOUNT_MSAT(0);
			ok = amount_msat_add(&chain_ev->output_value, amt, remote_amt);
			assert(ok);
			chain_ev->currency = tal_strdup(chain_ev, currency);
			chain_ev->origin_acct = NULL;
			/* 2s before the channel opened, minimum */
			chain_ev->timestamp = timestamp - 2;
			chain_ev->blockheight = 0;
			chain_ev->outpoint = opt;
			chain_ev->spending_txid = NULL;
			chain_ev->payment_id = NULL;

			/* Update the account info too */
			tags = tal_arr(chain_ev, enum mvt_tag, 1);
			tags[0] = CHANNEL_OPEN;

			/* Leased/pushed channels have some extra work */
			if (streq(opener, "local")) {
				tal_arr_expand(&tags, OPENER);
				ok = amount_msat_add(&amt, amt, push_amt);
				push_credit = AMOUNT_MSAT(0);
				push_debit = push_amt;
			} else {
				ok = amount_msat_sub(&amt, amt, push_amt);
				push_credit = push_amt;
				push_debit = AMOUNT_MSAT(0);
			}

			/* We assume pushes are all leases, even
			 * though they might just be pushes */
			if (!amount_msat_zero(push_amt))
				tal_arr_expand(&tags, LEASED);

			assert(ok);
			chain_ev->credit = amt;
			db_begin_transaction(db);
			log_chain_event(db, acct, chain_ev);
			maybe_update_account(db, acct, chain_ev, tags, 0);
			maybe_update_onchain_fees(cmd, db, &opt.txid);

			/* We won't count the close's fees if we're
			 * *not* the opener, which we didn't know
			 * until now, so now try to update the
			 * fees for the close tx's spending_txid..*/
			if (acct->closed_event_db_id)
				try_update_open_fees(cmd, acct);

			/* We log a channel event for the push amt */
			if (!amount_msat_zero(push_amt)) {
				struct channel_event *chan_ev;
				char *chan_tag;

				chan_tag = tal_fmt(tmpctx, "%s",
						   mvt_tag_str(LEASE_FEE));

				chan_ev = new_channel_event(tmpctx,
							    chan_tag,
							    push_credit,
							    push_debit,
							    AMOUNT_MSAT(0),
							    currency,
							    NULL, 0,
							    timestamp - 1);
				log_channel_event(db, acct, chan_ev);
			}

			db_commit_transaction(db);
			return true;
		}
	}

	return false;
}

/* Net out credit/debit --> basically find the diff */
static char *msat_net(const tal_t *ctx,
		      struct amount_msat credit,
		      struct amount_msat debit,
		      struct amount_msat *credit_net,
		      struct amount_msat *debit_net)
{
	if (amount_msat_eq(credit, debit)) {
		*credit_net = AMOUNT_MSAT(0);
		*debit_net = AMOUNT_MSAT(0);
	} else if (amount_msat_greater(credit, debit)) {
		if (!amount_msat_sub(credit_net, credit, debit))
			return tal_fmt(ctx, "unexpected fail, can't sub."
				       " %s - %s",
				       type_to_string(ctx, struct amount_msat,
						      &credit),
				       type_to_string(ctx, struct amount_msat,
						      &debit));
		*debit_net = AMOUNT_MSAT(0);
	} else {
		if (!amount_msat_sub(debit_net, debit, credit)) {
			return tal_fmt(ctx, "unexpected fail, can't sub."
				       " %s - %s",
				       type_to_string(ctx,
					       struct amount_msat,
					       &debit),
				       type_to_string(ctx,
					       struct amount_msat,
					       &credit));
		}
		*credit_net = AMOUNT_MSAT(0);
	}

	return NULL;
}

static char *msat_find_diff(struct amount_msat balance,
			    struct amount_msat credits,
			    struct amount_msat debits,
			    struct amount_msat *credit_diff,
			    struct amount_msat *debit_diff)
{
	struct amount_msat net_credit, net_debit;
	char *err;

	err = msat_net(tmpctx, credits, debits,
		       &net_credit, &net_debit);
	if (err)
		return err;

	/* If we're not missing events, debits == 0 */
	if (!amount_msat_zero(net_debit)) {
		assert(amount_msat_zero(net_credit));
		if (!amount_msat_add(credit_diff, net_debit, balance))
			return "Overflow finding credit_diff";
		*debit_diff = AMOUNT_MSAT(0);
	} else {
		assert(amount_msat_zero(net_debit));
		if (amount_msat_greater(net_credit, balance)) {
			if (!amount_msat_sub(debit_diff, net_credit,
					    balance))
				return "Err net_credit - amt";
			*credit_diff = AMOUNT_MSAT(0);
		} else {
			if (!amount_msat_sub(credit_diff, balance,
					     net_credit))
				return "Err amt - net_credit";

			*debit_diff = AMOUNT_MSAT(0);
		}
	}

	return NULL;
}

static void log_journal_entry(struct account *acct,
			      const char *currency,
			      u64 timestamp,
			      struct amount_msat credit_diff,
			      struct amount_msat debit_diff)
{
	struct channel_event *chan_ev;

	/* No diffs to register, no journal needed */
	if (amount_msat_zero(credit_diff)
	    && amount_msat_zero(debit_diff))
		return;

	chan_ev = new_channel_event(tmpctx,
				    tal_fmt(tmpctx, "%s",
					    account_entry_tag_str(JOURNAL_ENTRY)),
				    credit_diff,
				    debit_diff,
				    AMOUNT_MSAT(0),
				    currency,
				    NULL, 0,
				    timestamp);
	db_begin_transaction(db);
	log_channel_event(db, acct, chan_ev);
	db_commit_transaction(db);
}

static struct command_result *log_error(struct command *cmd,
					const char *buf,
					const jsmntok_t *error,
					void *arg UNNEEDED)
{
	plugin_log(cmd->plugin, LOG_BROKEN,
		   "error calling `listpeers`: %.*s",
		   json_tok_full_len(error),
		   json_tok_full(buf, error));

	return notification_handled(cmd);
}

static struct command_result *
listpeers_multi_done(struct command *cmd,
		     const char *buf,
		     const jsmntok_t *result,
		     struct new_account_info **new_accts)
{
	/* Let's register all these accounts! */
	for (size_t i = 0; i < tal_count(new_accts); i++) {
		struct new_account_info *info = new_accts[i];
		struct acct_balance **balances, *bal;
		struct amount_msat credit_diff, debit_diff;
		char *err;

		if (!new_missed_channel_account(cmd, buf, result,
					        info->acct,
					        info->currency,
					        info->timestamp)) {
			plugin_log(cmd->plugin, LOG_BROKEN,
				   "Unable to find account %s in listpeers",
				   info->acct->name);
			continue;
		}

		db_begin_transaction(db);
		err = account_get_balance(tmpctx, db, info->acct->name,
					  false, &balances);
		db_commit_transaction(db);

		if (err)
			plugin_err(cmd->plugin, err);

		/* FIXME: multiple currencies */
		if (tal_count(balances) > 0)
			bal = balances[0];
		else {
			bal = tal(tmpctx, struct acct_balance);
			bal->credit = AMOUNT_MSAT(0);
			bal->debit= AMOUNT_MSAT(0);
		}

		err = msat_find_diff(info->curr_bal,
				     bal->credit,
				     bal->debit,
				     &credit_diff, &debit_diff);
		if (err)
			plugin_err(cmd->plugin, err);

		log_journal_entry(info->acct,
				  info->currency,
				  info->timestamp - 1,
				  credit_diff, debit_diff);
	}

	return notification_handled(cmd);
}

struct event_info {
	struct chain_event *ev;
	struct account *acct;
};

static struct command_result *
listpeers_done(struct command *cmd, const char *buf,
	       const jsmntok_t *result, struct event_info *info)
{
	struct acct_balance **balances, *bal;
	struct amount_msat credit_diff, debit_diff;
	const char *err;
	/* Make sure to clean up when we're done */
	tal_steal(cmd, info);

	if (new_missed_channel_account(cmd, buf, result,
					info->acct,
					info->ev->currency,
					info->ev->timestamp)) {
		db_begin_transaction(db);
		err = account_get_balance(tmpctx, db, info->acct->name,
					  false, &balances);
		db_commit_transaction(db);

		if (err)
			plugin_err(cmd->plugin, err);

		/* FIXME: multiple currencies per account? */
		if (tal_count(balances) > 0)
			bal = balances[0];
		else {
			bal = tal(balances, struct acct_balance);
			bal->credit = AMOUNT_MSAT(0);
			bal->debit = AMOUNT_MSAT(0);
		}
		assert(tal_count(balances) == 1);

		/* The expected current balance is zero, since
		 * we just got the channel close event */
		err = msat_find_diff(AMOUNT_MSAT(0),
				     bal->credit,
				     bal->debit,
				     &credit_diff, &debit_diff);
		if (err)
			plugin_err(cmd->plugin, err);

		log_journal_entry(info->acct,
				  info->ev->currency,
				  info->ev->timestamp - 1,
				  credit_diff, debit_diff);
	} else
		plugin_log(cmd->plugin, LOG_BROKEN,
			   "Unable to find account %s in listpeers",
			   info->acct->name);

	/* Maybe mark acct as onchain resolved */
	db_begin_transaction(db);
	if (info->acct->closed_event_db_id)
		maybe_mark_account_onchain(db, info->acct);
	db_commit_transaction(db);
	return notification_handled(cmd);
}


static struct command_result *json_balance_snapshot(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params)
{
	const char *err;
	size_t i;
	u32 blockheight;
	u64 timestamp;
	struct new_account_info **new_accts;
	const jsmntok_t *accounts_tok, *acct_tok,
	      *snap_tok = json_get_member(buf, params, "balance_snapshot");

	if (snap_tok == NULL || snap_tok->type != JSMN_OBJECT)
		plugin_err(cmd->plugin,
			   "`balance_snapshot` payload did not scan %s: %.*s",
			   "no 'balance_snapshot'", json_tok_full_len(params),
			   json_tok_full(buf, params));

	err = json_scan(cmd, buf, snap_tok,
			"{blockheight:%"
			",timestamp:%}",
			JSON_SCAN(json_to_number, &blockheight),
			JSON_SCAN(json_to_u64, &timestamp));

	if (err)
		plugin_err(cmd->plugin,
			   "`balance_snapshot` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	accounts_tok = json_get_member(buf, snap_tok, "accounts");
	if (accounts_tok == NULL || accounts_tok->type != JSMN_ARRAY)
		plugin_err(cmd->plugin,
			   "`balance_snapshot` payload did not scan %s: %.*s",
			   "no 'balance_snapshot.accounts'",
			   json_tok_full_len(params),
			   json_tok_full(buf, params));

	new_accts = tal_arr(cmd, struct new_account_info *, 0);

	db_begin_transaction(db);
	json_for_each_arr(i, acct_tok, accounts_tok) {
		struct acct_balance **balances, *bal;
		struct amount_msat snap_balance, credit_diff, debit_diff;
		char *acct_name, *currency;

		err = json_scan(cmd, buf, acct_tok,
				"{account_id:%"
				",balance_msat:%"
				",coin_type:%}",
				JSON_SCAN_TAL(tmpctx, json_strdup, &acct_name),
				JSON_SCAN(json_to_msat, &snap_balance),
				JSON_SCAN_TAL(tmpctx, json_strdup,
					      &currency));
		if (err)
			plugin_err(cmd->plugin,
				   "`balance_snapshot` payload did not"
				   " scan %s: %.*s",
				   err, json_tok_full_len(params),
				   json_tok_full(buf, params));

		plugin_log(cmd->plugin, LOG_DBG, "account %s has balance %s",
			   acct_name,
			   type_to_string(tmpctx, struct amount_msat,
					  &snap_balance));

		/* Find the account balances */
		err = account_get_balance(cmd, db, acct_name,
					  /* Don't error if negative */
					  false,
					  &balances);

		if (err)
			plugin_err(cmd->plugin,
				   "Get account balance returned err"
				   " for account %s: %s",
				   acct_name, err);

		/* FIXME: multiple currency balances */
		if (tal_count(balances) > 0)
			bal = balances[0];
		else {
			bal = tal(balances, struct acct_balance);
			bal->credit = AMOUNT_MSAT(0);
			bal->debit = AMOUNT_MSAT(0);
		}

		/* Figure out what the net diff is btw reported & actual */
		err = msat_find_diff(snap_balance,
				     bal->credit,
				     bal->debit,
				     &credit_diff, &debit_diff);
		if (err)
			plugin_err(cmd->plugin,
				   "Unable to find_diff for amounts: %s",
				   err);

		if (!amount_msat_zero(credit_diff)
		    || !amount_msat_zero(debit_diff)) {
			struct account *acct;
			struct channel_event *ev;
			u64 timestamp;

			plugin_log(cmd->plugin, LOG_UNUSUAL,
				   "Snapshot balance does not equal ondisk"
				   " reported %s, off by (+%s/-%s) (account %s)"
				   " Logging journal entry.",
				   type_to_string(tmpctx, struct amount_msat,
						  &snap_balance),
				   type_to_string(tmpctx, struct amount_msat,
						  &debit_diff),
				   type_to_string(tmpctx, struct amount_msat,
						  &credit_diff),
				   acct_name);

			timestamp = time_now().ts.tv_sec;

			/* Log a channel "journal entry" to get
			 * the balances inline */
			acct = find_account(cmd, db, acct_name);
			if (!acct) {
				struct new_account_info *info;

				plugin_log(cmd->plugin, LOG_INFORM,
					   "account %s not found, adding"
					   " along with new balance",
					   acct_name);

				/* FIXME: lookup peer id for channel? */
				acct = new_account(cmd, acct_name, NULL);
				account_add(db, acct);

				/* If we're entering a channel account,
				 * from a balance entry, we need to
				 * go find the channel open info*/
				if (is_channel_account(acct)) {
					info = tal(new_accts, struct new_account_info);
					info->acct = tal_steal(info, acct);
					info->curr_bal = snap_balance;
					info->timestamp = timestamp;
					info->currency =
						tal_strdup(info, currency);

					tal_arr_expand(&new_accts, info);
					continue;
				}
			}

			ev = new_channel_event(cmd,
					       tal_fmt(tmpctx, "%s",
						       account_entry_tag_str(JOURNAL_ENTRY)),
					       credit_diff,
					       debit_diff,
					       AMOUNT_MSAT(0),
					       currency,
					       NULL, 0,
					       timestamp);

			log_channel_event(db, acct, ev);
		}
	}
	db_commit_transaction(db);

	if (tal_count(new_accts) > 0) {
		struct out_req *req;

		req = jsonrpc_request_start(cmd->plugin, NULL,
					    "listpeers",
					    listpeers_multi_done,
					    log_error,
					    new_accts);
		send_outreq(cmd->plugin, req);
		return command_still_pending(cmd);
	}

	return notification_handled(cmd);
}

static struct command_result *
parse_and_log_chain_move(struct command *cmd,
			 const char *buf,
			 const jsmntok_t *params,
			 const char *acct_name STEALS,
			 const struct amount_msat credit,
			 const struct amount_msat debit,
			 const char *coin_type STEALS,
			 const u64 timestamp,
			 const enum mvt_tag *tags)
{
	struct chain_event *e = tal(cmd, struct chain_event);
	struct sha256 *payment_hash = tal(cmd, struct sha256);
	struct bitcoin_txid *spending_txid = tal(cmd, struct bitcoin_txid);
	struct account *acct;
	u32 closed_count;
	const char *err;

	/* Fields we expect on *every* chain movement */
	err = json_scan(tmpctx, buf, params,
			"{coin_movement:"
			"{utxo_txid:%"
			",vout:%"
			",output_msat:%"
			",blockheight:%"
			"}}",
			JSON_SCAN(json_to_txid, &e->outpoint.txid),
			JSON_SCAN(json_to_number, &e->outpoint.n),
			JSON_SCAN(json_to_msat, &e->output_value),
			JSON_SCAN(json_to_number, &e->blockheight));

	if (err)
		plugin_err(cmd->plugin,
			   "`coin_movement` payload did"
			   " not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	/* Now try to get out the optional parts */
	err = json_scan(tmpctx, buf, params,
			"{coin_movement:"
			"{txid:%"
			"}}",
			JSON_SCAN(json_to_txid, spending_txid));

	if (err) {
		spending_txid = tal_free(spending_txid);
		err = tal_free(err);
	}

	e->spending_txid = tal_steal(e, spending_txid);

	/* Now try to get out the optional parts */
	err = json_scan(tmpctx, buf, params,
			"{coin_movement:"
			"{payment_hash:%"
			"}}",
			JSON_SCAN(json_to_sha256, payment_hash));

	if (err) {
		payment_hash = tal_free(payment_hash);
		err = tal_free(err);
	}

	err = json_scan(tmpctx, buf, params,
			"{coin_movement:"
			"{originating_account:%}}",
			JSON_SCAN_TAL(e, json_strdup, &e->origin_acct));

	if (err) {
		e->origin_acct = NULL;
		err = tal_free(err);
	}

	err = json_scan(tmpctx, buf, params,
			"{coin_movement:"
			"{output_count:%}}",
			JSON_SCAN(json_to_number, &closed_count));

	if (err) {
		closed_count = 0;
		err = tal_free(err);
	}

	e->payment_id = tal_steal(e, payment_hash);

	e->credit = credit;
	e->debit = debit;
	e->currency = tal_steal(e, coin_type);
	e->timestamp = timestamp;
	e->tag = mvt_tag_str(tags[0]);

	db_begin_transaction(db);
	acct = find_account(cmd, db, acct_name);

	if (!acct) {
		/* FIXME: lookup the peer id for this channel! */
		acct = new_account(cmd, acct_name, NULL);
		account_add(db, acct);
	}

	if (!log_chain_event(db, acct, e)) {
		db_commit_transaction(db);
		/* This is not a new event, do nothing */
		return notification_handled(cmd);
	}

	/* This event *might* have implications for account;
	 * update as necessary */
	maybe_update_account(db, acct, e, tags, closed_count);

	/* Can we calculate any onchain fees now? */
	err = maybe_update_onchain_fees(cmd, db,
					e->spending_txid ?
					e->spending_txid :
					&e->outpoint.txid);

	db_commit_transaction(db);

	if (err)
		plugin_err(cmd->plugin,
			   "Unable to update onchain fees %s",
			   err);

	/* If this is an account close event, it's possible
	 * that we *never* got the open event. (This happens
	 * if you add the plugin *after* you've closed the channel) */
	if (!acct->open_event_db_id
	    && acct->closed_event_db_id
	    && *acct->closed_event_db_id == e->db_id) {
		/* Find the channel open info for this peer */
		struct out_req *req;
		struct event_info *info;

		plugin_log(cmd->plugin, LOG_DBG,
			   "`channel_close` but no open for channel %s."
			   " Calling `listpeers` to fetch missing info",
			   acct->name);

		info = tal(NULL, struct event_info);
		info->ev = tal_steal(info, e);
		info->acct = tal_steal(info, acct);
		req = jsonrpc_request_start(cmd->plugin, NULL,
					    "listpeers",
					    listpeers_done,
					    log_error,
					    info);
		/* FIXME: use the peer_id to reduce work here */
		send_outreq(cmd->plugin, req);
		return command_still_pending(cmd);
	}

	/* Maybe mark acct as onchain resolved */
	db_begin_transaction(db);
	if (acct->closed_event_db_id)
		maybe_mark_account_onchain(db, acct);
	db_commit_transaction(db);

	return notification_handled(cmd);;
}

static struct command_result *
parse_and_log_channel_move(struct command *cmd,
			   const char *buf,
			   const jsmntok_t *params,
			   const char *acct_name STEALS,
			   const struct amount_msat credit,
			   const struct amount_msat debit,
			   const char *coin_type STEALS,
			   const u64 timestamp,
			   const enum mvt_tag *tags)
{
	struct channel_event *e = tal(cmd, struct channel_event);
	struct account *acct;
	const char *err;

	e->payment_id = tal(e, struct sha256);
	err = json_scan(tmpctx, buf, params,
			"{coin_movement:{payment_hash:%}}",
			JSON_SCAN(json_to_sha256, e->payment_id));
	if (err) {
		e->payment_id = tal_free(e->payment_id);
		err = tal_free(err);
	}

	err = json_scan(tmpctx, buf, params,
			"{coin_movement:{part_id:%}}",
			JSON_SCAN(json_to_number, &e->part_id));
	if (err) {
		e->part_id = 0;
		err = tal_free(err);
	}

	err = json_scan(tmpctx, buf, params,
			"{coin_movement:{fees_msat:%}}",
			JSON_SCAN(json_to_msat, &e->fees));
	if (err) {
		e->fees = AMOUNT_MSAT(0);
		err = tal_free(err);
	}

	e->credit = credit;
	e->debit = debit;
	e->currency = tal_steal(e, coin_type);
	e->timestamp = timestamp;
	e->tag = mvt_tag_str(tags[0]);

	/* Go find the account for this event */
	db_begin_transaction(db);
	acct = find_account(cmd, db, acct_name);
	if (!acct)
		plugin_err(cmd->plugin,
			   "Received channel event,"
			   " but no account exists %s",
			   acct_name);

	log_channel_event(db, acct, e);
	db_commit_transaction(db);

	return notification_handled(cmd);
}

static char *parse_tags(const tal_t *ctx,
			const char *buf,
			const jsmntok_t *tok,
			enum mvt_tag **tags)
{
	size_t i;
	const jsmntok_t *tag_tok,
	      *tags_tok = json_get_member(buf, tok, "tags");

	if (tags_tok == NULL || tags_tok->type != JSMN_ARRAY)
		return "Invalid/missing 'tags' field";

	*tags = tal_arr(ctx, enum mvt_tag, tags_tok->size);
	json_for_each_arr(i, tag_tok, tags_tok) {
		if (!json_to_coin_mvt_tag(buf, tag_tok, &(*tags)[i]))
			return "Unable to parse 'tags'";
	}

	return NULL;
}

static struct command_result * json_coin_moved(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	const char *err, *mvt_type, *acct_name, *coin_type;
	u32 version;
	u64 timestamp;
	struct amount_msat credit, debit;
	enum mvt_tag *tags;

	err = json_scan(tmpctx, buf, params,
			"{coin_movement:"
			"{version:%"
			",type:%"
			",account_id:%"
			",credit_msat:%"
			",debit_msat:%"
			",coin_type:%"
			",timestamp:%"
			"}}",
			JSON_SCAN(json_to_number, &version),
			JSON_SCAN_TAL(tmpctx, json_strdup, &mvt_type),
			JSON_SCAN_TAL(tmpctx, json_strdup, &acct_name),
			JSON_SCAN(json_to_msat, &credit),
			JSON_SCAN(json_to_msat, &debit),
			JSON_SCAN_TAL(tmpctx, json_strdup, &coin_type),
			JSON_SCAN(json_to_u64, &timestamp));

	if (err)
		plugin_err(cmd->plugin,
			   "`coin_movement` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	err = parse_tags(cmd, buf,
			 json_get_member(buf, params, "coin_movement"),
			 &tags);
	if (err)
		plugin_err(cmd->plugin,
			   "`coin_movement` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	/* We expect version 2 of coin movements */
	assert(version == 2);

	plugin_log(cmd->plugin, LOG_DBG, "coin_move %d %s -%s %s %"PRIu64,
		   version,
		   type_to_string(tmpctx, struct amount_msat, &credit),
		   type_to_string(tmpctx, struct amount_msat, &debit),
		   mvt_type, timestamp);

	if (streq(mvt_type, CHAIN_MOVE))
		return parse_and_log_chain_move(cmd, buf, params,
					        acct_name, credit, debit,
					        coin_type, timestamp, tags);


	assert(streq(mvt_type, CHANNEL_MOVE));
	return parse_and_log_channel_move(cmd, buf, params,
					  acct_name, credit, debit,
					  coin_type, timestamp, tags);
}

const struct plugin_notification notifs[] = {
	{
		"coin_movement",
		json_coin_moved,
	},
	{
		"balance_snapshot",
		json_balance_snapshot,
	}
};

static const struct plugin_command commands[] = {
	{
		"listbalances",
		"bookkeeping",
		"List current account balances",
		"List of current accounts and their balances",
		json_list_balances
	},
	{
		"listaccountevents",
		"bookkeeping",
		"List all events for an {account}",
		"List all events for an {account} (or all accounts, if"
		" no account specified) in {format}. Sorted by timestamp",
		json_list_account_events
	},
	{
		"inspect",
		"utilities",
		"See the current on-chain graph of an {account}",
		"Prints out the on-chain footprint of a given {account}.",
		json_inspect
	},
};

static const char *init(struct plugin *p, const char *b, const jsmntok_t *t)
{
	// FIXME: pass in database DSN as an option??
	db = notleak(db_setup(p, p, db_dsn));

	return NULL;
}

int main(int argc, char *argv[])
{
	setup_locale();

	plugin_main(argv, init, PLUGIN_STATIC, true, NULL,
		    commands, ARRAY_SIZE(commands),
		    notifs, ARRAY_SIZE(notifs),
		    NULL, 0,
		    NULL, 0,
		    NULL);
	return 0;
}
