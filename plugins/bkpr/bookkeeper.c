#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <common/bolt11.h>
#include <common/bolt12.h>
#include <common/coin_mvt.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/node_id.h>
#include <db/exec.h>
#include <errno.h>
#include <plugins/bkpr/account.h>
#include <plugins/bkpr/account_entry.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/channel_event.h>
#include <plugins/bkpr/channelsapy.h>
#include <plugins/bkpr/db.h>
#include <plugins/bkpr/incomestmt.h>
#include <plugins/bkpr/onchain_fee.h>
#include <plugins/bkpr/recorder.h>
#include <plugins/libplugin.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHAIN_MOVE "chain_mvt"
#define CHANNEL_MOVE "channel_mvt"

/* The database that we store all the accounting data in */
static struct db *db ;

static char *db_dsn;
static char *datadir;

static struct fee_sum *find_sum_for_txid(struct fee_sum **sums,
					 struct bitcoin_txid *txid)
{
	for (size_t i = 0; i < tal_count(sums); i++) {
		if (bitcoin_txid_eq(txid, sums[i]->txid))
			return sums[i];
	}
	return NULL;
}

struct apy_req {
	u64 *start_time;
	u64 *end_time;
};

static struct command_result *
getblockheight_done(struct command *cmd, const char *buf,
		    const jsmntok_t *result,
		    struct apy_req *req)
{
	const jsmntok_t *blockheight_tok;
	u32 blockheight;
	struct json_stream *res;
	struct channel_apy **apys, *net_apys;

	blockheight_tok = json_get_member(buf, result, "blockheight");
	if (!blockheight_tok)
		plugin_err(cmd->plugin, "getblockheight: "
			   "getinfo gave no 'blockheight'? '%.*s'",
			   result->end - result->start, buf);

	if (!json_to_u32(buf, blockheight_tok, &blockheight))
		plugin_err(cmd->plugin, "getblockheight: "
			   "getinfo gave non-unsigned-32-bit 'blockheight'? '%.*s'",
			   result->end - result->start, buf);

	/* Get the income events */
	db_begin_transaction(db);
	apys = compute_channel_apys(cmd, db,
				    *req->start_time,
				    *req->end_time,
				    blockheight);
	db_commit_transaction(db);

	/* Setup the net_apys entry */
	net_apys = new_channel_apy(cmd);
	net_apys->end_blockheight = 0;
	net_apys->start_blockheight = UINT_MAX;
	net_apys->our_start_bal = AMOUNT_MSAT(0);
	net_apys->total_start_bal = AMOUNT_MSAT(0);

	res = jsonrpc_stream_success(cmd);
	json_array_start(res, "channels_apy");
	for (size_t i = 0; i < tal_count(apys); i++) {
		json_add_channel_apy(res, apys[i]);

		/* Add to net/rollup APY */
		if (!channel_apy_sum(net_apys, apys[i]))
			return command_fail(cmd, PLUGIN_ERROR,
					     "Overflow adding APYs net");
	}

	/* Append a net/rollup entry */
	if (!amount_msat_zero(net_apys->total_start_bal)) {
		net_apys->acct_name = tal_fmt(net_apys, "net");
		json_add_channel_apy(res, net_apys);
	}
	json_array_end(res);

	return command_finished(cmd, res);
}

static struct command_result *json_channel_apy(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	struct out_req *req;
	struct apy_req *apyreq = tal(cmd, struct apy_req);

	if (!param(cmd, buf, params,
		   p_opt_def("start_time", param_u64, &apyreq->start_time, 0),
		   p_opt_def("end_time", param_u64, &apyreq->end_time,
			     SQLITE_MAX_UINT),
		   NULL))
		return command_param_failed();

	/* First get the current blockheight */
	req = jsonrpc_request_start(cmd->plugin, cmd, "getinfo",
				    &getblockheight_done,
				    forward_error,
				    apyreq);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *param_csv_format(struct command *cmd, const char *name,
					       const char *buffer, const jsmntok_t *tok,
					       struct csv_fmt **csv_fmt)
{
	*csv_fmt = cast_const(struct csv_fmt *,
			      csv_match_token(buffer, tok));
	if (*csv_fmt)
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     tal_fmt(cmd,
					     "should be one of: %s",
					     csv_list_fmts(cmd)));
}

static struct command_result *json_dump_income(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	struct json_stream *res;
	struct income_event **evs;
	struct csv_fmt *csv_fmt;
	const char *filename;
	bool *consolidate_fees;
	char *err;
	u64 *start_time, *end_time;

	if (!param(cmd, buf, params,
		   p_req("csv_format", param_csv_format, &csv_fmt),
		   p_opt("csv_file", param_string, &filename),
		   p_opt_def("consolidate_fees", param_bool,
			     &consolidate_fees, true),
		   p_opt_def("start_time", param_u64, &start_time, 0),
		   p_opt_def("end_time", param_u64, &end_time, SQLITE_MAX_UINT),
		   NULL))
		return command_param_failed();

	/* Ok, go find me some income events! */
	db_begin_transaction(db);
	evs = list_income_events(cmd, db, *start_time, *end_time,
				 *consolidate_fees);
	db_commit_transaction(db);

	if (!filename)
		filename = csv_filename(cmd, csv_fmt);

	err = csv_print_income_events(cmd, csv_fmt, filename, evs);
	if (err)
		return command_fail(cmd, PLUGIN_ERROR,
				    "Unable to create csv file: %s",
				    err);

	res = jsonrpc_stream_success(cmd);
	json_add_string(res, "csv_file", filename);
	json_add_string(res, "csv_format", csv_fmt->fmt_name);
	return command_finished(cmd, res);
}

static struct command_result *json_list_income(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	struct json_stream *res;
	struct income_event **evs;
	bool *consolidate_fees;
	u64 *start_time, *end_time;

	if (!param(cmd, buf, params,
		   p_opt_def("consolidate_fees", param_bool,
			     &consolidate_fees, true),
		   p_opt_def("start_time", param_u64, &start_time, 0),
		   p_opt_def("end_time", param_u64, &end_time, SQLITE_MAX_UINT),
		   NULL))
		return command_param_failed();

	/* Ok, go find me some income events! */
	db_begin_transaction(db);
	evs = list_income_events(cmd, db, *start_time, *end_time,
				 *consolidate_fees);
	db_commit_transaction(db);

	res = jsonrpc_stream_success(cmd);

	json_array_start(res, "income_events");
	for (size_t i = 0; i < tal_count(evs); i++)
		json_add_income_event(res, evs[i]);

	json_array_end(res);
	return command_finished(cmd, res);
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
		   p_req("account", param_string, &acct_name),
		   NULL))
		return command_param_failed();

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
			json_add_amount_msat(res, "fees_paid_msat",
					     fee_sum->fees_paid);
		else
			json_add_amount_msat(res, "fees_paid_msat",
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
				json_add_amount_msat(res, "output_value_msat",
						     ev->output_value);
				json_add_amount_msat(res, "credit_msat",
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
					json_add_amount_msat(res,
							     "output_value_msat",
							     ev->output_value);
					json_add_string(res, "currency",
							ev->currency);
				}
				json_add_string(res, "spend_tag", ev->tag);
				json_add_txid(res, "spending_txid",
					      ev->spending_txid);
				json_add_amount_msat(res,
						     "debit_msat", ev->debit);
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
					  false, /* don't skip ignored */
					  &balances,
					  NULL);

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
		if (accts[i]->peer_id) {
			json_add_node_id(res, "peer_id", accts[i]->peer_id);
			json_add_bool(res, "we_opened", accts[i]->we_opened);
			json_add_bool(res, "account_closed",
				     !(!accts[i]->closed_event_db_id));
			json_add_bool(res, "account_resolved",
				      accts[i]->onchain_resolved_block > 0);
			if (accts[i]->onchain_resolved_block > 0)
				json_add_u32(res, "resolved_at_block",
					     accts[i]->onchain_resolved_block);
		}

		json_array_start(res, "balances");
		for (size_t j = 0; j < tal_count(balances); j++) {
			json_object_start(res, NULL);
			json_add_amount_msat(res, "balance_msat",
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

static void find_push_amts(const char *buf,
			   const jsmntok_t *curr_chan,
			   bool is_opener,
			   struct amount_msat *push_credit,
			   struct amount_msat *push_debit,
			   bool *is_leased)
{
	const char *err;
	struct amount_msat push_amt;

	/* Try to pull out fee_rcvd_msat */
	err = json_scan(tmpctx, buf, curr_chan,
			"{funding:{fee_rcvd_msat:%}}",
			JSON_SCAN(json_to_msat,
				  push_credit));

	if (!err) {
		*is_leased = true;
		*push_debit = AMOUNT_MSAT(0);
		return;
	}

	/* Try to pull out fee_paid_msat */
	err = json_scan(tmpctx, buf, curr_chan,
			"{funding:{fee_paid_msat:%}}",
			JSON_SCAN(json_to_msat,
				  push_debit));
	if (!err) {
		*is_leased = true;
		*push_credit = AMOUNT_MSAT(0);
		return;
	}

	/* Try to pull out pushed amt? */
	err = json_scan(tmpctx, buf, curr_chan,
			"{funding:{pushed_msat:%}}",
			JSON_SCAN(json_to_msat, &push_amt));

	if (!err) {
		*is_leased = false;
		if (is_opener) {
			*push_credit = AMOUNT_MSAT(0);
			*push_debit = push_amt;
		} else {
			*push_credit = push_amt;
			*push_debit = AMOUNT_MSAT(0);
		}
		return;
	}

	/* Nothing pushed nor fees paid */
	*is_leased = false;
	*push_credit = AMOUNT_MSAT(0);
	*push_debit = AMOUNT_MSAT(0);
}

static bool new_missed_channel_account(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *result,
				       struct account *acct,
				       const char *currency,
				       u64 timestamp)
{
	struct chain_event *chain_ev;
	const char *err;
	size_t i;
	const jsmntok_t *curr_chan, *chan_arr_tok;

	chan_arr_tok = json_get_member(buf, result, "channels");
	assert(chan_arr_tok && chan_arr_tok->type == JSMN_ARRAY);

	json_for_each_arr(i, curr_chan, chan_arr_tok) {
	        struct bitcoin_outpoint opt;
		struct amount_msat amt, remote_amt,
			push_credit, push_debit;
		struct node_id peer_id;
		char *opener, *chan_id;
		enum mvt_tag *tags;
		bool ok, is_opener, is_leased;

		err = json_scan(tmpctx, buf, curr_chan,
				"{peer_id:%,"
				"channel_id:%,"
				"funding_txid:%,"
				"funding_outnum:%,"
				"funding:{local_funds_msat:%,"
					 "remote_funds_msat:%},"
				"opener:%}",
				JSON_SCAN(json_to_node_id, &peer_id),
				JSON_SCAN_TAL(tmpctx, json_strdup, &chan_id),
				JSON_SCAN(json_to_txid, &opt.txid),
				JSON_SCAN(json_to_number, &opt.n),
				JSON_SCAN(json_to_msat, &amt),
				JSON_SCAN(json_to_msat, &remote_amt),
				JSON_SCAN_TAL(tmpctx, json_strdup, &opener));
		if (err)
			plugin_err(cmd->plugin,
				   "failure scanning listpeerchannels"
				   " result: %s", err);

		if (!streq(chan_id, acct->name))
			continue;

		plugin_log(cmd->plugin, LOG_DBG,
			   "Logging channel account from list %s",
			   acct->name);

		chain_ev = tal(cmd, struct chain_event);
		chain_ev->tag = mvt_tag_str(CHANNEL_OPEN);
		chain_ev->debit = AMOUNT_MSAT(0);
		ok = amount_msat_add(&chain_ev->output_value,
				     amt, remote_amt);
		assert(ok);
		chain_ev->currency = tal_strdup(chain_ev, currency);
		chain_ev->origin_acct = NULL;
		/* 2s before the channel opened, minimum */
		chain_ev->timestamp = timestamp - 2;
		chain_ev->blockheight = 0;
		chain_ev->outpoint = opt;
		chain_ev->spending_txid = NULL;
		chain_ev->payment_id = NULL;
		chain_ev->ignored = false;
		chain_ev->stealable = false;
		chain_ev->desc = NULL;

		/* Update the account info too */
		tags = tal_arr(chain_ev, enum mvt_tag, 1);
		tags[0] = CHANNEL_OPEN;

		is_opener = streq(opener, "local");

		/* Leased/pushed channels have some extra work */
		find_push_amts(buf, curr_chan, is_opener,
			       &push_credit, &push_debit,
			       &is_leased);

		if (is_leased)
			tal_arr_expand(&tags, LEASED);
		if (is_opener)
			tal_arr_expand(&tags, OPENER);

		chain_ev->credit = amt;
		db_begin_transaction(db);
		if (!log_chain_event(db, acct, chain_ev))
			goto done;

		maybe_update_account(db, acct, chain_ev,
				     tags, 0, &peer_id);
		maybe_update_onchain_fees(cmd, db, &opt.txid);

		/* We won't count the close's fees if we're
		 * *not* the opener, which we didn't know
		 * until now, so now try to update the
		 * fees for the close tx's spending_txid..*/
		if (acct->closed_event_db_id)
			try_update_open_fees(cmd, acct);

		/* We log a channel event for the push amt */
		if (!amount_msat_zero(push_credit)
		    || !amount_msat_zero(push_debit)) {
			struct channel_event *chan_ev;
			char *chan_tag;

			chan_tag = tal_fmt(tmpctx, "%s",
					   mvt_tag_str(
					    is_leased ?
					      LEASE_FEE : PUSHED));
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

done:
			db_commit_transaction(db);
			return true;
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
				       fmt_amount_msat(ctx, credit),
				       fmt_amount_msat(ctx, debit));
		*debit_net = AMOUNT_MSAT(0);
	} else {
		if (!amount_msat_sub(debit_net, debit, credit)) {
			return tal_fmt(ctx, "unexpected fail, can't sub."
				       " %s - %s",
				       fmt_amount_msat(ctx, debit),
				       fmt_amount_msat(ctx, credit));
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
		   "error calling rpc: %.*s",
		   json_tok_full_len(error),
		   json_tok_full(buf, error));

	return notification_handled(cmd);
}

static struct command_result *listpeerchannels_multi_done(struct command *cmd,
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
				   "Unable to find account %s in listpeerchannels",
				   info->acct->name);
			continue;
		}

		db_begin_transaction(db);
		err = account_get_balance(tmpctx, db, info->acct->name,
					  false, false, &balances, NULL);
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
	plugin_log(cmd->plugin, LOG_DBG, "Snapshot balances updated");
	return notification_handled(cmd);
}

static char *do_account_close_checks(const tal_t *ctx,
				     struct chain_event *e,
				     struct account *acct)
{
	struct account *closed_acct;

	db_begin_transaction(db);

	/* If is an external acct event, might be close channel related */
	if (!is_channel_account(acct) && e->origin_acct) {
		closed_acct = find_account(ctx, db, e->origin_acct);
	} else if (!is_channel_account(acct) && !e->spending_txid)
		closed_acct = find_close_account(ctx, db, &e->outpoint.txid);
	else
		/* Get most up to date account entry */
		closed_acct = find_account(ctx, db, acct->name);


	if (closed_acct && closed_acct->closed_event_db_id) {
		maybe_mark_account_onchain(db, closed_acct);
		if (closed_acct->onchain_resolved_block > 0) {
			char *err;
			err = update_channel_onchain_fees(ctx, db, closed_acct);
			if (err) {
				db_commit_transaction(db);
				return err;
			}
		}
	}

	db_commit_transaction(db);

	return NULL;
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
		struct account *acct;
		struct amount_msat snap_balance, credit_diff, debit_diff;
		char *acct_name, *currency;
		bool existed;

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
			   fmt_amount_msat(tmpctx, snap_balance));

		/* Find the account balances */
		err = account_get_balance(cmd, db, acct_name,
					  /* Don't error if negative */
					  false,
					  /* Ignore non-clightning
					   * balances items */
					  true,
					  &balances,
					  NULL);

		if (err)
			plugin_err(cmd->plugin,
				   "Get account balance returned err"
				   " for account %s: %s",
				   acct_name, err);

		/* multiple currency balances! */
		bal = NULL;
		for (size_t j = 0; j < tal_count(balances); j++) {
			if (streq(balances[j]->currency, currency))
				bal = balances[j];
		}

		if (!bal) {
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

		acct = find_account(cmd, db, acct_name);
		if (!acct) {
			plugin_log(cmd->plugin, LOG_INFORM,
				   "account %s not found, adding",
				   acct_name);

			/* FIXME: lookup peer id for channel? */
			acct = new_account(cmd, acct_name, NULL);
			account_add(db, acct);
			existed = false;
		} else
			existed = true;

		/* If we're entering a channel account,
		 * from a balance entry, we need to
		 * go find the channel open info*/
		if (!existed && is_channel_account(acct)) {
			struct new_account_info *info;
			u64 timestamp_now;

			timestamp_now = time_now().ts.tv_sec;
			info = tal(new_accts, struct new_account_info);
			info->acct = tal_steal(info, acct);
			info->curr_bal = snap_balance;
			info->timestamp = timestamp_now;
			info->currency =
				tal_strdup(info, currency);

			tal_arr_expand(&new_accts, info);
			continue;
		}

		if (!amount_msat_zero(credit_diff) || !amount_msat_zero(debit_diff)) {
			struct channel_event *ev;

			plugin_log(cmd->plugin, LOG_UNUSUAL,
				   "Snapshot balance does not equal ondisk"
				   " reported %s, off by (+%s/-%s) (account %s)"
				   " Logging journal entry.",
				   fmt_amount_msat(tmpctx, snap_balance),
				   fmt_amount_msat(tmpctx, debit_diff),
				   fmt_amount_msat(tmpctx, credit_diff),
				   acct_name);


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

		req = jsonrpc_request_start(cmd->plugin, cmd,
					    "listpeerchannels",
					    listpeerchannels_multi_done,
					    log_error,
					    new_accts);
		/* FIXME(vicenzopalazzo) require the channel by channel_id to avoid parsing not useful json  */
		return send_outreq(cmd->plugin, req);
	}

	plugin_log(cmd->plugin, LOG_DBG, "Snapshot balances updated");
	return notification_handled(cmd);
}

/* Returns true if "fatal" error, otherwise just a normal error */
static char *fetch_out_desc_invstr(const tal_t *ctx, const char *buf,
				   const jsmntok_t *tok, char **err)
{
	char *bolt, *desc, *fail;

	/* It's a bolt11! Parse it out to a desc */
	if (!json_scan(ctx, buf, tok, "{bolt11:%}",
		       JSON_SCAN_TAL(ctx, json_strdup, &bolt))) {
		struct bolt11 *bolt11;
		const u5 *sigdata;
		struct sha256 hash;
		bool have_n;

		bolt11 = bolt11_decode_nosig(ctx, bolt,
				       /* No desc/features/chain checks */
				       NULL, NULL, NULL,
				       &hash, &sigdata, &have_n,
				       &fail);

		if (bolt11) {
			if (bolt11->description)
				desc = tal_strdup(ctx, bolt11->description);
			else if (bolt11->description_hash)
				desc = tal_fmt(ctx, "%s",
					       fmt_sha256(ctx,
						      bolt11->description_hash));
			else
				desc = NULL;
		} else {
			*err = tal_fmt(ctx, "failed to parse bolt11 %s: %s",
				       bolt, fail);
			return NULL;
		}
	} else if (!json_scan(ctx, buf, tok, "{bolt12:%}",
			      JSON_SCAN_TAL(ctx, json_strdup, &bolt))) {
		struct tlv_invoice *bolt12;

		bolt12 = invoice_decode_nosig(ctx, bolt, strlen(bolt),
					      /* No features/chain checks */
					      NULL, NULL,
					      &fail);
		if (!bolt12) {
			*err = tal_fmt(ctx, "failed to parse"
				       " bolt12 %s: %s",
				       bolt, fail);
			return NULL;
		}

		if (bolt12->offer_description)
			desc = tal_strndup(ctx,
				cast_signed(char *, bolt12->offer_description),
				tal_bytelen(bolt12->offer_description));
		else
			desc = NULL;
	} else
		desc = NULL;

	*err = NULL;
	return desc;
}

static struct command_result *
listinvoices_done(struct command *cmd, const char *buf,
		  const jsmntok_t *result, struct sha256 *payment_hash)
{
	size_t i;
	const jsmntok_t *inv_arr_tok, *inv_tok;
	const char *desc;
	inv_arr_tok = json_get_member(buf, result, "invoices");
	assert(inv_arr_tok->type == JSMN_ARRAY);

	desc = NULL;
	json_for_each_arr(i, inv_tok, inv_arr_tok) {
		char *err;

		/* Found desc in "description" */
		if (!json_scan(cmd, buf, inv_tok, "{description:%}",
				JSON_SCAN_TAL(cmd, json_strdup, &desc)))
			break;

		/* if 'description' doesn't exist, try bolt11/bolt12 */
		desc = fetch_out_desc_invstr(cmd, buf, inv_tok, &err);
		if (desc || err) {
			if (err)
				plugin_log(cmd->plugin,
					   LOG_BROKEN, "%s", err);
			break;
		}
	}

	if (desc) {
		db_begin_transaction(db);
		add_payment_hash_desc(db, payment_hash,
				      json_escape_unescape(cmd,
					      (struct json_escape *)desc));
		db_commit_transaction(db);
	} else
		plugin_log(cmd->plugin, LOG_DBG,
			   "listinvoices:"
			   " description/bolt11/bolt12"
			   " not found (%.*s)",
			   result->end - result->start, buf);

	return notification_handled(cmd);
}

static struct command_result *
listsendpays_done(struct command *cmd, const char *buf,
		  const jsmntok_t *result, struct sha256 *payment_hash)
{
	size_t i;
	const jsmntok_t *pays_arr_tok, *pays_tok;
	const char *desc;
	pays_arr_tok = json_get_member(buf, result, "payments");
	assert(pays_arr_tok->type == JSMN_ARRAY);

	/* Did we find a matching entry? */
	desc = NULL;
	json_for_each_arr(i, pays_tok, pays_arr_tok) {
		char *err;

		desc = fetch_out_desc_invstr(cmd, buf, pays_tok, &err);
		if (desc || err) {
			if (err)
				plugin_log(cmd->plugin,
					   LOG_BROKEN, "%s", err);
			break;
		}
	}

	if (desc) {
		db_begin_transaction(db);
		add_payment_hash_desc(db, payment_hash, desc);
		db_commit_transaction(db);
	} else
		plugin_log(cmd->plugin, LOG_DBG,
			   "listpays: bolt11/bolt12 not found:"
			   "(%.*s)",
			   result->end - result->start, buf);

	return notification_handled(cmd);
}

static struct command_result *lookup_invoice_desc(struct command *cmd,
						  struct amount_msat credit,
						  struct sha256 *payment_hash STEALS)
{
	struct out_req *req;

	/* Otherwise will go away when event is cleaned up */
	tal_steal(cmd, payment_hash);
	if (!amount_msat_zero(credit))
		req = jsonrpc_request_start(cmd->plugin, cmd,
					    "listinvoices",
					    listinvoices_done,
					    log_error,
					    payment_hash);
	else
		req = jsonrpc_request_start(cmd->plugin, cmd,
					    "listsendpays",
					    listsendpays_done,
					    log_error,
					    payment_hash);

	json_add_sha256(req->js, "payment_hash", payment_hash);
	return send_outreq(cmd->plugin, req);
}

struct event_info {
	struct chain_event *ev;
	struct account *acct;
};

static struct command_result *
listpeerchannels_done(struct command *cmd, const char *buf,
	       const jsmntok_t *result, struct event_info *info)
{
	struct acct_balance **balances, *bal;
	struct amount_msat credit_diff, debit_diff;
	const char *err;

	if (new_missed_channel_account(cmd, buf, result,
					info->acct,
					info->ev->currency,
					info->ev->timestamp)) {
		db_begin_transaction(db);
		err = account_get_balance(tmpctx, db, info->acct->name,
					  false, false, &balances, NULL);
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
	err = do_account_close_checks(cmd, info->ev, info->acct);
	if (err)
		plugin_err(cmd->plugin, err);

	if (info->ev->payment_id &&
	    streq(info->ev->tag, mvt_tag_str(INVOICE))) {
		return lookup_invoice_desc(cmd, info->ev->credit,
					   info->ev->payment_id);
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
			 const enum mvt_tag *tags,
			 const char *desc)
{
	struct chain_event *e = tal(cmd, struct chain_event);
	struct sha256 *payment_hash = tal(cmd, struct sha256);
	struct bitcoin_txid *spending_txid = tal(cmd, struct bitcoin_txid);
	struct node_id *peer_id;
	struct account *acct, *orig_acct;
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

	peer_id = tal(cmd, struct node_id);
	err = json_scan(tmpctx, buf, params,
			"{coin_movement:"
			"{peer_id:%}}",
			JSON_SCAN(json_to_node_id, peer_id));

	if (err) {
		peer_id = tal_free(peer_id);
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
	e->desc = tal_steal(e, desc);

	e->ignored = false;
	e->stealable = false;
	for (size_t i = 0; i < tal_count(tags); i++) {
		e->ignored |= tags[i] == IGNORED;
		e->stealable |= tags[i] == STEALABLE;
	}

	db_begin_transaction(db);
	acct = find_account(tmpctx, db, acct_name);

	if (!acct) {
		/* FIXME: lookup the peer id for this channel! */
		acct = new_account(tmpctx, acct_name, NULL);
		account_add(db, acct);
	}

	if (e->origin_acct) {
		orig_acct = find_account(tmpctx, db, e->origin_acct);
		/* Go fetch the originating account
		 * (we might not have it) */
		if (!orig_acct) {
			orig_acct = new_account(tmpctx, e->origin_acct, NULL);
			account_add(db, orig_acct);
		}
	} else
		orig_acct = NULL;


	if (!log_chain_event(db, acct, e)) {
		db_commit_transaction(db);
		/* This is not a new event, do nothing */
		return notification_handled(cmd);
	}

	/* This event *might* have implications for account;
	 * update as necessary */
	maybe_update_account(db, acct, e, tags, closed_count,
			     peer_id);

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

	/* If this is a spend confirmation event, it's possible
	 * that it we've got an external deposit that's now
	 * confirmed */
	if (e->spending_txid) {
		db_begin_transaction(db);
		/* Go see if there's any deposits to an external
		 * that are now confirmed */
		/* FIXME: might need updating when we can splice? */
		maybe_closeout_external_deposits(db, e);
		db_commit_transaction(db);
	}

	/* If this is a channel account event, it's possible
	 * that we *never* got the open event. (This happens
	 * if you add the plugin *after* you've closed the channel) */
	if ((!acct->open_event_db_id && is_channel_account(acct))
	    || (orig_acct && is_channel_account(orig_acct)
		&& !orig_acct->open_event_db_id)) {
		/* Find the channel open info for this peer */
		struct out_req *req;
		struct event_info *info;

		plugin_log(cmd->plugin, LOG_DBG,
			   "channel event received but no open for channel %s."
			   " Calling `listpeerchannls` to fetch missing info",
			   acct->name);

		info = tal(cmd, struct event_info);
		info->ev = tal_steal(info, e);
		info->acct = tal_steal(info,
				       is_channel_account(acct) ?
				       acct : orig_acct);

		req = jsonrpc_request_start(cmd->plugin, cmd,
					    "listpeerchannels",
					    listpeerchannels_done,
					    log_error,
					    info);
		/* FIXME: use the peer_id to reduce work here */
		return send_outreq(cmd->plugin, req);
	}

	/* Maybe mark acct as onchain resolved */
	err = do_account_close_checks(cmd, e, acct);
	if (err)
		plugin_err(cmd->plugin, err);

	/* Check for invoice desc data, necessary */
	if (e->payment_id) {
		for (size_t i = 0; i < tal_count(tags); i++) {
			if (tags[i] != INVOICE)
				continue;

			return lookup_invoice_desc(cmd, e->credit,
						   e->payment_id);
		}
	}

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
			   const enum mvt_tag *tags,
			   const char *desc)
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
	e->desc = tal_steal(e, desc);
	e->rebalance_id = NULL;

	/* Go find the account for this event */
	db_begin_transaction(db);
	acct = find_account(tmpctx, db, acct_name);
	if (!acct)
		plugin_err(cmd->plugin,
			   "Received channel event,"
			   " but no account exists %s",
			   acct_name);

	log_channel_event(db, acct, e);

	/* Check for invoice desc data, necessary */
	if (e->payment_id) {
		for (size_t i = 0; i < tal_count(tags); i++) {
			if (tags[i] != INVOICE)
				continue;

			/* We only do rebalance checks for debits,
			 * the credit event always arrives first */
			if (!amount_msat_zero(e->debit))
				maybe_record_rebalance(db, e);

			db_commit_transaction(db);
			return lookup_invoice_desc(cmd, e->credit,
						   e->payment_id);
		}
	}

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

static struct command_result *json_coin_moved(struct command *cmd,
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

	err = parse_tags(tmpctx, buf,
			 json_get_member(buf, params, "coin_movement"),
			 &tags);
	if (err)
		plugin_err(cmd->plugin,
			   "`coin_movement` payload did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	/* We expect version 2 of coin movements */
	assert(version == 2);

	plugin_log(cmd->plugin, LOG_DBG, "coin_move %d (%s) %s -%s %s %"PRIu64,
		   version,
		   mvt_tag_str(tags[0]),
		   fmt_amount_msat(tmpctx, credit),
		   fmt_amount_msat(tmpctx, debit),
		   mvt_type, timestamp);

	if (streq(mvt_type, CHAIN_MOVE))
		return parse_and_log_chain_move(cmd, buf, params,
					        acct_name, credit, debit,
					        coin_type, timestamp, tags,
						NULL);


	assert(streq(mvt_type, CHANNEL_MOVE));
	return parse_and_log_channel_move(cmd, buf, params,
					  acct_name, credit, debit,
					  coin_type, timestamp, tags,
					  NULL);
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
		"bkpr-listbalances",
		"bookkeeping",
		"List current account balances",
		"List of current accounts and their balances",
		json_list_balances
	},
	{
		"bkpr-listaccountevents",
		"bookkeeping",
		"List all events for an {account}",
		"List all events for an {account} (or all accounts, if"
		" no account specified) in {format}. Sorted by timestamp",
		json_list_account_events
	},
	{
		"bkpr-inspect",
		"utilities",
		"See the current on-chain graph of an {account}",
		"Prints out the on-chain footprint of a given {account}.",
		json_inspect
	},
	{
		"bkpr-listincome",
		"bookkeeping",
		"List all income impacting events",
		"List all events for this node that impacted income",
		json_list_income
	},
	{
		"bkpr-dumpincomecsv",
		"bookkeeping",
		"Print out all the income events to a csv file in "
		" {csv_format",
		"Dump income statment data to {csv_file} in {csv_format}."
		" Optionally, {consolidate_fee}s into single entries"
		" (default: true)",
		json_dump_income
	},
	{
		"bkpr-channelsapy",
		"bookkeeping",
		"Stats on channel fund usage",
		"Print out stats on chanenl fund usage",
		json_channel_apy
	},
};

static const char *init(struct plugin *p, const char *b, const jsmntok_t *t)
{
	/* Switch to bookkeeper-dir, if specified */
	if (datadir && chdir(datadir) != 0) {
		if (mkdir(datadir, 0700) != 0 && errno != EEXIST)
			plugin_err(p,
				   "Unable to create 'bookkeeper-dir'=%s",
				   datadir);
		if (chdir(datadir) != 0)
			plugin_err(p,
				   "Unable to switch to 'bookkeeper-dir'=%s",
				   datadir);
	}

	/* No user suppled db_dsn, set one up here */
	if (!db_dsn)
		db_dsn = tal_fmt(NULL, "sqlite3://accounts.sqlite3");

	plugin_log(p, LOG_DBG, "Setting up database at %s", db_dsn);
	db = notleak(db_setup(p, p, db_dsn));
	db_dsn = tal_free(db_dsn);

	return NULL;
}

int main(int argc, char *argv[])
{
	setup_locale();

	/* No datadir is default */
	datadir = NULL;
	db_dsn = NULL;

	plugin_main(argv, init, PLUGIN_STATIC, true, NULL,
		    commands, ARRAY_SIZE(commands),
		    notifs, ARRAY_SIZE(notifs),
		    NULL, 0,
		    NULL, 0,
		    plugin_option("bookkeeper-dir",
				  "string",
				  "Location for bookkeeper records.",
				  charp_option, NULL, &datadir),
		    plugin_option("bookkeeper-db",
				  "string",
				  "Location of the bookkeeper database",
				  charp_option, NULL, &db_dsn),
		    NULL);

	return 0;
}
