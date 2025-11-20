#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <common/bolt11.h>
#include <common/bolt12.h>
#include <common/clock_time.h>
#include <common/coin_mvt.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/node_id.h>
#include <db/exec.h>
#include <errno.h>
#include <inttypes.h>
#include <plugins/bkpr/account.h>
#include <plugins/bkpr/account_entry.h>
#include <plugins/bkpr/blockheights.h>
#include <plugins/bkpr/bookkeeper.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/channel_event.h>
#include <plugins/bkpr/channelsapy.h>
#include <plugins/bkpr/descriptions.h>
#include <plugins/bkpr/incomestmt.h>
#include <plugins/bkpr/onchain_fee.h>
#include <plugins/bkpr/rebalances.h>
#include <plugins/bkpr/recorder.h>
#include <plugins/libplugin.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHAIN_MOVE "chain_mvt"
#define CHANNEL_MOVE "channel_mvt"

static struct bkpr *bkpr_of(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct bkpr);
}

struct refresh_info {
	size_t calls_remaining;
	struct command_result *(*cb)(struct command *, void *);
	void *arg;
};

/* Rules: call use_rinfo when handing to a callback.
 * Have the callback return rinfo_one_done(). */
static struct refresh_info *use_rinfo(struct refresh_info *rinfo)
{
	rinfo->calls_remaining++;
	return rinfo;
}

/* Recursion */
static struct command_result *limited_listchannelmoves(struct command *cmd,
						       struct refresh_info *rinfo);

static struct command_result *rinfo_one_done(struct command *cmd,
					     struct refresh_info *rinfo)
{
	assert(rinfo->calls_remaining > 0);
	if (--rinfo->calls_remaining == 0)
		return rinfo->cb(cmd, rinfo->arg);
	else
		return command_still_pending(cmd);
}

struct command_result *ignore_datastore_reply(struct command *cmd,
					      const char *method,
					      const char *buf,
					      const jsmntok_t *result,
					      void *arg)
{
	return command_still_pending(cmd);
}

/* FIXME: reorder to avoid fwd decls. */
static void
parse_and_log_chain_move(struct command *cmd,
			 const char *buf,
			 const jsmntok_t *chainmove,
			 struct refresh_info *rinfo);
static void
parse_and_log_channel_move(struct command *cmd,
			   const char *buf,
			   const jsmntok_t *channelmove,
			   struct refresh_info *rinfo,
			   bool log);

static struct command_result *datastore_done(struct command *cmd,
					     const char *method,
					     const char *buf,
					     const jsmntok_t *result,
					     struct refresh_info *rinfo)
{
	return rinfo_one_done(cmd, rinfo);
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

static struct command_result *listchannelmoves_done(struct command *cmd,
						    const char *method,
						    const char *buf,
						    const jsmntok_t *result,
						    struct refresh_info *rinfo)
{
	const jsmntok_t *moves, *t;
	size_t i;
	struct bkpr *bkpr = bkpr_of(cmd->plugin);
	be64 be_index;

	moves = json_get_member(buf, result, "channelmoves");
	if (moves->size > 2) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "%u channelmoves, only logging first and last",
			   moves->size);
	}

	json_for_each_arr(i, t, moves)
		parse_and_log_channel_move(cmd, buf, t, rinfo,
					   i == 0 || i == moves->size - 1);

	be_index = cpu_to_be64(bkpr->channelmoves_index);
	jsonrpc_set_datastore_binary(cmd, "bookkeeper/channelmoves_index",
				     &be_index, sizeof(be_index),
				     "create-or-replace",
				     datastore_done, NULL, use_rinfo(rinfo));

	/* If there might be more, try asking for more */
	if (moves->size != 0)
		limited_listchannelmoves(cmd, rinfo);

	return rinfo_one_done(cmd, rinfo);
}

/* We do 1000 at a time to avoid overwhelming lightningd */
static struct command_result *limited_listchannelmoves(struct command *cmd,
						       struct refresh_info *rinfo)
{
	struct bkpr *bkpr = bkpr_of(cmd->plugin);
	struct out_req *req;

	req = jsonrpc_request_start(cmd, "listchannelmoves",
				    listchannelmoves_done,
				    plugin_broken_cb,
				    use_rinfo(rinfo));
	json_add_string(req->js, "index", "created");
	json_add_u64(req->js, "start", bkpr->channelmoves_index + 1);
	json_add_u64(req->js, "limit", 1000);
	return send_outreq(req);
}

static struct command_result *listchainmoves_done(struct command *cmd,
						  const char *method,
						  const char *buf,
						  const jsmntok_t *result,
						  struct refresh_info *rinfo)
{
	const jsmntok_t *moves, *t;
	size_t i;
	struct bkpr *bkpr = bkpr_of(cmd->plugin);
	be64 be_index;

	moves = json_get_member(buf, result, "chainmoves");
	json_for_each_arr(i, t, moves)
		parse_and_log_chain_move(cmd, buf, t, rinfo);

	be_index = cpu_to_be64(bkpr->chainmoves_index);
	jsonrpc_set_datastore_binary(cmd, "bookkeeper/chainmoves_index",
				     &be_index, sizeof(be_index),
				     "create-or-replace",
				     datastore_done, NULL, use_rinfo(rinfo));

	limited_listchannelmoves(cmd, rinfo);
	return rinfo_one_done(cmd, rinfo);
}

static struct command_result *refresh_moves_(struct command *cmd,
					     struct command_result *(*cb)(
						     struct command *,
						     void *),
					     void *arg)
{
	struct refresh_info *rinfo = tal(cmd, struct refresh_info);
	struct out_req *req;
	struct bkpr *bkpr = bkpr_of(cmd->plugin);

	rinfo->cb = cb;
	rinfo->arg = arg;
	rinfo->calls_remaining = 0;
	req = jsonrpc_request_start(cmd, "listchainmoves",
				    listchainmoves_done,
				    plugin_broken_cb,
				    use_rinfo(rinfo));
	json_add_string(req->js, "index", "created");
	json_add_u64(req->js, "start", bkpr->chainmoves_index + 1);
	return send_outreq(req);
}

#define refresh_moves(cmd, cb, arg)					\
	refresh_moves_((cmd),						\
		       typesafe_cb_preargs(struct command_result *, void *, \
					   (cb), (arg),			\
					   struct command *),		\
		       arg)

struct apy_req {
	u64 *start_time;
	u64 *end_time;
};

static struct command_result *
getblockheight_done(struct command *cmd,
		    const char *method,
		    const char *buf,
		    const jsmntok_t *result,
		    struct apy_req *req)
{
	const jsmntok_t *blockheight_tok;
	u32 blockheight;
	struct json_stream *res;
	struct channel_apy **apys, *net_apys;
	struct bkpr *bkpr = bkpr_of(cmd->plugin);

	blockheight_tok = json_get_member(buf, result, "blockheight");
	if (!blockheight_tok)
		plugin_err(cmd->plugin, "getblockheight: "
			   "getinfo gave no 'blockheight'? '%.*s'",
			   result->end - result->start, buf + result->start);

	if (!json_to_u32(buf, blockheight_tok, &blockheight))
		plugin_err(cmd->plugin, "getblockheight: "
			   "getinfo gave non-unsigned-32-bit 'blockheight'? '%.*s'",
			   result->end - result->start, buf + result->start);

	/* Get the income events */
	apys = compute_channel_apys(cmd, bkpr, cmd,
				    *req->start_time,
				    *req->end_time,
				    blockheight);

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
	if (!amount_msat_is_zero(net_apys->total_start_bal)) {
		net_apys->acct_name = tal_fmt(net_apys, "net");
		json_add_channel_apy(res, net_apys);
	}
	json_array_end(res);

	return command_finished(cmd, res);
}

static struct command_result *
do_channel_apy(struct command *cmd, struct apy_req *apyreq)
{
	struct out_req *req;

	/* First get the current blockheight */
	req = jsonrpc_request_start(cmd, "getinfo",
				    &getblockheight_done,
				    forward_error,
				    apyreq);
	return send_outreq(req);
}

static struct command_result *json_channel_apy(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	struct apy_req *apyreq = tal(cmd, struct apy_req);

	if (!param(cmd, buf, params,
		   p_opt_def("start_time", param_u64, &apyreq->start_time, 0),
		   p_opt_def("end_time", param_u64, &apyreq->end_time,
			     SQLITE_MAX_UINT),
		   NULL))
		return command_param_failed();

	return refresh_moves(cmd, do_channel_apy, apyreq);
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

struct dump_income_info {
	struct csv_fmt *csv_fmt;
	const char *filename;
	bool *consolidate_fees;
	u64 *start_time, *end_time;
};

static struct command_result *do_dump_income(struct command *cmd,
					     struct dump_income_info *info)
{
	struct bkpr *bkpr = bkpr_of(cmd->plugin);
	struct json_stream *res;
	struct income_event **evs;
	char *err;

	/* Ok, go find me some income events! */
	evs = list_income_events(cmd, bkpr, cmd, *info->start_time, *info->end_time,
				 *info->consolidate_fees);

	if (!info->filename)
		info->filename = csv_filename(info, info->csv_fmt);

	err = csv_print_income_events(cmd, info->csv_fmt, info->filename, evs);
	if (err)
		return command_fail(cmd, PLUGIN_ERROR,
				    "Unable to create csv file: %s",
				    err);

	res = jsonrpc_stream_success(cmd);
	json_add_string(res, "csv_file", info->filename);
	json_add_string(res, "csv_format", info->csv_fmt->fmt_name);
	return command_finished(cmd, res);
}

static struct command_result *json_dump_income(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	struct dump_income_info *info = tal(cmd, struct dump_income_info);

	if (!param(cmd, buf, params,
		   p_req("csv_format", param_csv_format, &info->csv_fmt),
		   p_opt("csv_file", param_string, &info->filename),
		   p_opt_def("consolidate_fees", param_bool,
			     &info->consolidate_fees, true),
		   p_opt_def("start_time", param_u64, &info->start_time, 0),
		   p_opt_def("end_time", param_u64, &info->end_time, SQLITE_MAX_UINT),
		   NULL))
		return command_param_failed();

	return refresh_moves(cmd, do_dump_income, info);
}

struct list_income_info {
	bool *consolidate_fees;
	u64 *start_time, *end_time;
};

static struct command_result *do_list_income(struct command *cmd,
					     struct list_income_info *info)
{
	struct json_stream *res;
	struct income_event **evs;
	struct bkpr *bkpr = bkpr_of(cmd->plugin);

	/* Ok, go find me some income events! */
	evs = list_income_events(cmd, bkpr, cmd, *info->start_time, *info->end_time,
				 *info->consolidate_fees);

	res = jsonrpc_stream_success(cmd);

	json_array_start(res, "income_events");
	for (size_t i = 0; i < tal_count(evs); i++)
		json_add_income_event(res, evs[i]);

	json_array_end(res);
	return command_finished(cmd, res);
}

static struct command_result *json_list_income(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	struct list_income_info *info = tal(cmd, struct list_income_info);

	if (!param(cmd, buf, params,
		   p_opt_def("consolidate_fees", param_bool,
			     &info->consolidate_fees, true),
		   p_opt_def("start_time", param_u64, &info->start_time, 0),
		   p_opt_def("end_time", param_u64, &info->end_time, SQLITE_MAX_UINT),
		   NULL))
		return command_param_failed();

	return refresh_moves(cmd, do_list_income, info);
}

static struct command_result *do_inspect(struct command *cmd,
					 char *acct_name)
{
	struct json_stream *res;
	struct account *acct;
	struct fee_sum **fee_sums;
	struct txo_set **txos;
	struct bkpr *bkpr = bkpr_of(cmd->plugin);

	if (!is_channel_account(acct_name))
		return command_fail(cmd, PLUGIN_ERROR,
				    "`inspect` not supported for"
				    " non-channel accounts");

	acct = find_account(bkpr, acct_name);
	if (!acct)
		return command_fail(cmd, PLUGIN_ERROR,
				    "Account %s not found",
				    acct_name);

	find_txo_chain(cmd, bkpr, cmd, acct, &txos);
	fee_sums = find_account_onchain_fees(cmd, bkpr, acct);

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
				} else if (!streq(pr->txo->acct_name, acct->name)
					   /* We make an exception for wallet events */
					   && !is_wallet_account(pr->txo->acct_name))
					continue;
			} else if (pr->spend
				   && !streq(pr->spend->acct_name, acct->name))
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
				json_add_string(res, "currency",
						chainparams->lightning_hrp);
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
							chainparams->lightning_hrp);
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

static struct command_result *json_inspect(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *params)
{
	char *acct_name;

	/* Only available for channel accounts? */
	if (!param(cmd, buf, params,
		   p_req("account", param_string, cast_const2(const char **, &acct_name)),
		   NULL))
		return command_param_failed();

	return refresh_moves(cmd, do_inspect, acct_name);
}

static void json_add_events(struct json_stream *res,
			    const struct bkpr *bkpr,
			    struct channel_event **channel_events,
			    struct chain_event **chain_events,
			    struct onchain_fee **onchain_fees)
{
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
			json_add_chain_event(res, bkpr, chain);
			i++;
			continue;
		}

		if (chan && chan->timestamp == lowest) {
			json_add_channel_event(res, bkpr, chan);
			j++;
			continue;
		}

		/* Last thing left is the fee */
		json_add_onchain_fee(res, fee);
		k++;
	}
}

struct account_events_info {
	const char *acct_name;
	struct sha256 *payment_id;
};

static struct command_result *do_account_events(struct command *cmd,
						struct account_events_info *info)
{
	struct json_stream *res;
	struct account *acct;
	struct bitcoin_txid *tx_id;
	struct channel_event **channel_events;
	struct chain_event **chain_events;
	struct onchain_fee **onchain_fees;
	struct bkpr *bkpr = bkpr_of(cmd->plugin);

	if (info->acct_name && info->payment_id != NULL) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can only specify one of "
				    "{account} or {payment_id}");
	}

	if (info->acct_name) {
		acct = find_account(bkpr, info->acct_name);
		if (!acct)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Account '%s' not found",
					    info->acct_name);
	} else
		acct = NULL;

	if (acct) {
		channel_events = account_get_channel_events(cmd, bkpr, cmd, acct);
		chain_events = account_get_chain_events(cmd, bkpr, cmd, acct);
		onchain_fees = account_get_chain_fees(tmpctx, bkpr, acct->name);
	} else if (info->payment_id != NULL) {
		channel_events = get_channel_events_by_id(cmd, bkpr, cmd, info->payment_id);

		tx_id = tal(cmd, struct bitcoin_txid);
		tx_id->shad.sha = *info->payment_id;
		/* Transaction ids are stored as big-endian in the database */
		reverse_bytes(tx_id->shad.sha.u.u8, sizeof(tx_id->shad.sha.u.u8));

		chain_events = find_chain_events_bytxid(cmd, bkpr, cmd, tx_id);
		onchain_fees = get_chain_fees_by_txid(cmd, bkpr, tx_id);
	} else {
		channel_events = list_channel_events(cmd, bkpr, cmd);
		chain_events = list_chain_events(cmd, bkpr, cmd);
		onchain_fees = list_chain_fees(cmd, bkpr);
	}

	res = jsonrpc_stream_success(cmd);
	json_array_start(res, "events");
	json_add_events(res, bkpr, channel_events, chain_events, onchain_fees);
	json_array_end(res);
	return command_finished(cmd, res);
}

/* Find all the events for this account, ordered by timestamp */
static struct command_result *json_list_account_events(struct command *cmd,
						       const char *buf,
						       const jsmntok_t *params)
{
	struct account_events_info *info = tal(cmd, struct account_events_info);

	if (!param(cmd, buf, params,
		   p_opt("account", param_string, &info->acct_name),
		   p_opt("payment_id", param_sha256, &info->payment_id),
		   NULL))
		return command_param_failed();

	return refresh_moves(cmd, do_account_events, info);
}

struct edit_desc_info {
	struct bitcoin_outpoint *outpoint;
	const char *new_desc;
};

static struct command_result *do_edit_desc(struct command *cmd,
					   struct edit_desc_info *info)
{
	struct json_stream *res;
	struct chain_event **chain_events;
	struct bkpr *bkpr = bkpr_of(cmd->plugin);

	add_utxo_description(cmd, bkpr, info->outpoint, info->new_desc);
	chain_events = get_chain_events_by_outpoint(cmd, bkpr, cmd, info->outpoint);

	res = jsonrpc_stream_success(cmd);
	json_array_start(res, "updated");
	json_add_events(res, bkpr, NULL, chain_events, NULL);
	json_array_end(res);

	return command_finished(cmd, res);
}

static struct command_result *json_edit_desc_utxo(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *params)
{
	struct edit_desc_info *info = tal(cmd, struct edit_desc_info);

	if (!param(cmd, buf, params,
		   p_req("outpoint", param_outpoint, &info->outpoint),
		   p_req("description", param_string, &info->new_desc),
		   NULL))
		return command_param_failed();

	return refresh_moves(cmd, do_edit_desc, info);
}

struct edit_desc_payment_info {
	struct sha256 *identifier;
	const char *new_desc;
};

static struct command_result *do_edit_desc_payment(struct command *cmd,
						   struct edit_desc_payment_info *info)
{
	struct json_stream *res;
	struct channel_event **channel_events;
	struct chain_event **chain_events;
	struct bkpr *bkpr = bkpr_of(cmd->plugin);

	add_payment_hash_description(cmd, bkpr, info->identifier, info->new_desc);

	chain_events = get_chain_events_by_id(cmd, bkpr, cmd, info->identifier);
	channel_events = get_channel_events_by_id(cmd, bkpr, cmd, info->identifier);

	res = jsonrpc_stream_success(cmd);
	json_array_start(res, "updated");
	json_add_events(res, bkpr, channel_events, chain_events, NULL);
	json_array_end(res);

	return command_finished(cmd, res);
}

static struct command_result *json_edit_desc_payment_id(struct command *cmd,
							const char *buf,
							const jsmntok_t *params)
{
	struct edit_desc_payment_info *info = tal(cmd, struct edit_desc_payment_info);

	if (!param(cmd, buf, params,
		   p_req("payment_id", param_sha256, &info->identifier),
		   p_req("description", param_string, &info->new_desc),
		   NULL))
		return command_param_failed();

	return refresh_moves(cmd, do_edit_desc_payment, info);
}

static struct command_result *do_list_balances(struct command *cmd,
					       void *unused)
{
	struct json_stream *res;
	struct account **accts;
	struct bkpr *bkpr = bkpr_of(cmd->plugin);

	res = jsonrpc_stream_success(cmd);
	/* List of accts */
	accts = list_accounts(cmd, bkpr);

	json_array_start(res, "accounts");
	for (size_t i = 0; i < tal_count(accts); i++) {
		struct amount_msat credit, debit, balance;
		bool has_events;

		has_events = account_get_credit_debit(bkpr, cmd,
						      accts[i]->name,
						      &credit, &debit);
		if (!amount_msat_sub(&balance, credit, debit)) {
			plugin_err(cmd->plugin,
				   "Account balance underflow for account %s (credit %s, debit %s)",
				   accts[i]->name,
				   fmt_amount_msat(tmpctx, credit),
				   fmt_amount_msat(tmpctx, debit));
		}

		/* Skip the external acct balance, it's effectively
		 * meaningless */
		if (is_external_account(accts[i]->name))
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

		/* FIXME: This API is now overkill! */
		json_array_start(res, "balances");
		/* We expect no entry if account is not used. */
		for (size_t j = 0; j < has_events; j++) {
			json_object_start(res, NULL);
			json_add_amount_msat(res, "balance_msat",
					     balance);
			json_add_string(res, "coin_type",
					chainparams->lightning_hrp);
			json_object_end(res);
		}
		json_array_end(res);

		json_object_end(res);
	}
	json_array_end(res);

	return command_finished(cmd, res);
}

static struct command_result *json_list_balances(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	return refresh_moves(cmd, do_list_balances, NULL);
}

struct new_account_info {
	struct account *acct;
	struct amount_msat curr_bal;
	u32 timestamp;
};

static struct command_result *log_error(struct command *cmd,
					const char *method,
					const char *buf,
					const jsmntok_t *error,
					void *arg UNNEEDED)
{
	plugin_log(cmd->plugin, LOG_BROKEN,
		   "error calling %s: %.*s",
		   method, json_tok_full_len(error),
		   json_tok_full(buf, error));

	return notification_handled(cmd);
}

static char *do_account_close_checks(struct command *cmd,
				     struct bkpr *bkpr,
				     struct chain_event *e,
				     struct account *acct)
{
	struct account *closed_acct;

	/* If is an external acct event, might be close channel related */
	if (!is_channel_account(acct->name) && e->origin_acct) {
		closed_acct = find_account(bkpr, e->origin_acct);
	} else if (!is_channel_account(acct->name) && !e->spending_txid) {
		const char *acctname;

		acctname = find_close_account_name(tmpctx, bkpr, cmd, &e->outpoint.txid);
		if (acctname) {
			closed_acct = find_account(bkpr, acctname);
		} else {
			closed_acct = NULL;
		}
	} else
		/* Get most up to date account entry */
		closed_acct = find_account(bkpr, acct->name);


	if (closed_acct && closed_acct->closed_event_db_id) {
		u64 closeheight = account_onchain_closeheight(bkpr, cmd, closed_acct);
		if (closeheight != 0) {
			char *err;
			account_update_closeheight(cmd, closed_acct, closeheight);
			err = update_channel_onchain_fees(cmd, cmd, bkpr, closed_acct);
			if (err) {
				return err;
			}
		}
	}

	return NULL;
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

		bolt12 = invoice_decode_minimal(ctx, bolt, strlen(bolt),
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

struct payment_hash_info {
	struct refresh_info *rinfo;
	struct sha256 payment_hash;
};

static struct command_result *
listinvoices_done(struct command *cmd,
		  const char *method,
		  const char *buf,
		  const jsmntok_t *result,
		  struct payment_hash_info *phinfo)
{
	size_t i;
	const jsmntok_t *inv_arr_tok, *inv_tok;
	const char *desc;
	struct bkpr *bkpr = bkpr_of(cmd->plugin);

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
		add_payment_hash_description(cmd, bkpr, &phinfo->payment_hash,
				      json_escape_unescape(cmd,
					      (struct json_escape *)desc));

	} else
		plugin_log(cmd->plugin, LOG_DBG,
			   "listinvoices:"
			   " description/bolt11/bolt12"
			   " not found (%.*s)",
			   result->end - result->start, buf + result->start);

	return rinfo_one_done(cmd, phinfo->rinfo);
}

static struct command_result *
listsendpays_done(struct command *cmd,
		  const char *method,
		  const char *buf,
		  const jsmntok_t *result,
		  struct payment_hash_info *phinfo)
{
	size_t i;
	const jsmntok_t *pays_arr_tok, *pays_tok;
	const char *desc;
	struct bkpr *bkpr = bkpr_of(cmd->plugin);

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
		add_payment_hash_description(cmd, bkpr, &phinfo->payment_hash, desc);
	} else
		plugin_log(cmd->plugin, LOG_DBG,
			   "listpays: bolt11/bolt12 not found:"
			   "(%.*s)",
			   result->end - result->start, buf + result->start);

	return rinfo_one_done(cmd, phinfo->rinfo);
}

static struct command_result *lookup_invoice_desc(struct command *cmd,
						  struct amount_msat credit,
						  const struct sha256 *payment_hash,
						  struct refresh_info *rinfo)
{
	struct out_req *req;
	struct payment_hash_info *phinfo;

	phinfo = tal(cmd, struct payment_hash_info);
	phinfo->payment_hash = *payment_hash;
	phinfo->rinfo = use_rinfo(rinfo);

	if (!amount_msat_is_zero(credit))
		req = jsonrpc_request_start(cmd,
					    "listinvoices",
					    listinvoices_done,
					    log_error,
					    phinfo);
	else
		req = jsonrpc_request_start(cmd,
					    "listsendpays",
					    listsendpays_done,
					    log_error,
					    phinfo);

	json_add_sha256(req->js, "payment_hash", payment_hash);
	return send_outreq(req);
}

static enum mvt_tag *json_to_tags(const tal_t *ctx, const char *buffer, const jsmntok_t *tok)
{
	size_t i;
	const jsmntok_t *t;
	enum mvt_tag *tags = tal_arr(ctx, enum mvt_tag, tok->size);

	json_for_each_arr(i, t, tok) {
		if (!json_to_coin_mvt_tag(buffer, t, &tags[i]))
			return tal_free(tags);
	}

	return tags;
}

static void
parse_and_log_chain_move(struct command *cmd,
			 const char *buf,
			 const jsmntok_t *chainmove,
			 struct refresh_info *rinfo)
{
	struct chain_event *e = tal(cmd, struct chain_event);
	struct sha256 *payment_hash = tal(cmd, struct sha256);
	struct bitcoin_txid *spending_txid = tal(cmd, struct bitcoin_txid);
	struct node_id *peer_id;
	struct account *acct;
	u32 closed_count;
	char *acct_name;
	const char *err;
	struct bkpr *bkpr = bkpr_of(cmd->plugin);
	enum mvt_tag tag, *tags;

	/* Fields we expect on *every* chain movement */
	closed_count = 0;
	err = json_scan(tmpctx, buf, chainmove,
			"{account_id:%"
			",created_index:%"
			",credit_msat:%"
			",debit_msat:%"
			",timestamp:%"
			",utxo:%"
			",output_msat:%"
			",blockheight:%"
			",primary_tag:%"
			",extra_tags:%"
			",output_count?:%"
			"}",
			JSON_SCAN_TAL(tmpctx, json_strdup, &acct_name),
			JSON_SCAN(json_to_u64, &e->db_id),
			JSON_SCAN(json_to_msat, &e->credit),
			JSON_SCAN(json_to_msat, &e->debit),
			JSON_SCAN(json_to_u64, &e->timestamp),
			JSON_SCAN(json_to_outpoint, &e->outpoint),
			JSON_SCAN(json_to_msat, &e->output_value),
			JSON_SCAN(json_to_number, &e->blockheight),
			JSON_SCAN(json_to_coin_mvt_tag, &tag),
			JSON_SCAN_TAL(tmpctx, json_to_tags, &tags),
			JSON_SCAN(json_to_number, &closed_count));
	if (err)
		plugin_err(cmd->plugin,
			   "chainmove did"
			   " not scan %s: %.*s",
			   err, json_tok_full_len(chainmove),
			   json_tok_full(buf, chainmove));

	/* Now try to get out the optional parts */
	err = json_scan(tmpctx, buf, chainmove,
			"{spending_txid:%"
			"}",
			JSON_SCAN(json_to_txid, spending_txid));

	if (err) {
		spending_txid = tal_free(spending_txid);
		err = tal_free(err);
	}

	e->spending_txid = tal_steal(e, spending_txid);

	/* Now try to get out the optional parts */
	err = json_scan(tmpctx, buf, chainmove,
			"{coin_movement:"
			"{payment_hash:%"
			"}}",
			JSON_SCAN(json_to_sha256, payment_hash));

	if (err) {
		payment_hash = tal_free(payment_hash);
		err = tal_free(err);
	}

	err = json_scan(tmpctx, buf, chainmove,
			"{originating_account:%}",
			JSON_SCAN_TAL(e, json_strdup, &e->origin_acct));

	if (err) {
		e->origin_acct = NULL;
		err = tal_free(err);
	}

	peer_id = tal(cmd, struct node_id);
	err = json_scan(tmpctx, buf, chainmove,
			"{peer_id:%}",
			JSON_SCAN(json_to_node_id, peer_id));

	if (err) {
		peer_id = tal_free(peer_id);
		err = tal_free(err);
	}
	e->payment_id = tal_steal(e, payment_hash);

	e->tag = mvt_tag_str(tag);
	e->stealable = false;
	e->splice_close = false;
	e->foreign = false;
	for (size_t i = 0; i < tal_count(tags); i++) {
		e->stealable |= tags[i] == MVT_STEALABLE;
		e->splice_close |= tags[i] == MVT_SPLICE;
		e->foreign |= tags[i] == MVT_FOREIGN;
	}
	/* FIXME: tags below is expected to contain primary tag too */
	tal_arr_insert(&tags, 0, tag);

	/* For tests, we log these harder! */
	if (e->foreign)
		plugin_log(cmd->plugin, LOG_DBG,
			   "Foreign chain event: %s (%s) %s -%s %"PRIu64" %d %s %s",
			   e->tag, acct_name,
			   fmt_amount_msat(tmpctx, e->credit),
			   fmt_amount_msat(tmpctx, e->debit),
			   e->timestamp, e->blockheight,
			   fmt_bitcoin_outpoint(tmpctx, &e->outpoint),
			   e->spending_txid ? fmt_bitcoin_txid(tmpctx, e->spending_txid) : "");

	plugin_log(cmd->plugin, LOG_DBG, "coin_move 2 (%s) %s -%s %s %"PRIu64,
		   e->tag,
		   fmt_amount_msat(tmpctx, e->credit),
		   fmt_amount_msat(tmpctx, e->debit),
		   CHAIN_MOVE, e->timestamp);

	/* FIXME: lookup the peer id for this channel! */
	acct = find_or_create_account(cmd, bkpr, acct_name);

	if (e->origin_acct)
		find_or_create_account(cmd, bkpr, e->origin_acct);

	/* Make this visible for queries (we expect increasing!).  If we raced, this is not true. */
	if (e->db_id <= bkpr->chainmoves_index)
		return;

	bkpr->chainmoves_index = e->db_id;

	/* This event *might* have implications for account;
	 * update as necessary */
	maybe_update_account(cmd, acct, e, tags, closed_count,
			     peer_id);

	/* Can we calculate any onchain fees now? */
	err = maybe_update_onchain_fees(cmd, cmd, bkpr,
					e->spending_txid ?
					e->spending_txid :
					&e->outpoint.txid);

	if (err)
		plugin_err(cmd->plugin,
			   "Unable to update onchain fees %s",
			   err);

	/* If this is a spend confirmation event, it's possible
	 * that it we've got an external deposit that's now
	 * confirmed */
	if (e->spending_txid) {
		/* Go see if there's any deposits to an external
		 * that are now confirmed */
		/* FIXME: might need updating when we can splice? */
		maybe_closeout_external_deposits(cmd, bkpr, e->spending_txid,
						 e->blockheight);
	}

	/* Maybe mark acct as onchain resolved */
	err = do_account_close_checks(cmd, bkpr, e, acct);
	if (err)
		plugin_err(cmd->plugin, "%s", err);

	/* Check for invoice desc data, necessary */
	if (e->payment_id) {
		for (size_t i = 0; i < tal_count(tags); i++) {
			if (tags[i] != MVT_INVOICE)
				continue;

			lookup_invoice_desc(cmd, e->credit,
					    e->payment_id, rinfo);
			break;
		}
	}
}

static void
parse_and_log_channel_move(struct command *cmd,
			   const char *buf,
			   const jsmntok_t *channelmove,
			   struct refresh_info *rinfo,
			   bool log)
{
	struct channel_event *e = tal(cmd, struct channel_event);
	struct account *acct;
	const char *err;
	char *acct_name;
	enum mvt_tag tag;
	struct bkpr *bkpr = bkpr_of(cmd->plugin);

	/* Fields we expect on *every* channel movement */
	e->part_id = 0;
	e->fees = AMOUNT_MSAT(0);
	err = json_scan(tmpctx, buf, channelmove,
			"{account_id:%"
			",created_index:%"
			",credit_msat:%"
			",debit_msat:%"
			",timestamp:%"
			",primary_tag:%"
			",part_id?:%"
			",fees_msat?:%}",
			JSON_SCAN_TAL(tmpctx, json_strdup, &acct_name),
			JSON_SCAN(json_to_u64, &e->db_id),
			JSON_SCAN(json_to_msat, &e->credit),
			JSON_SCAN(json_to_msat, &e->debit),
			JSON_SCAN(json_to_u64, &e->timestamp),
			JSON_SCAN(json_to_coin_mvt_tag, &tag),
			JSON_SCAN(json_to_number, &e->part_id),
			JSON_SCAN(json_to_msat, &e->fees));
	if (err)
		plugin_err(cmd->plugin,
			   "channelmove did"
			   " not scan %s: %.*s",
			   err, json_tok_full_len(channelmove),
			   json_tok_full(buf, channelmove));

	e->tag = mvt_tag_str(tag);

	e->payment_id = tal(e, struct sha256);
	err = json_scan(tmpctx, buf, channelmove,
			"{payment_hash:%}",
			JSON_SCAN(json_to_sha256, e->payment_id));
	if (err) {
		e->payment_id = tal_free(e->payment_id);
		err = tal_free(err);
	}

	if (log)
		plugin_log(cmd->plugin, LOG_DBG, "coin_move 2 (%s) %s -%s %s %"PRIu64,
			   e->tag,
			   fmt_amount_msat(tmpctx, e->credit),
			   fmt_amount_msat(tmpctx, e->debit),
			   CHANNEL_MOVE, e->timestamp);

	/* Go find the account for this event */
	acct = find_account(bkpr, acct_name);
	if (!acct)
		plugin_err(cmd->plugin,
			   "Received channel event,"
			   " but no account exists %s",
			   acct_name);

	/* Make this visible for queries (we expect increasing!).  If we raced, this is not true. */
	if (e->db_id <= bkpr->channelmoves_index)
		return;
	bkpr->channelmoves_index = e->db_id;

	/* Check for invoice desc data, necessary */
	if (e->payment_id && tag == MVT_INVOICE) {
		/* We only do rebalance checks for debits,
		 * the credit event always arrives first */
		if (!amount_msat_is_zero(e->debit))
			maybe_record_rebalance(cmd, bkpr, e);

		lookup_invoice_desc(cmd, e->credit, e->payment_id, rinfo);
		return;
	}
}

static bool json_to_tok(const char *buffer, const jsmntok_t *tok, const jsmntok_t **ret)
{
	*ret = tok;
	return true;
}

static struct command_result *inject_refresh_done(struct command *notif_cmd,
						  void *unused)
{
	return notification_handled(notif_cmd);
}

static struct command_result *inject_done(struct command *notif_cmd,
					  const char *methodname,
					  const char *buf,
					  const jsmntok_t *result,
					  void *unused)
{
	/* We could do this lazily, but tests assume it happens now */
	return refresh_moves(notif_cmd, inject_refresh_done, NULL);
}

/* FIXME: Deprecate */
static struct command_result *json_utxo_deposit(struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *acct_name, *origin_acct;
	struct amount_msat amount;
	struct bitcoin_outpoint outpoint;
	u64 timestamp;
	u32 blockheight;
	const jsmntok_t *transfer_from;
	const char *err;
	struct out_req *req;

	transfer_from = NULL;
	err = json_scan(tmpctx, buf, params,
			"{utxo_deposit:{"
			"account:%"
			",transfer_from?:%"
			",outpoint:%"
			",amount_msat:%"
			",timestamp:%"
			",blockheight:%"
			"}}",
			JSON_SCAN_TAL(tmpctx, json_strdup, &acct_name),
			JSON_SCAN(json_to_tok, &transfer_from),
			JSON_SCAN(json_to_outpoint, &outpoint),
			JSON_SCAN(json_to_msat, &amount),
			JSON_SCAN(json_to_u64, &timestamp),
			JSON_SCAN(json_to_u32, &blockheight));

	if (err)
		plugin_err(cmd->plugin,
			   "`utxo_deposit` parameters did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	if (!transfer_from || json_tok_is_null(buf, transfer_from))
		origin_acct = NULL;
	else
		origin_acct = json_strdup(tmpctx, buf, transfer_from);

	req = jsonrpc_request_start(cmd, "injectutxodeposit",
				    inject_done,
				    plugin_broken_cb,
				    NULL);
	json_add_string(req->js, "account", acct_name);
	if (origin_acct)
		json_add_string(req->js, "transfer_from", origin_acct);
	json_add_outpoint(req->js, "outpoint", &outpoint);
	json_add_amount_msat(req->js, "amount_msat", amount);
	json_add_u64(req->js, "timestamp", timestamp);
	json_add_u32(req->js, "blockheight", blockheight);
	return send_outreq(req);
}

static struct command_result *json_utxo_spend(struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *acct_name;
	struct amount_msat amount;
	struct bitcoin_txid spending_txid;
	struct bitcoin_outpoint outpoint;
	u64 timestamp;
	u32 blockheight;
	const char *err;
	struct out_req *req;

	err = json_scan(tmpctx, buf, params,
			"{utxo_spend:{"
			"account:%"
			",outpoint:%"
			",spending_txid:%"
			",amount_msat:%"
			",timestamp:%"
			",blockheight:%"
			"}}",
			JSON_SCAN_TAL(tmpctx, json_strdup, &acct_name),
			JSON_SCAN(json_to_outpoint, &outpoint),
			JSON_SCAN(json_to_txid, &spending_txid),
			JSON_SCAN(json_to_msat, &amount),
			JSON_SCAN(json_to_u64, &timestamp),
			JSON_SCAN(json_to_u32, &blockheight));

	if (err)
		plugin_err(cmd->plugin,
			   "`utxo_spend` parameters did not scan %s: %.*s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	req = jsonrpc_request_start(cmd, "injectutxospend",
				    inject_done,
				    plugin_broken_cb,
				    NULL);
	json_add_string(req->js, "account", acct_name);
	json_add_outpoint(req->js, "outpoint", &outpoint);
	json_add_txid(req->js, "spending_txid", &spending_txid);
	json_add_amount_msat(req->js, "amount_msat", amount);
	json_add_u64(req->js, "timestamp", timestamp);
	json_add_u32(req->js, "blockheight", blockheight);
	return send_outreq(req);
}

const struct plugin_notification notifs[] = {
	{
		"utxo_deposit",
		json_utxo_deposit,
	},
	{
		"utxo_spend",
		json_utxo_spend,
	},
};

static const struct plugin_command commands[] = {
	{
		"bkpr-listbalances",
		json_list_balances
	},
	{
		"bkpr-listaccountevents",
		json_list_account_events
	},
	{
		"bkpr-inspect",
		json_inspect
	},
	{
		"bkpr-listincome",
		json_list_income
	},
	{
		"bkpr-dumpincomecsv",
		json_dump_income
	},
	{
		"bkpr-channelsapy",
		json_channel_apy
	},
	{
		"bkpr-editdescriptionbypaymentid",
		json_edit_desc_payment_id
	},
	{
		"bkpr-editdescriptionbyoutpoint",
		json_edit_desc_utxo
	},
};

static bool json_hex_to_be64(const char *buffer, const jsmntok_t *tok,
			     be64 *val)
{
	return hex_decode(buffer + tok->start, tok->end - tok->start,
			  val, sizeof(*val));
}

static const char *init(struct command *init_cmd, const char *b, const jsmntok_t *t)
{
	struct plugin *p = init_cmd->plugin;
	struct bkpr *bkpr = bkpr_of(p);
	be64 index;

	bkpr->accounts = init_accounts(bkpr, init_cmd);
	bkpr->onchain_fees = init_onchain_fees(bkpr, init_cmd);
	bkpr->descriptions = init_descriptions(bkpr, init_cmd);
	bkpr->rebalances = init_rebalances(bkpr, init_cmd);
	bkpr->blockheights = init_blockheights(bkpr, init_cmd);

	/* Callers always expect the wallet account to exist. */
	find_or_create_account(init_cmd, bkpr, ACCOUNT_NAME_WALLET);

	/* Not existing is OK! */
	if (rpc_scan_datastore_hex(tmpctx, init_cmd, "bookkeeper/channelmoves_index",
				   JSON_SCAN(json_hex_to_be64, &index)) == NULL) {
		bkpr->channelmoves_index = be64_to_cpu(index);
	} else
		bkpr->channelmoves_index = 0;
	if (rpc_scan_datastore_hex(tmpctx, init_cmd, "bookkeeper/chainmoves_index",
				   JSON_SCAN(json_hex_to_be64, &index)) == NULL) {
		bkpr->chainmoves_index = be64_to_cpu(index);
	} else
		bkpr->chainmoves_index = 0;

	return NULL;
}

int main(int argc, char *argv[])
{
	struct bkpr *bkpr;
	setup_locale();

	/* No datadir is default */
	bkpr = tal(NULL, struct bkpr);
	plugin_main(argv, init, take(bkpr), PLUGIN_STATIC, true, NULL,
		    commands, ARRAY_SIZE(commands),
		    notifs, ARRAY_SIZE(notifs),
		    NULL, 0,
		    NULL, 0,
		    NULL);

	return 0;
}
