#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/coin_mvt.h>
#include <common/node_id.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <inttypes.h>
#include <plugins/bkpr/account.h>
#include <plugins/bkpr/account_entry.h>
#include <plugins/bkpr/blockheights.h>
#include <plugins/bkpr/bookkeeper.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/channel_event.h>
#include <plugins/bkpr/onchain_fee.h>
#include <plugins/bkpr/rebalances.h>
#include <plugins/bkpr/recorder.h>
#include <plugins/bkpr/sql.h>
#include <plugins/libplugin.h>

struct chain_event **list_chain_events_timebox(const tal_t *ctx,
					       const struct bkpr *bkpr,
					       struct command *cmd,
					       u64 start_time,
					       u64 end_time)
{
	return chain_events_from_sql(ctx, bkpr, cmd,
				     SELECT_CHAIN_EVENTS
				     " WHERE timestamp > %"PRIu64
				     "  AND timestamp <= %"PRIu64
				     "  AND created_index <= %"PRIu64
				     " ORDER BY timestamp, created_index;",
				     start_time, end_time,
				     bkpr->chainmoves_index);
}

struct chain_event **list_chain_events(const tal_t *ctx,
				       const struct bkpr *bkpr,
				       struct command *cmd)
{
	return list_chain_events_timebox(ctx, bkpr, cmd, 0, SQLITE_MAX_UINT);
}

struct chain_event **account_get_chain_events(const tal_t *ctx,
					      const struct bkpr *bkpr,
					      struct command *cmd,
					      struct account *acct)
{
	return chain_events_from_sql(ctx, bkpr, cmd,
				     SELECT_CHAIN_EVENTS
				     " WHERE account_id = '%s'"
				     "  AND created_index <= %"PRIu64
				     " ORDER BY timestamp, created_index;",
				     sql_string(tmpctx, acct->name),
				     bkpr->chainmoves_index);
}

static struct chain_event **find_txos_for_tx(const tal_t *ctx,
					     const struct bkpr *bkpr,
					     struct command *cmd,
					     const struct bitcoin_txid *txid)
{
	return chain_events_from_sql(ctx, bkpr, cmd,
				     SELECT_CHAIN_EVENTS
				     /* utxo is txid:outnum */
				     " WHERE utxo LIKE '%s:%%'"
				     "  AND created_index <= %"PRIu64
				     " ORDER BY "
				     "  utxo"
				     ", spending_txid NULLS FIRST"
				     ", blockheight",
				     fmt_bitcoin_txid(tmpctx, txid),
				     bkpr->chainmoves_index);
}

static struct txo_pair *new_txo_pair(const tal_t *ctx)
{
	struct txo_pair *pr = tal(ctx, struct txo_pair);
	pr->txo = NULL;
	pr->spend = NULL;
	return pr;
}

static struct txo_set *find_txo_set(const tal_t *ctx,
				    const struct bkpr *bkpr,
				    struct command *cmd,
				    const struct bitcoin_txid *txid,
				    const char *acct_name,
				    bool *is_complete)
{
	struct txo_pair *pr;
	struct chain_event **evs;
	struct txo_set *txos = tal(ctx, struct txo_set);

	/* In some special cases (the opening tx), we only
	 * want the outputs that pertain to a given account,
	 * most other times we want all utxos, regardless of account */
	evs = find_txos_for_tx(ctx, bkpr, cmd, txid);
	txos->pairs = tal_arr(txos, struct txo_pair *, 0);
	txos->txid = tal_dup(txos, struct bitcoin_txid, txid);

	pr = NULL;

	/* If there's nothing for this txid, we're missing data */
	if (is_complete)
		*is_complete = tal_count(evs) > 0;

	for (size_t i = 0; i < tal_count(evs); i++) {
		struct chain_event *ev = evs[i];

		if (acct_name && !streq(ev->acct_name, acct_name))
			continue;

		if (ev->spending_txid) {
			if (!pr) {
				/* We're missing data!! */
				pr = new_txo_pair(txos->pairs);
				if (is_complete)
					*is_complete = false;
			} else {
				assert(pr->txo);
				/* Make sure it's the same txo */
				assert(bitcoin_outpoint_eq(&pr->txo->outpoint,
							   &ev->outpoint));
			}

			pr->spend = tal_steal(pr, ev);
			tal_arr_expand(&txos->pairs, pr);
			pr = NULL;
		} else {
			/* We might not have a spend event
			 * for everything */
			if (pr) {
				/* Disappear "channel_proposed" events */
				if (streq(pr->txo->tag,
					  mvt_tag_str(MVT_CHANNEL_PROPOSED)))
					pr = tal_free(pr);
				else
					tal_arr_expand(&txos->pairs, pr);
			}
			pr = new_txo_pair(txos->pairs);
			pr->txo = tal_steal(pr, ev);
		}
	}

	/* Might have a single entry 'pr' left over */
	if (pr)
		tal_arr_expand(&txos->pairs, pr);

	return txos;
}

static bool txid_in_list(struct bitcoin_txid **list,
			 struct bitcoin_txid *txid)
{
	for (size_t i = 0; i < tal_count(list); i++) {
		if (bitcoin_txid_eq(list[i], txid))
			return true;
	}

	return false;
}

bool find_txo_chain(const tal_t *ctx,
		    const struct bkpr *bkpr,
		    struct command *cmd,
		    const struct account *acct,
		    struct txo_set ***sets)
{
	struct bitcoin_txid **txids;
	struct chain_event *open_ev;
	bool is_complete = true;
	const char *start_acct_name;

	assert(acct->open_event_db_id);
	open_ev = find_chain_event_by_id(ctx, bkpr, cmd,
					 *acct->open_event_db_id);

	if (sets)
		*sets = tal_arr(ctx, struct txo_set *, 0);
	txids = tal_arr(ctx, struct bitcoin_txid *, 0);
	tal_arr_expand(&txids, &open_ev->outpoint.txid);

	/* We only want to filter by the account for the very
	 * first utxo that we get the tree for, so we
	 * start w/ this acct id... */
	start_acct_name = open_ev->acct_name;

	for (size_t i = 0; i < tal_count(txids); i++) {
		struct txo_set *set;
		bool set_complete;

		set = find_txo_set(ctx, bkpr, cmd, txids[i],
				   start_acct_name,
				   &set_complete);

		/* After first use, we free the acct dbid ptr,
		 * which will pass in NULL and not filter by
		 * account for any subsequent txo_set hunt */
		start_acct_name = NULL;

		is_complete &= set_complete;
		for (size_t j = 0; j < tal_count(set->pairs); j++) {
			struct txo_pair *pr = set->pairs[j];

			/* Has this been resolved? */
			if ((pr->txo
			     && is_channel_account(pr->txo->acct_name))
			     && !pr->spend)
				is_complete = false;

			/* wallet accts and zero-fee-htlc anchors
			 * might overlap txids */
			if (pr->spend
			    && pr->spend->spending_txid
			    /* 'to_miner' outputs are skipped */
			    && !streq(pr->spend->tag, "to_miner")
			    && !txid_in_list(txids, pr->spend->spending_txid)
			    /* We dont trace utxos for non related accts */
			    && (streq(pr->spend->acct_name, acct->name)
				/* Unless it's stealable, in which case
				 * we track the resolution of the htlc tx */
				|| pr->spend->stealable))
				tal_arr_expand(&txids,
					       pr->spend->spending_txid);
		}

		if (sets)
			tal_arr_expand(sets, set);
	}

	return is_complete;
}

const char *find_close_account_name(const tal_t *ctx,
				    const struct bkpr *bkpr,
				    struct command *cmd,
				    const struct bitcoin_txid *txid)
{
	const char *buf;
	const jsmntok_t *result, *rows, *row;
	size_t i;
	const char *acct_name = NULL;

	/* We look for a CHANNEL_CLOSE spend, but ignore “spliced” close events. */
	result = sql_req(ctx, cmd, &buf,
			 "SELECT account_id"
			 " FROM chainmoves cm"
			 " WHERE cm.primary_tag = '%s'"
			 "   AND cm.spending_txid = X'%s'"
			 "   AND NOT EXISTS ("
			 "         SELECT 1 FROM chainmoves_extra_tags et"
			 "         WHERE et.row = cm.created_index"
			 "           AND et.extra_tags = 'spliced'"
			 "       )"
			 "   AND"
			 "    cm.created_index <= %"PRIu64
			 " LIMIT 1",
			 sql_string(tmpctx, mvt_tag_str(MVT_CHANNEL_CLOSE)),
			 fmt_bitcoin_txid(tmpctx, txid),
			 bkpr->chainmoves_index);

	rows = json_get_member(buf, result, "rows");
	json_for_each_arr(i, row, rows) {
		/* Single column => row->size == 1; first value token is row+1 */
		const jsmntok_t *val = row + 1;
		acct_name = json_strdup(ctx, buf, val);
		break; /* only need the first row */
	}

	return acct_name; /* NULL if none found */
}

u64 account_onchain_closeheight(const struct bkpr *bkpr,
				struct command *cmd,
				const struct account *acct)
{
	const u8 *ctx = tal(NULL, u8);
	struct txo_set **sets;
	struct chain_event *close_ev;
	u64 height;

	assert(acct->closed_count > 0);

	close_ev = find_chain_event_by_id(ctx, bkpr, cmd,
					 *acct->closed_event_db_id);

	if (find_txo_chain(ctx, bkpr, cmd, acct, &sets)) {
		/* Ok now we find the max block height of the
		 * spending chain_events for this channel */
		bool ok;
		const char *buf;
		const jsmntok_t *result, *rows, *row;
		size_t i;

		/* Have we accounted for all the outputs */
		ok = false;
		for (i = 0; i < tal_count(sets); i++) {
			if (bitcoin_txid_eq(sets[i]->txid,
					    close_ev->spending_txid)) {

				ok = tal_count(sets[i]->pairs)
						== acct->closed_count;
				break;
			}
		}

		if (!ok) {
			tal_free(ctx);
			return 0;
		}

		result = sql_req(tmpctx, cmd, &buf,
				 "SELECT blockheight"
				 " FROM chainmoves"
				 " WHERE account_id = '%s'"
				 "   AND spending_txid IS NOT NULL"
				 "   AND created_index <= %"PRIu64
				 " ORDER BY blockheight DESC"
				 " LIMIT 1",
				 sql_string(tmpctx, acct->name),
				 bkpr->chainmoves_index);

		rows = json_get_member(buf, result, "rows");
		assert(rows && rows->type == JSMN_ARRAY);

		height = 0;
		json_for_each_arr(i, row, rows) {
			const jsmntok_t *val = row + 1;
			assert(row->size == 1);
			ok = json_to_u64(buf, val, &height);
			assert(ok);
			break;
		}
	} else {
		height = 0;
	}

	tal_free(ctx);
	return height;
}

struct chain_event *find_chain_event_by_id(const tal_t *ctx,
					   const struct bkpr *bkpr,
					   struct command *cmd,
					   u64 created_index)
{
	struct chain_event **evs =
		chain_events_from_sql(tmpctx, bkpr, cmd,
				      SELECT_CHAIN_EVENTS
				      " WHERE created_index = %"PRIu64
				      " LIMIT 1;",
				      created_index);

	if (tal_count(evs) == 0)
		return NULL;

	return tal_steal(ctx, evs[0]);
}

struct chain_event **get_chain_events_by_outpoint(const tal_t *ctx,
						  const struct bkpr *bkpr,
						  struct command *cmd,
						  const struct bitcoin_outpoint *outpoint)
{
	return chain_events_from_sql(ctx, bkpr, cmd,
				     SELECT_CHAIN_EVENTS
				     " WHERE utxo = '%s'"
				     "   AND credit_msat > 0"
				     "  AND created_index <= %"PRIu64
				     " ORDER BY timestamp, created_index",
				     fmt_bitcoin_outpoint(tmpctx, outpoint),
				     bkpr->chainmoves_index);
}

struct chain_event **get_chain_events_by_id(const tal_t *ctx,
					    const struct bkpr *bkpr,
					    struct command *cmd,
					    const struct sha256 *id)
{
	return chain_events_from_sql(ctx, bkpr, cmd,
				     SELECT_CHAIN_EVENTS
				     " WHERE payment_hash = X'%s'"
				     "   AND created_index <= %"PRIu64
				     " ORDER BY timestamp, created_index",
				     fmt_sha256(tmpctx, id),
				     bkpr->chainmoves_index);
}

bool account_get_credit_debit(const struct bkpr *bkpr,
			      struct command *cmd,
			      const char *acct_name,
			      struct amount_msat *credit,
			      struct amount_msat *debit)
{
	const jsmntok_t *result, *rows, *row;
	const char *buf;
	bool exists;

	/* Get sum from chain_events */
	result = sql_req(tmpctx, cmd, &buf,
			 "SELECT"
			 "  CAST(SUM(credit_msat) AS BIGINT)"
			 ", CAST(SUM(debit_msat) AS BIGINT)"
			 " FROM chainmoves"
			 " WHERE account_id = '%s'"
			 " AND created_index <= %"PRIu64,
			 sql_string(tmpctx, acct_name),
			 bkpr->chainmoves_index);
	rows = json_get_member(buf, result, "rows");
	assert(rows && rows->type == JSMN_ARRAY && rows->size == 1);
	row = rows + 1;
	assert(row->size == 2);
	if (json_tok_is_null(buf, row + 1)) {
		*credit = *debit = AMOUNT_MSAT(0);
		exists = false;
	} else {
		json_to_msat(buf, row + 1, credit);
		json_to_msat(buf, row + 2, debit);
		exists = true;
	}

	/* Get sum from channel_events */
	result = sql_req(tmpctx, cmd, &buf,
			 "SELECT"
			 "  CAST(SUM(credit_msat) AS BIGINT)"
			 ", CAST(SUM(debit_msat) AS BIGINT)"
			 " FROM channelmoves"
			 " WHERE account_id = '%s'"
			 " AND created_index <= %"PRIu64,
			 sql_string(tmpctx, acct_name),
			 bkpr->channelmoves_index);
	rows = json_get_member(buf, result, "rows");
	assert(rows && rows->type == JSMN_ARRAY && rows->size == 1);
	row = rows + 1;
	assert(row->size == 2);
	if (!json_tok_is_null(buf, row + 1)) {
		struct amount_msat channel_credit, channel_debit;
		json_to_msat(buf, row + 1, &channel_credit);
		json_to_msat(buf, row + 2, &channel_debit);

		if (!amount_msat_accumulate(credit, channel_credit)) {
			plugin_err(cmd->plugin, "db overflow: chain credit %s, adding channel credit %s",
				   fmt_amount_msat(tmpctx, *credit),
				   fmt_amount_msat(tmpctx, channel_credit));
		}

		if (!amount_msat_accumulate(debit, channel_debit)) {
			plugin_err(cmd->plugin, "db overflow: chain debit %s, adding channel debit %s",
				   fmt_amount_msat(tmpctx, *debit),
				   fmt_amount_msat(tmpctx, channel_debit));
		}
		exists = true;
	}
	return exists;
}

struct channel_event **list_channel_events_timebox(const tal_t *ctx,
						   const struct bkpr *bkpr,
						   struct command *cmd,
						   u64 start_time,
						   u64 end_time)
{
	return channel_events_from_sql(ctx, cmd,
				       SELECT_CHANNEL_EVENTS
				       " WHERE timestamp > %"PRIu64
				       "   AND timestamp <= %"PRIu64
				       "   AND created_index <= %"PRIu64
				       " ORDER BY timestamp, created_index;",
				       start_time, end_time,
				       bkpr->channelmoves_index);
}

struct channel_event **list_channel_events(const tal_t *ctx,
					   const struct bkpr *bkpr,
					   struct command *cmd)
{
	return list_channel_events_timebox(ctx, bkpr, cmd, 0, SQLITE_MAX_UINT);
}


struct channel_event **account_get_channel_events(const tal_t *ctx,
						  const struct bkpr *bkpr,
						  struct command *cmd,
						  struct account *acct)
{
	return channel_events_from_sql(ctx, cmd,
				       SELECT_CHANNEL_EVENTS
				       " WHERE account_id = '%s'"
				       "  AND created_index <= %"PRIu64
				       " ORDER BY timestamp, created_index",
				       sql_string(tmpctx, acct->name),
				       bkpr->channelmoves_index);
}

struct channel_event **get_channel_events_by_id(const tal_t *ctx,
						const struct bkpr *bkpr,
						struct command *cmd,
						const struct sha256 *id)
{
	return channel_events_from_sql(ctx, cmd,
				       SELECT_CHANNEL_EVENTS
				       " WHERE payment_hash = X'%s'"
				       "  AND created_index <= %"PRIu64
				       " ORDER BY timestamp, created_index",
				       fmt_sha256(tmpctx, id),
				       bkpr->channelmoves_index);
}

struct chain_event **find_chain_events_bytxid(const tal_t *ctx,
					      const struct bkpr *bkpr,
					      struct command *cmd,
					      const struct bitcoin_txid *txid)
{
	return chain_events_from_sql(ctx, bkpr, cmd,
				     SELECT_CHAIN_EVENTS
				     " WHERE created_index <= %"PRIu64
				     " AND (spending_txid = X'%s'"
				     "    OR (utxo LIKE '%s%%' AND spending_txid IS NULL))"
				     " ORDER BY account_id, created_index",
				     bkpr->chainmoves_index,
				     fmt_bitcoin_txid(tmpctx, txid),   /* spending_txid match */
				     fmt_bitcoin_txid(tmpctx, txid));  /* utxo prefix (txid:*) */
}

void maybe_record_rebalance(struct command *cmd,
			    struct bkpr *bkpr,
			    const struct channel_event *out)
{
	/* If there's a matching credit event, this is
	 * a rebalance. Mark everything with the payment_id
	 * and amt as such. If you repeat a payment_id
	 * with the same amt, they'll be marked as rebalances
	 * also */
	const char *buf;
	const jsmntok_t *res, *rows, *row, *val;
	size_t i;
	struct amount_msat credit;
	bool ok;

	/* The amount of we were credited is debit - fees */
	ok = amount_msat_sub(&credit, out->debit, out->fees);
	assert(ok);

	/* Look for a matching credit-side event for the same payment */
	res = sql_req(tmpctx, cmd, &buf,
		      "SELECT created_index"
		      " FROM channelmoves"
		      " WHERE payment_hash = X'%s'"
		      "   AND credit_msat = %"PRIu64
		      "   AND created_index <= %"PRIu64,
		      fmt_sha256(tmpctx, out->payment_id),
		      credit.millisatoshis /* Raw: sql query */,
		      bkpr->channelmoves_index);

	rows = json_get_member(buf, res, "rows");
	json_for_each_arr(i, row, rows) {
		u64 id;
		val = row + 1;              /* single column */
		ok = json_to_u64(buf, val, &id);
		assert(ok);

		/* Already has one? */
		if (find_rebalance(bkpr, id))
			continue;

		add_rebalance_pair(cmd, bkpr, out->db_id, id);
		break;
	}
}

void maybe_closeout_external_deposits(struct command *cmd,
				      struct bkpr *bkpr,
				      const struct bitcoin_txid *txid,
				      u32 blockheight)
{
	const char *buf;
	const jsmntok_t *res, *rows, *row;
	size_t i;

	/* Find any unconfirmed external deposits for this txid. */
	res = sql_req(tmpctx, cmd, &buf,
		      "SELECT utxo"
		      " FROM chainmoves"
		      " WHERE blockheight = 0"
		      "   AND utxo LIKE '%s:%%'"
		      "   AND account_id = '%s'"
		      "   AND created_index <= %"PRIu64,
		      /* utxo is '<txid>:<vout>' so we prefix-match on txid: */
		      fmt_bitcoin_txid(tmpctx, txid),
		      sql_string(tmpctx, ACCOUNT_NAME_EXTERNAL),
		      bkpr->chainmoves_index);

	rows = json_get_member(buf, res, "rows");
	json_for_each_arr(i, row, rows) {
		const jsmntok_t *val = row + 1; /* single column */
		struct bitcoin_outpoint outp;
		bool ok;

		ok = json_to_outpoint(buf, val, &outp);
		assert(ok);
		add_blockheight(cmd, bkpr, &outp.txid, blockheight);
	}
}

