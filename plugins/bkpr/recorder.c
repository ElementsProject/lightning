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
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/channel_event.h>
#include <plugins/bkpr/onchain_fee.h>
#include <plugins/bkpr/recorder.h>


static struct chain_event *stmt2chain_event(const tal_t *ctx, struct db_stmt *stmt)
{
	struct chain_event *e = tal(ctx, struct chain_event);
	e->db_id = db_col_u64(stmt, "e.id");
	e->acct_db_id = db_col_u64(stmt, "e.account_id");
	e->acct_name = db_col_strdup(e, stmt, "a.name");

	if (!db_col_is_null(stmt, "e.origin"))
		e->origin_acct = db_col_strdup(e, stmt, "e.origin");
	else
		e->origin_acct = NULL;

	e->tag = db_col_strdup(e, stmt, "e.tag");

	e->credit = db_col_amount_msat(stmt, "e.credit");
	e->debit = db_col_amount_msat(stmt, "e.debit");
	e->output_value = db_col_amount_msat(stmt, "e.output_value");

	e->currency = db_col_strdup(e, stmt, "e.currency");
	e->timestamp = db_col_u64(stmt, "e.timestamp");
	e->blockheight = db_col_int(stmt, "e.blockheight");

	db_col_txid(stmt, "e.utxo_txid", &e->outpoint.txid);
	e->outpoint.n = db_col_int(stmt, "e.outnum");

	if (!db_col_is_null(stmt, "e.payment_id")) {
		e->payment_id = tal(e, struct sha256);
		db_col_sha256(stmt, "e.payment_id", e->payment_id);
	} else
		e->payment_id = NULL;

	if (!db_col_is_null(stmt, "e.spending_txid")) {
		e->spending_txid = tal(e, struct bitcoin_txid);
		db_col_txid(stmt, "e.spending_txid", e->spending_txid);
	} else
		e->spending_txid = NULL;

	e->ignored = db_col_int(stmt, "e.ignored") == 1;
	e->stealable = db_col_int(stmt, "e.stealable") == 1;

	if (!db_col_is_null(stmt, "e.ev_desc"))
		e->desc = db_col_strdup(e, stmt, "e.ev_desc");
	else
		e->desc = NULL;

	return e;
}

static struct chain_event **find_chain_events(const tal_t *ctx,
					      struct db_stmt *stmt TAKES)
{
	struct chain_event **results;

	db_query_prepared(stmt);
	if (stmt->error)
		db_fatal(stmt->db, "find_chain_events err: %s", stmt->error);
	results = tal_arr(ctx, struct chain_event *, 0);
	while (db_step(stmt)) {
		struct chain_event *e = stmt2chain_event(results, stmt);
		tal_arr_expand(&results, e);
	}

	if (taken(stmt))
		tal_free(stmt);

	return results;
}

static struct channel_event *stmt2channel_event(const tal_t *ctx, struct db_stmt *stmt)
{
	struct channel_event *e = tal(ctx, struct channel_event);

	e->db_id = db_col_u64(stmt, "e.id");
	e->acct_db_id = db_col_u64(stmt, "e.account_id");
	e->acct_name = db_col_strdup(e, stmt, "a.name");

	e->tag = db_col_strdup(e, stmt, "e.tag");

	e->credit = db_col_amount_msat(stmt, "e.credit");
	e->debit = db_col_amount_msat(stmt, "e.debit");
	e->fees = db_col_amount_msat(stmt, "e.fees");

	e->currency = db_col_strdup(e, stmt, "e.currency");
	if (!db_col_is_null(stmt, "e.payment_id")) {
		e->payment_id = tal(e, struct sha256);
		db_col_sha256(stmt, "e.payment_id", e->payment_id);
	} else
		e->payment_id = NULL;
	e->part_id = db_col_int(stmt, "e.part_id");
	e->timestamp = db_col_u64(stmt, "e.timestamp");

	if (!db_col_is_null(stmt, "e.ev_desc"))
		e->desc = db_col_strdup(e, stmt, "e.ev_desc");
	else
		e->desc = NULL;

	if (!db_col_is_null(stmt, "e.rebalance_id")) {
		e->rebalance_id = tal(e, u64);
		*e->rebalance_id = db_col_u64(stmt, "e.rebalance_id");
	} else
		e->rebalance_id = NULL;

	return e;
}

static struct rebalance *stmt2rebalance(const tal_t *ctx, struct db_stmt *stmt)
{
	struct rebalance *r = tal(ctx, struct rebalance);

	r->in_ev_id = db_col_u64(stmt, "in_e.id");
	r->out_ev_id = db_col_u64(stmt, "out_e.id");
	r->in_acct_name = db_col_strdup(r, stmt, "in_acct.name");
	r->out_acct_name = db_col_strdup(r, stmt, "out_acct.name");
	r->rebal_msat = db_col_amount_msat(stmt, "in_e.credit");
	r->fee_msat = db_col_amount_msat(stmt, "out_e.fees");

	return r;
}

struct chain_event **list_chain_events_timebox(const tal_t *ctx,
					       struct db *db,
					       u64 start_time,
					       u64 end_time)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  e.id"
				     ", e.account_id"
				     ", a.name"
				     ", e.origin"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.output_value"
				     ", e.currency"
				     ", e.timestamp"
				     ", e.blockheight"
				     ", e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid"
				     ", e.payment_id"
				     ", e.ignored"
				     ", e.stealable"
				     ", e.ev_desc"
				     " FROM chain_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON e.account_id = a.id"
				     " WHERE e.timestamp > ?"
				     "  AND e.timestamp <= ?"
				     " ORDER BY e.timestamp, e.id;"));

	db_bind_u64(stmt, start_time);
	db_bind_u64(stmt, end_time);
	return find_chain_events(ctx, take(stmt));
}

struct chain_event **list_chain_events(const tal_t *ctx, struct db *db)
{
	return list_chain_events_timebox(ctx, db, 0, SQLITE_MAX_UINT);
}

struct chain_event **account_get_chain_events(const tal_t *ctx,
					      struct db *db,
					      struct account *acct)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  e.id"
				     ", e.account_id"
				     ", a.name"
				     ", e.origin"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.output_value"
				     ", e.currency"
				     ", e.timestamp"
				     ", e.blockheight"
				     ", e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid"
				     ", e.payment_id"
				     ", e.ignored"
				     ", e.stealable"
				     ", e.ev_desc"
				     " FROM chain_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON e.account_id = a.id"
				     " WHERE e.account_id = ?"
				     " ORDER BY e.timestamp, e.id"));

	db_bind_int(stmt, acct->db_id);
	return find_chain_events(ctx, take(stmt));
}

static struct chain_event **find_txos_for_tx(const tal_t *ctx,
					     struct db *db,
					     struct bitcoin_txid *txid)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  e.id"
				     ", e.account_id"
				     ", a.name"
				     ", e.origin"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.output_value"
				     ", e.currency"
				     ", e.timestamp"
				     ", e.blockheight"
				     ", e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid"
				     ", e.payment_id"
				     ", e.ignored"
				     ", e.stealable"
				     ", e.ev_desc"
				     " FROM chain_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON e.account_id = a.id"
				     " WHERE e.utxo_txid = ?"
				     " ORDER BY "
				     "  e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid NULLS FIRST"
				     ", e.blockheight"));

	db_bind_txid(stmt, txid);
	return find_chain_events(ctx, take(stmt));
}

struct fee_sum **calculate_onchain_fee_sums(const tal_t *ctx, struct db *db)
{
	struct db_stmt *stmt;
	struct fee_sum **sums;
	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  of.txid"
				     ", of.account_id"
				     ", a.name"
				     ", of.currency"
				     ", CAST(SUM(of.credit) AS BIGINT) as credit"
				     ", CAST(SUM(of.debit) AS BIGINT) as debit"
				     " FROM onchain_fees of"
				     " LEFT OUTER JOIN accounts a"
				     " ON of.account_id = a.id"
				     " GROUP BY of.txid"
				     ", of.account_id"
				     ", a.name"
				     ", of.currency"
				     " ORDER BY txid, account_id"));

	db_query_prepared(stmt);

	sums = tal_arr(ctx, struct fee_sum *, 0);
	while (db_step(stmt)) {
		struct fee_sum *sum;
		struct amount_msat debit;
		bool ok;

		sum = tal(sums, struct fee_sum);
		sum->txid = tal(sum, struct bitcoin_txid);

		db_col_txid(stmt, "of.txid", sum->txid);
		sum->acct_db_id = db_col_u64(stmt, "of.account_id");
		sum->acct_name = db_col_strdup(sum, stmt, "a.name");
		sum->currency = db_col_strdup(sum, stmt, "of.currency");
		sum->fees_paid = db_col_amount_msat(stmt, "credit");
		debit = db_col_amount_msat(stmt, "debit");

		ok = amount_msat_sub(&sum->fees_paid, sum->fees_paid,
				     debit);
		assert(ok);
		tal_arr_expand(&sums, sum);
	}

	tal_free(stmt);
	return sums;
}

u64 onchain_fee_last_timestamp(struct db *db,
			       u64 acct_db_id,
			       struct bitcoin_txid *txid)
{
	struct db_stmt *stmt;
	u64 timestamp;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  timestamp"
				     " FROM onchain_fees"
				     " WHERE account_id = ?"
				     " AND txid = ?"
				     " ORDER BY timestamp DESC"));


	db_bind_u64(stmt, acct_db_id);
	db_bind_txid(stmt, txid);
	db_query_prepared(stmt);

	if (db_step(stmt))
		timestamp = db_col_u64(stmt, "timestamp");
	else
		timestamp = 0;

	tal_free(stmt);
	return timestamp;
}

struct fee_sum **find_account_onchain_fees(const tal_t *ctx,
					   struct db *db,
					   struct account *acct)
{
	struct db_stmt *stmt;
	struct fee_sum **sums;
	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  txid"
				     ", CAST(SUM(credit) AS BIGINT) as credit"
				     ", CAST(SUM(debit) AS BIGINT) as debit"
				     " FROM onchain_fees"
				     " WHERE account_id = ?"
				     " GROUP BY txid"
				     " ORDER BY txid"));

	db_bind_u64(stmt, acct->db_id);
	db_query_prepared(stmt);

	sums = tal_arr(ctx, struct fee_sum *, 0);
	while (db_step(stmt)) {
		struct fee_sum *sum;
		struct amount_msat amt;
		bool ok;

		sum = tal(sums, struct fee_sum);
		sum->acct_db_id = acct->db_id;
		sum->txid = tal(sum, struct bitcoin_txid);
		db_col_txid(stmt, "txid", sum->txid);

		sum->fees_paid = db_col_amount_msat(stmt, "credit");
		amt = db_col_amount_msat(stmt, "debit");
		ok = amount_msat_sub(&sum->fees_paid, sum->fees_paid, amt);
		assert(ok);
		tal_arr_expand(&sums, sum);
	}

	tal_free(stmt);
	return sums;
}

static struct txo_pair *new_txo_pair(const tal_t *ctx)
{
	struct txo_pair *pr = tal(ctx, struct txo_pair);
	pr->txo = NULL;
	pr->spend = NULL;
	return pr;
}

static struct txo_set *find_txo_set(const tal_t *ctx,
				    struct db *db,
				    struct bitcoin_txid *txid,
				    u64 *acct_db_id,
				    bool *is_complete)
{
	struct txo_pair *pr;
	struct chain_event **evs;
	struct txo_set *txos = tal(ctx, struct txo_set);

	/* In some special cases (the opening tx), we only
	 * want the outputs that pertain to a given account,
	 * most other times we want all utxos, regardless of account */
	evs = find_txos_for_tx(ctx, db, txid);
	txos->pairs = tal_arr(txos, struct txo_pair *, 0);
	txos->txid = tal_dup(txos, struct bitcoin_txid, txid);

	pr = NULL;

	/* If there's nothing for this txid, we're missing data */
	if (is_complete)
		*is_complete = tal_count(evs) > 0;

	for (size_t i = 0; i < tal_count(evs); i++) {
		struct chain_event *ev = evs[i];

		if (acct_db_id && ev->acct_db_id != *acct_db_id)
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
					  mvt_tag_str(CHANNEL_PROPOSED)))
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

static bool is_channel_acct(struct chain_event *ev)
{
	return !streq(ev->acct_name, WALLET_ACCT)
		&& !streq(ev->acct_name, EXTERNAL_ACCT);
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
		    struct db *db,
		    struct account *acct,
		    struct txo_set ***sets)
{
	struct bitcoin_txid **txids;
	struct chain_event *open_ev;
	bool is_complete = true;
	u64 *start_acct_id = tal(NULL, u64);

	assert(acct->open_event_db_id);
	open_ev = find_chain_event_by_id(ctx, db,
					 *acct->open_event_db_id);

	if (sets)
		*sets = tal_arr(ctx, struct txo_set *, 0);
	txids = tal_arr(ctx, struct bitcoin_txid *, 0);
	tal_arr_expand(&txids, &open_ev->outpoint.txid);

	/* We only want to filter by the account for the very
	 * first utxo that we get the tree for, so we
	 * start w/ this acct id... */
	*start_acct_id = open_ev->acct_db_id;

	for (size_t i = 0; i < tal_count(txids); i++) {
		struct txo_set *set;
		bool set_complete;

		set = find_txo_set(ctx, db, txids[i],
				   start_acct_id,
				   &set_complete);

		/* After first use, we free the acct dbid ptr,
		 * which will pass in NULL and not filter by
		 * account for any subsequent txo_set hunt */
		if (start_acct_id)
			start_acct_id = tal_free(start_acct_id);

		is_complete &= set_complete;
		for (size_t j = 0; j < tal_count(set->pairs); j++) {
			struct txo_pair *pr = set->pairs[j];

			/* Has this been resolved? */
			if ((pr->txo
			     && is_channel_acct(pr->txo))
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
			    && (pr->spend->acct_db_id == acct->db_id
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

struct account *find_close_account(const tal_t *ctx,
				   struct db *db,
				   struct bitcoin_txid *txid)
{
	struct db_stmt *stmt;
	struct account *close_acct;
	char *acct_name;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  a.name"
				     " FROM chain_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON e.account_id = a.id"
				     " WHERE "
				     "  e.tag = ?"
				     "  AND e.spending_txid = ?"));

	db_bind_text(stmt, mvt_tag_str(CHANNEL_CLOSE));
	db_bind_txid(stmt, txid);
	db_query_prepared(stmt);

	if (db_step(stmt)) {
		acct_name = db_col_strdup(stmt, stmt, "a.name");
		close_acct = find_account(ctx, db, acct_name);
	} else
		close_acct = NULL;

	tal_free(stmt);
	return close_acct;
}

void maybe_mark_account_onchain(struct db *db, struct account *acct)
{
	const u8 *ctx = tal(NULL, u8);
	struct txo_set **sets;
	struct chain_event *close_ev;
	struct db_stmt *stmt;

	assert(acct->closed_count > 0);

	close_ev = find_chain_event_by_id(ctx, db,
					 *acct->closed_event_db_id);

	if (find_txo_chain(ctx, db, acct, &sets)) {
		/* Ok now we find the max block height of the
		 * spending chain_events for this channel */
		bool ok;

		/* Have we accounted for all the outputs */
		ok = false;
		for (size_t i = 0; i < tal_count(sets); i++) {
			if (bitcoin_txid_eq(sets[i]->txid,
					    close_ev->spending_txid)) {

				ok = tal_count(sets[i]->pairs)
						== acct->closed_count;
				break;
			}
		}

		if (!ok) {
			tal_free(ctx);
			return;
		}

		stmt = db_prepare_v2(db, SQL("SELECT"
				     " blockheight"
				     " FROM chain_events"
				     " WHERE account_id = ?"
				     "  AND spending_txid IS NOT NULL"
				     " ORDER BY blockheight DESC"
				     " LIMIT 1"));

		db_bind_u64(stmt, acct->db_id);
		db_query_prepared(stmt);
		ok = db_step(stmt);
		assert(ok);

		acct->onchain_resolved_block = db_col_int(stmt, "blockheight");
		tal_free(stmt);

		/* Ok, now we update the account with this blockheight */
		stmt = db_prepare_v2(db, SQL("UPDATE accounts SET"
					     "  onchain_resolved_block = ?"
					     " WHERE"
					     " id = ?"));
		db_bind_int(stmt, acct->onchain_resolved_block);
		db_bind_u64(stmt, acct->db_id);
		db_exec_prepared_v2(take(stmt));
	}

	tal_free(ctx);
}

void add_payment_hash_desc(struct db *db,
			   struct sha256 *payment_hash,
			   const char *desc)
{
	struct db_stmt *stmt;

	/* Ok, now we update the account with this blockheight */
	stmt = db_prepare_v2(db, SQL("UPDATE channel_events SET"
				     "  ev_desc = ?"
				     " WHERE"
				     " payment_id = ?"));
	db_bind_text(stmt, desc);
	db_bind_sha256(stmt, payment_hash);
	db_exec_prepared_v2(take(stmt));

	/* Ok, now we update the account with this blockheight */
	stmt = db_prepare_v2(db, SQL("UPDATE chain_events SET"
				     "  ev_desc = ?"
				     " WHERE"
				     " payment_id = ?"));
	db_bind_text(stmt, desc);
	db_bind_sha256(stmt, payment_hash);
	db_exec_prepared_v2(take(stmt));
}

struct chain_event *find_chain_event_by_id(const tal_t *ctx,
					   struct db *db,
					   u64 event_db_id)
{
	struct db_stmt *stmt;
	struct chain_event *e;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  e.id"
				     ", e.account_id"
				     ", a.name"
				     ", e.origin"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.output_value"
				     ", e.currency"
				     ", e.timestamp"
				     ", e.blockheight"
				     ", e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid"
				     ", e.payment_id"
				     ", e.ignored"
				     ", e.stealable"
				     ", e.ev_desc"
				     " FROM chain_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON e.account_id = a.id"
				     " WHERE "
				     " e.id = ?"));

	db_bind_u64(stmt, event_db_id);
	db_query_prepared(stmt);
	if (db_step(stmt))
		e = stmt2chain_event(ctx, stmt);
	else
		e = NULL;

	tal_free(stmt);
	return e;
}

static struct chain_event *find_chain_event(const tal_t *ctx,
					    struct db *db,
					    const struct account *acct,
					    const struct bitcoin_outpoint *outpoint,
					    const struct bitcoin_txid *spending_txid,
					    const char *tag)

{
	struct db_stmt *stmt;
	struct chain_event *e;

	if (spending_txid) {
		stmt = db_prepare_v2(db, SQL("SELECT"
					     "  e.id"
					     ", e.account_id"
					     ", a.name"
					     ", e.origin"
					     ", e.tag"
					     ", e.credit"
					     ", e.debit"
					     ", e.output_value"
					     ", e.currency"
					     ", e.timestamp"
					     ", e.blockheight"
					     ", e.utxo_txid"
					     ", e.outnum"
					     ", e.spending_txid"
					     ", e.payment_id"
					     ", e.ignored"
					     ", e.stealable"
					     ", e.ev_desc"
					     " FROM chain_events e"
					     " LEFT OUTER JOIN accounts a"
					     " ON e.account_id = a.id"
					     " WHERE "
					     " e.spending_txid = ?"
					     " AND e.account_id = ?"
					     " AND e.utxo_txid = ?"
					     " AND e.outnum = ?"));
		db_bind_txid(stmt, spending_txid);
	} else {
		stmt = db_prepare_v2(db, SQL("SELECT"
					     "  e.id"
					     ", e.account_id"
					     ", a.name"
					     ", e.origin"
					     ", e.tag"
					     ", e.credit"
					     ", e.debit"
					     ", e.output_value"
					     ", e.currency"
					     ", e.timestamp"
					     ", e.blockheight"
					     ", e.utxo_txid"
					     ", e.outnum"
					     ", e.spending_txid"
					     ", e.payment_id"
					     ", e.ignored"
					     ", e.stealable"
					     ", e.ev_desc"
					     " FROM chain_events e"
					     " LEFT OUTER JOIN accounts a"
					     " ON e.account_id = a.id"
					     " WHERE "
					     " e.tag = ?"
					     " AND e.account_id = ?"
					     " AND e.utxo_txid = ?"
					     " AND e.outnum = ?"
					     " AND e.spending_txid IS NULL"));
		db_bind_text(stmt, tag);
	}

	db_bind_u64(stmt, acct->db_id);
	db_bind_txid(stmt, &outpoint->txid);
	db_bind_int(stmt, outpoint->n);

	db_query_prepared(stmt);
	if (db_step(stmt))
		e = stmt2chain_event(ctx, stmt);
	else
		e = NULL;

	tal_free(stmt);
	return e;
}

char *account_get_balance(const tal_t *ctx,
			  struct db *db,
			  const char *acct_name,
			  bool calc_sum,
			  bool skip_ignored,
			  struct acct_balance ***balances,
			  bool *account_exists)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  CAST(SUM(ce.credit) AS BIGINT) as credit"
				     ", CAST(SUM(ce.debit) AS BIGINT) as debit"
				     ", ce.currency"
				     " FROM chain_events ce"
				     " LEFT OUTER JOIN accounts a"
				     " ON a.id = ce.account_id"
				     " WHERE a.name = ?"
				     " AND ce.ignored != ?"
				     " GROUP BY ce.currency"));

	db_bind_text(stmt, acct_name);
	/* We populate ignored with a 0 or 1,
	 * if we want both 0+1, we just ignore everything with a 2 */
	db_bind_int(stmt, skip_ignored ? 1 : 2);
	db_query_prepared(stmt);
	*balances = tal_arr(ctx, struct acct_balance *, 0);
	if (account_exists)
		*account_exists = false;

	while (db_step(stmt)) {
		struct acct_balance *bal;

		bal = tal(*balances, struct acct_balance);

		bal->currency = db_col_strdup(bal, stmt, "ce.currency");
		bal->credit = db_col_amount_msat(stmt, "credit");
		bal->debit = db_col_amount_msat(stmt, "debit");
		tal_arr_expand(balances, bal);

		if (account_exists)
			*account_exists = true;
	}
	tal_free(stmt);

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  CAST(SUM(ce.credit) AS BIGINT) as credit"
				     ", CAST(SUM(ce.debit) AS BIGINT) as debit"
				     ", ce.currency"
				     " FROM channel_events ce"
				     " LEFT OUTER JOIN accounts a"
				     " ON a.id = ce.account_id"
				     " WHERE a.name = ?"
				     " GROUP BY ce.currency"));
	db_bind_text(stmt, acct_name);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		struct amount_msat amt;
		struct acct_balance *bal = NULL;
		char *currency;

		currency = db_col_strdup(ctx, stmt, "ce.currency");

		/* Find the currency entry from above */
		for (size_t i = 0; i < tal_count(*balances); i++) {
			if (streq((*balances)[i]->currency, currency)) {
				bal = (*balances)[i];
				break;
			}
		}

		if (!bal) {
			bal = tal(*balances, struct acct_balance);
			bal->credit = AMOUNT_MSAT(0);
			bal->debit = AMOUNT_MSAT(0);
			bal->currency = tal_steal(bal, currency);
			tal_arr_expand(balances, bal);
		}

		amt = db_col_amount_msat(stmt, "credit");
		if (!amount_msat_add(&bal->credit, bal->credit, amt)) {
			tal_free(stmt);
			return "overflow adding channel_event credits";
		}

		amt = db_col_amount_msat(stmt, "debit");
		if (!amount_msat_add(&bal->debit, bal->debit, amt)) {
			tal_free(stmt);
			return "overflow adding channel_event debits";
		}
	}
	tal_free(stmt);

	if (!calc_sum)
		return NULL;

	for (size_t i = 0; i < tal_count(*balances); i++) {
		struct acct_balance *bal = (*balances)[i];
		if (!amount_msat_sub(&bal->balance, bal->credit, bal->debit))
			return tal_fmt(ctx,
				"%s channel balance is negative? %s - %s",
				bal->currency,
				fmt_amount_msat(ctx, bal->credit),
				fmt_amount_msat(ctx, bal->debit));
	}

	return NULL;
}

struct channel_event **list_channel_events_timebox(const tal_t *ctx,
						   struct db *db,
						   u64 start_time,
						   u64 end_time)

{
	struct db_stmt *stmt;
	struct channel_event **results;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  e.id"
				     ", e.account_id"
				     ", a.name"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.fees"
				     ", e.currency"
				     ", e.payment_id"
				     ", e.part_id"
				     ", e.timestamp"
				     ", e.ev_desc"
				     ", e.rebalance_id"
				     " FROM channel_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON a.id = e.account_id"
				     " WHERE e.timestamp > ?"
				     "  AND e.timestamp <= ?"
				     " ORDER BY e.timestamp, e.id;"));

	db_bind_u64(stmt, start_time);
	db_bind_u64(stmt, end_time);
	db_query_prepared(stmt);

	results = tal_arr(ctx, struct channel_event *, 0);
	while (db_step(stmt)) {
		struct channel_event *e = stmt2channel_event(results, stmt);
		tal_arr_expand(&results, e);
	}
	tal_free(stmt);

	return results;
}

struct channel_event **list_channel_events(const tal_t *ctx, struct db *db)
{
	return list_channel_events_timebox(ctx, db, 0, SQLITE_MAX_UINT);
}


struct channel_event **account_get_channel_events(const tal_t *ctx,
						  struct db *db,
						  struct account *acct)
{
	struct db_stmt *stmt;
	struct channel_event **results;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  e.id"
				     ", a.name"
				     ", e.account_id"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.fees"
				     ", e.currency"
				     ", e.payment_id"
				     ", e.part_id"
				     ", e.timestamp"
				     ", e.ev_desc"
				     ", e.rebalance_id"
				     " FROM channel_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON a.id = e.account_id"
				     " WHERE e.account_id = ?"
				     " ORDER BY e.timestamp, e.id"));

	db_bind_u64(stmt, acct->db_id);
	db_query_prepared(stmt);

	results = tal_arr(ctx, struct channel_event *, 0);
	while (db_step(stmt)) {
		struct channel_event *e = stmt2channel_event(results, stmt);
		tal_arr_expand(&results, e);
	}
	tal_free(stmt);

	return results;
}

static struct onchain_fee *stmt2onchain_fee(const tal_t *ctx,
					    struct db_stmt *stmt)
{
	struct onchain_fee *of = tal(ctx, struct onchain_fee);

	of->acct_db_id = db_col_u64(stmt, "of.account_id");
	of->acct_name = db_col_strdup(of, stmt, "a.name");
	db_col_txid(stmt, "of.txid", &of->txid);
	of->credit = db_col_amount_msat(stmt, "of.credit");
	of->debit = db_col_amount_msat(stmt, "of.debit");
	of->currency = db_col_strdup(of, stmt, "of.currency");
	of->timestamp = db_col_u64(stmt, "of.timestamp");
	of->update_count = db_col_int(stmt, "of.update_count");

	return of;
}

struct onchain_fee **account_get_chain_fees(const tal_t *ctx, struct db *db,
					    struct account *acct)
{
	struct db_stmt *stmt;
	struct onchain_fee **results;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  of.account_id"
				     ", a.name"
				     ", of.txid"
				     ", of.credit"
				     ", of.debit"
				     ", of.currency"
				     ", of.timestamp"
				     ", of.update_count"
				     " FROM onchain_fees of"
				     " LEFT OUTER JOIN accounts a"
				     " ON a.id = of.account_id"
				     " WHERE of.account_id = ?"
				     " ORDER BY "
				     "  of.timestamp"
				     ", of.txid"
				     ", of.update_count"));

	db_bind_u64(stmt, acct->db_id);
	db_query_prepared(stmt);

	results = tal_arr(ctx, struct onchain_fee *, 0);
	while (db_step(stmt)) {
		struct onchain_fee *of = stmt2onchain_fee(results, stmt);
		tal_arr_expand(&results, of);
	}
	tal_free(stmt);

	return results;
}

struct onchain_fee **list_chain_fees_timebox(const tal_t *ctx, struct db *db,
					     u64 start_time, u64 end_time)
{
	struct db_stmt *stmt;
	struct onchain_fee **results;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  of.account_id"
				     ", a.name"
				     ", of.txid"
				     ", of.credit"
				     ", of.debit"
				     ", of.currency"
				     ", of.timestamp"
				     ", of.update_count"
				     " FROM onchain_fees of"
				     " LEFT OUTER JOIN accounts a"
				     " ON a.id = of.account_id"
				     " WHERE timestamp > ?"
				     "  AND timestamp <= ?"
				     " ORDER BY "
				     "  of.timestamp"
				     ", of.account_id"
				     ", of.txid"
				     ", of.update_count"));

	db_bind_u64(stmt, start_time);
	db_bind_u64(stmt, end_time);
	db_query_prepared(stmt);

	results = tal_arr(ctx, struct onchain_fee *, 0);
	while (db_step(stmt)) {
		struct onchain_fee *of = stmt2onchain_fee(results, stmt);
		tal_arr_expand(&results, of);
	}
	tal_free(stmt);

	return results;
}

struct onchain_fee **list_chain_fees(const tal_t *ctx, struct db *db)
{
	return list_chain_fees_timebox(ctx, db, 0, SQLITE_MAX_UINT);
}

static struct account *stmt2account(const tal_t *ctx, struct db_stmt *stmt)
{
	struct account *a = tal(ctx, struct account);

	a->db_id = db_col_u64(stmt, "id");
	a->name = db_col_strdup(a, stmt, "name");

	if (!db_col_is_null(stmt, "peer_id")) {
		a->peer_id = tal(a, struct node_id);
		db_col_node_id(stmt, "peer_id", a->peer_id);
	} else
		a->peer_id = NULL;
	a->is_wallet = db_col_int(stmt, "is_wallet") != 0;
	a->we_opened = db_col_int(stmt, "we_opened") != 0;
	a->leased = db_col_int(stmt, "leased") != 0;

	if (!db_col_is_null(stmt, "onchain_resolved_block")) {
		a->onchain_resolved_block = db_col_int(stmt, "onchain_resolved_block");
	} else
		a->onchain_resolved_block = 0;

	if (!db_col_is_null(stmt, "opened_event_id")) {
		a->open_event_db_id = tal(a, u64);
		*a->open_event_db_id = db_col_u64(stmt, "opened_event_id");
	} else
		a->open_event_db_id = NULL;

	if (!db_col_is_null(stmt, "closed_event_id")) {
		a->closed_event_db_id = tal(a, u64);
		*a->closed_event_db_id = db_col_u64(stmt, "closed_event_id");
	} else
		a->closed_event_db_id = NULL;

	a->closed_count = db_col_int(stmt, "closed_count");

	return a;
}

struct account *find_account(const tal_t *ctx,
			     struct db *db,
			     const char *name)
{
	struct db_stmt *stmt;
	struct account *a;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  id"
				     ", name"
				     ", peer_id"
				     ", opened_event_id"
				     ", closed_event_id"
				     ", onchain_resolved_block"
				     ", is_wallet"
				     ", we_opened"
				     ", leased"
				     ", closed_count"
				     " FROM accounts"
				     " WHERE name = ?"));

	db_bind_text(stmt, name);
	db_query_prepared(stmt);

	if (db_step(stmt))
		a = stmt2account(ctx, stmt);
	else
		a = NULL;

	tal_free(stmt);

	return a;
}

struct onchain_fee **account_onchain_fees(const tal_t *ctx,
					  struct db *db,
					  struct account *acct)
{
	struct db_stmt *stmt;
	struct onchain_fee **results;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  of.account_id"
				     ", a.name"
				     ", of.txid"
				     ", of.credit"
				     ", of.debit"
				     ", of.currency"
				     ", of.timestamp"
				     ", of.update_count"
				     " FROM onchain_fees of"
				     " LEFT OUTER JOIN accounts a"
				     " ON a.id = of.account_id"
				     " WHERE of.account_id = ?;"));

	db_bind_u64(stmt, acct->db_id);
	db_query_prepared(stmt);

	results = tal_arr(ctx, struct onchain_fee *, 0);
	while (db_step(stmt)) {
		struct onchain_fee *of = stmt2onchain_fee(results, stmt);
		tal_arr_expand(&results, of);
	}
	tal_free(stmt);

	return results;
}

struct account **list_accounts(const tal_t *ctx, struct db *db)
{
	struct db_stmt *stmt;
	struct account **results;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  id"
				     ", name"
				     ", peer_id"
				     ", opened_event_id"
				     ", closed_event_id"
				     ", onchain_resolved_block"
				     ", is_wallet"
				     ", we_opened"
				     ", leased"
				     ", closed_count"
				     " FROM accounts;"));
	db_query_prepared(stmt);

	results = tal_arr(ctx, struct account *, 0);
	while (db_step(stmt)) {
		struct account *a = stmt2account(results, stmt);
		tal_arr_expand(&results, a);
	}
	tal_free(stmt);

	return results;
}

void account_add(struct db *db, struct account *acct)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("INSERT INTO accounts"
				     " ("
				     "  name"
				     ", peer_id"
				     ", is_wallet"
				     ", we_opened"
				     ", leased"
				     ")"
				     " VALUES"
				     " (?, ?, ?, ?, ?);"));

	db_bind_text(stmt, acct->name);
	if (acct->peer_id)
		db_bind_node_id(stmt, acct->peer_id);
	else
		db_bind_null(stmt);
	db_bind_int(stmt, acct->is_wallet ? 1 : 0);
	db_bind_int(stmt, acct->we_opened ? 1 : 0);
	db_bind_int(stmt, acct->leased ? 1 : 0);

	db_exec_prepared_v2(stmt);
	acct->db_id = db_last_insert_id_v2(stmt);
	tal_free(stmt);
}

void maybe_update_account(struct db *db,
			  struct account *acct,
			  struct chain_event *e,
			  const enum mvt_tag *tags,
			  u32 closed_count,
			  struct node_id *peer_id)
{
	struct db_stmt *stmt;
	bool updated = false;

	for (size_t i = 0; i < tal_count(tags); i++) {
		switch (tags[i]) {
			case CHANNEL_PROPOSED:
			case CHANNEL_OPEN:
				updated = true;
				acct->open_event_db_id = tal(acct, u64);
				*acct->open_event_db_id = e->db_id;
				break;
			case CHANNEL_CLOSE:
				updated = true;
				acct->closed_event_db_id = tal(acct, u64);
				*acct->closed_event_db_id = e->db_id;
				break;
			case LEASED:
				updated = true;
				acct->leased = true;
				break;
			case OPENER:
				updated = true;
				acct->we_opened = true;
				break;
			case DEPOSIT:
			case WITHDRAWAL:
			case PENALTY:
			case INVOICE:
			case ROUTED:
			case PUSHED:
			case CHANNEL_TO_US:
			case HTLC_TIMEOUT:
			case HTLC_FULFILL:
			case HTLC_TX:
			case TO_WALLET:
			case IGNORED:
			case ANCHOR:
			case TO_THEM:
			case PENALIZED:
			case STOLEN:
			case TO_MINER:
			case LEASE_FEE:
			case STEALABLE:
			case SPLICE:
				/* Ignored */
				break;
		}
	}

	if (peer_id) {
		updated = true;
		acct->peer_id = tal_dup(acct, struct node_id, peer_id);
	}

	if (closed_count > 0) {
		updated = true;
		acct->closed_count = closed_count;
	}

	/* Nothing new here */
	if (!updated)
		return;

	/* Otherwise, we update the account ! */
	stmt = db_prepare_v2(db, SQL("UPDATE accounts SET"
				     "  opened_event_id = ?"
				     ", closed_event_id = ?"
				     ", we_opened = ?"
				     ", leased = ?"
				     ", closed_count = ?"
				     ", peer_id = ?"
				     " WHERE"
				     " name = ?"));

	if (acct->open_event_db_id)
		db_bind_u64(stmt, *acct->open_event_db_id);
	else
		db_bind_null(stmt);

	if (acct->closed_event_db_id)
		db_bind_u64(stmt, *acct->closed_event_db_id);
	else
		db_bind_null(stmt);

	db_bind_int(stmt, acct->we_opened ? 1 : 0);
	db_bind_int(stmt, acct->leased ? 1 : 0);
	db_bind_int(stmt, acct->closed_count);
	if (acct->peer_id)
		db_bind_node_id(stmt, acct->peer_id);
	else
		db_bind_null(stmt);

	db_bind_text(stmt, acct->name);

	db_exec_prepared_v2(take(stmt));
}

void log_channel_event(struct db *db,
		       const struct account *acct,
		       struct channel_event *e)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("INSERT INTO channel_events"
				     " ("
				     "  account_id"
				     ", tag"
				     ", credit"
				     ", debit"
				     ", fees"
				     ", currency"
				     ", payment_id"
				     ", part_id"
				     ", timestamp"
				     ", ev_desc"
				     ", rebalance_id"
				     ")"
				     " VALUES"
				     " (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"));

	db_bind_u64(stmt, acct->db_id);
	db_bind_text(stmt, e->tag);
	db_bind_amount_msat(stmt, &e->credit);
	db_bind_amount_msat(stmt, &e->debit);
	db_bind_amount_msat(stmt, &e->fees);
	db_bind_text(stmt, e->currency);
	if (e->payment_id)
		db_bind_sha256(stmt, e->payment_id);
	else
		db_bind_null(stmt);
	db_bind_int(stmt, e->part_id);
	db_bind_u64(stmt, e->timestamp);
	if (e->desc)
		db_bind_text(stmt, e->desc);
	else
		db_bind_null(stmt);

	if (e->rebalance_id)
		db_bind_u64(stmt, *e->rebalance_id);
	else
		db_bind_null(stmt);

	db_exec_prepared_v2(stmt);
	e->db_id = db_last_insert_id_v2(stmt);
	e->acct_db_id = acct->db_id;
	e->acct_name = tal_strdup(e, acct->name);
	tal_free(stmt);
}

static struct chain_event **find_chain_events_bytxid(const tal_t *ctx, struct db *db,
						     struct bitcoin_txid *txid)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT "
				     "  e.id"
				     ", e.account_id"
				     ", a.name"
				     ", e.origin"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.output_value"
				     ", e.currency"
				     ", e.timestamp"
				     ", e.blockheight"
				     ", e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid"
				     ", e.payment_id"
				     ", e.ignored"
				     ", e.stealable"
				     ", e.ev_desc"
				     " FROM chain_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON a.id = e.account_id"
				     " WHERE e.spending_txid = ?"
				     " OR (e.utxo_txid = ? AND e.spending_txid IS NULL)"
				     " ORDER BY e.account_id"));

	db_bind_txid(stmt, txid);
	db_bind_txid(stmt, txid);
	return find_chain_events(ctx, take(stmt));
}

static u64 find_acct_id(struct db *db, const char *name)
{
	u64 acct_id;
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  id"
				     " FROM accounts"
				     " WHERE name = ?"));

	db_bind_text(stmt, name);
	db_query_prepared(stmt);
	if (db_step(stmt))
		acct_id = db_col_u64(stmt, "id");
	else
		acct_id = 0;

	tal_free(stmt);
	return acct_id;
}

static void insert_chain_fees_diff(struct db *db,
				   u64 acct_id,
				   struct bitcoin_txid *txid,
				   struct amount_msat amount,
				   const char *currency,
				   u64 timestamp)
{
	struct db_stmt *stmt;
	u32 update_count;
	struct amount_msat current_amt, credit, debit;

	/* First, look to see if there's an already existing
	 * record to update */
	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  update_count"
				     ", credit"
				     ", debit"
				     " FROM onchain_fees"
				     " WHERE txid = ?"
				     " AND account_id = ?"
				     " ORDER BY update_count"));

	db_bind_txid(stmt, txid);
	db_bind_u64(stmt, acct_id);
	db_query_prepared(stmt);

	/* If there's no current record, add it */
	current_amt = AMOUNT_MSAT(0);
	update_count = 0;
	while (db_step(stmt)) {
		update_count = db_col_int(stmt, "update_count");
		credit = db_col_amount_msat(stmt, "credit");
		debit = db_col_amount_msat(stmt, "debit");

		/* These should apply perfectly, as we sorted them by
		 * insert order */
		if (!amount_msat_add(&current_amt, current_amt, credit))
			db_fatal(db, "Overflow when adding onchain fees");

		if (!amount_msat_sub(&current_amt, current_amt, debit))
			db_fatal(db, "Underflow when subtracting onchain fees");

	}
	tal_free(stmt);

	/* If they're already equal, no need to update */
	if (amount_msat_eq(current_amt, amount))
		return;

	if (!amount_msat_sub(&credit, amount, current_amt)) {
		credit = AMOUNT_MSAT(0);
		if (!amount_msat_sub(&debit, current_amt, amount))
			db_fatal(db, "shouldn't happen, unable to subtract");
	} else
		debit = AMOUNT_MSAT(0);

	stmt = db_prepare_v2(db, SQL("INSERT INTO onchain_fees"
				     " ("
				     "  account_id"
				     ", txid"
				     ", credit"
				     ", debit"
				     ", currency"
				     ", timestamp"
				     ", update_count"
				     ") VALUES"
				     " (?, ?, ?, ?, ?, ?, ?);"));

	db_bind_u64(stmt, acct_id);
	db_bind_txid(stmt, txid);
	db_bind_amount_msat(stmt, &credit);
	db_bind_amount_msat(stmt, &debit);
	db_bind_text(stmt, currency);
	db_bind_u64(stmt, timestamp);
	db_bind_int(stmt, ++update_count);
	db_exec_prepared_v2(take(stmt));
}

char *update_channel_onchain_fees(const tal_t *ctx,
				  struct db *db,
				  struct account *acct)
{
	struct chain_event *close_ev, **events;
	struct amount_msat onchain_amt;

	assert(acct->onchain_resolved_block);
	close_ev = find_chain_event_by_id(ctx, db,
					  *acct->closed_event_db_id);
	events = find_chain_events_bytxid(ctx, db,
					  close_ev->spending_txid);

	/* Starting balance is close-ev's debit amount */
	onchain_amt = AMOUNT_MSAT(0);
	for (size_t i = 0; i < tal_count(events); i++) {
		struct chain_event *ev = events[i];

		/* Ignore:
		    - htlc_fufill (to me)
		    - anchors (already exlc from output)
		    - to_external (if !htlc_fulfill)
		*/
		if (is_channel_acct(ev)
		    && streq("htlc_fulfill", ev->tag))
			continue;

		if (streq("anchor", ev->tag))
			continue;

		/* Ignore stuff it's paid to
		 * the peer's account (external),
		 * except for fulfilled htlcs (which originated
		 * in our balance) */
		if (streq(ev->acct_name, EXTERNAL_ACCT)
		    && !streq("htlc_fulfill", ev->tag))
			continue;

		/* anything else we count? */
		if (!amount_msat_add(&onchain_amt, onchain_amt,
				     ev->credit))
			return tal_fmt(ctx, "Unable to add"
				       "onchain + %s's credit",
				       ev->tag);
	}

	/* Was this an 'old state' tx, where we ended up
	 * with more sats than we had on record? */
	if (amount_msat_greater(onchain_amt, close_ev->debit)) {
		struct channel_event *ev;
		struct amount_msat diff;

		if (!amount_msat_sub(&diff, onchain_amt,
				     close_ev->debit))
			return tal_fmt(ctx, "Unable to sub"
				       "close debit from onchain_amt");
		/* Add in/out journal entries for it */
		ev = new_channel_event(ctx,
				       tal_fmt(tmpctx, "%s",
					       account_entry_tag_str(PENALTY_ADJ)),
				       diff,
				       AMOUNT_MSAT(0),
				       AMOUNT_MSAT(0),
				       close_ev->currency,
				       NULL, 0,
				       close_ev->timestamp);
		log_channel_event(db, acct, ev);
		ev = new_channel_event(ctx,
				       tal_fmt(tmpctx, "%s",
					       account_entry_tag_str(PENALTY_ADJ)),
				       AMOUNT_MSAT(0),
				       diff,
				       AMOUNT_MSAT(0),
				       close_ev->currency,
				       NULL, 0,
				       close_ev->timestamp);
		log_channel_event(db, acct, ev);
	} else {
		struct amount_msat fees;
		if (!amount_msat_sub(&fees, close_ev->debit,
				     onchain_amt))
			return tal_fmt(ctx, "Unable to sub"
				       "onchain sum from %s",
				       close_ev->tag);

		insert_chain_fees_diff(db, acct->db_id,
				       close_ev->spending_txid,
				       fees, close_ev->currency,
				       close_ev->timestamp);
	}

	return NULL;
}

static char *is_closed_channel_txid(const tal_t *ctx, struct db *db,
				    struct chain_event *ev,
				    struct bitcoin_txid *txid,
				    bool *is_channel_close_tx)
{
	struct account *acct;
	struct chain_event *closed;
	u8 *inner_ctx = tal(NULL, u8);

	/* Figure out if this is a channel close tx */
	acct = find_account(inner_ctx, db, ev->acct_name);
	assert(acct);

	/* There's a separate process for figuring out
	 * our onchain fees for channel closures */
	if (!acct->closed_event_db_id) {
		*is_channel_close_tx = false;
		tal_free(inner_ctx);
		return NULL;
	}

	/* is the closed utxo the same as the one
	 * we're trying to find fees for now */
	closed = find_chain_event_by_id(inner_ctx, db,
			*acct->closed_event_db_id);
	if (!closed) {
		*is_channel_close_tx = false;
		tal_free(inner_ctx);
		return tal_fmt(ctx, "Unable to find"
			      " db record (chain_evt)"
			      " with id %"PRIu64,
			      *acct->closed_event_db_id);
	}

	if (!closed->spending_txid) {
		*is_channel_close_tx = false;
		tal_free(inner_ctx);
		return tal_fmt(ctx, "Marked a closing"
			      " event that's not"
			      " actually a spend");
	}

	*is_channel_close_tx =
		bitcoin_txid_eq(txid, closed->spending_txid);
	tal_free(inner_ctx);
	return NULL;
}

void maybe_record_rebalance(struct db *db,
			    struct channel_event *out)
{
	/* If there's a matching credit event, this is
	 * a rebalance. Mark everything with the payment_id
	 * and amt as such. If you repeat a payment_id
	 * with the same amt, they'll be marked as rebalances
	 * also */
	struct db_stmt *stmt;
	struct amount_msat credit;
	bool ok;

	/* The amount of we were credited is debit - fees */
	ok = amount_msat_sub(&credit, out->debit, out->fees);
	assert(ok);

	stmt = db_prepare_v2(db, SQL("SELECT "
				     "  e.id"
				     " FROM channel_events e"
				     " WHERE e.payment_id = ?"
				     " AND e.credit = ?"
				     " AND e.rebalance_id IS NULL"));

	db_bind_sha256(stmt, out->payment_id);
	db_bind_amount_msat(stmt, &credit);
	db_query_prepared(stmt);

	if (!db_step(stmt)) {
		/* No matching invoice found */
		tal_free(stmt);
		return;
	}

	/* We just take the first one */
	out->rebalance_id = tal(out, u64);
	*out->rebalance_id = db_col_u64(stmt, "e.id");
	tal_free(stmt);

	/* Set rebalance flag on both records */
	stmt = db_prepare_v2(db, SQL("UPDATE channel_events SET"
				     "  rebalance_id = ?"
				     " WHERE"
				     " id = ?"));
	db_bind_u64(stmt, *out->rebalance_id);
	db_bind_u64(stmt, out->db_id);
	db_exec_prepared_v2(take(stmt));

	stmt = db_prepare_v2(db, SQL("UPDATE channel_events SET"
				     "  rebalance_id = ?"
				     " WHERE"
				     " id = ?"));
	db_bind_u64(stmt, out->db_id);
	db_bind_u64(stmt, *out->rebalance_id);
	db_exec_prepared_v2(take(stmt));
}

struct rebalance **list_rebalances(const tal_t *ctx, struct db *db)
{
	struct rebalance **result;
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT "
				     "  in_e.id"
				     ", out_e.id"
				     ", in_acct.name"
				     ", out_acct.name"
				     ", in_e.credit"
				     ", out_e.fees"
				     " FROM channel_events in_e"
				     " LEFT OUTER JOIN channel_events out_e"
				     " ON in_e.rebalance_id = out_e.id"
				     " LEFT OUTER JOIN accounts out_acct"
				     " ON out_acct.id = out_e.account_id"
				     " LEFT OUTER JOIN accounts in_acct"
				     " ON in_acct.id = in_e.account_id"
				     " WHERE in_e.rebalance_id IS NOT NULL"
				     "  AND in_e.credit > 0"));
	db_query_prepared(stmt);
	result = tal_arr(ctx, struct rebalance *, 0);
	while (db_step(stmt)) {
		struct rebalance *r = stmt2rebalance(result, stmt);
		tal_arr_expand(&result, r);
	}
	tal_free(stmt);
	return result;
}

char *maybe_update_onchain_fees(const tal_t *ctx, struct db *db,
			        struct bitcoin_txid *txid)
{
	size_t no_accts = 0, plus_ones;
	u64 last_id = 0, wallet_id, extern_id;
	bool contains_wallet = false, skip_wallet = false;
	struct chain_event **events;
	struct amount_msat deposit_msat = AMOUNT_MSAT(0),
			   withdraw_msat = AMOUNT_MSAT(0),
			   fees_msat, fee_part_msat;
	char *err = NULL;
	u8 *inner_ctx = tal(NULL, u8);

	/* Find all the deposits/withdrawals for this txid */
	events = find_chain_events_bytxid(inner_ctx, db, txid);
	wallet_id = find_acct_id(db, WALLET_ACCT);
	extern_id = find_acct_id(db, EXTERNAL_ACCT);

	/* If we don't even have two events, skip */
	if (tal_count(events) < 2)
		goto finished;

	for (size_t i = 0; i < tal_count(events); i++) {
		bool is_channel_close_tx;
		err = is_closed_channel_txid(ctx, db,
					     events[i], txid,
					     &is_channel_close_tx);

		if (err)
			goto finished;

		/* We skip channel close txs here! */
		if (is_channel_close_tx)
			goto finished;

		if (events[i]->spending_txid) {
			if (!amount_msat_add(&withdraw_msat, withdraw_msat,
					     events[i]->debit)) {
				err = tal_fmt(ctx, "Overflow adding withdrawal debits for"
					      " txid: %s",
					      fmt_bitcoin_txid(ctx,
							     txid));
				goto finished;
			}
		} else {
			if (!amount_msat_add(&deposit_msat, deposit_msat,
					     events[i]->credit)) {
				err = tal_fmt(ctx, "Overflow adding deposit credits for"
					      " txid: %s",
					      fmt_bitcoin_txid(ctx,
							     txid));
				goto finished;
			}
		}

		/* While we're here, also count number of accts
		 * that were involved! Two little tricks here.
		 *
		 * One) we sorted the output
		 * by acct id, so we can cheat how we count: if
		 * it's a different acct_id than the last seen, we inc
		 * the counter.
		 *
		 * Two) who "gets" fee attribution is complicated
		 * and requires knowing if the wallet/external accts
		 * were involved (everything else is channel accts)
		 * */
		if (last_id != events[i]->acct_db_id) {
			last_id = events[i]->acct_db_id;
			/* Don't count external accts */
			if (last_id != extern_id)
				no_accts++;

			contains_wallet |= (last_id == wallet_id);
		}
	}

	/* Only affects external accounts, we can ignore */
	if (no_accts == 0)
		goto finished;

	/* If either is zero, keep waiting */
	if (amount_msat_zero(withdraw_msat)
	    || amount_msat_zero(deposit_msat))
		goto finished;

	/* If our withdraws < deposits, wait for more data */
	if (amount_msat_less(withdraw_msat, deposit_msat))
		goto finished;

	if (!amount_msat_sub(&fees_msat, withdraw_msat, deposit_msat)) {
		err = tal_fmt(ctx, "Err subtracting withdraw %s from deposit %s"
			      " for txid %s",
			      fmt_amount_msat(ctx, withdraw_msat),
			      fmt_amount_msat(ctx, deposit_msat),
			      fmt_bitcoin_txid(ctx, txid));
		goto finished;
	}

	/* Now we need to figure out how to allocate fees to each account
	 * that was involved in the tx. This is a lil complex, buckle up*/

	/* If the wallet's involved + there were any other accounts, decr by one */
	if (no_accts > 1 && contains_wallet) {
		skip_wallet = true;
		no_accts--;
	}

	/* Now we divide by the number of accts involved, to figure out the
	 * value to log for each account! */
	fee_part_msat = amount_msat_div(fees_msat, no_accts);

	/* So we don't lose any msats b/c of rounding, find the number of
	 * accts to add an extra msat onto */
	plus_ones = fees_msat.millisatoshis % no_accts; /* Raw: mod calc */

	/* Now we log (or update the existing record) for each acct */
	last_id = 0;
	for (size_t i = 0; i < tal_count(events); i++) {
		struct amount_msat fees;

		if (last_id == events[i]->acct_db_id)
			continue;

		last_id = events[i]->acct_db_id;

		/* We *never* assign fees to external accounts;
		 * if external funds were contributed to a tx
		 * we wouldn't record it -- fees are solely ours */
		if (last_id == extern_id)
			continue;

		/* We only attribute fees to the wallet
		 * if the wallet is the only game in town */
		if (skip_wallet && last_id == wallet_id) {
			/* But we might need to clean up any fees assigned
			 * to the wallet from a previous round, where it
			 * *was* the only game in town */
			insert_chain_fees_diff(db, last_id, txid,
					       AMOUNT_MSAT(0),
					       events[i]->currency,
					       events[i]->timestamp);
			continue;
		}

		/* Add an extra msat onto plus_ones accts
		 * so we don't lose any precision in
		 * our accounting */
		if (plus_ones > 0) {
			plus_ones--;
			if (!amount_msat_add(&fees, fee_part_msat,
					     AMOUNT_MSAT(1))) {
				err = "Overflow adding 1 ... yeah right";
				/* We're gonna keep going, yolo */
				fees = fee_part_msat;
			}
		} else
			fees = fee_part_msat;

		/* FIXME: fee_currency property of acct? */
		insert_chain_fees_diff(db, last_id, txid, fees,
				       events[i]->currency,
				       events[i]->timestamp);

	}

finished:
	tal_free(inner_ctx);
	return err;
}

void maybe_closeout_external_deposits(struct db *db,
			              struct chain_event *ev)
{
	struct db_stmt *stmt;

	assert(ev->spending_txid);
	stmt = db_prepare_v2(db, SQL("SELECT "
				     "  e.id"
				     " FROM chain_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON e.account_id = a.id"
				     " WHERE e.blockheight = ?"
				     " AND e.utxo_txid = ?"
				     " AND a.name = ?"));

	/* Blockheight for unconfirmeds is zero */
	db_bind_int(stmt, 0);
	db_bind_txid(stmt, ev->spending_txid);
	db_bind_text(stmt, EXTERNAL_ACCT);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		struct db_stmt *update_stmt;
		u64 id;

		id = db_col_u64(stmt, "e.id");
		update_stmt = db_prepare_v2(db, SQL("UPDATE chain_events SET"
						    " blockheight = ?"
						    " WHERE id = ?"));

		db_bind_int(update_stmt, ev->blockheight);
		db_bind_u64(update_stmt, id);
		db_exec_prepared_v2(take(update_stmt));
	}

	tal_free(stmt);
}

bool log_chain_event(struct db *db,
		     const struct account *acct,
		     struct chain_event *e)
{
	struct db_stmt *stmt;

	/* We're responsible for de-duping chain events! */
	if (find_chain_event(e, db, acct,
			     &e->outpoint, e->spending_txid,
			     e->tag))
		return false;

	stmt = db_prepare_v2(db, SQL("INSERT INTO chain_events"
				     " ("
				     "  account_id"
				     ", origin"
				     ", tag"
				     ", credit"
				     ", debit"
				     ", output_value"
				     ", currency"
				     ", timestamp"
				     ", blockheight"
				     ", utxo_txid"
				     ", outnum"
				     ", payment_id"
				     ", spending_txid"
				     ", ignored"
				     ", stealable"
				     ", ev_desc"
				     ")"
				     " VALUES "
				     "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"));

	db_bind_u64(stmt, acct->db_id);
	if (e->origin_acct)
		db_bind_text(stmt, e->origin_acct);
	else
		db_bind_null(stmt);
	db_bind_text(stmt, e->tag);
	db_bind_amount_msat(stmt, &e->credit);
	db_bind_amount_msat(stmt, &e->debit);
	db_bind_amount_msat(stmt, &e->output_value);
	db_bind_text(stmt, e->currency);
	db_bind_u64(stmt, e->timestamp);
	db_bind_int(stmt, e->blockheight);
	db_bind_txid(stmt, &e->outpoint.txid);
	db_bind_int(stmt, e->outpoint.n);

	if (e->payment_id)
		db_bind_sha256(stmt, e->payment_id);
	else
		db_bind_null(stmt);

	if (e->spending_txid)
		db_bind_txid(stmt, e->spending_txid);
	else
		db_bind_null(stmt);

	db_bind_int(stmt, e->ignored ? 1 : 0);
	db_bind_int(stmt, e->stealable ? 1 : 0);
	if (e->desc)
		db_bind_text(stmt, e->desc);
	else
		db_bind_null(stmt);
	db_exec_prepared_v2(stmt);
	e->db_id = db_last_insert_id_v2(stmt);
	e->acct_db_id = acct->db_id;
	e->acct_name = tal_strdup(e, acct->name);
	tal_free(stmt);
	return true;
}
