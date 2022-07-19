#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/coin_mvt.h>
#include <common/node_id.h>
#include <common/type_to_string.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <inttypes.h>
#include <plugins/bkpr/account.h>
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

	db_col_amount_msat(stmt, "e.credit", &e->credit);
	db_col_amount_msat(stmt, "e.debit", &e->debit);
	db_col_amount_msat(stmt, "e.output_value", &e->output_value);

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

	return e;
}

static struct chain_event **find_chain_events(const tal_t *ctx,
					      struct db_stmt *stmt TAKES)
{
	struct chain_event **results;

	db_query_prepared(stmt);
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

	db_col_amount_msat(stmt, "e.credit", &e->credit);
	db_col_amount_msat(stmt, "e.debit", &e->debit);
	db_col_amount_msat(stmt, "e.fees", &e->fees);

	e->currency = db_col_strdup(e, stmt, "e.currency");
	if (!db_col_is_null(stmt, "e.payment_id")) {
		e->payment_id = tal(e, struct sha256);
		db_col_sha256(stmt, "e.payment_id", e->payment_id);
	} else
		e->payment_id = NULL;
	e->part_id = db_col_int(stmt, "e.part_id");
	e->timestamp = db_col_u64(stmt, "e.timestamp");

	return e;
}

struct chain_event **list_chain_events(const tal_t *ctx, struct db *db)
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
				     " FROM chain_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON e.account_id = a.id"
				     " ORDER BY e.timestamp, e.id;"));

	return find_chain_events(ctx, take(stmt));
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
				     " FROM chain_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON e.account_id = a.id"
				     " WHERE e.account_id = ?"
				     " ORDER BY e.timestamp, e.id"));

	db_bind_int(stmt, 0, acct->db_id);
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
				     " FROM chain_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON e.account_id = a.id"
				     " WHERE e.utxo_txid = ?"
				     " ORDER BY "
				     "  e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid NULLS FIRST"));

	db_bind_txid(stmt, 0, txid);
	return find_chain_events(ctx, take(stmt));
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
				     " ORDER BY txid, update_count"));

	db_bind_u64(stmt, 0, acct->db_id);
	db_query_prepared(stmt);

	sums = tal_arr(ctx, struct fee_sum *, 0);
	while (db_step(stmt)) {
		struct fee_sum *sum;
		struct amount_msat amt;
		bool ok;

		sum = tal(sums, struct fee_sum);
		sum->txid = tal(sum, struct bitcoin_txid);
		db_col_txid(stmt, "txid", sum->txid);

		db_col_amount_msat(stmt, "credit", &sum->fees_paid);
		db_col_amount_msat(stmt, "debit", &amt);
		ok = amount_msat_sub(&sum->fees_paid, sum->fees_paid, amt);
		assert(ok);
		tal_arr_expand(&sums, sum);
	}

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
			if (pr)
				tal_arr_expand(&txos->pairs, pr);
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
			    && !txid_in_list(txids, pr->spend->spending_txid)
			    /* We dont trace utxos for non related accts */
			    && pr->spend->acct_db_id == acct->db_id) {
				tal_arr_expand(&txids,
					       pr->spend->spending_txid);
			}
		}

		tal_arr_expand(sets, set);
	}

	return is_complete;
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
				     " FROM chain_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON e.account_id = a.id"
				     " WHERE "
				     " e.id = ?"));

	db_bind_u64(stmt, 0, event_db_id);
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
					    const struct bitcoin_txid *spending_txid)

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
					     " FROM chain_events e"
					     " LEFT OUTER JOIN accounts a"
					     " ON e.account_id = a.id"
					     " WHERE "
					     " e.account_id = ?"
					     " AND e.utxo_txid = ?"
					     " AND e.outnum = ?"
					     " AND e.spending_txid = ?"));
		db_bind_txid(stmt, 3, spending_txid);
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
					     " FROM chain_events e"
					     " LEFT OUTER JOIN accounts a"
					     " ON e.account_id = a.id"
					     " WHERE "
					     " e.account_id = ?"
					     " AND e.utxo_txid = ?"
					     " AND e.outnum = ?"
					     " AND e.spending_txid IS NULL"));
	}

	db_bind_u64(stmt, 0, acct->db_id);
	db_bind_txid(stmt, 1, &outpoint->txid);
	db_bind_int(stmt, 2, outpoint->n);

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
			  struct acct_balance ***balances)
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
				     " GROUP BY ce.currency"));

	db_bind_text(stmt, 0, acct_name);
	db_query_prepared(stmt);
	*balances = tal_arr(ctx, struct acct_balance *, 0);

	while (db_step(stmt)) {
		struct acct_balance *bal;

		bal = tal(*balances, struct acct_balance);

		bal->currency = db_col_strdup(bal, stmt, "ce.currency");
		db_col_amount_msat(stmt, "credit", &bal->credit);
		db_col_amount_msat(stmt, "debit", &bal->debit);
		tal_arr_expand(balances, bal);
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
	db_bind_text(stmt, 0, acct_name);
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

		db_col_amount_msat(stmt, "credit", &amt);
		if (!amount_msat_add(&bal->credit, bal->credit, amt)) {
			tal_free(stmt);
			return "overflow adding channel_event credits";
		}

		db_col_amount_msat(stmt, "debit", &amt);
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
				type_to_string(ctx, struct amount_msat,
					       &bal->credit),
				type_to_string(ctx, struct amount_msat,
					       &bal->debit));
	}

	return NULL;
}

struct channel_event **list_channel_events(const tal_t *ctx, struct db *db)
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
				     " FROM channel_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON a.id = e.account_id"
				     " ORDER BY e.timestamp, e.id;"));

	db_query_prepared(stmt);

	results = tal_arr(ctx, struct channel_event *, 0);
	while (db_step(stmt)) {
		struct channel_event *e = stmt2channel_event(results, stmt);
		tal_arr_expand(&results, e);
	}
	tal_free(stmt);

	return results;
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
				     " FROM channel_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON a.id = e.account_id"
				     " WHERE e.account_id = ?"
				     " ORDER BY e.timestamp, e.id"));

	db_bind_u64(stmt, 0, acct->db_id);
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
	db_col_amount_msat(stmt, "of.credit", &of->credit);
	db_col_amount_msat(stmt, "of.debit", &of->debit);
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

	db_bind_u64(stmt, 0, acct->db_id);
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
				     " ORDER BY "
				     "  of.timestamp"
				     ", of.account_id"
				     ", of.txid"
				     ", of.update_count"));
	db_query_prepared(stmt);

	results = tal_arr(ctx, struct onchain_fee *, 0);
	while (db_step(stmt)) {
		struct onchain_fee *of = stmt2onchain_fee(results, stmt);
		tal_arr_expand(&results, of);
	}
	tal_free(stmt);

	return results;
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
				     " FROM accounts"
				     " WHERE name = ?"));

	db_bind_text(stmt, 0, name);
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

	db_bind_u64(stmt, 0, acct->db_id);
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

	db_bind_text(stmt, 0, acct->name);
	if (acct->peer_id)
		db_bind_node_id(stmt, 1, acct->peer_id);
	else
		db_bind_null(stmt, 1);
	db_bind_int(stmt, 2, acct->is_wallet ? 1 : 0);
	db_bind_int(stmt, 3, acct->we_opened ? 1 : 0);
	db_bind_int(stmt, 4, acct->leased ? 1 : 0);

	db_exec_prepared_v2(stmt);
	acct->db_id = db_last_insert_id_v2(stmt);
	tal_free(stmt);
}

void maybe_update_account(struct db *db,
			  struct account *acct,
			  struct chain_event *e,
			  const enum mvt_tag *tags)
{
	struct db_stmt *stmt;
	bool updated = false;

	for (size_t i = 0; i < tal_count(tags); i++) {
		switch (tags[i]) {
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
				/* Ignored */
				break;
		}
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
				     " WHERE"
				     " name = ?"));

	if (acct->open_event_db_id)
		db_bind_u64(stmt, 0, *acct->open_event_db_id);
	else
		db_bind_null(stmt, 0);

	if (acct->closed_event_db_id)
		db_bind_u64(stmt, 1, *acct->closed_event_db_id);
	else
		db_bind_null(stmt, 1);

	db_bind_int(stmt, 2, acct->we_opened ? 1 : 0);
	db_bind_int(stmt, 3, acct->leased ? 1 : 0);

	db_bind_text(stmt, 4, acct->name);

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
				     ")"
				     " VALUES"
				     " (?, ?, ?, ?, ?, ?, ?, ?, ?);"));

	db_bind_u64(stmt, 0, acct->db_id);
	db_bind_text(stmt, 1, e->tag);
	db_bind_amount_msat(stmt, 2, &e->credit);
	db_bind_amount_msat(stmt, 3, &e->debit);
	db_bind_amount_msat(stmt, 4, &e->fees);
	db_bind_text(stmt, 5, e->currency);
	if (e->payment_id)
		db_bind_sha256(stmt, 6, e->payment_id);
	else
		db_bind_null(stmt, 6);
	db_bind_int(stmt, 7, e->part_id);
	db_bind_u64(stmt, 8, e->timestamp);

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
				     " FROM chain_events e"
				     " LEFT OUTER JOIN accounts a"
				     " ON a.id = e.account_id"
				     " WHERE e.spending_txid = ?"
				     " OR (e.utxo_txid = ? AND e.spending_txid IS NULL)"
				     " ORDER BY e.account_id"));

	db_bind_txid(stmt, 0, txid);
	db_bind_txid(stmt, 1, txid);
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

	db_bind_text(stmt, 0, name);
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

	db_bind_txid(stmt, 0, txid);
	db_bind_u64(stmt, 1, acct_id);
	db_query_prepared(stmt);

	/* If there's no current record, add it */
	current_amt = AMOUNT_MSAT(0);
	update_count = 0;
	while (db_step(stmt)) {
		update_count = db_col_int(stmt, "update_count");
		db_col_amount_msat(stmt, "credit", &credit);
		db_col_amount_msat(stmt, "debit", &debit);

		/* These should apply perfectly, as we sorted them by
		 * insert order */
		if (!amount_msat_add(&current_amt, current_amt, credit))
			db_fatal("Overflow when adding onchain fees");

		if (!amount_msat_sub(&current_amt, current_amt, debit))
			db_fatal("Underflow when subtracting onchain fees");

	}
	tal_free(stmt);

	/* If they're already equal, no need to update */
	if (amount_msat_eq(current_amt, amount))
		return;

	if (!amount_msat_sub(&credit, amount, current_amt)) {
		credit = AMOUNT_MSAT(0);
		if (!amount_msat_sub(&debit, current_amt, amount))
			db_fatal("shouldn't happen, unable to subtract");
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

	db_bind_u64(stmt, 0, acct_id);
	db_bind_txid(stmt, 1, txid);
	db_bind_amount_msat(stmt, 2, &credit);
	db_bind_amount_msat(stmt, 3, &debit);
	db_bind_text(stmt, 4, currency);
	db_bind_u64(stmt, 5, timestamp);
	db_bind_int(stmt, 6, ++update_count);
	db_exec_prepared_v2(take(stmt));
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
		if (events[i]->spending_txid) {
			struct account *acct;
			/* Figure out if this is a channel close
			 * that we're not the opener for */
			acct = find_account(inner_ctx, db,
					    events[i]->acct_name);
			assert(acct);

			/* If any of the spending_txid accounts are
			 * close accounts and we're not the opener,
			 * we end things */
			if (acct->closed_event_db_id && !acct->we_opened) {
				struct chain_event *closed;
				/* is the closed utxo the same as the one
				 * we're trying to find fees for now */
				closed = find_chain_event_by_id(inner_ctx,
						db, *acct->closed_event_db_id);
				if (!closed) {
					err = tal_fmt(ctx, "Unable to find"
						      " db record (chain_evt)"
						      " with id %"PRIu64,
						      *acct->closed_event_db_id);
					goto finished;
				}
				if (!closed->spending_txid) {
					err = tal_fmt(ctx, "Marked a closing"
						      " event that's not"
						      " actually a spend");
					goto finished;
				}

				if (bitcoin_txid_eq(txid, closed->spending_txid))
					goto finished;
			}
			if (!amount_msat_add(&withdraw_msat, withdraw_msat,
					     events[i]->debit)) {
				err = tal_fmt(ctx, "Overflow adding withdrawal debits for"
					      " txid: %s",
					      type_to_string(ctx, struct bitcoin_txid,
							     txid));
				goto finished;
			}
		} else {
			if (!amount_msat_add(&deposit_msat, deposit_msat,
					     events[i]->credit)) {
				err = tal_fmt(ctx, "Overflow adding deposit credits for"
					      " txid: %s",
					      type_to_string(ctx, struct bitcoin_txid,
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

	/* At this point, we have no way to know we've gotten all the data.
	 * But that's what the 'onchain_resolved_block' marker on
	 * accounts is for */
	if (!amount_msat_sub(&fees_msat, withdraw_msat, deposit_msat)) {
		err = tal_fmt(ctx, "Err subtracting withdraw %s from deposit %s"
			      " for txid %s",
			      type_to_string(ctx, struct amount_msat, &withdraw_msat),
			      type_to_string(ctx, struct amount_msat, &deposit_msat),
			      type_to_string(ctx, struct bitcoin_txid, txid));
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

bool log_chain_event(struct db *db,
		     const struct account *acct,
		     struct chain_event *e)
{
	struct db_stmt *stmt;

	/* We're responsible for de-duping chain events! */
	if (find_chain_event(e, db, acct,
			     &e->outpoint, e->spending_txid))
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
				     ")"
				     " VALUES"
				     " (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"));

	db_bind_u64(stmt, 0, acct->db_id);
	if (e->origin_acct)
		db_bind_text(stmt, 1, e->origin_acct);
	else
		db_bind_null(stmt, 1);
	db_bind_text(stmt, 2, e->tag);
	db_bind_amount_msat(stmt, 3, &e->credit);
	db_bind_amount_msat(stmt, 4, &e->debit);
	db_bind_amount_msat(stmt, 5, &e->output_value);
	db_bind_text(stmt, 6, e->currency);
	db_bind_u64(stmt, 7, e->timestamp);
	db_bind_int(stmt, 8, e->blockheight);
	db_bind_txid(stmt, 9, &e->outpoint.txid);
	db_bind_int(stmt, 10, e->outpoint.n);

	if (e->payment_id)
		db_bind_sha256(stmt, 11, e->payment_id);
	else
		db_bind_null(stmt, 11);

	if (e->spending_txid)
		db_bind_txid(stmt, 12, e->spending_txid);
	else
		db_bind_null(stmt, 12);

	db_exec_prepared_v2(stmt);
	e->db_id = db_last_insert_id_v2(stmt);
	e->acct_db_id = acct->db_id;
	e->acct_name = tal_strdup(e, acct->name);
	tal_free(stmt);
	return true;
}
