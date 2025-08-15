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
#include <plugins/bkpr/bookkeeper.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/channel_event.h>
#include <plugins/bkpr/onchain_fee.h>
#include <plugins/bkpr/recorder.h>
#include <plugins/libplugin.h>


static struct chain_event *stmt2chain_event(const tal_t *ctx, struct db_stmt *stmt)
{
	struct chain_event *e = tal(ctx, struct chain_event);
	e->db_id = db_col_u64(stmt, "e.id");
	e->acct_name = db_col_strdup(e, stmt, "e.account_name");

	if (!db_col_is_null(stmt, "e.origin"))
		e->origin_acct = db_col_strdup(e, stmt, "e.origin");
	else
		e->origin_acct = NULL;

	e->tag = db_col_strdup(e, stmt, "e.tag");

	e->credit = db_col_amount_msat(stmt, "e.credit");
	e->debit = db_col_amount_msat(stmt, "e.debit");
	e->output_value = db_col_amount_msat(stmt, "e.output_value");

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

	e->stealable = db_col_int(stmt, "e.stealable") == 1;

	if (!db_col_is_null(stmt, "e.ev_desc"))
		e->desc = db_col_strdup(e, stmt, "e.ev_desc");
	else
		e->desc = NULL;

	e->splice_close = db_col_int(stmt, "e.spliced") == 1;

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
	e->acct_name = db_col_strdup(e, stmt, "e.account_name");

	e->tag = db_col_strdup(e, stmt, "e.tag");

	e->credit = db_col_amount_msat(stmt, "e.credit");
	e->debit = db_col_amount_msat(stmt, "e.debit");
	e->fees = db_col_amount_msat(stmt, "e.fees");

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

static struct channel_event **find_channel_events(const tal_t *ctx,
						  struct db_stmt *stmt TAKES)
{
	struct channel_event **results;

	db_query_prepared(stmt);
	if (stmt->error)
		db_fatal(stmt->db, "find_channel_events err: %s", stmt->error);
	results = tal_arr(ctx, struct channel_event *, 0);
	while (db_step(stmt)) {
		struct channel_event *e = stmt2channel_event(results, stmt);
		tal_arr_expand(&results, e);
	}

	if (taken(stmt))
		tal_free(stmt);

	return results;
}

static struct rebalance *stmt2rebalance(const tal_t *ctx, struct db_stmt *stmt)
{
	struct rebalance *r = tal(ctx, struct rebalance);

	r->in_ev_id = db_col_u64(stmt, "in_e.id");
	r->out_ev_id = db_col_u64(stmt, "out_e.id");
	r->in_acct_name = db_col_strdup(r, stmt, "in_e.account_name");
	r->out_acct_name = db_col_strdup(r, stmt, "out_e.account_name");
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
				     ", e.account_name"
				     ", e.origin"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.output_value"
				     ", e.timestamp"
				     ", e.blockheight"
				     ", e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid"
				     ", e.payment_id"
				     ", e.stealable"
				     ", e.ev_desc"
				     ", e.spliced"
				     " FROM chain_events e"
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
				     ", e.account_name"
				     ", e.origin"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.output_value"
				     ", e.timestamp"
				     ", e.blockheight"
				     ", e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid"
				     ", e.payment_id"
				     ", e.stealable"
				     ", e.ev_desc"
				     ", e.spliced"
				     " FROM chain_events e"
				     " WHERE e.account_name = ?"
				     " ORDER BY e.timestamp, e.id"));

	db_bind_text(stmt, acct->name);
	return find_chain_events(ctx, take(stmt));
}

static struct chain_event **find_txos_for_tx(const tal_t *ctx,
					     struct db *db,
					     struct bitcoin_txid *txid)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  e.id"
				     ", e.account_name"
				     ", e.origin"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.output_value"
				     ", e.timestamp"
				     ", e.blockheight"
				     ", e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid"
				     ", e.payment_id"
				     ", e.stealable"
				     ", e.ev_desc"
				     ", e.spliced"
				     " FROM chain_events e"
				     " WHERE e.utxo_txid = ?"
				     " ORDER BY "
				     "  e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid NULLS FIRST"
				     ", e.blockheight"));

	db_bind_txid(stmt, txid);
	return find_chain_events(ctx, take(stmt));
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
				    const char *acct_name,
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
		    struct db *db,
		    const struct account *acct,
		    struct txo_set ***sets)
{
	struct bitcoin_txid **txids;
	struct chain_event *open_ev;
	bool is_complete = true;
	const char *start_acct_name;

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
	start_acct_name = open_ev->acct_name;

	for (size_t i = 0; i < tal_count(txids); i++) {
		struct txo_set *set;
		bool set_complete;

		set = find_txo_set(ctx, db, txids[i],
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
				    struct db *db,
				    const struct bitcoin_txid *txid)
{
	struct db_stmt *stmt;
	char *acct_name;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  e.account_name"
				     " FROM chain_events e"
				     " WHERE "
				     "  e.tag = ?"
				     "  AND e.spending_txid = ?"
				     /* ignore splicing 'close' events */
				     "  AND e.spliced = 0 "));

	db_bind_text(stmt, mvt_tag_str(MVT_CHANNEL_CLOSE));
	db_bind_txid(stmt, txid);
	db_query_prepared(stmt);

	if (db_step(stmt)) {
		acct_name = db_col_strdup(ctx, stmt, "e.account_name");
	} else
		acct_name = NULL;

	tal_free(stmt);
	return acct_name;
}

u64 account_onchain_closeheight(struct db *db, const struct account *acct)
{
	const u8 *ctx = tal(NULL, u8);
	struct txo_set **sets;
	struct chain_event *close_ev;
	struct db_stmt *stmt;
	u64 height;

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
			return 0;
		}

		stmt = db_prepare_v2(db, SQL("SELECT"
				     " blockheight"
				     " FROM chain_events"
				     " WHERE account_name = ?"
				     "  AND spending_txid IS NOT NULL"
				     " ORDER BY blockheight DESC"
				     " LIMIT 1"));

		db_bind_text(stmt, acct->name);
		db_query_prepared(stmt);
		ok = db_step(stmt);
		assert(ok);

		height = db_col_int(stmt, "blockheight");
		tal_free(stmt);
	} else {
		height = 0;
	}

	tal_free(ctx);
	return height;
}

void edit_utxo_description(struct db *db,
			   struct bitcoin_outpoint *outpoint,
			   const char *desc)
{
	struct db_stmt *stmt;

	/* Ok, now we update the account with this blockheight */
	stmt = db_prepare_v2(db, SQL("UPDATE chain_events SET"
				     "  ev_desc = ?"
				     " WHERE"
				     " utxo_txid = ?"
				     " AND outnum = ?"
				     " AND credit > 0"));
	db_bind_text(stmt, desc);
	db_bind_txid(stmt, &outpoint->txid);
	db_bind_int(stmt, outpoint->n);

	db_exec_prepared_v2(take(stmt));
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
				     ", e.account_name"
				     ", e.origin"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.output_value"
				     ", e.timestamp"
				     ", e.blockheight"
				     ", e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid"
				     ", e.payment_id"
				     ", e.stealable"
				     ", e.ev_desc"
				     ", e.spliced"
				     " FROM chain_events e"
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

struct chain_event **get_chain_events_by_outpoint(const tal_t *ctx,
						  struct db *db,
						  const struct bitcoin_outpoint *outpoint,
						  bool credits_only)
{
	struct db_stmt *stmt;
	if (credits_only)
		stmt = db_prepare_v2(db, SQL("SELECT"
					     "  e.id"
					     ", e.account_name"
					     ", e.origin"
					     ", e.tag"
					     ", e.credit"
					     ", e.debit"
					     ", e.output_value"
					     ", e.timestamp"
					     ", e.blockheight"
					     ", e.utxo_txid"
					     ", e.outnum"
					     ", e.spending_txid"
					     ", e.payment_id"
					     ", e.stealable"
					     ", e.ev_desc"
					     ", e.spliced"
					     " FROM chain_events e"
					     " WHERE "
					     " e.utxo_txid = ?"
					     " AND e.outnum = ?"
					     " AND credit > 0"));
	else
		stmt = db_prepare_v2(db, SQL("SELECT"
					     "  e.id"
					     ", e.account_name"
					     ", e.origin"
					     ", e.tag"
					     ", e.credit"
					     ", e.debit"
					     ", e.output_value"
					     ", e.timestamp"
					     ", e.blockheight"
					     ", e.utxo_txid"
					     ", e.outnum"
					     ", e.spending_txid"
					     ", e.payment_id"
					     ", e.stealable"
					     ", e.ev_desc"
					     ", e.spliced"
					     " FROM chain_events e"
					     " WHERE "
					     " e.utxo_txid = ?"
					     " AND e.outnum = ?"));

	db_bind_txid(stmt, &outpoint->txid);
	db_bind_int(stmt, outpoint->n);
	return find_chain_events(ctx, take(stmt));
}

struct chain_event **get_chain_events_by_id(const tal_t *ctx,
					    struct db *db,
					    const struct sha256 *id)
{
	struct db_stmt *stmt;
	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  e.id"
				     ", e.account_name"
				     ", e.origin"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.output_value"
				     ", e.timestamp"
				     ", e.blockheight"
				     ", e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid"
				     ", e.payment_id"
				     ", e.stealable"
				     ", e.ev_desc"
				     ", e.spliced"
				     " FROM chain_events e"
				     " WHERE "
				     " e.payment_id = ?"));

	db_bind_sha256(stmt, id);
	return find_chain_events(ctx, take(stmt));
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
					     ", e.account_name"
					     ", e.origin"
					     ", e.tag"
					     ", e.credit"
					     ", e.debit"
					     ", e.output_value"
					     ", e.timestamp"
					     ", e.blockheight"
					     ", e.utxo_txid"
					     ", e.outnum"
					     ", e.spending_txid"
					     ", e.payment_id"
					     ", e.stealable"
					     ", e.ev_desc"
					     ", e.spliced"
					     " FROM chain_events e"
					     " WHERE "
					     " e.spending_txid = ?"
					     " AND e.account_name = ?"
					     " AND e.utxo_txid = ?"
					     " AND e.outnum = ?"));
		db_bind_txid(stmt, spending_txid);
	} else {
		stmt = db_prepare_v2(db, SQL("SELECT"
					     "  e.id"
					     ", e.account_name"
					     ", e.origin"
					     ", e.tag"
					     ", e.credit"
					     ", e.debit"
					     ", e.output_value"
					     ", e.timestamp"
					     ", e.blockheight"
					     ", e.utxo_txid"
					     ", e.outnum"
					     ", e.spending_txid"
					     ", e.payment_id"
					     ", e.stealable"
					     ", e.ev_desc"
					     ", e.spliced"
					     " FROM chain_events e"
					     " WHERE "
					     " e.tag = ?"
					     " AND e.account_name = ?"
					     " AND e.utxo_txid = ?"
					     " AND e.outnum = ?"
					     " AND e.spending_txid IS NULL"));
		db_bind_text(stmt, tag);
	}

	db_bind_text(stmt, acct->name);
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

bool account_get_credit_debit(struct plugin *plugin,
			      struct db *db,
			      const char *acct_name,
			      struct amount_msat *credit,
			      struct amount_msat *debit)
{
	struct db_stmt *stmt;
	bool exists;

	/* Get sum from chain_events */
	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  CAST(SUM(ce.credit) AS BIGINT) as credit"
				     ", CAST(SUM(ce.debit) AS BIGINT) as debit"
				     " FROM chain_events ce"
				     " WHERE ce.account_name = ?"));
	db_bind_text(stmt, acct_name);
	db_query_prepared(stmt);

	db_step(stmt);
	if (db_col_is_null(stmt, "credit")) {
		db_col_ignore(stmt, "debit");
		*credit = *debit = AMOUNT_MSAT(0);
		exists = false;
	} else {
		*credit = db_col_amount_msat(stmt, "credit");
		*debit = db_col_amount_msat(stmt, "debit");
		exists = true;
	}
	tal_free(stmt);

	/* Get sum from channel_events */
	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  CAST(SUM(ce.credit) AS BIGINT) as credit"
				     ", CAST(SUM(ce.debit) AS BIGINT) as debit"
				     " FROM channel_events ce"
				     " WHERE ce.account_name = ?"));
	db_bind_text(stmt, acct_name);
	db_query_prepared(stmt);
	db_step(stmt);

	if (db_col_is_null(stmt, "credit")) {
		db_col_ignore(stmt, "debit");
	} else {
		if (!amount_msat_accumulate(credit,
					    db_col_amount_msat(stmt, "credit"))) {
			plugin_err(plugin, "db overflow: chain credit %s, adding channel credit %s",
				   fmt_amount_msat(tmpctx, *credit),
				   fmt_amount_msat(tmpctx,
						   db_col_amount_msat(stmt, "credit")));
		}

		if (!amount_msat_accumulate(debit,
					    db_col_amount_msat(stmt, "debit"))) {
			plugin_err(plugin, "db overflow: chain debit %s, adding channel debit %s",
				   fmt_amount_msat(tmpctx, *debit),
				   fmt_amount_msat(tmpctx,
						   db_col_amount_msat(stmt, "debit")));
		}
		exists = true;
	}
	tal_free(stmt);
	return exists;
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
				     ", e.account_name"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.fees"
				     ", e.payment_id"
				     ", e.part_id"
				     ", e.timestamp"
				     ", e.ev_desc"
				     ", e.rebalance_id"
				     " FROM channel_events e"
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

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  e.id"
				     ", e.account_name"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.fees"
				     ", e.payment_id"
				     ", e.part_id"
				     ", e.timestamp"
				     ", e.ev_desc"
				     ", e.rebalance_id"
				     " FROM channel_events e"
				     " WHERE e.account_name = ?"
				     " ORDER BY e.timestamp, e.id"));

	db_bind_text(stmt, acct->name);
	return find_channel_events(ctx, take(stmt));
}

struct channel_event **get_channel_events_by_id(const tal_t *ctx,
						struct db *db,
						struct sha256 *id)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  e.id"
				     ", e.account_name"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.fees"
				     ", e.payment_id"
				     ", e.part_id"
				     ", e.timestamp"
				     ", e.ev_desc"
				     ", e.rebalance_id"
				     " FROM channel_events e"
				     " WHERE e.payment_id = ?"
				     " ORDER BY e.timestamp, e.id"));

	db_bind_sha256(stmt, id);
	return find_channel_events(ctx, take(stmt));
}

void log_channel_event(struct db *db,
		       const struct account *acct,
		       struct channel_event *e)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("INSERT INTO channel_events"
				     " ("
				     "  account_name"
				     ", tag"
				     ", credit"
				     ", debit"
				     ", fees"
				     ", payment_id"
				     ", part_id"
				     ", timestamp"
				     ", ev_desc"
				     ", rebalance_id"
				     ")"
				     " VALUES"
				     " (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"));

	db_bind_text(stmt, acct->name);
	db_bind_text(stmt, e->tag);
	db_bind_amount_msat(stmt, e->credit);
	db_bind_amount_msat(stmt, e->debit);
	db_bind_amount_msat(stmt, e->fees);
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
	e->acct_name = tal_strdup(e, acct->name);
	tal_free(stmt);
}

struct chain_event **find_chain_events_bytxid(const tal_t *ctx, struct db *db,
					      struct bitcoin_txid *txid)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT "
				     "  e.id"
				     ", e.account_name"
				     ", e.origin"
				     ", e.tag"
				     ", e.credit"
				     ", e.debit"
				     ", e.output_value"
				     ", e.timestamp"
				     ", e.blockheight"
				     ", e.utxo_txid"
				     ", e.outnum"
				     ", e.spending_txid"
				     ", e.payment_id"
				     ", e.stealable"
				     ", e.ev_desc"
				     ", e.spliced"
				     " FROM chain_events e"
				     " WHERE e.spending_txid = ?"
				     " OR (e.utxo_txid = ? AND e.spending_txid IS NULL)"
				     " ORDER BY e.account_name"));

	db_bind_txid(stmt, txid);
	db_bind_txid(stmt, txid);
	return find_chain_events(ctx, take(stmt));
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
	db_bind_amount_msat(stmt, credit);
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
				     ", in_e.account_name"
				     ", out_e.account_name"
				     ", in_e.credit"
				     ", out_e.fees"
				     " FROM channel_events in_e"
				     " LEFT OUTER JOIN channel_events out_e"
				     " ON in_e.rebalance_id = out_e.id"
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

void maybe_closeout_external_deposits(struct db *db,
			              const struct bitcoin_txid *txid,
				      u32 blockheight)
{
	struct db_stmt *stmt;

	assert(txid);
	stmt = db_prepare_v2(db, SQL("SELECT "
				     "  e.id"
				     " FROM chain_events e"
				     " WHERE e.blockheight = ?"
				     " AND e.utxo_txid = ?"
				     " AND e.account_name = ?"));

	/* Blockheight for unconfirmeds is zero */
	db_bind_int(stmt, 0);
	db_bind_txid(stmt, txid);
	db_bind_text(stmt, ACCOUNT_NAME_EXTERNAL);
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		struct db_stmt *update_stmt;
		u64 id;

		id = db_col_u64(stmt, "e.id");
		update_stmt = db_prepare_v2(db, SQL("UPDATE chain_events SET"
						    " blockheight = ?"
						    " WHERE id = ?"));

		db_bind_int(update_stmt, blockheight);
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
	if (find_chain_event(tmpctx, db, acct,
			     &e->outpoint, e->spending_txid,
			     e->tag))
		return false;

	stmt = db_prepare_v2(db, SQL("INSERT INTO chain_events"
				     " ("
				     "  account_name"
				     ", origin"
				     ", tag"
				     ", credit"
				     ", debit"
				     ", output_value"
				     ", timestamp"
				     ", blockheight"
				     ", utxo_txid"
				     ", outnum"
				     ", payment_id"
				     ", spending_txid"
				     ", stealable"
				     ", ev_desc"
				     ", spliced"
				     ")"
				     " VALUES "
				     "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"));

	db_bind_text(stmt, acct->name);
	if (e->origin_acct)
		db_bind_text(stmt, e->origin_acct);
	else
		db_bind_null(stmt);
	db_bind_text(stmt, e->tag);
	db_bind_amount_msat(stmt, e->credit);
	db_bind_amount_msat(stmt, e->debit);
	db_bind_amount_msat(stmt, e->output_value);
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

	db_bind_int(stmt, e->stealable ? 1 : 0);
	if (e->desc)
		db_bind_text(stmt, e->desc);
	else
		db_bind_null(stmt);
	db_bind_int(stmt, e->splice_close ? 1 : 0);
	db_exec_prepared_v2(stmt);
	e->db_id = db_last_insert_id_v2(stmt);
	e->acct_name = tal_strdup(e, acct->name);
	tal_free(stmt);
	return true;
}
