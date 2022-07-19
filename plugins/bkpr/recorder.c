#include "config.h"
#include <ccan/array_size/array_size.h>
#include <common/coin_mvt.h>
#include <common/node_id.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <plugins/bkpr/account.h>
#include <plugins/bkpr/chain_event.h>
#include <plugins/bkpr/channel_event.h>
#include <plugins/bkpr/onchain_fee.h>
#include <plugins/bkpr/recorder.h>

static struct chain_event *stmt2chain_event(const tal_t *ctx, struct db_stmt *stmt)
{
	struct chain_event *e = tal(ctx, struct chain_event);
	e->db_id = db_col_u64(stmt, "id");
	e->acct_db_id = db_col_u64(stmt, "account_id");

	e->tag = db_col_strdup(e, stmt, "tag");

	db_col_amount_msat(stmt, "credit", &e->credit);
	db_col_amount_msat(stmt, "debit", &e->debit);
	db_col_amount_msat(stmt, "output_value", &e->output_value);

	e->currency = db_col_strdup(e, stmt, "currency");
	e->timestamp = db_col_u64(stmt, "timestamp");
	e->blockheight = db_col_int(stmt, "blockheight");

	db_col_txid(stmt, "utxo_txid", &e->outpoint.txid);
	e->outpoint.n = db_col_int(stmt, "outnum");

	if (!db_col_is_null(stmt, "payment_id")) {
		e->payment_id = tal(e, struct sha256);
		db_col_sha256(stmt, "payment_id", e->payment_id);
	} else
		e->payment_id = NULL;

	if (!db_col_is_null(stmt, "spending_txid")) {
		e->spending_txid = tal(e, struct bitcoin_txid);
		db_col_txid(stmt, "spending_txid", e->spending_txid);
	} else
		e->spending_txid = NULL;

	return e;
}

static struct channel_event *stmt2channel_event(const tal_t *ctx, struct db_stmt *stmt)
{
	struct channel_event *e = tal(ctx, struct channel_event);

	e->db_id = db_col_u64(stmt, "id");
	e->acct_db_id = db_col_u64(stmt, "account_id");

	e->tag = db_col_strdup(e, stmt, "tag");

	db_col_amount_msat(stmt, "credit", &e->credit);
	db_col_amount_msat(stmt, "debit", &e->debit);
	db_col_amount_msat(stmt, "fees", &e->fees);

	e->currency = db_col_strdup(e, stmt, "currency");
	db_col_sha256(stmt, "payment_id", &e->payment_id);
	e->part_id = db_col_int(stmt, "part_id");
	e->timestamp = db_col_u64(stmt, "timestamp");

	return e;
}

struct chain_event **account_get_chain_events(const tal_t *ctx,
					      struct db *db,
					      struct account *acct)
{
	struct db_stmt *stmt;
	struct chain_event **results;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  id"
				     ", account_id"
				     ", tag"
				     ", credit"
				     ", debit"
				     ", output_value"
				     ", currency"
				     ", timestamp"
				     ", blockheight"
				     ", utxo_txid"
				     ", outnum"
				     ", spending_txid"
				     ", payment_id"
				     " FROM chain_events"
				     " WHERE account_id = ?;"));

	db_bind_int(stmt, 0, acct->db_id);
	db_query_prepared(stmt);

	results = tal_arr(ctx, struct chain_event *, 0);
	while (db_step(stmt)) {
		struct chain_event *e = stmt2chain_event(results, stmt);
		tal_arr_expand(&results, e);
	}
	tal_free(stmt);

	return results;
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
					     "  id"
					     ", account_id"
					     ", tag"
					     ", credit"
					     ", debit"
					     ", output_value"
					     ", currency"
					     ", timestamp"
					     ", blockheight"
					     ", utxo_txid"
					     ", outnum"
					     ", spending_txid"
					     ", payment_id"
					     " FROM chain_events"
					     " WHERE "
					     " account_id = ?"
					     " AND utxo_txid = ?"
					     " AND outnum = ?"
					     " AND spending_txid = ?"));
		db_bind_txid(stmt, 3, spending_txid);
	} else {
		stmt = db_prepare_v2(db, SQL("SELECT"
					     "  id"
					     ", account_id"
					     ", tag"
					     ", credit"
					     ", debit"
					     ", output_value"
					     ", currency"
					     ", timestamp"
					     ", blockheight"
					     ", utxo_txid"
					     ", outnum"
					     ", spending_txid"
					     ", payment_id"
					     " FROM chain_events"
					     " WHERE "
					     " account_id = ?"
					     " AND utxo_txid = ?"
					     " AND outnum = ?"
					     " AND spending_txid IS NULL"));
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

struct channel_event **account_get_channel_events(const tal_t *ctx,
						  struct db *db,
						  struct account *acct)
{
	struct db_stmt *stmt;
	struct channel_event **results;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  id"
				     ", account_id"
				     ", tag"
				     ", credit"
				     ", debit"
				     ", fees"
				     ", currency"
				     ", payment_id"
				     ", part_id"
				     ", timestamp"
				     " FROM channel_events"
				     " WHERE account_id = ?;"));

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

static struct onchain_fee *stmt2onchain_fee(const tal_t *ctx, struct db_stmt *stmt)
{
	struct onchain_fee *of = tal(ctx, struct onchain_fee);

	of->acct_db_id = db_col_u64(stmt, "account_id");
	db_col_txid(stmt, "txid", &of->txid);
	db_col_amount_msat(stmt, "amount", &of->amount);
	of->currency = db_col_strdup(of, stmt, "currency");

	return of;
}

struct onchain_fee **account_onchain_fees(const tal_t *ctx,
					  struct db *db,
					  struct account *acct)
{
	struct db_stmt *stmt;
	struct onchain_fee **results;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  account_id"
				     ", txid"
				     ", amount"
				     ", currency"
				     " FROM onchain_fees"
				     " WHERE account_id = ?;"));

	db_bind_int(stmt, 0, acct->db_id);
	db_query_prepared(stmt);

	results = tal_arr(ctx, struct onchain_fee*, 0);
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
	db_bind_sha256(stmt, 6, &e->payment_id);
	db_bind_int(stmt, 7, e->part_id);
	db_bind_u64(stmt, 8, e->timestamp);

	db_exec_prepared_v2(stmt);
	e->db_id = db_last_insert_id_v2(stmt);
	e->acct_db_id = acct->db_id;
	tal_free(stmt);
}

void log_chain_event(struct db *db,
		     const struct account *acct,
		     struct chain_event *e)
{
	struct db_stmt *stmt;

	/* We're responsible for de-duping chain events! */
	if (find_chain_event(e, db, acct,
			     &e->outpoint, e->spending_txid))
		return;

	stmt = db_prepare_v2(db, SQL("INSERT INTO chain_events"
				     " ("
				     "  account_id"
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
	db_bind_text(stmt, 1, e->tag);
	db_bind_amount_msat(stmt, 2, &e->credit);
	db_bind_amount_msat(stmt, 3, &e->debit);
	db_bind_amount_msat(stmt, 4, &e->output_value);
	db_bind_text(stmt, 5, e->currency);
	db_bind_u64(stmt, 6, e->timestamp);
	db_bind_int(stmt, 7, e->blockheight);
	db_bind_txid(stmt, 8, &e->outpoint.txid);
	db_bind_int(stmt, 9, e->outpoint.n);
	db_bind_sha256(stmt, 10, e->payment_id);

	if (e->spending_txid)
		db_bind_txid(stmt, 11, e->spending_txid);
	else
		db_bind_null(stmt, 11);

	db_exec_prepared_v2(stmt);
	e->db_id = db_last_insert_id_v2(stmt);
	e->acct_db_id = acct->db_id;
	tal_free(stmt);
}
