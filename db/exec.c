#include "config.h"
#include <ccan/tal/tal.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>

/**
 * db_get_version - Determine the current DB schema version
 *
 * Will attempt to determine the current schema version of the
 * database @db by querying the `version` table. If the table does not
 * exist it'll return schema version -1, so that migration 0 is
 * applied, which should create the `version` table.
 */
int db_get_version(struct db *db)
{
	int res = -1;
	struct db_stmt *stmt = db_prepare_v2(db, SQL("SELECT version FROM version LIMIT 1"));

	/*
	 * Tentatively execute a query, but allow failures. Some databases
	 * like postgres will terminate the DB transaction if there is an
	 * error during the execution of a query, e.g., trying to access a
	 * table that doesn't exist yet, so we need to terminate and restart
	 * the DB transaction.
	 */
	if (!db_query_prepared(stmt)) {
		db_commit_transaction(stmt->db);
		db_begin_transaction(stmt->db);
		tal_free(stmt);
		return res;
	}

	if (db_step(stmt))
		res = db_col_int(stmt, "version");

	tal_free(stmt);
	return res;
}

u32 db_data_version_get(struct db *db)
{
	struct db_stmt *stmt;
	u32 version;
	stmt = db_prepare_v2(db, SQL("SELECT intval FROM vars WHERE name = 'data_version'"));
	db_query_prepared(stmt);
	db_step(stmt);
	version = db_col_int(stmt, "intval");
	tal_free(stmt);
	return version;
}

void db_set_intvar(struct db *db, char *varname, s64 val)
{
	size_t changes;
	struct db_stmt *stmt = db_prepare_v2(db, SQL("UPDATE vars SET intval=? WHERE name=?;"));
	db_bind_int(stmt, 0, val);
	db_bind_text(stmt, 1, varname);
	if (!db_exec_prepared_v2(stmt))
		db_fatal("Error executing update: %s", stmt->error);
	changes = db_count_changes(stmt);
	tal_free(stmt);

	if (changes == 0) {
		stmt = db_prepare_v2(db, SQL("INSERT INTO vars (name, intval) VALUES (?, ?);"));
		db_bind_text(stmt, 0, varname);
		db_bind_int(stmt, 1, val);
		if (!db_exec_prepared_v2(stmt))
			db_fatal("Error executing insert: %s", stmt->error);
		tal_free(stmt);
	}
}

s64 db_get_intvar(struct db *db, char *varname, s64 defval)
{
	s64 res = defval;
	struct db_stmt *stmt = db_prepare_v2(
	    db, SQL("SELECT intval FROM vars WHERE name= ? LIMIT 1"));
	db_bind_text(stmt, 0, varname);
	if (db_query_prepared(stmt) && db_step(stmt))
		res = db_col_int(stmt, "intval");

	tal_free(stmt);
	return res;
}

/* Leak tracking. */

/* By making the update conditional on the current value we expect we
 * are implementing an optimistic lock: if the update results in
 * changes on the DB we know that the data_version did not change
 * under our feet and no other transaction ran in the meantime.
 *
 * Notice that this update effectively locks the row, so that other
 * operations attempting to change this outside the transaction will
 * wait for this transaction to complete. The external change will
 * ultimately fail the changes test below, it'll just delay its abort
 * until our transaction is committed.
 */
static void db_data_version_incr(struct db *db)
{
       struct db_stmt *stmt = db_prepare_v2(
	       db, SQL("UPDATE vars "
		       "SET intval = intval + 1 "
		       "WHERE name = 'data_version'"
		       " AND intval = ?"));
       db_bind_int(stmt, 0, db->data_version);
       db_exec_prepared_v2(stmt);
       if (db_count_changes(stmt) != 1)
	       db_fatal("Optimistic lock on the database failed. There"
			" may be a concurrent access to the database."
			" Aborting since concurrent access is unsafe.");
       tal_free(stmt);
       db->data_version++;
}

void db_begin_transaction_(struct db *db, const char *location)
{
	bool ok;
	if (db->in_transaction)
		db_fatal("Already in transaction from %s", db->in_transaction);

	/* No writes yet. */
	db->dirty = false;

	db_prepare_for_changes(db);
	ok = db->config->begin_tx_fn(db);
	if (!ok)
		db_fatal("Failed to start DB transaction: %s", db->error);

	db->in_transaction = location;
}

bool db_in_transaction(struct db *db)
{
	return db->in_transaction;
}

void db_commit_transaction(struct db *db)
{
	bool ok;
	assert(db->in_transaction);
	db_assert_no_outstanding_statements(db);

	/* Increment before reporting changes to an eventual plugin. */
	if (db->dirty)
		db_data_version_incr(db);

	db_report_changes(db, NULL, 0);
	ok = db->config->commit_tx_fn(db);

	if (!ok)
		db_fatal("Failed to commit DB transaction: %s", db->error);

	db->in_transaction = NULL;
	db->dirty = false;
}
