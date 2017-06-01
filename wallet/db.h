#ifndef WALLET_DB_H
#define WALLET_DB_H

#include "config.h"
#include "daemon/log.h"

#include <sqlite3.h>
#include <stdbool.h>

struct db {
	char *filename;
	bool in_transaction;
	const char *err;
	sqlite3 *sql;
};

/**
 * db_setup - Open a the lightningd database and update the schema
 *
 * Opens the database, creating it if necessary, and applying
 * migrations until the schema is updated to the current state.
 *
 * Params:
 *  @ctx: the tal_t context to allocate from
 *  @log: where to log messages to
 */
struct db *db_setup(const tal_t *ctx);

/**
 * db_query - Prepare and execute a query, and return the result
 */
sqlite3_stmt *PRINTF_FMT(3, 4)
	db_query(const char *caller, struct db *db, const char *fmt, ...);

bool PRINTF_FMT(3, 4)
	db_exec(const char *caller, struct db *db, const char *fmt, ...);

/**
 * db_begin_transaction - Begin a transaction
 *
 * We do not support nesting multiple transactions, so make sure that
 * we are not in a transaction when calling this. Returns true if we
 * succeeded in starting a transaction.
 */
bool db_begin_transaction(struct db *db);

/**
 * db_commit_transaction - Commit a running transaction
 *
 * Requires that we are currently in a transaction. Returns whether
 * the commit was successful.
 */
bool db_commit_transaction(struct db *db);

/**
 * db_rollback_transaction - Whoops... undo! undo!
 */
bool db_rollback_transaction(struct db *db);

/**
 * db_set_intvar - Set an integer variable in the database
 *
 * Utility function to store generic integer values in the
 * database.
 */
bool db_set_intvar(struct db *db, char *varname, s64 val);

/**
 * db_get_intvar - Retrieve an integer variable from the database
 *
 * Either returns the value in the database, or @defval if
 * the query failed or no such variable exists.
 */
s64 db_get_intvar(struct db *db, char *varname, s64 defval);

#endif /* WALLET_DB_H */
