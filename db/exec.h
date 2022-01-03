#ifndef LIGHTNING_DB_EXEC_H
#define LIGHTNING_DB_EXEC_H
#include "config.h"

#include <ccan/short_types/short_types.h>
#include <ccan/take/take.h>

struct db;

/**
 * db_set_intvar - Set an integer variable in the database
 *
 * Utility function to store generic integer values in the
 * database.
 */
void db_set_intvar(struct db *db, char *varname, s64 val);

/**
 * db_get_intvar - Retrieve an integer variable from the database
 *
 * Either returns the value in the database, or @defval if
 * the query failed or no such variable exists.
 */
s64 db_get_intvar(struct db *db, char *varname, s64 defval);

/* Get the current data version (entries). */
u32 db_data_version_get(struct db *db);

/* Get the current database version (migrations). */
int db_get_version(struct db *db);

/**
 * db_begin_transaction - Begin a transaction
 *
 * Begin a new DB transaction.  fatal() on database error.
 */
#define db_begin_transaction(db) \
	db_begin_transaction_((db), __FILE__ ":" stringify(__LINE__))
void db_begin_transaction_(struct db *db, const char *location);

bool db_in_transaction(struct db *db);

/**
 * db_commit_transaction - Commit a running transaction
 *
 * Requires that we are currently in a transaction.  fatal() if we
 * fail to commit.
 */
void db_commit_transaction(struct db *db);


#endif /* LIGHTNING_DB_EXEC_H */
