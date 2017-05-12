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

#endif /* WALLET_DB_H */
