#ifndef LIGHTNING_DB_UTILS_H
#define LIGHTNING_DB_UTILS_H
#include "config.h"
#include <ccan/take/take.h>
#include <ccan/tal/tal.h>

struct db;
struct db_stmt;

size_t db_query_colnum(const struct db_stmt *stmt,
		       const char *colname);

/* Return next 'row' result of statement */
bool db_step(struct db_stmt *stmt);

/* TODO(cdecker) Remove the v2 suffix after finishing the migration */
#define db_prepare_v2(db,query)						\
	db_prepare_v2_(__FILE__ ":" stringify(__LINE__), db, query)


/**
 * db_exec_prepared -- Execute a prepared statement
 *
 * After preparing a statement using `db_prepare`, and after binding all
 * non-null variables using the `db_bind_*` functions, it can be executed with
 * this function. It is a small, transaction-aware, wrapper around `db_step`,
 * that calls fatal() if the execution fails. This may take ownership of
 * `stmt` if annotated with `take()`and will free it before returning.
 *
 * If you'd like to issue a query and access the rows returned by the query
 * please use `db_query_prepared` instead, since this function will not expose
 * returned results, and the `stmt` can only be used for calls to
 * `db_count_changes` and `db_last_insert_id` after executing.
 *
 * @stmt: The prepared statement to execute
 */
void db_exec_prepared_v2(struct db_stmt *stmt TAKES);

/**
 * db_query_prepared -- Execute a prepared query
 *
 * After preparing a query using `db_prepare`, and after binding all non-null
 * variables using the `db_bind_*` functions, it can be executed with this
 * function. This function must be called before calling `db_step` or any of
 * the `db_col_*` column access functions.
 *
 * If you are not executing a read-only statement, please use
 * `db_exec_prepared` instead.
 *
 * @stmt: The prepared statement to execute
 */
void db_query_prepared(struct db_stmt *stmt);

/**
 * Variation which allows failure.
 */
bool db_query_prepared_canfail(struct db_stmt *stmt);

size_t db_count_changes(struct db_stmt *stmt);
void db_report_changes(struct db *db, const char *final, size_t min);
void db_prepare_for_changes(struct db *db);

u64 db_last_insert_id_v2(struct db_stmt *stmt);

/**
 * db_prepare -- Prepare a DB query/command
 *
 * Create an instance of `struct db_stmt` that encapsulates a SQL query or command.
 *
 * @query MUST be wrapped in a `SQL()` macro call, since that allows the
 * extraction and translation of the query into the target SQL dialect.
 *
 * It does not execute the query and does not check its validity, but
 * allocates the placeholders detected in the query. The placeholders in the
 * `stmt` can then be bound using the `db_bind_*` functions, and executed
 * using `db_exec_prepared` for write-only statements and `db_query_prepared`
 * for read-only statements.
 *
 * @db: Database to query/exec
 * @query: The SQL statement to compile
 */
struct db_stmt *db_prepare_v2_(const char *location, struct db *db,
			       const char *query_id);

/**
 * db_open - Open or create a database
 */
#define db_open(ctx, filename, developer, errfn, arg)		\
	db_open_((ctx), (filename), (developer),			\
		 typesafe_cb_postargs(void, void *, (errfn), (arg),	\
				      bool, const char *, va_list),		\
		 (arg))

struct db *db_open_(const tal_t *ctx, const char *filename, bool developer,
		    void (*errorfn)(void *arg, bool fatal, const char *fmt, va_list ap),
		    void *arg);

/**
 * Report a statement that changes the wallet
 *
 * Allows the DB driver to report an expanded statement during
 * execution. Changes are queued up and reported to the `db_write` plugin hook
 * upon committing.
 */
void db_changes_add(struct db_stmt *db_stmt, const char * expanded);
void db_assert_no_outstanding_statements(struct db *db);

/**
 * Access pending changes that have been added to the current transaction.
 */
const char **db_changes(struct db *db);

/**
 * Accessor for internal use.
 *
 * Like db_prepare_v2() but creates temporary noop translation, and
 * assumes not a read-only op.  Use this inside db-specific backends
 * to re-use the normal db hook and replication logic.
 */
struct db_stmt *db_prepare_untranslated(struct db *db, const char *query);

/* Errors and warnings... */
void db_fatal(const struct db *db, const char *fmt, ...)
	PRINTF_FMT(2, 3);
void db_warn(const struct db *db, const char *fmt, ...)
	PRINTF_FMT(2, 3);

#endif /* LIGHTNING_DB_UTILS_H */
