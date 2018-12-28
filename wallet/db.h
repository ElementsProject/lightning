#ifndef LIGHTNING_WALLET_DB_H
#define LIGHTNING_WALLET_DB_H
#include "config.h"

#include <bitcoin/preimage.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>
#include <bitcoin/tx.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <secp256k1_ecdh.h>
#include <sqlite3.h>
#include <stdbool.h>

struct log;

struct db {
	char *filename;
	const char *in_transaction;
	sqlite3 *sql;
};

/**
 * db_setup - Open a the lightningd database and update the schema
 *
 * Opens the database, creating it if necessary, and applying
 * migrations until the schema is updated to the current state.
 * Calls fatal() on error.
 *
 * Params:
 *  @ctx: the tal_t context to allocate from
 *  @log: where to log messages to
 */
struct db *db_setup(const tal_t *ctx, struct log *log);

/**
 * db_query - Prepare and execute a query, and return the result (or NULL)
 */
sqlite3_stmt *PRINTF_FMT(3, 4)
	db_query_(const char *location, struct db *db, const char *fmt, ...);
#define db_query(db, ...) \
	db_query_(__FILE__ ":" stringify(__LINE__), db, __VA_ARGS__)

/**
 * db_begin_transaction - Begin a transaction
 *
 * Begin a new DB transaction.  fatal() on database error.
 */
#define db_begin_transaction(db) \
	db_begin_transaction_((db), __FILE__ ":" stringify(__LINE__))
void db_begin_transaction_(struct db *db, const char *location);

/**
 * db_commit_transaction - Commit a running transaction
 *
 * Requires that we are currently in a transaction.  fatal() if we
 * fail to commit.
 */
void db_commit_transaction(struct db *db);

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

/**
 * db_prepare -- Prepare a DB query/command
 *
 * Tiny wrapper around `sqlite3_prepare_v2` that checks and sets
 * errors like `db_query` and `db_exec` do. It returns a statement
 * `stmt` if the given query/command was successfully compiled into a
 * statement, `NULL` otherwise. On failure `db->err` will be set with
 * the human readable error.
 *
 * @db: Database to query/exec
 * @query: The SQL statement to compile
 */
#define db_prepare(db,query) \
	db_prepare_(__FILE__ ":" stringify(__LINE__), db, query)
sqlite3_stmt *db_prepare_(const char *location, struct db *db, const char *query);

/**
 * db_exec_prepared -- Execute a prepared statement
 *
 * After preparing a statement using `db_prepare`, and after binding
 * all non-null variables using the `sqlite3_bind_*` functions, it can
 * be executed with this function. It is a small, transaction-aware,
 * wrapper around `sqlite3_step`, that calls fatal() if the execution
 * fails. This will take ownership of `stmt` and will free
 * it before returning.
 *
 * @db: The database to execute on
 * @stmt: The prepared statement to execute
 */
#define db_exec_prepared(db,stmt) db_exec_prepared_(__func__,db,stmt)
void db_exec_prepared_(const char *caller, struct db *db, sqlite3_stmt *stmt);

/**
 * db_exec_prepared_mayfail - db_exec_prepared, but don't fatal() it fails.
 */
#define db_exec_prepared_mayfail(db,stmt) \
	db_exec_prepared_mayfail_(__func__,db,stmt)
bool db_exec_prepared_mayfail_(const char *caller,
			       struct db *db,
			       sqlite3_stmt *stmt);

/* Wrapper around sqlite3_finalize(), for tracking statements. */
void db_stmt_done(sqlite3_stmt *stmt);

/* Call when you know there should be no outstanding db statements. */
void db_assert_no_outstanding_statements(void);

/* Do not keep db open across a fork: needed for --daemon */
void db_close_for_fork(struct db *db);
void db_reopen_after_fork(struct db *db);

#define sqlite3_column_arr(ctx, stmt, col, type)			\
	((type *)sqlite3_column_arr_((ctx), (stmt), (col),		\
				     sizeof(type), TAL_LABEL(type, "[]"), \
				     __func__))
void *sqlite3_column_arr_(const tal_t *ctx, sqlite3_stmt *stmt, int col,
			  size_t bytes, const char *label, const char *caller);

bool sqlite3_bind_short_channel_id(sqlite3_stmt *stmt, int col,
				   const struct short_channel_id *id);
bool sqlite3_column_short_channel_id(sqlite3_stmt *stmt, int col,
				     struct short_channel_id *dest);
bool sqlite3_bind_short_channel_id_array(sqlite3_stmt *stmt, int col,
					 const struct short_channel_id *id);
struct short_channel_id *
sqlite3_column_short_channel_id_array(const tal_t *ctx,
				      sqlite3_stmt *stmt, int col);
bool sqlite3_bind_tx(sqlite3_stmt *stmt, int col, const struct bitcoin_tx *tx);
struct bitcoin_tx *sqlite3_column_tx(const tal_t *ctx, sqlite3_stmt *stmt,
				     int col);
bool sqlite3_bind_signature(sqlite3_stmt *stmt, int col, const secp256k1_ecdsa_signature *sig);
bool sqlite3_column_signature(sqlite3_stmt *stmt, int col, secp256k1_ecdsa_signature *sig);

bool sqlite3_column_pubkey(sqlite3_stmt *stmt, int col,  struct pubkey *dest);
bool sqlite3_bind_pubkey(sqlite3_stmt *stmt, int col, const struct pubkey *pk);

bool sqlite3_bind_pubkey_array(sqlite3_stmt *stmt, int col,
			       const struct pubkey *pks);
struct pubkey *sqlite3_column_pubkey_array(const tal_t *ctx,
					   sqlite3_stmt *stmt, int col);

bool sqlite3_column_preimage(sqlite3_stmt *stmt, int col,  struct preimage *dest);
bool sqlite3_bind_preimage(sqlite3_stmt *stmt, int col, const struct preimage *p);

bool sqlite3_column_sha256(sqlite3_stmt *stmt, int col,  struct sha256 *dest);
bool sqlite3_bind_sha256(sqlite3_stmt *stmt, int col, const struct sha256 *p);

bool sqlite3_column_sha256_double(sqlite3_stmt *stmt, int col,  struct sha256_double *dest);
bool sqlite3_bind_sha256_double(sqlite3_stmt *stmt, int col, const struct sha256_double *p);
struct secret *sqlite3_column_secrets(const tal_t *ctx,
				      sqlite3_stmt *stmt, int col);

struct json_escaped *sqlite3_column_json_escaped(const tal_t *ctx,
						 sqlite3_stmt *stmt, int col);
bool sqlite3_bind_json_escaped(sqlite3_stmt *stmt, int col,
			       const struct json_escaped *esc);
#endif /* LIGHTNING_WALLET_DB_H */
