#ifndef LIGHTNING_WALLET_DB_H
#define LIGHTNING_WALLET_DB_H
#include "config.h"

#include <bitcoin/preimage.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>
#include <bitcoin/tx.h>
#include <ccan/autodata/autodata.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <common/amount.h>
#include <secp256k1_ecdh.h>
#include <sqlite3.h>
#include <stdbool.h>

struct lightningd;
struct log;
struct node_id;
struct db_stmt;
struct db;

/**
 * Macro to annotate a named SQL query.
 *
 * This macro is used to annotate SQL queries that might need rewriting for
 * different SQL dialects. It is used both as a marker for the query
 * extraction logic in devtools/sql-rewrite.py to identify queries, as well as
 * a way to swap out the query text with it's name so that the query execution
 * engine can then look up the rewritten query using its name.
 *
 */
#define NAMED_SQL(name,x) x

/**
 * Simple annotation macro that auto-generates names for NAMED_SQL
 *
 * If this macro is changed it is likely that the extraction logic in
 * devtools/sql-rewrite.py needs to change as well, since they need to
 * generate identical names to work correctly.
 */
#define SQL(x) NAMED_SQL( __FILE__ ":" stringify(__LINE__) ":" stringify(__COUNTER__), x)


/**
 * db_setup - Open a the lightningd database and update the schema
 *
 * Opens the database, creating it if necessary, and applying
 * migrations until the schema is updated to the current state.
 * Calls fatal() on error.
 *
 * Params:
 *  @ctx: the tal_t context to allocate from
 *  @ld: the lightningd context to hand to upgrade functions.
 *  @log: where to log messages to
 */
struct db *db_setup(const tal_t *ctx, struct lightningd *ld, struct log *log);

/**
 * db_select - Prepare and execute a SELECT, and return the result
 *
 * A simpler version of db_select_prepare.
 */
sqlite3_stmt *db_select_(const char *location, struct db *db, const char *query);
#define db_select(db, query) \
	db_select_(__FILE__ ":" stringify(__LINE__), db, query)

/**
 * db_begin_transaction - Begin a transaction
 *
 * Begin a new DB transaction.  fatal() on database error.
 */
#define db_begin_transaction(db) \
	db_begin_transaction_((db), __FILE__ ":" stringify(__LINE__))
void db_begin_transaction_(struct db *db, const char *location);

bool db_in_transaction(struct db *db);

// FIXME(cdecker) Need to maybe add a pointer to the db_stmt we are referring to
// FIXME(cdecker) Comment
u64 db_last_insert_id(struct db *db);

// FIXME(cdecker) Need to maybe add a pointer to the db_stmt we are referring to
// FIXME(cdecker) Comment
size_t db_changes(struct db *db);

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
 * db_select_prepare -- Prepare a DB select statement (read-only!)
 *
 * Tiny wrapper around `sqlite3_prepare_v2` that checks and sets
 * errors like `db_query` and `db_exec` do.  It calls fatal if
 * the stmt is not valid.
 *
 * Call db_select_step() until it returns false (which will also consume
 * the stmt).
 *
 * @db: Database to query/exec
 * @query: The SELECT SQL statement to compile
 */
#define db_select_prepare(db, query) \
	db_select_prepare_(__FILE__ ":" stringify(__LINE__), db, query)
sqlite3_stmt *db_select_prepare_(const char *location,
				 struct db *db, const char *query);

/**
 * db_select_step -- iterate through db results.
 *
 * Returns false and frees stmt if we've reached end, otherwise
 * it means sqlite3_step has returned SQLITE_ROW.
 */
#define db_select_step(db, stmt)					\
	db_select_step_(__FILE__ ":" stringify(__LINE__), db, stmt)
bool db_select_step_(const char *location,
		     struct db *db, struct sqlite3_stmt *stmt);

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

/* Wrapper around sqlite3_finalize(), for tracking statements. */
void db_stmt_done(sqlite3_stmt *stmt);

/* Call when you know there should be no outstanding db statements. */
void db_assert_no_outstanding_statements(void);

#define sqlite3_column_arr(ctx, stmt, col, type)			\
	((type *)sqlite3_column_arr_((ctx), (stmt), (col),		\
				     sizeof(type), TAL_LABEL(type, "[]"), \
				     __func__))
void *sqlite3_column_arr_(const tal_t *ctx, sqlite3_stmt *stmt, int col,
			  size_t bytes, const char *label, const char *caller);

bool sqlite3_bind_short_channel_id(sqlite3_stmt *stmt, int col,
				   const struct short_channel_id *id);
WARN_UNUSED_RESULT bool sqlite3_column_short_channel_id(sqlite3_stmt *stmt, int col,
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

bool sqlite3_column_node_id(sqlite3_stmt *stmt, int col, struct node_id *dest);
bool sqlite3_bind_node_id(sqlite3_stmt *stmt, int col, const struct node_id *id);

bool sqlite3_bind_pubkey_array(sqlite3_stmt *stmt, int col,
			       const struct pubkey *pks);
struct pubkey *sqlite3_column_pubkey_array(const tal_t *ctx,
					   sqlite3_stmt *stmt, int col);

bool sqlite3_bind_node_id_array(sqlite3_stmt *stmt, int col,
				const struct node_id *ids);
struct node_id *sqlite3_column_node_id_array(const tal_t *ctx,
					     sqlite3_stmt *stmt, int col);

bool sqlite3_column_preimage(sqlite3_stmt *stmt, int col,  struct preimage *dest);
bool sqlite3_bind_preimage(sqlite3_stmt *stmt, int col, const struct preimage *p);

bool sqlite3_column_sha256(sqlite3_stmt *stmt, int col,  struct sha256 *dest);
bool sqlite3_bind_sha256(sqlite3_stmt *stmt, int col, const struct sha256 *p);

bool sqlite3_column_sha256_double(sqlite3_stmt *stmt, int col,  struct sha256_double *dest);
bool sqlite3_bind_sha256_double(sqlite3_stmt *stmt, int col, const struct sha256_double *p);
struct secret *sqlite3_column_secrets(const tal_t *ctx,
				      sqlite3_stmt *stmt, int col);

struct json_escape *sqlite3_column_json_escape(const tal_t *ctx,
					       sqlite3_stmt *stmt, int col);
bool sqlite3_bind_json_escape(sqlite3_stmt *stmt, int col,
			      const struct json_escape *esc);

struct amount_msat sqlite3_column_amount_msat(sqlite3_stmt *stmt, int col);
struct amount_sat sqlite3_column_amount_sat(sqlite3_stmt *stmt, int col);
void sqlite3_bind_amount_msat(sqlite3_stmt *stmt, int col,
			      struct amount_msat msat);
void sqlite3_bind_amount_sat(sqlite3_stmt *stmt, int col,
			     struct amount_sat sat);

/* Helpers to read and write absolute times from and to the database. */
void sqlite3_bind_timeabs(sqlite3_stmt *stmt, int col, struct timeabs t);
struct timeabs sqlite3_column_timeabs(sqlite3_stmt *stmt, int col);


void db_bind_null(struct db_stmt *stmt, int pos);
void db_bind_int(struct db_stmt *stmt, int pos, int val);
void db_bind_u64(struct db_stmt *stmt, int pos, u64 val);
void db_bind_blob(struct db_stmt *stmt, int pos, u8 *val, size_t len);
void db_bind_text(struct db_stmt *stmt, int pos, const char *val);
bool db_exec_prepared_v2(struct db_stmt *stmt TAKES);

void db_stmt_free(struct db_stmt *stmt);

struct db_stmt *db_prepare_v2_(const char *location, struct db *db,
			       const char *query_id);
#define db_prepare_v2(db,query) \
	db_prepare_v2_(__FILE__ ":" stringify(__LINE__), db, query)

#endif /* LIGHTNING_WALLET_DB_H */
