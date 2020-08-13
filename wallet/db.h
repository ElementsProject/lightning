#ifndef LIGHTNING_WALLET_DB_H
#define LIGHTNING_WALLET_DB_H
#include "config.h"

#include <bitcoin/preimage.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>
#include <bitcoin/tx.h>
#include <ccan/autodata/autodata.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <common/amount.h>
#include <secp256k1_ecdh.h>
#include <stdbool.h>

struct ext_key;
struct lightningd;
struct log;
struct node_id;
struct onionreply;
struct db_stmt;
struct db;
struct wally_psbt;

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
#define SQL(x) NAMED_SQL( __FILE__ ":" stringify(__COUNTER__), x)


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
 *  @bip32_base: the base all of our pubkeys are constructed on
 */
struct db *db_setup(const tal_t *ctx, struct lightningd *ld,
		    const struct ext_key *bip32_base);

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

void db_bind_null(struct db_stmt *stmt, int pos);
void db_bind_int(struct db_stmt *stmt, int pos, int val);
void db_bind_u64(struct db_stmt *stmt, int pos, u64 val);
void db_bind_blob(struct db_stmt *stmt, int pos, const u8 *val, size_t len);
void db_bind_text(struct db_stmt *stmt, int pos, const char *val);
void db_bind_preimage(struct db_stmt *stmt, int pos, const struct preimage *p);
void db_bind_sha256(struct db_stmt *stmt, int pos, const struct sha256 *s);
void db_bind_sha256d(struct db_stmt *stmt, int pos, const struct sha256_double *s);
void db_bind_secret(struct db_stmt *stmt, int pos, const struct secret *s);
void db_bind_secret_arr(struct db_stmt *stmt, int col, const struct secret *s);
void db_bind_txid(struct db_stmt *stmt, int pos, const struct bitcoin_txid *t);
void db_bind_node_id(struct db_stmt *stmt, int pos, const struct node_id *ni);
void db_bind_node_id_arr(struct db_stmt *stmt, int col,
			 const struct node_id *ids);
void db_bind_pubkey(struct db_stmt *stmt, int pos, const struct pubkey *p);
void db_bind_short_channel_id(struct db_stmt *stmt, int col,
			      const struct short_channel_id *id);
void db_bind_short_channel_id_arr(struct db_stmt *stmt, int col,
				  const struct short_channel_id *id);
void db_bind_signature(struct db_stmt *stmt, int col,
		       const secp256k1_ecdsa_signature *sig);
void db_bind_timeabs(struct db_stmt *stmt, int col, struct timeabs t);
void db_bind_tx(struct db_stmt *stmt, int col, const struct wally_tx *tx);
void db_bind_psbt(struct db_stmt *stmt, int col, const struct wally_psbt *psbt);
void db_bind_amount_msat(struct db_stmt *stmt, int pos,
			 const struct amount_msat *msat);
void db_bind_amount_sat(struct db_stmt *stmt, int pos,
			const struct amount_sat *sat);
void db_bind_json_escape(struct db_stmt *stmt, int pos,
			 const struct json_escape *esc);
void db_bind_onionreply(struct db_stmt *stmt, int col,
			const struct onionreply *r);

bool db_step(struct db_stmt *stmt);
u64 db_column_u64(struct db_stmt *stmt, int col);
int db_column_int(struct db_stmt *stmt, int col);
size_t db_column_bytes(struct db_stmt *stmt, int col);
int db_column_is_null(struct db_stmt *stmt, int col);
const void* db_column_blob(struct db_stmt *stmt, int col);
const unsigned char *db_column_text(struct db_stmt *stmt, int col);
void db_column_preimage(struct db_stmt *stmt, int col, struct preimage *preimage);
void db_column_amount_msat(struct db_stmt *stmt, int col, struct amount_msat *msat);
void db_column_amount_sat(struct db_stmt *stmt, int col, struct amount_sat *sat);
struct json_escape *db_column_json_escape(const tal_t *ctx, struct db_stmt *stmt, int col);
void db_column_sha256(struct db_stmt *stmt, int col, struct sha256 *sha);
void db_column_sha256d(struct db_stmt *stmt, int col, struct sha256_double *shad);
void db_column_secret(struct db_stmt *stmt, int col, struct secret *s);
struct secret *db_column_secret_arr(const tal_t *ctx, struct db_stmt *stmt,
				    int col);
void db_column_txid(struct db_stmt *stmt, int pos, struct bitcoin_txid *t);
void db_column_node_id(struct db_stmt *stmt, int pos, struct node_id *ni);
struct node_id *db_column_node_id_arr(const tal_t *ctx, struct db_stmt *stmt,
				      int col);
void db_column_pubkey(struct db_stmt *stmt, int pos, struct pubkey *p);
bool db_column_short_channel_id(struct db_stmt *stmt, int col,
				struct short_channel_id *dest);
struct short_channel_id *
db_column_short_channel_id_arr(const tal_t *ctx, struct db_stmt *stmt, int col);
bool db_column_signature(struct db_stmt *stmt, int col,
			 secp256k1_ecdsa_signature *sig);
struct timeabs db_column_timeabs(struct db_stmt *stmt, int col);
struct bitcoin_tx *db_column_tx(const tal_t *ctx, struct db_stmt *stmt, int col);
struct bitcoin_tx *db_column_psbt_to_tx(const tal_t *ctx, struct db_stmt *stmt, int col);

struct onionreply *db_column_onionreply(const tal_t *ctx,
					struct db_stmt *stmt, int col);

#define db_column_arr(ctx, stmt, col, type)			\
	((type *)db_column_arr_((ctx), (stmt), (col),		\
				sizeof(type), TAL_LABEL(type, "[]"),	\
				__func__))
void *db_column_arr_(const tal_t *ctx, struct db_stmt *stmt, int col,
		     size_t bytes, const char *label, const char *caller);


/* Some useful default variants */
int db_column_int_or_default(struct db_stmt *stmt, int col, int def);
void db_column_amount_msat_or_default(struct db_stmt *stmt, int col,
				      struct amount_msat *msat,
				      struct amount_msat def);

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
bool db_exec_prepared_v2(struct db_stmt *stmt TAKES);

/**
 * db_query_prepared -- Execute a prepared query
 *
 * After preparing a query using `db_prepare`, and after binding all non-null
 * variables using the `db_bind_*` functions, it can be executed with this
 * function. This function must be called before calling `db_step` or any of
 * the `db_column_*` column access functions.
 *
 * If you are not executing a read-only statement, please use
 * `db_exec_prepared` instead.
 *
 * @stmt: The prepared statement to execute
 */
bool db_query_prepared(struct db_stmt *stmt);
size_t db_count_changes(struct db_stmt *stmt);
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

/* TODO(cdecker) Remove the v2 suffix after finishing the migration */
#define db_prepare_v2(db,query)						\
	db_prepare_v2_(__FILE__ ":" stringify(__LINE__), db, query)

/**
 * Access pending changes that have been added to the current transaction.
 */
const char **db_changes(struct db *db);

/* Get the current data version. */
u32 db_data_version_get(struct db *db);

#endif /* LIGHTNING_WALLET_DB_H */
