#ifndef LIGHTNING_WALLET_DB_COMMON_H
#define LIGHTNING_WALLET_DB_COMMON_H
#include "config.h"
#include <ccan/autodata/autodata.h>
#include <ccan/short_types/short_types.h>
#include <sqlite3.h>
#include <stdbool.h>

/* For testing, we want to catch fatal messages. */
#ifndef db_fatal
#define db_fatal fatal
#endif

struct db {
	char *filename;
	const char *in_transaction;
	sqlite3 *sql;

	/* DB-specific context */
	void *conn;

	/* The configuration, including translated queries for the current
	 * instance. */
	const struct db_config *config;

	const char **changes;

	char *error;
};

struct db_query {
	const char *name;
	const char *query;

	/* How many placeholders are in the query (and how many will we have
	   to allocate when instantiating this query)? */
	size_t placeholders;

	/* Is this a read-only query? If it is there's no need to tell plugins
	 * about it. */
	bool readonly;
};

enum db_binding_type {
	DB_BINDING_UNINITIALIZED = 0,
	DB_BINDING_NULL,
	DB_BINDING_BLOB,
	DB_BINDING_TEXT,
	DB_BINDING_UINT64,
	DB_BINDING_INT,
};

struct db_binding {
	enum db_binding_type type;
	union {
		int i;
		u64 u64;
		const char* text;
		const u8 *blob;
	} v;
	size_t len;
};

struct db_stmt {
	/* Database we are querying */
	struct db *db;

	/* Which SQL statement are we trying to execute? */
	struct db_query *query;

	/* Which parameters are we binding to the statement? */
	struct db_binding *bindings;

	/* Where are we calling this statement from? */
	const char *location;

	const char *error;

	/* Pointer to DB-specific statement. */
	void *inner_stmt;

	bool executed;
};

struct db_config {
	const char *name;
	struct db_query *queries;
	size_t num_queries;

	/* Function used to get a string representation of the executed query
	 * for the `db_write` plugin hook. */
	const char *(*expand_fn)(struct db_stmt *stmt);

	/* Function used to execute a statement that doesn't result in a
	 * response. */
	bool (*exec_fn)(struct db_stmt *stmt);

	/* Function to execute a query that will result in a response. */
	bool (*query_fn)(struct db_stmt *stmt);

	/* Function used to step forwards through query results. Returns
	 * `false` if there are no more rows to return. */
	bool (*step_fn)(struct db_stmt *stmt);

	bool (*begin_tx_fn)(struct db *db);
	bool (*commit_tx_fn)(struct db *db);

	/* The free function must make sure that any associated state stored
	 * in `stmt->inner_stmt` is freed correctly, setting the pointer to
	 * NULL after cleaning up. It will ultmately be called by the
	 * destructor of `struct db_stmt`, before clearing the db_stmt
	 * itself. */
	void (*stmt_free_fn)(struct db_stmt *db_stmt);

	/* Column access in a row. Only covers the primitives, others need to
	 * use these internally to translate (hence the non-allocating
	 * column_{text,blob}_fn since most other types want in place
	 * assignment. */
	bool (*column_is_null_fn)(struct db_stmt *stmt, int col);
	u64 (*column_u64_fn)(struct db_stmt *stmt, int col);
	size_t (*column_bytes_fn)(struct db_stmt *stmt, int col);
	const void *(*column_blob_fn)(struct db_stmt *stmt, int col);
	const unsigned char *(*column_text_fn)(struct db_stmt *stmt, int col);
	s64 (*column_int_fn)(struct db_stmt *stmt, int col);
};

/* Provide a way for DB backends to register themselves */
AUTODATA_TYPE(db_backends, struct db_config);

#endif /* LIGHTNING_WALLET_DB_COMMON_H */
