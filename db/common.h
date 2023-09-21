#ifndef LIGHTNING_DB_COMMON_H
#define LIGHTNING_DB_COMMON_H
#include "config.h"
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/strset/strset.h>
#include <common/autodata.h>
#include <common/utils.h>
#include <stdarg.h>

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

struct db {
	char *filename;
	const char *in_transaction;

	/* DB-specific context */
	void *conn;

	/* function to log warnings, or fail (if fatal == true). vprintf-style */
	void (*errorfn)(void *arg, bool fatal, const char *fmt, va_list ap);
	void *errorfn_arg;

	/* The configuration for the current database driver */
	const struct db_config *config;

	/* Translated queries for the current database domain + driver */
	const struct db_query_set *queries;

	const char **changes;

	/* List of statements that have been created but not executed yet. */
	struct list_head pending_statements;
	char *error;

	/* Were there any modifying statements in the current transaction?
	 * Used to bump the data_version in the DB.*/
	bool dirty;

	/* The current DB version we expect to update if changes are
	 * committed. */
	u32 data_version;

	void (*report_changes_fn)(struct db *);

	/* Set by --developer */
	bool developer;
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

	/* If this is a select statement, what column names */
	const struct sqlname_map *colnames;
	size_t num_colnames;
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
		s32 i;
		u64 u64;
		const char* text;
		const u8 *blob;
	} v;
	size_t len;
};

struct db_stmt {
	/* Our entry in the list of pending statements. */
	struct list_node list;

	/* Bind counter */
	int bind_pos;

	/* Database we are querying */
	struct db *db;

	/* Which SQL statement are we trying to execute? */
	const struct db_query *query;

	/* Which parameters are we binding to the statement? */
	struct db_binding *bindings;

	/* Where are we calling this statement from? */
	const char *location;

	const char *error;

	/* Pointer to DB-specific statement. */
	void *inner_stmt;

	bool executed;

	int row;

	/* --developer: map as we reference into a SELECT statement
	 * in query. */
	struct strset *cols_used;
};

struct db_query_set {
	const char *name;
	const struct db_query *query_table;
	size_t query_table_size;
};

struct db_config {
	const char *name;

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

	u64 (*last_insert_id_fn)(struct db_stmt *stmt);
	size_t (*count_changes_fn)(struct db_stmt *stmt);

	bool (*setup_fn)(struct db *db);
	void (*teardown_fn)(struct db *db);

	bool (*vacuum_fn)(struct db *db);

	bool (*rename_column)(struct db *db,
			      const char *tablename,
			      const char *from, const char *to);
	bool (*delete_columns)(struct db *db,
			       const char *tablename,
			       const char **colnames, size_t num_cols);
};

/* Provide a way for DB backends to register themselves */
AUTODATA_TYPE(db_backends, struct db_config);

/* Provide a way for DB query sets to register themselves */
AUTODATA_TYPE(db_queries, struct db_query_set);

/* devtools/sql-rewrite.py generates this simple htable */
struct sqlname_map {
	const char *sqlname;
	int val;
};

#endif /* LIGHTNING_DB_COMMON_H */
