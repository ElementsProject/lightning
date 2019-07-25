#ifndef LIGHTNING_WALLET_DB_COMMON_H
#define LIGHTNING_WALLET_DB_COMMON_H
#include "config.h"
#include <ccan/autodata/autodata.h>
#include <ccan/short_types/short_types.h>
#include <sqlite3.h>

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
};

struct db_config {
	const char *name;
	struct db_query *queries;
	size_t num_queries;
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
	/* Which SQL statement are we trying to execute? */
	struct db_query *query;

	/* Which parameters are we binding to the statement? */
	struct db_binding *bindings;

	/* Where are we calling this statement from? */
	const char *location;
};

/* Provide a way for DB backends to register themselves */
AUTODATA_TYPE(db_backends, struct db_config);

#endif /* LIGHTNING_WALLET_DB_COMMON_H */
