#include <wallet/db_common.h>
#include "gen_db_sqlite3.c"
#include <ccan/ccan/tal/str/str.h>
#include <lightningd/log.h>
#include <sqlite3.h>
#include <stdio.h>

#if HAVE_SQLITE3

static const char *db_sqlite3_expand(struct db_stmt *stmt)
{
#if HAVE_SQLITE3_EXPANDED_SQL
	sqlite3_stmt *s = (sqlite3_stmt*)stmt->inner_stmt;
	const char *sql;
	char *expanded_sql;
	expanded_sql = sqlite3_expanded_sql(s);
	sql = tal_strdup(stmt, expanded_sql);
	sqlite3_free(expanded_sql);
	return sql;
#else
	return NULL;
#endif
}

static const char *db_sqlite3_fmt_error(struct db_stmt *stmt)
{
	return tal_fmt(stmt, "%s: %s: %s", stmt->location, stmt->query->query,
		       sqlite3_errmsg(stmt->db->conn));
}

static bool db_sqlite3_query(struct db_stmt *stmt)
{
	sqlite3_stmt *s;
	sqlite3 *conn = (sqlite3*)stmt->db->conn;
	int err;

	err = sqlite3_prepare_v2(conn, stmt->query->query, -1, &s, NULL);

	for (size_t i=0; i<stmt->query->placeholders; i++) {
		struct db_binding *b = &stmt->bindings[i];

		/* sqlite3 uses printf-like offsets, we don't... */
		int pos = i+1;
		switch (b->type) {
		case DB_BINDING_UNINITIALIZED:
			db_fatal("DB binding not initialized: position=%zu, "
				 "query=\"%s\n",
				 i, stmt->query->query);
		case DB_BINDING_UINT64:
			sqlite3_bind_int64(s, pos, b->v.u64);
			break;
		case DB_BINDING_INT:
			sqlite3_bind_int(s, pos, b->v.i);
			break;
		case DB_BINDING_BLOB:
			sqlite3_bind_blob(s, pos, b->v.blob, b->len,
					  SQLITE_TRANSIENT);
			break;
		case DB_BINDING_TEXT:
			sqlite3_bind_text(s, pos, b->v.text, b->len,
					  SQLITE_TRANSIENT);
			break;
		case DB_BINDING_NULL:
			sqlite3_bind_null(s, pos);
			break;
		}
	}

	if (err != SQLITE_OK) {
		tal_free(stmt->error);
		stmt->error = db_sqlite3_fmt_error(stmt);
		return false;
	}

	stmt->inner_stmt = s;
	return true;
}

static bool db_sqlite3_exec(struct db_stmt *stmt)
{
	int err;
	if (!db_sqlite3_query(stmt)) {
		/* If the prepare step caused an error we hand it up. */
		return false;
	}

	err = sqlite3_step(stmt->inner_stmt);
	if (err != SQLITE_DONE) {
		tal_free(stmt->error);
		stmt->error = db_sqlite3_fmt_error(stmt);
		return false;
	}

	return true;
}

static bool db_sqlite3_step(struct db_stmt *stmt)
{
	sqlite3_stmt *s = (sqlite3_stmt*)stmt->inner_stmt;
	return sqlite3_step(s) ==  SQLITE_ROW;
}

static bool db_sqlite3_begin_tx(struct db *db)
{
	int err;
	char *errmsg;
	err = sqlite3_exec(db->conn, "BEGIN TRANSACTION;", NULL, NULL, &errmsg);
	if (err != SQLITE_OK) {
		db->error = tal_fmt(db, "Failed to begin a transaction: %s", errmsg);
		return false;
	}
	return true;
}

static bool db_sqlite3_commit_tx(struct db *db)
{
	int err;
	char *errmsg;
	err = sqlite3_exec(db->conn, "COMMIT;", NULL, NULL, &errmsg);
	if (err != SQLITE_OK) {
		db->error = tal_fmt(db, "Failed to begin a transaction: %s", errmsg);
		return false;
	}
	return true;
}

static void db_sqlite3_stmt_free(struct db_stmt *stmt)
{
	if (stmt->inner_stmt)
		sqlite3_finalize(stmt->inner_stmt);
	tal_free(stmt);
}

struct db_config db_sqlite3_config = {
	.name = "sqlite3",
	.queries = db_sqlite3_queries,
	.num_queries = DB_SQLITE3_QUERY_COUNT,
	.expand_fn = &db_sqlite3_expand,
	.exec_fn = &db_sqlite3_exec,
	.query_fn = &db_sqlite3_query,
	.step_fn = &db_sqlite3_step,
	.begin_tx_fn = &db_sqlite3_begin_tx,
	.commit_tx_fn = &db_sqlite3_commit_tx,
	.stmt_free_fn = &db_sqlite3_stmt_free,
};

AUTODATA(db_backends, &db_sqlite3_config);

#endif
