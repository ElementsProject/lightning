#include "db_sqlite3_sqlgen.c"
#include <ccan/ccan/tal/str/str.h>
#include <common/utils.h>
#include <lightningd/log.h>

#if HAVE_SQLITE3
  #include <sqlite3.h>

#if !HAVE_SQLITE3_EXPANDED_SQL
/* Prior to sqlite3 v3.14, we have to use tracing to dump statements */
static void trace_sqlite3(void *stmtv, const char *stmt)
{
	struct db_stmt *s = (struct db_stmt*)stmtv;
	db_changes_add(s, stmt);
}
#endif

static const char *db_sqlite3_fmt_error(struct db_stmt *stmt)
{
	return tal_fmt(stmt, "%s: %s: %s", stmt->location, stmt->query->query,
		       sqlite3_errmsg(stmt->db->conn));
}

static bool db_sqlite3_setup(struct db *db)
{
	char *filename;
	sqlite3_stmt *stmt;
	sqlite3 *sql;
	int err, flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;

	if (!strstarts(db->filename, "sqlite3://") || strlen(db->filename) < 10)
		db_fatal("Could not parse the wallet DSN: %s", db->filename);

	/* Strip the scheme from the dsn. */
	filename = db->filename + strlen("sqlite3://");

	err = sqlite3_open_v2(filename, &sql, flags, NULL);

	if (err != SQLITE_OK) {
		db_fatal("failed to open database %s: %s", filename,
			 sqlite3_errstr(err));
	}
	db->conn = sql;

	/* In case another process (litestream?) grabs a lock, we don't
	 * want to return SQLITE_BUSY immediately (which will cause a
	 * fatal error): give it 60 seconds.
	 * We *could* make this an option, but surely the user prefers a
	 * long timeout over an outright crash.
	 */
	sqlite3_busy_timeout(db->conn, 60000);

	sqlite3_prepare_v2(db->conn, "PRAGMA foreign_keys = ON;", -1, &stmt, NULL);
	err = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return err == SQLITE_DONE;
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
	bool success;
#if !HAVE_SQLITE3_EXPANDED_SQL
	/* Register the tracing function if we don't have an explicit way of
	 * expanding the statement. */
	sqlite3_trace(stmt->db->conn, trace_sqlite3, stmt);
#endif

	if (!db_sqlite3_query(stmt)) {
		/* If the prepare step caused an error we hand it up. */
		success = false;
		goto done;
	}

	err = sqlite3_step(stmt->inner_stmt);
	if (err != SQLITE_DONE) {
		tal_free(stmt->error);
		stmt->error = db_sqlite3_fmt_error(stmt);
		success = false;
		goto done;
	}

#if HAVE_SQLITE3_EXPANDED_SQL
	/* Manually expand and call the callback */
	char *expanded_sql;
	expanded_sql = sqlite3_expanded_sql(stmt->inner_stmt);
	db_changes_add(stmt, expanded_sql);
	sqlite3_free(expanded_sql);
#endif
	success = true;

done:
#if !HAVE_SQLITE3_EXPANDED_SQL
	/* Unregister the trace callback to avoid it accessing the potentially
	 * stale pointer to stmt */
	sqlite3_trace(stmt->db->conn, NULL, NULL);
#endif

	return success;
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
		db->error = tal_fmt(db, "Failed to commit a transaction: %s", errmsg);
		return false;
	}
	return true;
}

static bool db_sqlite3_column_is_null(struct db_stmt *stmt, int col)
{
	sqlite3_stmt *s = (sqlite3_stmt*)stmt->inner_stmt;
	return sqlite3_column_type(s, col) == SQLITE_NULL;
}

static u64 db_sqlite3_column_u64(struct db_stmt *stmt, int col)
{
	sqlite3_stmt *s = (sqlite3_stmt*)stmt->inner_stmt;
	return sqlite3_column_int64(s, col);
}

static s64 db_sqlite3_column_int(struct db_stmt *stmt, int col)
{
	sqlite3_stmt *s = (sqlite3_stmt*)stmt->inner_stmt;
	return sqlite3_column_int(s, col);
}

static size_t db_sqlite3_column_bytes(struct db_stmt *stmt, int col)
{
	sqlite3_stmt *s = (sqlite3_stmt*)stmt->inner_stmt;
	return sqlite3_column_bytes(s, col);
}

static const void *db_sqlite3_column_blob(struct db_stmt *stmt, int col)
{
	sqlite3_stmt *s = (sqlite3_stmt*)stmt->inner_stmt;
	return sqlite3_column_blob(s, col);
}

static const unsigned char *db_sqlite3_column_text(struct db_stmt *stmt, int col)
{
	sqlite3_stmt *s = (sqlite3_stmt*)stmt->inner_stmt;
	return sqlite3_column_text(s, col);
}

static void db_sqlite3_stmt_free(struct db_stmt *stmt)
{
	if (stmt->inner_stmt)
		sqlite3_finalize(stmt->inner_stmt);
	stmt->inner_stmt = NULL;
}

static size_t db_sqlite3_count_changes(struct db_stmt *stmt)
{
	sqlite3 *s = stmt->db->conn;
	return sqlite3_changes(s);
}

static void db_sqlite3_close(struct db *db)
{
	sqlite3_close(db->conn);
	db->conn = NULL;
}

static u64 db_sqlite3_last_insert_id(struct db_stmt *stmt)
{
	sqlite3 *s = stmt->db->conn;
	return sqlite3_last_insert_rowid(s);
}

static bool db_sqlite3_vacuum(struct db *db)
{
	int err;
	sqlite3_stmt *stmt;

	sqlite3_prepare_v2(db->conn, "VACUUM;", -1, &stmt, NULL);
	err = sqlite3_step(stmt);
	if (err != SQLITE_DONE)
		db->error = tal_fmt(db, "%s", sqlite3_errmsg(db->conn));
	sqlite3_finalize(stmt);

	return err == SQLITE_DONE;
}

static bool colname_to_delete(const char **colnames,
			      size_t num_colnames,
			      const char *columnname)
{
	for (size_t i = 0; i < num_colnames; i++) {
		if (streq(columnname, colnames[i]))
			return true;
	}
	return false;
}

static const char *find_column_name(const tal_t *ctx,
				    const char *sqlpart,
				    size_t *after)
{
	size_t start = 0;

	while (isspace(sqlpart[start]))
		start++;
	*after = strspn(sqlpart + start, "abcdefghijklmnopqrstuvwxyz_0123456789") + start;
	if (*after == start)
		return NULL;
	return tal_strndup(ctx, sqlpart + start, *after - start);
}

/* Move table out the way, return columns */
static char **prepare_table_manip(const tal_t *ctx,
				  struct db *db, const char *tablename)
{
	sqlite3_stmt *stmt;
	const char *sql;
	char *cmd, *bracket;
	char **parts;
	int err;

	/* Get schema. */
	sqlite3_prepare_v2(db->conn, "SELECT sql FROM sqlite_master WHERE type = ? AND name = ?;", -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, "table", strlen("table"), SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 2, tablename, strlen(tablename), SQLITE_TRANSIENT);
	err = sqlite3_step(stmt);
	if (err != SQLITE_ROW) {
		db->error = tal_fmt(db, "getting schema: %s",
				    sqlite3_errmsg(db->conn));
		sqlite3_finalize(stmt);
		return NULL;
	}

	sql = tal_strdup(tmpctx, (const char *)sqlite3_column_text(stmt, 0));
	sqlite3_finalize(stmt);

	bracket = strchr(sql, '(');
	if (!strstarts(sql, "CREATE TABLE") || !bracket) {
		db->error = tal_fmt(db, "strange schema for %s: %s",
				    tablename, sql);
		return NULL;
	}

	/* Split after ( by commas: any lower case is assumed to be a field */
	parts = tal_strsplit(ctx, bracket + 1, ",", STR_EMPTY_OK);

	/* Turn off foreign keys first. */
	sqlite3_prepare_v2(db->conn, "PRAGMA foreign_keys = OFF;", -1, &stmt, NULL);
	if (sqlite3_step(stmt) != SQLITE_DONE)
		goto sqlite_stmt_err;
	sqlite3_finalize(stmt);

	cmd = tal_fmt(tmpctx, "ALTER TABLE %s RENAME TO temp_%s;",
		      tablename, tablename);
	sqlite3_prepare_v2(db->conn, cmd, -1, &stmt, NULL);
	if (sqlite3_step(stmt) != SQLITE_DONE)
		goto sqlite_stmt_err;
	sqlite3_finalize(stmt);

	return parts;

sqlite_stmt_err:
	db->error = tal_fmt(db, "%s", sqlite3_errmsg(db->conn));
	sqlite3_finalize(stmt);
	return tal_free(parts);
}

static bool complete_table_manip(struct db *db,
				 const char *tablename,
				 const char **coldefs,
				 const char **oldcolnames)
{
	sqlite3_stmt *stmt;
	char *create_cmd, *insert_cmd, *drop_cmd;

	/* Create table */
	create_cmd = tal_fmt(tmpctx, "CREATE TABLE %s (", tablename);
	for (size_t i = 0; i < tal_count(coldefs); i++) {
		if (i != 0)
			tal_append_fmt(&create_cmd, ", ");
		tal_append_fmt(&create_cmd, "%s", coldefs[i]);
	}
	tal_append_fmt(&create_cmd, ";");

	sqlite3_prepare_v2(db->conn, create_cmd, -1, &stmt, NULL);
	if (sqlite3_step(stmt) != SQLITE_DONE)
		goto sqlite_stmt_err;
	sqlite3_finalize(stmt);

	/* Populate table from old one */
	insert_cmd = tal_fmt(tmpctx, "INSERT INTO %s SELECT ", tablename);
	for (size_t i = 0; i < tal_count(oldcolnames); i++) {
		if (i != 0)
			tal_append_fmt(&insert_cmd, ", ");
		tal_append_fmt(&insert_cmd, "%s", oldcolnames[i]);
	}
	tal_append_fmt(&insert_cmd, " FROM temp_%s;", tablename);

	sqlite3_prepare_v2(db->conn, insert_cmd, -1, &stmt, NULL);
	if (sqlite3_step(stmt) != SQLITE_DONE)
		goto sqlite_stmt_err;
	sqlite3_finalize(stmt);

	/* Cleanup temp table */
	drop_cmd = tal_fmt(tmpctx, "DROP TABLE temp_%s;", tablename);
	sqlite3_prepare_v2(db->conn, drop_cmd, -1, &stmt, NULL);
	if (sqlite3_step(stmt) != SQLITE_DONE)
		goto sqlite_stmt_err;
	sqlite3_finalize(stmt);

	/* Allow links between them (esp. cascade deletes!) */
	sqlite3_prepare_v2(db->conn, "PRAGMA foreign_keys = ON;", -1, &stmt, NULL);
	if (sqlite3_step(stmt) != SQLITE_DONE)
		goto sqlite_stmt_err;
	sqlite3_finalize(stmt);

	return true;

sqlite_stmt_err:
	db->error = tal_fmt(db, "%s", sqlite3_errmsg(db->conn));
	sqlite3_finalize(stmt);
	return false;
}

static bool db_sqlite3_rename_column(struct db *db,
				     const char *tablename,
				     const char *from, const char *to)
{
	char **parts;
	const char **coldefs, **oldcolnames;
	bool colname_found = false;

	parts = prepare_table_manip(tmpctx, db, tablename);
	if (!parts)
		return false;

	coldefs = tal_arr(tmpctx, const char *, 0);
	oldcolnames = tal_arr(tmpctx, const char *, 0);

	for (size_t i = 0; parts[i]; i++) {
		/* columnname DETAILS */
		size_t after_name;
		const char *colname = find_column_name(tmpctx, parts[i],
						       &after_name);

		/* Things like "PRIMARY KEY xxx" must be copied verbatim */
		if (!colname) {
			tal_arr_expand(&coldefs, parts[i]);
			continue;
		}
		if (streq(colname, from)) {
			char *newdef;
			colname_found = true;
			/* Create column with new name */
			newdef = tal_fmt(coldefs,
					 "%s%s", to, parts[i] + after_name);
			tal_arr_expand(&coldefs, newdef);
			tal_arr_expand(&oldcolnames, colname);
		} else {
			/* Not mentioned, keep it as is! */
			tal_arr_expand(&coldefs, parts[i]);
			tal_arr_expand(&oldcolnames, colname);
		}
	}

	if (!colname_found) {
		db->error = tal_fmt(db, "No column called %s", from);
		return false;
	}
	return complete_table_manip(db, tablename, coldefs, oldcolnames);
}

static bool db_sqlite3_delete_columns(struct db *db,
				      const char *tablename,
				      const char **colnames, size_t num_cols)
{
	char **parts;
	const char **coldefs, **oldcolnames;
	size_t colnames_found = 0;

	parts = prepare_table_manip(tmpctx, db, tablename);
	if (!parts)
		return false;

	coldefs = tal_arr(tmpctx, const char *, 0);
	oldcolnames = tal_arr(tmpctx, const char *, 0);

	for (size_t i = 0; parts[i]; i++) {
		/* columnname DETAILS */
		size_t after_name;
		const char *colname = find_column_name(tmpctx, parts[i],
						       &after_name);

		/* Things like "PRIMARY KEY xxx" must be copied verbatim */
		if (!colname) {
			tal_arr_expand(&coldefs, parts[i]);
			continue;
		}

		/* Don't mention columns we're supposed to delete */
		if (colname_to_delete(colnames, num_cols, colname)) {
			colnames_found++;
			continue;
		}

		/* Keep it as is! */
		tal_arr_expand(&coldefs, parts[i]);
		tal_arr_expand(&oldcolnames, colname);
	}

	if (colnames_found != num_cols) {
		db->error = tal_fmt(db, "Only %zu/%zu columns found",
				    colnames_found, num_cols);
		return false;
	}
	return complete_table_manip(db, tablename, coldefs, oldcolnames);
}

struct db_config db_sqlite3_config = {
	.name = "sqlite3",
	.query_table = db_sqlite3_queries,
	.query_table_size = ARRAY_SIZE(db_sqlite3_queries),
	.exec_fn = &db_sqlite3_exec,
	.query_fn = &db_sqlite3_query,
	.step_fn = &db_sqlite3_step,
	.begin_tx_fn = &db_sqlite3_begin_tx,
	.commit_tx_fn = &db_sqlite3_commit_tx,
	.stmt_free_fn = &db_sqlite3_stmt_free,

	.column_is_null_fn = &db_sqlite3_column_is_null,
	.column_u64_fn = &db_sqlite3_column_u64,
	.column_int_fn = &db_sqlite3_column_int,
	.column_bytes_fn = &db_sqlite3_column_bytes,
	.column_blob_fn = &db_sqlite3_column_blob,
	.column_text_fn = &db_sqlite3_column_text,

	.last_insert_id_fn = &db_sqlite3_last_insert_id,
	.count_changes_fn = &db_sqlite3_count_changes,
	.setup_fn = &db_sqlite3_setup,
	.teardown_fn = &db_sqlite3_close,

	.vacuum_fn = db_sqlite3_vacuum,
	.rename_column = db_sqlite3_rename_column,
	.delete_columns = db_sqlite3_delete_columns,
};

AUTODATA(db_backends, &db_sqlite3_config);

#endif
