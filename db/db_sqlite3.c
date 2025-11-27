#include "config.h"
#include <ccan/ccan/tal/str/str.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>

#if HAVE_SQLITE3
  #include <sqlite3.h>

struct db_sqlite3 {
	/* The actual db connection.  */
	sqlite3 *conn;
	/* A replica db connection, if requested, or NULL otherwise.  */
	sqlite3 *backup_conn;
};

/**
 * @param conn: The db->conn void * pointer.
 *
 * @return the actual sqlite3 connection.
 */
static inline
sqlite3 *conn2sql(void *conn)
{
	struct db_sqlite3 *wrapper = (struct db_sqlite3 *) conn;
	return wrapper->conn;
}

static void replicate_statement(const struct db *db,
				struct db_sqlite3 *wrapper,
				const char *qry)
{
	sqlite3_stmt *stmt;
	int err;

	if (!wrapper->backup_conn)
		return;

	sqlite3_prepare_v2(wrapper->backup_conn,
			   qry, -1, &stmt, NULL);
	err = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if (err != SQLITE_DONE)
		db_fatal(db, "Failed to replicate query: %s: %s: %s",
			 sqlite3_errstr(err),
			 sqlite3_errmsg(wrapper->backup_conn),
			 qry);
}

static void db_sqlite3_changes_add(struct db_sqlite3 *wrapper,
				   struct db_stmt *stmt,
				   const char *qry)
{
	replicate_statement(stmt->db, wrapper, qry);
	db_changes_add(stmt, qry);
}

/* Check if both sqlite3 databases have a data_version variable,
 * *and* are the same.
 */
static bool have_same_data_version(sqlite3 *a, sqlite3 *b)
{
	sqlite3_stmt *stmt;
	const char *qry = "SELECT intval FROM vars"
			  " WHERE name = 'data_version';";
	int err;

	u64 version_a;
	u64 version_b;

	sqlite3_prepare_v2(a, qry, -1, &stmt, NULL);
	err = sqlite3_step(stmt);
	if (err != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return false;
	}
	version_a = sqlite3_column_int64(stmt, 0);
	sqlite3_finalize(stmt);

	sqlite3_prepare_v2(b, qry, -1, &stmt, NULL);
	err = sqlite3_step(stmt);
	if (err != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return false;
	}
	version_b = sqlite3_column_int64(stmt, 0);
	sqlite3_finalize(stmt);

	return version_a == version_b;
}

static const char *db_sqlite3_fmt_error(struct db_stmt *stmt)
{
	return tal_fmt(stmt, "%s: %s: %s", stmt->location, stmt->query->query,
		       sqlite3_errmsg(conn2sql(stmt->db->conn)));
}

static bool db_sqlite3_setup(struct db *db, bool create)
{
	char *filename;
	char *sep;
	char *backup_filename = NULL;
	sqlite3_stmt *stmt;
	sqlite3 *sql;
	int err, flags;
	struct db_sqlite3 *wrapper;

	if (!strstarts(db->filename, "sqlite3://") || strlen(db->filename) < 10)
		db_fatal(db, "Could not parse the wallet DSN: %s", db->filename);

	flags = SQLITE_OPEN_READWRITE;
	if (create)
		flags |= SQLITE_OPEN_CREATE;

	/* Strip the scheme from the dsn. */
	filename = db->filename + strlen("sqlite3://");
	/* Look for a replica specification.  */
	sep = strchr(filename, ':');
	if (sep) {
		/* Split at ':'.  */
		filename = tal_strndup(db, filename, sep - filename);
		backup_filename = tal_strdup(db, sep + 1);
	}

	wrapper = tal(db, struct db_sqlite3);
	db->conn = wrapper;

	err = sqlite3_open_v2(filename, &sql, flags, NULL);
	if (err != SQLITE_OK) {
		/* Note: even on error, the sql connection is allocated! */
		sqlite3_close(sql);
		if (!create)
			return false;
		db_fatal(db, "failed to open database %s: %s", filename,
			 sqlite3_errstr(err));
	}
	wrapper->conn = sql;

	err = sqlite3_extended_result_codes(wrapper->conn, 1);
	if (err != SQLITE_OK) {
		db_fatal(db, "failed to enable extended result codes: %s",
			 sqlite3_errstr(err));
	}

	if (!backup_filename)
		wrapper->backup_conn = NULL;
	else {
		err = sqlite3_open_v2(backup_filename,
				      &wrapper->backup_conn,
				      flags, NULL);
		if (err != SQLITE_OK) {
			db_fatal(db, "failed to open backup database %s: %s",
				 backup_filename,
				 sqlite3_errstr(err));
		}

		sqlite3_prepare_v2(wrapper->backup_conn,
				   "PRAGMA foreign_keys = ON;", -1, &stmt,
				   NULL);
		err = sqlite3_step(stmt);
		sqlite3_finalize(stmt);

		if (err != SQLITE_DONE) {
			db_fatal(db, "failed to use backup database %s: %s",
				 backup_filename,
				 sqlite3_errstr(err));
		}
	}

	/* If we have a backup db, but it does not have a matching
	 * data_version, copy over the main database.  */
	if (wrapper->backup_conn &&
	    !have_same_data_version(wrapper->conn, wrapper->backup_conn)) {
		/* Copy the main database over the backup database.  */
		sqlite3_backup *copier = sqlite3_backup_init(wrapper->backup_conn,
							     "main",
							     wrapper->conn,
							     "main");
		if (!copier) {
			db_fatal(db, "failed to initiate copy to %s: %s",
				 backup_filename,
				 sqlite3_errmsg(wrapper->backup_conn));
		}
		err = sqlite3_backup_step(copier, -1);
		if (err != SQLITE_DONE) {
			db_fatal(db, "failed to copy database to %s: %s",
				 backup_filename,
				 sqlite3_errstr(err));
		}
		sqlite3_backup_finish(copier);
	}

	/* In case another process (litestream?) grabs a lock, we don't
	 * want to return SQLITE_BUSY immediately (which will cause a
	 * fatal error): give it 60 seconds.
	 * We *could* make this an option, but surely the user prefers a
	 * long timeout over an outright crash.
	 */
	sqlite3_busy_timeout(conn2sql(db->conn), 60000);

	sqlite3_prepare_v2(conn2sql(db->conn),
			   "PRAGMA foreign_keys = ON;", -1, &stmt, NULL);
	err = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if (err != SQLITE_DONE)
		return false;

	if (db->developer) {
		sqlite3_prepare_v2(conn2sql(db->conn),
				   "PRAGMA trusted_schema = OFF;", -1, &stmt, NULL);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);

		sqlite3_prepare_v2(conn2sql(db->conn),
				   "PRAGMA cell_size_check = ON;", -1, &stmt, NULL);
		sqlite3_step(stmt);
		sqlite3_finalize(stmt);
	}

	return true;
}

static bool db_sqlite3_query(struct db_stmt *stmt)
{
	sqlite3_stmt *s;
	sqlite3 *conn = conn2sql(stmt->db->conn);
	int err;
	const char *query = stmt->query->query;
	char *modified_query = NULL;

	/* STRICT tables for developer mode, and not during upgrades. */
	if (stmt->db->developer &&
	    !stmt->db->in_migration &&
	    strncasecmp(query, "CREATE TABLE", 12) == 0 &&
	    !strstr(query, "STRICT")) {
		modified_query = tal_fmt(stmt, "%s STRICT", query);
		query = modified_query;
	}

	err = sqlite3_prepare_v2(conn, query, -1, &s, NULL);

	if (modified_query)
		tal_free(modified_query);

	for (size_t i=0; i<stmt->query->placeholders; i++) {
		struct db_binding *b = &stmt->bindings[i];

		/* sqlite3 uses printf-like offsets, we don't... */
		int pos = i+1;
		switch (b->type) {
		case DB_BINDING_UNINITIALIZED:
			db_fatal(stmt->db, "DB binding not initialized: position=%zu, "
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
	char *expanded_sql;
	struct db_sqlite3 *wrapper = (struct db_sqlite3 *) stmt->db->conn;

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

	/* Manually expand and call the callback */
	expanded_sql = sqlite3_expanded_sql(stmt->inner_stmt);
	db_sqlite3_changes_add(wrapper, stmt, expanded_sql);
	sqlite3_free(expanded_sql);

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

	struct db_sqlite3 *wrapper = (struct db_sqlite3 *) db->conn;

	err = sqlite3_exec(conn2sql(db->conn),
			   "BEGIN TRANSACTION;", NULL, NULL, &errmsg);
	if (err != SQLITE_OK) {
		db->error = tal_fmt(db, "Failed to begin a transaction: %s", errmsg);
		return false;
	}
	replicate_statement(db, wrapper, "BEGIN TRANSACTION;");
	return true;
}

static bool db_sqlite3_commit_tx(struct db *db)
{
	int err;
	char *errmsg;

	struct db_sqlite3 *wrapper = (struct db_sqlite3 *) db->conn;

	err = sqlite3_exec(conn2sql(db->conn),
				    "COMMIT;", NULL, NULL, &errmsg);
	if (err != SQLITE_OK) {
		db->error = tal_fmt(db, "Failed to commit a transaction: %s", errmsg);
		return false;
	}
	replicate_statement(db, wrapper, "COMMIT;");
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
	sqlite3 *s = conn2sql(stmt->db->conn);
	return sqlite3_changes(s);
}

static void db_sqlite3_close(struct db *db)
{
	struct db_sqlite3 *wrapper = (struct db_sqlite3 *) db->conn;

	if (wrapper->backup_conn)
		sqlite3_close(wrapper->backup_conn);
	sqlite3_close(wrapper->conn);

	db->conn = tal_free(db->conn);
}

static u64 db_sqlite3_last_insert_id(struct db_stmt *stmt)
{
	sqlite3 *s = conn2sql(stmt->db->conn);
	return sqlite3_last_insert_rowid(s);
}

static bool db_sqlite3_vacuum(struct db *db)
{
	int err;
	sqlite3_stmt *stmt;

	struct db_sqlite3 *wrapper = (struct db_sqlite3 *) db->conn;

	sqlite3_prepare_v2(conn2sql(db->conn), "VACUUM;", -1, &stmt, NULL);
	err = sqlite3_step(stmt);
	if (err != SQLITE_DONE)
		db->error = tal_fmt(db, "%s",
				    sqlite3_errmsg(conn2sql(db->conn)));
	sqlite3_finalize(stmt);
	replicate_statement(db, wrapper, "VACUUM;");

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

/* Returns NULL if this doesn't look like a column definition */
static const char *find_column_name(const tal_t *ctx,
				    const char *sqlpart,
				    size_t *after)
{
	size_t start = 0;

	while (cisspace(sqlpart[start]))
		start++;
	*after = strspn(sqlpart + start, "abcdefghijklmnopqrstuvwxyz_0123456789") + start;
	if (*after == start || !cisspace(sqlpart[*after]))
		return NULL;
	return tal_strndup(ctx, sqlpart + start, *after - start);
}

/* Move table out the way, return columns.
 * Note: with db_hook, frees tmpctx! */
static char **prepare_table_manip(const tal_t *ctx,
				  struct db *db, const char *tablename)
{
	sqlite3_stmt *stmt;
	const char *sql;
	char *cmd, *bracket;
	char **parts;
	int err;
	struct db_sqlite3 *wrapper = (struct db_sqlite3 *)db->conn;

	/* Get schema. */
	sqlite3_prepare_v2(wrapper->conn, "SELECT sql FROM sqlite_master WHERE type = ? AND name = ?;", -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, "table", strlen("table"), SQLITE_TRANSIENT);
	sqlite3_bind_text(stmt, 2, tablename, strlen(tablename), SQLITE_TRANSIENT);

	err = sqlite3_step(stmt);
	if (err != SQLITE_ROW) {
		db->error = tal_fmt(db, "getting schema: %s",
				    sqlite3_errmsg(wrapper->conn));
		sqlite3_finalize(stmt);
		return NULL;
	}

	sql = tal_strdup(tmpctx, (const char *)sqlite3_column_text(stmt, 0));
	sqlite3_finalize(stmt);

	/* We MUST use generic routines to write to db, since they
	 * mirror changes to the db hook! */
	bracket = strchr(sql, '(');
	if (!strstarts(sql, "CREATE TABLE") || !bracket)
		db_fatal(db, "Bad sql from prepare_table_manip %s: %s",
			 tablename, sql);

	/* Split after ( by commas: any lower case is assumed to be a field */
	parts = tal_strsplit(ctx, bracket + 1, ",", STR_EMPTY_OK);

	/* Now, we actually need to turn OFF transactions for a moment, as
	 * this pragma only has an effect outside a tx! */
	db_commit_transaction(db);

	/* But core insists we're "in a transaction" for all ops, so fake it */
	db->in_transaction = "Not really";
	db->transaction_started = true;
	/* Turn off foreign keys first. */
	db_prepare_for_changes(db);
	db_exec_prepared_v2(take(db_prepare_untranslated(db,
							 "PRAGMA foreign_keys = OFF;")));
	db_report_changes(db, NULL, 0);
	db->in_transaction = NULL;
	db->transaction_started = false;

	db_begin_transaction(db);
	cmd = tal_fmt(tmpctx, "ALTER TABLE %s RENAME TO temp_%s;",
		      tablename, tablename);
	db_exec_prepared_v2(take(db_prepare_untranslated(db, cmd)));

	return parts;
}

static bool complete_table_manip(struct db *db,
				 const char *tablename,
				 const char **coldefs,
				 const char **oldcolnames)
{
	char *create_cmd, *insert_cmd, *drop_cmd;

	/* Create table */
	create_cmd = tal_fmt(tmpctx, "CREATE TABLE %s (", tablename);
	for (size_t i = 0; i < tal_count(coldefs); i++) {
		if (i != 0)
			tal_append_fmt(&create_cmd, ", ");
		tal_append_fmt(&create_cmd, "%s", coldefs[i]);
	}
	tal_append_fmt(&create_cmd, ";");

	db_exec_prepared_v2(take(db_prepare_untranslated(db, create_cmd)));

	/* Populate table from old one */
	insert_cmd = tal_fmt(tmpctx, "INSERT INTO %s SELECT ", tablename);
	for (size_t i = 0; i < tal_count(oldcolnames); i++) {
		if (i != 0)
			tal_append_fmt(&insert_cmd, ", ");
		tal_append_fmt(&insert_cmd, "%s", oldcolnames[i]);
	}
	tal_append_fmt(&insert_cmd, " FROM temp_%s;", tablename);

	db_exec_prepared_v2(take(db_prepare_untranslated(db, insert_cmd)));

	/* Cleanup temp table */
	drop_cmd = tal_fmt(tmpctx, "DROP TABLE temp_%s;", tablename);
	db_exec_prepared_v2(take(db_prepare_untranslated(db, drop_cmd)));
	db_commit_transaction(db);

	/* Allow links between them (esp. cascade deletes!) */
	db->in_transaction = "Not really";
	db->transaction_started = true;
	db_prepare_for_changes(db);
	db_exec_prepared_v2(take(db_prepare_untranslated(db,
					       "PRAGMA foreign_keys = ON;")));
	db_report_changes(db, NULL, 0);
	db->in_transaction = NULL;
	db->transaction_started = false;

	/* migrations are performed inside transactions, so start one. */
	db_begin_transaction(db);
	return true;
}

/* FIXME: sqlite3 version 3.25.0 (2018-09-15) supports ALTER TABLE RENAME */
static bool db_sqlite3_rename_column(struct db *db,
				     const char *tablename,
				     const char *from, const char *to)
{
	char **parts;
	const char **coldefs, **oldcolnames;
	bool colname_found = false;

	parts = prepare_table_manip(NULL, db, tablename);
	if (!parts)
		return false;

	tal_steal(tmpctx, parts);
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

	parts = prepare_table_manip(NULL, db, tablename);
	if (!parts)
		return false;

	tal_steal(tmpctx, parts);
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

#endif /* HAVE_SQLITE3 */
