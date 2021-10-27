#include "db_sqlite3_sqlgen.c"
#include <ccan/ccan/tal/str/str.h>
#include <lightningd/log.h>

#if HAVE_SQLITE3
  #include <sqlite3.h>

struct db_sqlite3 {
	/* The actual db connection.  */
	sqlite3 *conn;
	/* A replica db connection, if requested, or NULL otherwise.  */
	sqlite3 *backup_conn;
	/* The backup object for the replica db connection.  */
	sqlite3_backup *backup;
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
		       sqlite3_errmsg(conn2sql(stmt->db->conn)));
}

static bool db_sqlite3_setup(struct db *db)
{
	char *filename;
	char *sep;
	char *backup_filename = NULL;
	sqlite3_stmt *stmt;
	sqlite3 *sql;
	int err, flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;

	struct db_sqlite3 *wrapper;

	if (!strstarts(db->filename, "sqlite3://") || strlen(db->filename) < 10)
		db_fatal("Could not parse the wallet DSN: %s", db->filename);

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
		db_fatal("failed to open database %s: %s", filename,
			 sqlite3_errstr(err));
	}
	wrapper->conn = sql;

	if (!backup_filename) {
		wrapper->backup_conn = NULL;
		wrapper->backup = NULL;
	} else {
		err = sqlite3_open_v2(backup_filename,
				      &wrapper->backup_conn,
				      flags, NULL);
		if (err != SQLITE_OK) {
			db_fatal("failed to open backup database %s: %s",
				 backup_filename,
				 sqlite3_errstr(err));
		}

		wrapper->backup = sqlite3_backup_init(wrapper->backup_conn,
						      "main",
						      wrapper->conn,
						      "main");
		if (!wrapper->backup) {
			db_fatal("failed to setup backup on database %s: %s",
				 backup_filename,
				 sqlite3_errmsg(wrapper->backup_conn));
		}

		/* Initial copy.  */
		err = sqlite3_backup_step(wrapper->backup, -1);
		if (err != SQLITE_DONE) {
			db_fatal("Failed initial backup: %s",
				 sqlite3_errstr(err));
		}
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
	return err == SQLITE_DONE;
}

static bool db_sqlite3_query(struct db_stmt *stmt)
{
	sqlite3_stmt *s;
	sqlite3 *conn = conn2sql(stmt->db->conn);
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
	sqlite3_trace(conn2sql(stmt->db->conn), trace_sqlite3, stmt);
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
	sqlite3_trace(conn2sql(stmt->db->conn), NULL, NULL);
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
	err = sqlite3_exec(conn2sql(db->conn),
			   "BEGIN TRANSACTION;", NULL, NULL, &errmsg);
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

	struct db_sqlite3 *wrapper = (struct db_sqlite3 *) db->conn;

	err = sqlite3_exec(conn2sql(db->conn),
				    "COMMIT;", NULL, NULL, &errmsg);
	if (err != SQLITE_OK) {
		db->error = tal_fmt(db, "Failed to commit a transaction: %s", errmsg);
		return false;
	}

	if (wrapper->backup) {
		/* This *should* be fast:
		 * https://sqlite.org/c3ref/backup_finish.html#sqlite3backupstep
		 * "If the source database is modified by using the same database
		 * connection as is used by the backup operation, then the backup
		 * database is automatically updated at the same time."
		 * So the `COMMIT;` should have updated the backup too, and the
		 * sqlite3_backup_step should return quickly.
		 */
		err = sqlite3_backup_step(wrapper->backup, -1);
		if (err != SQLITE_DONE) {
			db->error = tal_fmt(db,
					    "Failed to replicate transaction "
					    "to backup: %s",
					    sqlite3_errstr(err));
			return false;
		}
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
	sqlite3 *s = conn2sql(stmt->db->conn);
	return sqlite3_changes(s);
}

static void db_sqlite3_close(struct db *db)
{
	struct db_sqlite3 *wrapper = (struct db_sqlite3 *) db->conn;

	if (wrapper->backup) {
		sqlite3_backup_finish(wrapper->backup);
		sqlite3_close(wrapper->backup_conn);
	}
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

	if (err == SQLITE_DONE && wrapper->backup) {
		err = sqlite3_backup_step(wrapper->backup, -1);
		if (err != SQLITE_DONE)
			db->error = tal_fmt(db,
					    "Failed to replicate VACUUM "
					    "to backup: %s",
					    sqlite3_errstr(err));
	}

	return err == SQLITE_DONE;
}

struct db_config db_sqlite3_config = {
	.name = "sqlite3",
	.queries = db_sqlite3_queries,
	.num_queries = DB_SQLITE3_QUERY_COUNT,
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
};

AUTODATA(db_backends, &db_sqlite3_config);

#endif
