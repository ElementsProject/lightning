#include "db.h"

#include "daemon/log.h"
#include "lightningd/lightningd.h"

#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <inttypes.h>

#define DB_FILE "lightningd.sqlite3"

/* Do not reorder or remove elements from this array, it is used to
 * migrate existing databases from a previous state, based on the
 * string indices */
char *dbmigrations[] = {
    "CREATE TABLE version (version INTEGER)",
    "INSERT INTO version VALUES (1)",
    "CREATE TABLE outputs ( \
       prev_out_tx CHAR(64),			 \
       prev_out_index INTEGER,			 \
       value INTEGER,				 \
       type INTEGER,				 \
       status INTEGER,				 \
       keyindex INTEGER,			 \
       PRIMARY KEY (prev_out_tx, prev_out_index) \
    );",
    "CREATE TABLE vars (name VARCHAR(32), val VARCHAR(255), PRIMARY KEY (name));",
    NULL,
};

bool PRINTF_FMT(3, 4)
    db_exec(const char *caller, struct db *db, const char *fmt, ...)
{
	va_list ap;
	char *cmd, *errmsg;
	int err;

	if (db->in_transaction && db->err)
		return false;

	va_start(ap, fmt);
	cmd = tal_vfmt(db, fmt, ap);
	va_end(ap);

	err = sqlite3_exec(db->sql, cmd, NULL, NULL, &errmsg);
	if (err != SQLITE_OK) {
		db->in_transaction = false;
		tal_free(db->err);
		db->err = tal_fmt(db, "%s:%s:%s:%s", caller,
				  sqlite3_errstr(err), cmd, errmsg);
		sqlite3_free(errmsg);
		tal_free(cmd);
		return false;
	}
	tal_free(cmd);
	return true;
}

sqlite3_stmt *PRINTF_FMT(3, 4)
    db_query(const char *caller, struct db *db, const char *fmt, ...)
{
	va_list ap;
	char *query;
	sqlite3_stmt *stmt;
	int err;

	if (db->in_transaction && db->err)
		return NULL;

	va_start(ap, fmt);
	query = tal_vfmt(db, fmt, ap);
	va_end(ap);

	err = sqlite3_prepare_v2(db->sql, query, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		db->in_transaction = false;
		db->err = tal_fmt(db, "%s:%s:%s:%s", caller,
				  sqlite3_errstr(err), query, sqlite3_errmsg(db->sql));
	}
	return stmt;
}

/**
 * db_clear_error - Clear any errors from previous queries
 */
static void db_clear_error(struct db *db)
{
	db->err = tal_free(db->err);
}


static void close_db(struct db *db) { sqlite3_close(db->sql); }

bool db_begin_transaction(struct db *db)
{
	assert(!db->in_transaction);
	/* Clear any errors from previous transactions and
	 * non-transactional queries */
	db_clear_error(db);
	db->in_transaction = db_exec(__func__, db, "BEGIN TRANSACTION;");
	return db->in_transaction;
}

bool db_commit_transaction(struct db *db)
{
	assert(db->in_transaction);
	bool ret = db_exec(__func__, db, "COMMIT;");
	db->in_transaction = false;
	return ret;
}

bool db_rollback_transaction(struct db *db)
{
	assert(db->in_transaction);
	bool ret = db_exec(__func__, db, "ROLLBACK;");
	db->in_transaction = false;
	return ret;
}

/**
 * db_open - Open or create a sqlite3 database
 */
static struct db *db_open(const tal_t *ctx, char *filename)
{
	int err;
	struct db *db;
	sqlite3 *sql;

	if (SQLITE_VERSION_NUMBER != sqlite3_libversion_number())
		fatal("SQLITE version mistmatch: compiled %u, now %u",
		      SQLITE_VERSION_NUMBER, sqlite3_libversion_number());

	int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
	err = sqlite3_open_v2(filename, &sql, flags, NULL);

	if (err != SQLITE_OK) {
		fatal("failed to open database %s: %s", filename,
		      sqlite3_errstr(err));
	}

	db = tal(ctx, struct db);
	db->filename = tal_dup_arr(db, char, filename, strlen(filename), 0);
	db->sql = sql;
	tal_add_destructor(db, close_db);
	db->in_transaction = false;
	db->err = NULL;
	return db;
}

/**
 * db_get_version - Determine the current DB schema version
 *
 * Will attempt to determine the current schema version of the
 * database @db by querying the `version` table. If the table does not
 * exist it'll return schema version -1, so that migration 0 is
 * applied, which should create the `version` table.
 */
static int db_get_version(struct db *db)
{
	int err;
	u64 res = -1;
	sqlite3_stmt *stmt =
	    db_query(__func__, db, "SELECT version FROM version LIMIT 1");

	if (!stmt)
		return -1;

	err = sqlite3_step(stmt);
	if (err != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return -1;
	} else {
		res = sqlite3_column_int64(stmt, 0);
		sqlite3_finalize(stmt);
		return res;
	}
}

/**
 * db_mirgation_count - Count how many migrations are available
 *
 * Returns the maximum migration index, i.e., the version number of an
 * up-to-date database schema.
 */
static int db_migration_count(void)
{
	int count = 0;
	while (dbmigrations[count] != NULL)
		count++;
	return count - 1;
}

/**
 * db_migrate - Apply all remaining migrations from the current version
 */
static bool db_migrate(struct db *db)
{
	/* Attempt to read the version from the database */
	int current = db_get_version(db);
	int available = db_migration_count();

	if (!db_begin_transaction(db)) {
		/* No need to rollback, we didn't even start... */
		return false;
	}

	while (++current <= available) {
		if (!db_exec(__func__, db, "%s", dbmigrations[current]))
			goto fail;
	}

	/* Finally update the version number in the version table */
	db_exec(__func__, db, "UPDATE version SET version=%d;", available);

	if (!db_commit_transaction(db)) {
		goto fail;
	}

	return true;
fail:
	db_rollback_transaction(db);
	return false;
}

struct db *db_setup(const tal_t *ctx)
{
	struct db *db = db_open(ctx, DB_FILE);
	if (!db) {
		return db;
	}

	if (!db_migrate(db)) {
		return tal_free(db);
	}
	return db;
}

s64 db_get_intvar(struct db *db, char *varname, s64 defval)
{
	int err;
	s64 res = defval;
	const unsigned char *stringvar;
	sqlite3_stmt *stmt =
	    db_query(__func__, db,
		     "SELECT val FROM vars WHERE name='%s' LIMIT 1", varname);

	if (!stmt)
		return defval;

	err = sqlite3_step(stmt);
	if (err == SQLITE_ROW) {
		stringvar = sqlite3_column_text(stmt, 0);
		res = atol((const char *)stringvar);
	}
	sqlite3_finalize(stmt);
	return res;
}

bool db_set_intvar(struct db *db, char *varname, s64 val)
{
	/* Attempt to update */
	db_exec(__func__, db,
		"UPDATE vars SET val='%" PRId64 "' WHERE name='%s';", val,
		varname);
	if (sqlite3_changes(db->sql) > 0)
		return true;
	else
		return db_exec(
		    __func__, db,
		    "INSERT INTO vars (name, val) VALUES ('%s', '%" PRId64
		    "');",
		    varname, val);
}
