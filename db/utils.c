#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/utils.h>
#include <db/common.h>
#include <db/utils.h>

/* Matches the hash function used in devtools/sql-rewrite.py */
static u32 hash_djb2(const char *str)
{
	u32 hash = 5381;
	for (size_t i = 0; str[i]; i++)
		hash = ((hash << 5) + hash) ^ str[i];
	return hash;
}

size_t db_query_colnum(const struct db_stmt *stmt,
		       const char *colname)
{
	u32 col;

	assert(stmt->query->colnames != NULL);

	col = hash_djb2(colname) % stmt->query->num_colnames;
	for (;;) {
		const char *n = stmt->query->colnames[col].sqlname;
		if (!n)
			db_fatal(stmt->db, "Unknown column name %s in query %s",
				 colname, stmt->query->query);
		if (streq(n, colname))
			break;
		col = (col + 1) % stmt->query->num_colnames;
	}

	if (stmt->db->developer)
		strset_add(stmt->cols_used, colname);

	return stmt->query->colnames[col].val;
}

static void db_stmt_free(struct db_stmt *stmt)
{
	if (!stmt->executed)
		db_fatal(stmt->db, "Freeing an un-executed statement from %s: %s",
			 stmt->location, stmt->query->query);
	/* If they never got a db_step, we don't track */
	if (stmt->db->developer && stmt->cols_used) {
		for (size_t i = 0; i < stmt->query->num_colnames; i++) {
			if (!stmt->query->colnames[i].sqlname)
				continue;
			if (!strset_get(stmt->cols_used,
					stmt->query->colnames[i].sqlname)) {
				db_fatal(stmt->db, "Never accessed column %s in query %s",
					  stmt->query->colnames[i].sqlname,
					  stmt->query->query);
			}
		}
		strset_clear(stmt->cols_used);
	}

	if (stmt->inner_stmt)
		stmt->db->config->stmt_free_fn(stmt);
	assert(stmt->inner_stmt == NULL);
}


static struct db_stmt *db_prepare_core(struct db *db,
				       const char *location,
				       const struct db_query *db_query)
{
	struct db_stmt *stmt = tal(db, struct db_stmt);
	size_t num_slots = db_query->placeholders;

	/* Allocate the slots for placeholders/bindings, zeroed next since
	 * that sets the type to DB_BINDING_UNINITIALIZED for later checks. */
	stmt->bindings = tal_arrz(stmt, struct db_binding, num_slots);
	stmt->location = location;
	stmt->error = NULL;
	stmt->db = db;
	stmt->query = db_query;
	stmt->executed = false;
	stmt->inner_stmt = NULL;
	stmt->cols_used = NULL;
	stmt->bind_pos = -1;

	tal_add_destructor(stmt, db_stmt_free);
	list_add(&db->pending_statements, &stmt->list);

	return stmt;
}

struct db_stmt *db_prepare_v2_(const char *location, struct db *db,
			       const char *query_id)
{
	size_t pos;

	/* Normalize query_id paths, because unit tests are compiled with this
	 * prefix. */
	if (strncmp(query_id, "./", 2) == 0)
		query_id += 2;

	if (!db->in_transaction)
		db_fatal(db, "Attempting to prepare a db_stmt outside of a "
			 "transaction: %s", location);

	/* Look up the query by its ID */
	pos = hash_djb2(query_id) % db->queries->query_table_size;
	for (;;) {
		if (!db->queries->query_table[pos].name)
			db_fatal(db, "Could not resolve query %s", query_id);
		if (streq(query_id, db->queries->query_table[pos].name))
			break;
		pos = (pos + 1) % db->queries->query_table_size;
	}

	return db_prepare_core(db, location, &db->queries->query_table[pos]);
}

/* Provides replication and hook interface for raw SQL too */
struct db_stmt *db_prepare_untranslated(struct db *db, const char *query)
{
	struct db_query *db_query = tal(NULL, struct db_query);
	struct db_stmt *stmt;

	db_query->name = db_query->query = query;
	db_query->placeholders = strcount(query, "?");
	db_query->readonly = false;

	/* Use raw accessors! */
	db_query->colnames = NULL;
	db_query->num_colnames = 0;

	stmt = db_prepare_core(db, "db_prepare_untranslated", db_query);
	tal_steal(stmt, db_query);
	return stmt;
}

bool db_query_prepared_canfail(struct db_stmt *stmt)
{
	/* Make sure we don't accidentally execute a modifying query using a
	 * read-only path. */
	bool ret;
	assert(stmt->query->readonly);
	ret = stmt->db->config->query_fn(stmt);
	stmt->executed = true;
	list_del_from(&stmt->db->pending_statements, &stmt->list);
	return ret;
}

void db_query_prepared(struct db_stmt *stmt)
{
	if (!db_query_prepared_canfail(stmt))
		db_fatal(stmt->db, "query failed: %s: %s",
			 stmt->location, stmt->query->query);
}

bool db_step(struct db_stmt *stmt)
{
	bool ret;

	assert(stmt->executed);
	ret = stmt->db->config->step_fn(stmt);

	/* We only track cols_used if we return a result! */
	if (stmt->db->developer && ret && !stmt->cols_used) {
		stmt->cols_used = tal(stmt, struct strset);
		strset_init(stmt->cols_used);
	}

	return ret;
}

void db_exec_prepared_v2(struct db_stmt *stmt TAKES)
{
	bool ret = stmt->db->config->exec_fn(stmt);

	if (stmt->db->readonly)
		assert(stmt->query->readonly);

	/* If this was a write we need to bump the data_version upon commit. */
	stmt->db->dirty = stmt->db->dirty || !stmt->query->readonly;

	stmt->executed = true;
	list_del_from(&stmt->db->pending_statements, &stmt->list);

	/* The driver itself doesn't call `fatal` since we want to override it
	 * for testing. Instead we check here that the error message is set if
	 * we report an error. */
	if (!ret) {
		assert(stmt->error);
		db_fatal(stmt->db, "Error executing statement: %s", stmt->error);
	}

	if (taken(stmt))
	    tal_free(stmt);
}

size_t db_count_changes(struct db_stmt *stmt)
{
	assert(stmt->executed);
	return stmt->db->config->count_changes_fn(stmt);
}

const char **db_changes(struct db *db)
{
	return db->changes;
}

u64 db_last_insert_id_v2(struct db_stmt *stmt TAKES)
{
	u64 id;
	assert(stmt->executed);
	id = stmt->db->config->last_insert_id_fn(stmt);

	if (taken(stmt))
		tal_free(stmt);

	return id;
}

/* We expect min changes (ie. BEGIN TRANSACTION): report if more.
 * Optionally add "final" at the end (ie. COMMIT). */
void db_report_changes(struct db *db, const char *final, size_t min)
{
	assert(db->changes);
	assert(tal_count(db->changes) >= min);

	/* Having changes implies that we have a dirty TX. The opposite is
	 * currently not true, e.g., the postgres driver doesn't record
	 * changes yet. */
	assert(!tal_count(db->changes) || db->dirty);

	if (tal_count(db->changes) > min && db->report_changes_fn)
		db->report_changes_fn(db);
	db->changes = tal_free(db->changes);
}

void db_changes_add(struct db_stmt *stmt, const char * expanded)
{
	struct db *db = stmt->db;

	if (stmt->query->readonly) {
		return;
	}
	/* We get a "COMMIT;" after we've sent our changes. */
	if (!db->changes) {
		assert(streq(expanded, "COMMIT;"));
		return;
	}

	tal_arr_expand(&db->changes, tal_strdup(db->changes, expanded));
}

void db_assert_no_outstanding_statements(struct db *db)
{
	struct db_stmt *stmt;

	stmt = list_top(&db->pending_statements, struct db_stmt, list);
	if (stmt)
		db_fatal(stmt->db, "Unfinalized statement %s", stmt->location);
}

static void destroy_db(struct db *db)
{
	db_assert_no_outstanding_statements(db);

	if (db->config->teardown_fn)
		db->config->teardown_fn(db);
}

static struct db_config *db_config_find(const struct db *db, const char *dsn)
{
	size_t num_configs;
	struct db_config **configs = autodata_get(db_backends, &num_configs);
	const char *sep, *driver_name;
	sep = strstr(dsn, "://");

	if (!sep)
		db_fatal(db, "%s doesn't look like a valid data-source name (missing \"://\" separator.", dsn);

	driver_name = tal_strndup(tmpctx, dsn, sep - dsn);

	for (size_t i=0; i<num_configs; i++) {
		if (streq(driver_name, configs[i]->name)) {
			tal_free(driver_name);
			return configs[i];
		}
	}

	tal_free(driver_name);
	return NULL;
}

static struct db_query_set *db_queries_find(const struct db_config *config)
{
	size_t num_queries;
	struct db_query_set **queries = autodata_get(db_queries, &num_queries);

	for (size_t i = 0; i < num_queries; i++) {
		if (streq(config->name, queries[i]->name)) {
			return queries[i];
		}
	}
	return NULL;
}

void db_prepare_for_changes(struct db *db)
{
	assert(!db->changes);
	db->changes = tal_arr(db, const char *, 0);
}

void db_fatal(const struct db *db, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	db->errorfn(db->errorfn_arg, true, fmt, ap);
	va_end(ap);
}

void db_warn(const struct db *db, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	db->errorfn(db->errorfn_arg, false, fmt, ap);
	va_end(ap);
}

struct db *db_open_(const tal_t *ctx, const char *filename,
		    bool developer,
		    void (*errorfn)(void *arg, bool fatal, const char *fmt, va_list ap),
		    void *arg)
{
	struct db *db;

	db = tal(ctx, struct db);
	db->filename = tal_strdup(db, filename);
	db->developer = developer;
	db->errorfn = errorfn;
	db->errorfn_arg = arg;
	db->readonly = false;
	list_head_init(&db->pending_statements);
	if (!strstr(db->filename, "://"))
		db_fatal(db, "Could not extract driver name from \"%s\"", db->filename);

	db->config = db_config_find(db, db->filename);
	if (!db->config)
		db_fatal(db, "Unable to find DB driver for %s", db->filename);

	db->queries = db_queries_find(db->config);
	if (!db->queries)
		db_fatal(db, "Unable to find DB queries for %s", db->config->name);

	tal_add_destructor(db, destroy_db);
	db->in_transaction = NULL;
	db->changes = NULL;

	/* This must be outside a transaction, so catch it */
	assert(!db->in_transaction);

	db_prepare_for_changes(db);
	if (db->config->setup_fn && !db->config->setup_fn(db))
		db_fatal(db, "Error calling DB setup: %s", db->error);
	db_report_changes(db, NULL, 0);

	return db;
}
