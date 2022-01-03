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
	/* Will crash on NULL, which is the Right Thing */
	while (!streq(stmt->query->colnames[col].sqlname,
		      colname)) {
		col = (col + 1) % stmt->query->num_colnames;
	}

#if DEVELOPER
	strset_add(stmt->cols_used, colname);
#endif

	return stmt->query->colnames[col].val;
}

static void db_stmt_free(struct db_stmt *stmt)
{
	if (!stmt->executed)
		db_fatal("Freeing an un-executed statement from %s: %s",
			 stmt->location, stmt->query->query);
#if DEVELOPER
	/* If they never got a db_step, we don't track */
	if (stmt->cols_used) {
		for (size_t i = 0; i < stmt->query->num_colnames; i++) {
			if (!stmt->query->colnames[i].sqlname)
				continue;
			if (!strset_get(stmt->cols_used,
					stmt->query->colnames[i].sqlname)) {
				db_fatal("Never accessed column %s in query %s",
					  stmt->query->colnames[i].sqlname,
					  stmt->query->query);
			}
		}
		strset_clear(stmt->cols_used);
	}
#endif
	if (stmt->inner_stmt)
		stmt->db->config->stmt_free_fn(stmt);
	assert(stmt->inner_stmt == NULL);
}


struct db_stmt *db_prepare_v2_(const char *location, struct db *db,
			       const char *query_id)
{
	struct db_stmt *stmt = tal(db, struct db_stmt);
	size_t num_slots, pos;

	/* Normalize query_id paths, because unit tests are compiled with this
	 * prefix. */
	if (strncmp(query_id, "./", 2) == 0)
		query_id += 2;

	if (!db->in_transaction)
		db_fatal("Attempting to prepare a db_stmt outside of a "
			 "transaction: %s", location);

	/* Look up the query by its ID */
	pos = hash_djb2(query_id) % db->queries->query_table_size;
	for (;;) {
		if (!db->queries->query_table[pos].name)
			db_fatal("Could not resolve query %s", query_id);
		if (streq(query_id, db->queries->query_table[pos].name)) {
			stmt->query = &db->queries->query_table[pos];
			break;
		}
		pos = (pos + 1) % db->queries->query_table_size;
	}

	num_slots = stmt->query->placeholders;
	/* Allocate the slots for placeholders/bindings, zeroed next since
	 * that sets the type to DB_BINDING_UNINITIALIZED for later checks. */
	stmt->bindings = tal_arr(stmt, struct db_binding, num_slots);
	for (size_t i=0; i<num_slots; i++)
		stmt->bindings[i].type = DB_BINDING_UNINITIALIZED;

	stmt->location = location;
	stmt->error = NULL;
	stmt->db = db;
	stmt->executed = false;
	stmt->inner_stmt = NULL;

	tal_add_destructor(stmt, db_stmt_free);

	list_add(&db->pending_statements, &stmt->list);

#if DEVELOPER
	stmt->cols_used = NULL;
#endif /* DEVELOPER */

	return stmt;
}

#define db_prepare_v2(db,query) \
	db_prepare_v2_(__FILE__ ":" stringify(__LINE__), db, query)

bool db_query_prepared(struct db_stmt *stmt)
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

bool db_step(struct db_stmt *stmt)
{
	bool ret;

	assert(stmt->executed);
	ret = stmt->db->config->step_fn(stmt);

#if DEVELOPER
	/* We only track cols_used if we return a result! */
	if (ret && !stmt->cols_used) {
		stmt->cols_used = tal(stmt, struct strset);
		strset_init(stmt->cols_used);
	}
#endif
	return ret;
}

bool db_exec_prepared_v2(struct db_stmt *stmt TAKES)
{
	bool ret = stmt->db->config->exec_fn(stmt);

	/* If this was a write we need to bump the data_version upon commit. */
	stmt->db->dirty = stmt->db->dirty || !stmt->query->readonly;

	stmt->executed = true;
	list_del_from(&stmt->db->pending_statements, &stmt->list);

	/* The driver itself doesn't call `fatal` since we want to override it
	 * for testing. Instead we check here that the error message is set if
	 * we report an error. */
	if (!ret) {
		assert(stmt->error);
		db_fatal("Error executing statement: %s", stmt->error);
	}

	if (taken(stmt))
	    tal_free(stmt);

	return ret;
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

#if DEVELOPER
void db_assert_no_outstanding_statements(struct db *db)
{
	struct db_stmt *stmt;

	stmt = list_top(&db->pending_statements, struct db_stmt, list);
	if (stmt)
		db_fatal("Unfinalized statement %s", stmt->location);
}
#else
void db_assert_no_outstanding_statements(struct db *db)
{
}
#endif


static void destroy_db(struct db *db)
{
	db_assert_no_outstanding_statements(db);

	if (db->config->teardown_fn)
		db->config->teardown_fn(db);
}

static struct db_config *db_config_find(const char *dsn)
{
	size_t num_configs;
	struct db_config **configs = autodata_get(db_backends, &num_configs);
	const char *sep, *driver_name;
	sep = strstr(dsn, "://");

	if (!sep)
		db_fatal("%s doesn't look like a valid data-source name (missing \"://\" separator.", dsn);

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

struct db *db_open(const tal_t *ctx, char *filename)
{
	struct db *db;

	db = tal(ctx, struct db);
	db->filename = tal_strdup(db, filename);
	list_head_init(&db->pending_statements);
	if (!strstr(db->filename, "://"))
		db_fatal("Could not extract driver name from \"%s\"", db->filename);

	db->config = db_config_find(db->filename);
	if (!db->config)
		db_fatal("Unable to find DB driver for %s", db->filename);

	db->queries = db_queries_find(db->config);
	if (!db->queries)
		db_fatal("Unable to find DB queries for %s", db->config->name);

	tal_add_destructor(db, destroy_db);
	db->in_transaction = NULL;
	db->changes = NULL;

	/* This must be outside a transaction, so catch it */
	assert(!db->in_transaction);

	db_prepare_for_changes(db);
	if (db->config->setup_fn && !db->config->setup_fn(db))
		db_fatal("Error calling DB setup: %s", db->error);
	db_report_changes(db, NULL, 0);

	return db;
}
